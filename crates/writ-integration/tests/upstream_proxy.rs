//! Upstreams behind a proxy of the policy (M7.2), with the real `git`, the real `ssh`, the
//! real relay and tunnel (`writd upstream-ssh`, `writd upstream-tunnel`) and a test proxy in
//! front of the test remotes: syncs and writes reach an `ssh://` upstream through SOCKS5 and
//! HTTP CONNECT by a name only the proxy resolves (the daemon never does), an `https://` one
//! too, the host key scan through it; the proxy's password sent to it alone, missing until an
//! approver adds it; and every way a proxy can refuse or fail refused with its reason.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use writ_core::config::PolicyConfig;
use writ_core::names::{KeyId, RepoName};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_integration::binaries::bin;
use writ_integration::https_remote::HttpsRemote;
use writ_integration::proxy::{ProxyKind, ProxyMode, TestProxy};
use writ_integration::remote::TestRemote;
use writ_mirror::credential::{TokenRef, Tokens, UpstreamToken};
use writ_mirror::dial::{DialError, DialWhy, Dialer, ProxyRoute};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, MirrorError, Mirrors, SyncReport};
use writ_signer::Signer;
use writ_signer::software::SoftwareSigner;

/// A name nothing resolves (RFC 6761): only the proxy knows where it goes, as with an onion
/// name.
const HIDDEN: &str = "remote.proxied.invalid";

const PASSWORD: &str = "proxy-password-0123456789";
const TOKEN: &str = "writ-test-https-upstream-token-0123456789";

/// How the policy's proxy is written.
#[derive(Clone)]
struct ProxyEntry {
    url: String,
    /// The password key's id is `proxy-pass`; its token host 127.0.0.1.
    credential: bool,
    connect_timeout: Option<&'static str>,
}

impl ProxyEntry {
    fn of(proxy: &TestProxy, credential: bool) -> Self {
        Self {
            url: proxy.url(),
            credential,
            connect_timeout: None,
        }
    }

    fn yaml(&self, name: &str) -> String {
        let credential = match self.credential {
            true => ", credential: proxy-pass",
            false => "",
        };
        let timeout = self
            .connect_timeout
            .map(|t| format!(", connect_timeout: {t}"))
            .unwrap_or_default();
        format!(
            "proxies:\n  {name}: {{ url: \"{}\"{credential}{timeout} }}\n",
            self.url
        )
    }
}

/// An ssh test remote whose host is [`HIDDEN`] to the daemon, with an upstream repo `demo`.
struct Fixture {
    dir: TempDir,
    runtime: tokio::runtime::Runtime,
    remote: TestRemote,
    key: PrivateKey,
}

impl Fixture {
    fn new() -> Self {
        writ_integration::tools::require();
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let key = generate(KeyKind::Ed25519).unwrap();
        let remote = TestRemote::start(
            &runtime,
            &dir.path().join("remote"),
            key.public_key().clone(),
        );
        let fixture = Self {
            dir,
            runtime,
            remote,
            key,
        };
        let upstream = fixture.remote.repo("demo");
        fixture.git_ok(
            fixture.root(),
            &["init", "-q", "--bare", upstream.to_str().unwrap()],
        );
        fixture
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// A proxy of `kind` (asking for the password when `credential`) that maps [`HIDDEN`] to
    /// the remote.
    fn proxy(&self, kind: ProxyKind, credential: bool) -> TestProxy {
        let proxy = TestProxy::start(
            &self.runtime,
            kind,
            credential.then_some(("writ", PASSWORD)),
        );
        proxy.map(HIDDEN, ([127, 0, 0, 1], self.remote.port).into());
        proxy
    }

    fn url(&self) -> String {
        format!("ssh://git@{HIDDEN}:{}/demo.git", self.remote.port)
    }

    fn pin(&self) -> String {
        let key = self.remote.host_key.public_key().to_openssh().unwrap();
        let key: Vec<&str> = key.split(' ').take(2).collect();
        format!("[{HIDDEN}]:{} {}", self.remote.port, key.join(" "))
    }

    fn policy(&self, proxy: Option<&ProxyEntry>) -> PolicyConfig {
        let pin = self.pin();
        let (pin_host, pin_key) = pin.split_once(' ').unwrap();
        let proxies = proxy.map(|p| p.yaml("p")).unwrap_or_default();
        let via = proxy.map(|_| "    proxy: p\n").unwrap_or_default();
        PolicyConfig::from_yaml(&format!(
            "keys:\n  upstream-01: {{ use: upstream, kind: ssh, algorithm: ed25519 }}\n  \
             proxy-pass: {{ use: upstream, kind: token, host: \"127.0.0.1\" }}\n\
             upstream_hosts:\n  \"{pin_host}\": [\"{pin_key}\"]\n{proxies}\
             repos:\n  demo:\n    upstream: {}\n    upstream_credential: upstream-01\n{via}    \
             templates: [t]\n{TEMPLATES}",
            self.url()
        ))
        .unwrap()
    }

    fn config(&self) -> MirrorConfig {
        MirrorConfig {
            root: self.root().join("repos"),
            run_dir: self.root().join("mirror"),
            relay: bin("writd"),
            git: writ_mirror::testing::git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(&format!("{}\n", self.pin())).unwrap(),
            ca_certs: None,
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            first_sync_timeout: Duration::from_secs(60),
            max_fetch_bytes: 64 << 20,
            scan_timeout: writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        }
    }

    fn signer(&self) -> Arc<dyn Signer> {
        Arc::new(
            SoftwareSigner::new(vec![("upstream-01".parse().unwrap(), self.key.clone())]).unwrap(),
        )
    }

    fn open(&self, policy: &PolicyConfig, password: Option<&str>) -> Mirrors {
        self.runtime
            .block_on(Mirrors::open(
                self.config(),
                policy.repos(),
                policy.proxies(),
                self.signer(),
                &tokens(password),
            ))
            .unwrap()
    }

    fn sync(&self, mirrors: &Mirrors) -> Result<SyncReport, MirrorError> {
        self.runtime
            .block_on(async { mirrors.lock(&demo()).await?.sync().await })
    }

    fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.root())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "A")
            .env("GIT_AUTHOR_EMAIL", "a@b")
            .env("GIT_COMMITTER_NAME", "A")
            .env("GIT_COMMITTER_EMAIL", "a@b")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A commit on upstream's `main`.
    fn upstream_commit(&self, file: &str) -> String {
        let work = self.root().join("work");
        if !work.exists() {
            self.git_ok(self.root(), &["init", "-q", work.to_str().unwrap()]);
        }
        std::fs::write(work.join(file), format!("{file}\n")).unwrap();
        self.git_ok(&work, &["add", file]);
        self.git_ok(&work, &["commit", "-q", "-m", file]);
        let upstream = self.remote.repo("demo");
        self.git_ok(
            &work,
            &[
                "push",
                "-q",
                "-f",
                upstream.to_str().unwrap(),
                "HEAD:refs/heads/main",
            ],
        );
        self.git_ok(&work, &["rev-parse", "HEAD"])
    }

    fn mirror_main(&self) -> String {
        self.git_ok(
            &self.root().join("repos/demo.git"),
            &["rev-parse", "refs/heads/main"],
        )
    }

    fn sockets(&self) -> usize {
        std::fs::read_dir(self.root().join("mirror/sockets"))
            .unwrap()
            .count()
    }
}

const TEMPLATES: &str = "templates:\n  t:\n    operations: [fetch]\n    branches: [\"*\"]\n    \
     committer_emails: [\"a@b\"]\n    max_ttl: 1h\n    max_signatures: 1\n    \
     max_pushes: 1\n    max_ops_per_minute: 10\n    max_push_size: 1MB\n";

/// The keystore's tokens: the proxy's password when given.
fn tokens(password: Option<&str>) -> Tokens {
    password
        .map(|p| {
            let id = "proxy-pass".parse::<KeyId>().unwrap();
            (
                id.clone(),
                Arc::new(TokenRef::held(
                    id,
                    UpstreamToken::from_bytes(p.as_bytes()).unwrap(),
                )),
            )
        })
        .into_iter()
        .collect()
}

fn demo() -> RepoName {
    "demo".parse().unwrap()
}

/// The proxy's refusal, from a sync's error.
fn why(result: Result<SyncReport, MirrorError>) -> DialWhy {
    match result {
        Err(MirrorError::Proxy {
            failure: DialError::Proxy { proxy, why },
            ..
        }) => {
            assert_eq!(proxy.as_str(), "p");
            why
        }
        other => panic!("expected the proxy's refusal, got {other:?}"),
    }
}

#[test]
fn an_ssh_upstream_behind_a_proxy_is_synced_and_written_through_it_by_a_name_it_alone_resolves() {
    for kind in [ProxyKind::Socks5, ProxyKind::Http] {
        let f = Fixture::new();
        let main = f.upstream_commit("a");
        let proxy = f.proxy(kind, true);
        let policy = f.policy(Some(&ProxyEntry::of(&proxy, true)));
        let mirrors = f.open(&policy, Some(PASSWORD));
        let SyncReport::Synced { moved, .. } = f.sync(&mirrors).unwrap() else {
            panic!("synced");
        };
        assert_eq!(moved.len(), 1, "{kind:?}: {moved:?}");
        assert_eq!(f.mirror_main(), main);
        // Every tunnel asked for the registry's host by name: the daemon resolved nothing (it
        // can't: the name is .invalid), and the proxy took the password.
        let asked = proxy.asked();
        assert!(!asked.is_empty());
        let wanted = format!("{HIDDEN}:{}", f.remote.port);
        assert!(asked.iter().all(|a| *a == wanted), "{kind:?}: {asked:?}");
        // The repo check reads, syncs and writes (nothing pushed) through it too.
        let steps = f.runtime.block_on(mirrors.check(&demo())).unwrap();
        let said: Vec<(&str, bool)> = steps.iter().map(|s| (s.what, s.ok)).collect();
        assert_eq!(
            said,
            [("read", true), ("sync", true), ("write", true)],
            "{kind:?}: {steps:?}"
        );
        assert!(proxy.asked().len() > asked.len());
        // Every operation's sockets went with it.
        assert_eq!(f.sockets(), 0);
    }
}

/// A repo reached directly whose upstream can't be reached (here: a name no resolver knows,
/// which only a proxy could map): every operation goes through the daemon's own proxy, so git
/// only says that proxy failed; the error says the dial's reason with upstream named, for the
/// audit line, and the agent is told nothing of it (the review after M7.6, M-5 and M-6).
#[test]
fn a_direct_upstream_that_can_t_be_reached_is_named_in_the_error_never_to_the_agent() {
    let f = Fixture::new();
    f.upstream_commit("a");
    let mirrors = f.open(&f.policy(None), None);
    let error = f.sync(&mirrors).unwrap_err();
    let MirrorError::Upstream { upstream, why, .. } = &error else {
        panic!("expected upstream's dial failure, got {error:?}");
    };
    assert_eq!(upstream, &f.url());
    assert!(why.starts_with("cannot reach it: "), "{why}");
    assert!(error.to_string().contains(HIDDEN), "{error}");
    let told = error.for_agent();
    assert_eq!(told, "repo demo: upstream can't be reached as configured");
}

#[test]
fn an_https_upstream_behind_a_proxy_is_synced_through_it() {
    for kind in [ProxyKind::Socks5, ProxyKind::Http] {
        writ_integration::tools::require();
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let remote = HttpsRemote::start(&runtime, &dir.path().join("remote"), TOKEN);
        let upstream = dir.path().join("remote/demo.git");
        let git = |cwd: &Path, args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "A")
                .env("GIT_AUTHOR_EMAIL", "a@b")
                .env("GIT_COMMITTER_NAME", "A")
                .env("GIT_COMMITTER_EMAIL", "a@b")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(
            dir.path(),
            &["init", "-q", "--bare", upstream.to_str().unwrap()],
        );
        let work = dir.path().join("work");
        git(dir.path(), &["init", "-q", work.to_str().unwrap()]);
        std::fs::write(work.join("a"), "a\n").unwrap();
        git(&work, &["add", "a"]);
        git(&work, &["commit", "-q", "-m", "a"]);
        git(
            &work,
            &[
                "push",
                "-q",
                upstream.to_str().unwrap(),
                "HEAD:refs/heads/main",
            ],
        );
        // The certificate names a host no resolver knows: only the proxy reaches it, so a
        // request that skipped the proxy fails (the review after M7.6, T-6).
        let port = remote
            .url("demo")
            .rsplit_once(':')
            .unwrap()
            .1
            .split('/')
            .next()
            .unwrap()
            .to_owned();
        let name = writ_integration::https_remote::UNRESOLVED;
        let url = format!("https://{name}:{port}/demo.git");
        let proxy = TestProxy::start(&runtime, kind, Some(("writ", PASSWORD)));
        proxy.map(name, ([127, 0, 0, 1], port.parse::<u16>().unwrap()).into());
        let policy = PolicyConfig::from_yaml(&format!(
            "keys:\n  token-01: {{ use: upstream, kind: token, host: {name} }}\n  \
             proxy-pass: {{ use: upstream, kind: token, host: \"127.0.0.1\" }}\n\
             proxies:\n  p: {{ url: \"{}\", credential: proxy-pass }}\n\
             repos:\n  demo:\n    upstream: {url}\n    upstream_credential: token-01\n    \
             proxy: p\n    templates: [t]\n{TEMPLATES}",
            proxy.url()
        ))
        .unwrap();
        let mut tokens = tokens(Some(PASSWORD));
        tokens.insert(
            "token-01".parse().unwrap(),
            Arc::new(TokenRef::held(
                "token-01".parse().unwrap(),
                UpstreamToken::from_bytes(TOKEN.as_bytes()).unwrap(),
            )),
        );
        let config = MirrorConfig {
            root: dir.path().join("repos"),
            run_dir: dir.path().join("mirror"),
            relay: bin("writd"),
            git: writ_mirror::testing::git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(
                "unreachable.invalid ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
            )
            .unwrap(),
            ca_certs: Some(remote.ca_pem.clone()),
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            first_sync_timeout: Duration::from_secs(60),
            max_fetch_bytes: 64 << 20,
            scan_timeout: writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        };
        let mirrors = runtime
            .block_on(Mirrors::open(
                config,
                policy.repos(),
                policy.proxies(),
                Arc::new(SoftwareSigner::empty()),
                &tokens,
            ))
            .unwrap();
        let synced = runtime.block_on(async { mirrors.lock(&demo()).await?.sync().await });
        assert!(
            matches!(synced, Ok(SyncReport::Synced { .. })),
            "{kind:?}: {synced:?}"
        );
        let asked = proxy.asked();
        assert!(!asked.is_empty());
        assert!(
            asked.iter().all(|a| *a == format!("{name}:{port}")),
            "{kind:?}: {asked:?}"
        );
        // Every connection the remote took is one the proxy opened.
        assert_eq!(remote.connections(), asked.len(), "{kind:?}");
        assert!(remote.requests() > 0);
    }
}

#[test]
fn every_way_a_proxy_refuses_or_fails_refuses_the_sync_with_its_reason() {
    let f = Fixture::new();
    f.upstream_commit("a");
    for kind in [ProxyKind::Socks5, ProxyKind::Http] {
        // A wrong password: refused, and the password never in what is said.
        let proxy = f.proxy(kind, true);
        let mirrors = f.open(
            &f.policy(Some(&ProxyEntry::of(&proxy, true))),
            Some("not-it"),
        );
        let result = f.sync(&mirrors);
        let said = format!("{result:?}");
        assert_eq!(why(result), DialWhy::CredentialRefused, "{kind:?}");
        assert!(
            !said.contains("not-it") && !said.contains(PASSWORD),
            "{said}"
        );
        // A proxy that asks for a password the policy doesn't give.
        let no_user = ProxyEntry {
            url: proxy.url().replace("writ@", ""),
            credential: false,
            connect_timeout: None,
        };
        let mirrors = f.open(&f.policy(Some(&no_user)), None);
        assert_eq!(why(f.sync(&mirrors)), DialWhy::CredentialNeeded, "{kind:?}");
        // Refusing every tunnel.
        let proxy = f.proxy(kind, false);
        proxy.set_mode(ProxyMode::Refuse);
        let mirrors = f.open(&f.policy(Some(&ProxyEntry::of(&proxy, false))), None);
        let expected = match kind {
            ProxyKind::Socks5 => "not allowed by its rules (status 2)",
            ProxyKind::Http => "403 Forbidden",
        };
        assert_eq!(why(f.sync(&mirrors)), DialWhy::Refused(expected.to_owned()));
        // A name it doesn't know.
        let unknown = TestProxy::start(&f.runtime, kind, None);
        let mirrors = f.open(&f.policy(Some(&ProxyEntry::of(&unknown, false))), None);
        let expected = match kind {
            ProxyKind::Socks5 => "host unreachable (status 4)",
            ProxyKind::Http => "502 Bad Gateway",
        };
        assert_eq!(why(f.sync(&mirrors)), DialWhy::Refused(expected.to_owned()));
        // Silent past its connect_timeout.
        let silent = f.proxy(kind, false);
        silent.set_mode(ProxyMode::Silent);
        let mut entry = ProxyEntry::of(&silent, false);
        entry.connect_timeout = Some("1s");
        let mirrors = f.open(&f.policy(Some(&entry)), None);
        assert_eq!(why(f.sync(&mirrors)), DialWhy::Timeout(1), "{kind:?}");
    }
    // No proxy there at all: a port nothing listens on (taken, then let go).
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let gone = ProxyEntry {
        url: format!("socks5://127.0.0.1:{port}"),
        credential: false,
        connect_timeout: None,
    };
    let mirrors = f.open(&f.policy(Some(&gone)), None);
    match why(f.sync(&mirrors)) {
        DialWhy::Unreachable(said) => assert!(
            said.to_ascii_lowercase().starts_with("connection refused"),
            "{said}"
        ),
        other => panic!("expected the proxy unreachable, got {other:?}"),
    }
    // A proxy whose name nothing resolves: what the resolver said.
    let unknown = ProxyEntry {
        url: "socks5://proxy.nowhere.invalid:1080".to_owned(),
        credential: false,
        connect_timeout: None,
    };
    let mirrors = f.open(&f.policy(Some(&unknown)), None);
    match why(f.sync(&mirrors)) {
        DialWhy::Unreachable(said) => assert!(said.contains("lookup"), "{said}"),
        other => panic!("expected the proxy unreachable, got {other:?}"),
    }
    // Nothing was mirrored by any of them.
    let refs = f.git_ok(&f.root().join("repos/demo.git"), &["for-each-ref"]);
    assert_eq!(refs, "");
}

#[test]
fn a_missing_proxy_password_refuses_every_operation_until_it_is_added() {
    let f = Fixture::new();
    let main = f.upstream_commit("a");
    let proxy = f.proxy(ProxyKind::Socks5, true);
    let policy = f.policy(Some(&ProxyEntry::of(&proxy, true)));
    let mirrors = f.open(&policy, None);
    match f.sync(&mirrors) {
        Err(error @ MirrorError::NoProxyPassword { .. }) => assert_eq!(
            error.to_string(),
            "repo demo: proxy p's password (proxy-pass) isn't in the keystore yet: an approver \
             adds it with `writ admin token proxy-pass`"
        ),
        other => panic!("expected no password, got {other:?}"),
    }
    // Nothing was sent anywhere.
    assert_eq!(proxy.asked(), Vec::<String>::new());
    assert_eq!(f.remote.upload_packs(), 0);
    // Added (the daemon reopens the registry with the keystore's tokens): used at once.
    let reopened = f
        .runtime
        .block_on(mirrors.with_registry(
            policy.repos(),
            policy.proxies(),
            f.config().pinned,
            f.signer(),
            &tokens(Some(PASSWORD)),
        ))
        .unwrap();
    assert!(matches!(f.sync(&reopened), Ok(SyncReport::Synced { .. })));
    assert_eq!(f.mirror_main(), main);
}

#[test]
fn a_changed_proxy_reopens_the_repo_and_the_new_one_is_used_at_once() {
    let f = Fixture::new();
    f.upstream_commit("a");
    let first = f.proxy(ProxyKind::Socks5, false);
    let second = f.proxy(ProxyKind::Http, true);
    let policy = f.policy(Some(&ProxyEntry::of(&first, false)));
    let mirrors = f.open(&policy, Some(PASSWORD));
    f.sync(&mirrors).unwrap();
    let before = first.asked().len();
    assert!(before > 0);
    // The same registry: the repo kept, as it was.
    let same = f
        .runtime
        .block_on(mirrors.with_registry(
            policy.repos(),
            policy.proxies(),
            f.config().pinned,
            f.signer(),
            &tokens(Some(PASSWORD)),
        ))
        .unwrap();
    assert!(mirrors.shares_lock_with(&same, &demo()));
    // The proxy's entry changed (the repo's didn't): reopened, through the new one.
    let changed = f.policy(Some(&ProxyEntry::of(&second, true)));
    let reopened = f
        .runtime
        .block_on(mirrors.with_registry(
            changed.repos(),
            changed.proxies(),
            f.config().pinned,
            f.signer(),
            &tokens(Some(PASSWORD)),
        ))
        .unwrap();
    f.upstream_commit("b");
    assert!(matches!(f.sync(&reopened), Ok(SyncReport::Synced { .. })));
    assert_eq!(first.asked().len(), before);
    assert!(!second.asked().is_empty());
}

#[test]
fn the_host_key_scan_goes_through_the_proxy_which_resolves_the_name() {
    let f = Fixture::new();
    for kind in [ProxyKind::Socks5, ProxyKind::Http] {
        let proxy = f.proxy(kind, true);
        let policy = f.policy(Some(&ProxyEntry::of(&proxy, true)));
        let name = "p".parse().unwrap();
        let route = ProxyRoute::new(&name, policy.proxy(&name).unwrap(), &tokens(Some(PASSWORD)));
        let dialer = Dialer::Proxy(Arc::new(route));
        let keys = f
            .runtime
            .block_on(writ_mirror::scan::scan(
                HIDDEN,
                f.remote.port,
                &dialer,
                writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
            ))
            .unwrap();
        assert_eq!(
            keys.iter().map(|k| k.key_data()).collect::<Vec<_>>(),
            [f.remote.host_key.public_key().key_data()]
        );
        let asked = proxy.asked();
        assert!(!asked.is_empty());
        assert!(
            asked
                .iter()
                .all(|a| *a == format!("{HIDDEN}:{}", f.remote.port))
        );
        // Directly, the name reaches nothing.
        let direct = f.runtime.block_on(writ_mirror::scan::scan(
            HIDDEN,
            f.remote.port,
            &Dialer::Direct,
            writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        ));
        assert!(
            matches!(
                direct,
                Err(writ_mirror::scan::ScanError::Unreachable { .. })
            ),
            "{direct:?}"
        );
        // A refusing proxy: the scan says which proxy, and why.
        proxy.set_mode(ProxyMode::Refuse);
        let refused = f.runtime.block_on(writ_mirror::scan::scan(
            HIDDEN,
            f.remote.port,
            &dialer,
            writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        ));
        match refused {
            Err(writ_mirror::scan::ScanError::Unreachable { target, why }) => {
                assert_eq!(
                    target,
                    format!("{HIDDEN}:{} through proxy p", f.remote.port)
                );
                assert!(why.starts_with("proxy p: it refused the tunnel"), "{why}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
