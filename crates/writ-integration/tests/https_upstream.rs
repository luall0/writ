//! Mirror syncs against an HTTPS test remote (M4.5), with the real `git`, its real HTTPS and
//! the real credential helper (`writd upstream-credential`): the token reaches upstream and
//! nothing else (no file, no URL, no error), only through the daemon's proxy and only to the
//! registry's host; and everything a hostile or broken upstream could try (another
//! certificate, a redirect, too many bytes, no answer, the token printed back) refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use writ_core::config::PolicyConfig;
use writ_core::names::{KeyId, RepoName};
use writ_integration::binaries::bin;
use writ_integration::https_remote::{HttpsMode, HttpsRemote};
use writ_mirror::credential::{TokenRef, TokenSource, UpstreamToken};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, MirrorError, Mirrors, SyncReport};
use writ_signer::software::SoftwareSigner;

const TOKEN: &str = "writ-test-https-upstream-token-0123456789";

/// A pin for a host nothing reaches: the pinned set can't be empty, and an HTTPS upstream
/// needs none.
const UNREACHABLE_PIN: &str = "unreachable.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";

/// An HTTPS test remote with an upstream repo `demo` holding one commit on `main`.
struct Fixture {
    dir: TempDir,
    runtime: tokio::runtime::Runtime,
    remote: HttpsRemote,
    main: String,
    tokens: Arc<Keystore>,
}

/// The keystore as the mirrors see it: each use unwraps the token afresh (counted), or is
/// refused once `refusing` is set (a hardware key removed, a device refusing).
#[derive(Default)]
struct Keystore {
    uses: std::sync::atomic::AtomicUsize,
    refusing: std::sync::atomic::AtomicBool,
}

impl TokenSource for Keystore {
    fn unwrap(&self, id: &KeyId, version: &str) -> Result<UpstreamToken, String> {
        assert_eq!((id.as_str(), version), ("token-01", "v1"));
        self.uses.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("the device refuses".to_owned());
        }
        UpstreamToken::from_bytes(TOKEN.as_bytes()).map_err(str::to_owned)
    }
}

impl Keystore {
    fn uses(&self) -> usize {
        self.uses.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Fixture {
    fn new() -> Self {
        writ_integration::tools::require();
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let remote = HttpsRemote::start(&runtime, &dir.path().join("remote"), TOKEN);
        let mut fixture = Self {
            dir,
            runtime,
            remote,
            main: String::new(),
            tokens: Arc::default(),
        };
        let upstream = fixture.upstream();
        fixture.git_ok(
            fixture.root(),
            &["init", "-q", "--bare", upstream.to_str().unwrap()],
        );
        fixture.main = fixture.upstream_commit("main", "a", "a\n");
        fixture
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn upstream(&self) -> PathBuf {
        self.root().join("remote/demo.git")
    }

    fn mirror(&self) -> PathBuf {
        self.root().join("repos/demo.git")
    }

    fn config(&self) -> MirrorConfig {
        MirrorConfig {
            root: self.root().join("repos"),
            run_dir: self.root().join("mirror"),
            relay: bin("writd"),
            git: writ_mirror::testing::git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN).unwrap(),
            ca_certs: Some(self.remote.ca_pem.clone()),
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 64 << 20,
            scan_timeout: writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        }
    }

    fn open_at(&self, config: MirrorConfig, url: &str) -> Result<Mirrors, MirrorError> {
        let policy = PolicyConfig::from_yaml(&policy_yaml(url)).unwrap();
        let signer = Arc::new(SoftwareSigner::empty());
        let id: KeyId = "token-01".parse().unwrap();
        let source: Arc<dyn TokenSource> = self.tokens.clone();
        let tokens = BTreeMap::from([(
            id.clone(),
            Arc::new(TokenRef::new(id, "v1".to_owned(), source)),
        )]);
        self.runtime.block_on(Mirrors::open(
            config,
            policy.repos(),
            policy.proxies(),
            signer,
            &tokens,
        ))
    }

    fn open_with(&self, config: MirrorConfig) -> Mirrors {
        self.open_at(config, &self.remote.url("demo")).unwrap()
    }

    fn open(&self) -> Mirrors {
        self.open_with(self.config())
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

    /// A commit on upstream's `branch` (made in a scratch clone, pushed locally).
    fn upstream_commit(&self, branch: &str, file: &str, content: &str) -> String {
        let work = self.root().join("work");
        if !work.exists() {
            self.git_ok(self.root(), &["init", "-q", work.to_str().unwrap()]);
        }
        std::fs::write(work.join(file), content).unwrap();
        self.git_ok(&work, &["add", file]);
        self.git_ok(&work, &["commit", "-q", "-m", file]);
        let upstream = self.upstream();
        self.git_ok(
            &work,
            &[
                "push",
                "-q",
                "-f",
                upstream.to_str().unwrap(),
                &format!("HEAD:refs/heads/{branch}"),
            ],
        );
        self.git_ok(&work, &["rev-parse", "HEAD"])
    }

    fn refs(&self) -> Vec<String> {
        let out = self.git_ok(
            &self.mirror(),
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        );
        out.lines().map(str::to_owned).collect()
    }

    /// The files left in the operations' socket directory.
    fn sockets(&self) -> Vec<String> {
        std::fs::read_dir(self.root().join("mirror/sockets"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Every file under the daemon's side (the mirrors and their run directory) holding the
    /// token, by path.
    fn files_holding_the_token(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for dir in ["repos", "mirror"] {
            walk(&self.root().join(dir), &mut |path| {
                let bytes = std::fs::read(path).unwrap_or_default();
                if bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()) {
                    found.push(path.to_owned());
                }
            });
        }
        found
    }
}

fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.map(Result::unwrap) {
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            walk(&path, visit);
        } else if kind.is_file() {
            visit(&path);
        }
    }
}

fn demo() -> RepoName {
    "demo".parse().unwrap()
}

fn policy_yaml(upstream: &str) -> String {
    let host = match writ_core::upstream::Upstream::parse(upstream) {
        Ok(writ_core::upstream::Upstream::Https(url)) => url.host().to_owned(),
        _ => "127.0.0.1".to_owned(),
    };
    format!(
        "keys:\n  token-01: {{ use: upstream, kind: token, host: \"{host}\" }}\n\
         repos:\n  demo:\n    upstream: {upstream}\n    upstream_credential: token-01\n    \
         templates: [t]\n\
         templates:\n  t:\n    operations: [fetch]\n    branches: [\"*\"]\n    \
         committer_emails: [\"a@b\"]\n    max_ttl: 1h\n    max_signatures: 1\n    \
         max_pushes: 1\n    max_ops_per_minute: 10\n    max_push_size: 1MB\n"
    )
}

#[test]
fn an_https_upstream_syncs_with_the_token_which_nothing_else_holds() {
    let f = Fixture::new();
    let mirrors = f.open();
    let SyncReport::Synced { moved, .. } = f.sync(&mirrors).unwrap() else {
        panic!("synced");
    };
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert_eq!(f.refs(), [format!("refs/heads/main {}", f.main)]);
    // Every authorized request carried the default user name; the token went nowhere else.
    let users = f.remote.users();
    assert!(!users.is_empty());
    assert!(users.iter().all(|u| u == "writ"), "{users:?}");
    assert_eq!(f.files_holding_the_token(), Vec::<PathBuf>::new());
    // The mirror's config names no remote, URL or credential.
    let config = std::fs::read_to_string(f.mirror().join("config")).unwrap();
    for word in ["remote", "url", "credential", "https"] {
        assert!(!config.contains(word), "{word} in {config}");
    }
    // The operation's sockets are gone.
    assert_eq!(f.sockets(), Vec::<String>::new());

    // Upstream moves on: the next sync follows.
    let next = f.upstream_commit("main", "b", "b\n");
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs(), [format!("refs/heads/main {next}")]);
}

/// M7.6: the mirrors hold no token, only where to unwrap it: each operation unwraps it once,
/// and one whose unwrap is refused fails alone, before reaching upstream, the mirror still
/// open.
#[test]
fn the_token_is_unwrapped_for_each_operation_and_a_refused_unwrap_fails_that_one_alone() {
    let f = Fixture::new();
    let mirrors = f.open();
    assert_eq!(f.tokens.uses(), 0, "opening the mirrors unwraps nothing");
    f.sync(&mirrors).unwrap();
    assert_eq!(f.tokens.uses(), 1);
    f.sync(&mirrors).unwrap();
    assert_eq!(f.tokens.uses(), 2, "once per operation");
    let requests = f.remote.requests();

    f.tokens
        .refusing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    match f.sync(&mirrors) {
        Err(MirrorError::TokenUnwrap { repo, key, why }) => {
            assert_eq!(repo, demo());
            assert_eq!(key.as_str(), "token-01");
            assert_eq!(why, "the device refuses");
        }
        other => panic!("expected TokenUnwrap, got {other:?}"),
    }
    assert_eq!(f.remote.requests(), requests, "nothing reached upstream");
    assert_eq!(f.sockets(), Vec::<String>::new());

    // The device answers again: the next operation works, on the same mirrors.
    f.tokens
        .refusing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let next = f.upstream_commit("main", "b", "b\n");
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs(), [format!("refs/heads/main {next}")]);
}

#[test]
fn the_user_named_in_the_url_is_the_one_sent_with_the_token() {
    let f = Fixture::new();
    let url = f
        .remote
        .url("demo")
        .replace("https://", "https://x-token-auth@");
    let mirrors = f.open_at(f.config(), &url).unwrap();
    f.sync(&mirrors).unwrap();
    let users = f.remote.users();
    assert!(!users.is_empty());
    assert!(users.iter().all(|u| u == "x-token-auth"), "{users:?}");
}

#[test]
fn a_token_upstream_refuses_fails_the_sync_without_showing_it() {
    let f = Fixture::new();
    let mirrors = f.open();
    f.remote.set_token("another-token-entirely");
    match f.sync(&mirrors) {
        Err(MirrorError::Git { stderr, .. }) => {
            assert!(stderr.contains("Authentication failed"), "{stderr}");
            assert!(!stderr.contains(TOKEN), "{stderr}");
        }
        other => panic!("expected Git, got {other:?}"),
    }
    assert!(f.refs().is_empty());
    assert!(f.remote.users().is_empty());
    assert_eq!(f.sockets(), Vec::<String>::new());
    // The right token again: the sync works.
    f.remote.set_token(TOKEN);
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs().len(), 1);
}

#[test]
fn a_certificate_from_a_ca_the_daemon_does_not_trust_is_refused_before_any_token() {
    let f = Fixture::new();
    // The operator's CA file holds another certificate.
    let other = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let mut config = f.config();
    config.ca_certs = Some(other.cert.pem());
    let mirrors = f.open_with(config);
    match f.sync(&mirrors) {
        Err(MirrorError::Certificate { why, .. }) => {
            assert!(!why.contains(TOKEN), "{why}");
        }
        other => panic!("expected Certificate, got {other:?}"),
    }
    // The system's CAs (no CA file): the remote's self-signed certificate is refused too.
    let mut config = f.config();
    config.ca_certs = None;
    let mirrors = f.open_with(config);
    assert!(
        matches!(f.sync(&mirrors), Err(MirrorError::Certificate { .. })),
        "the system's CAs don't trust a self-signed certificate"
    );
    assert!(
        !f.root().join("mirror/ca_certs.pem").exists(),
        "the old CA file is gone"
    );
    assert!(f.remote.users().is_empty(), "no request carried the token");
    assert!(f.refs().is_empty());
}

#[test]
fn a_redirect_is_refused_and_the_token_never_follows_it() {
    let f = Fixture::new();
    let elsewhere = HttpsRemote::start(&f.runtime, &f.root().join("remote"), TOKEN);
    f.remote.set_mode(HttpsMode::Redirect(format!(
        "https://127.0.0.1:{}",
        elsewhere.port
    )));
    let mirrors = f.open();
    match f.sync(&mirrors) {
        Err(MirrorError::Git { stderr, .. }) => {
            assert!(stderr.contains("returned error: 302"), "{stderr}");
        }
        other => panic!("expected Git, got {other:?}"),
    }
    assert_eq!(elsewhere.requests(), 0, "git never went where it was sent");
    assert!(f.refs().is_empty());
}

#[test]
fn a_sync_past_the_byte_cap_is_refused_on_both_sides() {
    let f = Fixture::new();
    let mut small = f.config();
    small.max_fetch_bytes = 100_000;
    let mirrors = f.open_with(small.clone());
    // A remote that floods its refs: cut at the cap, nothing lands.
    f.remote.set_mode(HttpsMode::Flood(500_000));
    match f.sync(&mirrors) {
        Err(MirrorError::TooLarge { max, .. }) => assert_eq!(max, 100_000),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(f.refs().is_empty());
    assert_eq!(f.sockets(), Vec::<String>::new());
    // A pack bigger than the cap (300 KB of random bytes): the same.
    f.remote.set_mode(HttpsMode::Serve);
    let mut random = vec![0u8; 300_000];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").unwrap(),
        &mut random,
    )
    .unwrap();
    let random: String = random.iter().map(|b| format!("{b:02x}")).collect();
    f.upstream_commit("main", "big", &random);
    assert!(matches!(
        f.sync(&mirrors),
        Err(MirrorError::TooLarge { .. })
    ));
    assert!(f.refs().is_empty());
    // Under a cap above it, the same sync passes.
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs().len(), 1);
}

#[test]
fn an_upstream_that_never_answers_is_cut_at_the_deadline() {
    let f = Fixture::new();
    f.remote.set_mode(HttpsMode::Hang);
    let mut config = f.config();
    config.timeout = Duration::from_secs(2);
    let mirrors = f.open_with(config);
    match f.sync(&mirrors) {
        Err(MirrorError::Timeout { seconds, .. }) => assert_eq!(seconds, 2),
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(f.refs().is_empty());
    assert_eq!(f.sockets(), Vec::<String>::new());
    f.remote.set_mode(HttpsMode::Serve);
    let report = f.runtime.block_on(mirrors.sync_if_stale(&demo())).unwrap();
    assert!(matches!(report, SyncReport::Synced { .. }), "{report:?}");
}

#[test]
fn a_hostile_upstream_printing_the_token_back_has_it_taken_out() {
    let f = Fixture::new();
    f.remote.set_mode(HttpsMode::Echo);
    let mirrors = f.open();
    match f.sync(&mirrors) {
        Err(MirrorError::Git { stderr, .. }) => {
            assert!(
                stderr.contains(
                    "the password you sent is <redacted>, split <redacted>, as Basic <redacted>"
                ),
                "{stderr}"
            );
            assert!(!stderr.contains(TOKEN), "{stderr}");
            use base64ct::Encoding as _;
            let basic = base64ct::Base64::encode_string(format!("writ:{TOKEN}").as_bytes());
            assert!(!stderr.contains(&basic), "{stderr}");
        }
        other => panic!("expected Git, got {other:?}"),
    }
}

#[test]
fn the_operator_s_cas_are_the_only_ones_git_is_given() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    // With `ca_certs`, git also gets an empty CA directory: curl built with a default one
    // (Debian's) keeps trusting it when only the file is named (the end-to-end scenario 13
    // shows it with a certificate the system store trusts).
    let ca_path = f.root().join("mirror/ca_path");
    drop(f.open());
    let mode = std::fs::metadata(&ca_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    assert_eq!(std::fs::read_dir(&ca_path).unwrap().count(), 0);

    // A certificate planted there is gone before any sync: the operator's file names another
    // CA, so the remote is refused.
    std::fs::write(ca_path.join("planted.pem"), &f.remote.ca_pem).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let mut config = f.config();
    config.ca_certs = Some(other.cert.pem());
    let mirrors = f.open_with(config);
    assert_eq!(std::fs::read_dir(&ca_path).unwrap().count(), 0);
    assert!(
        matches!(f.sync(&mirrors), Err(MirrorError::Certificate { .. })),
        "only the operator's CAs"
    );
    assert!(f.remote.users().is_empty(), "no request carried the token");

    // Something that can't be removed (a directory) stops the start: never a CA path that
    // isn't empty.
    std::fs::create_dir(ca_path.join("certs")).unwrap();
    match f.open_at(f.config(), &f.remote.url("demo")) {
        Err(MirrorError::Io { what, path, .. }) => {
            assert_eq!(what, "cannot remove");
            assert_eq!(path, ca_path.join("certs"));
        }
        other => panic!("expected the CA path refused, got {:?}", other.err()),
    }
}
