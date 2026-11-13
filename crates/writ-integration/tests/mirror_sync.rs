//! Mirror syncs against a test remote, with the real `git`, the real `ssh` and the real
//! relay (`writd upstream-ssh`): what a sync takes from upstream, and everything a hostile or
//! broken upstream could try (bad objects, another object format, another host key, too many
//! bytes, no answer) refused with nothing left in the mirror.

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
use writ_core::config::{NotesRef, PolicyConfig};
use writ_core::names::RepoName;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_integration::binaries::bin;
use writ_integration::remote::{Mode, TestRemote};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{
    MAX_LOOKUPS, MAX_NOTE_TEXT, MAX_NOTES, MirrorConfig, MirrorError, Mirrors, Note, NotesPushed,
    SyncReport,
};
use writ_signer::Signer;
use writ_signer::software::SoftwareSigner;

/// A test remote with an upstream repo `demo`, and what the daemon needs to mirror it.
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
        fixture.git_ok(
            fixture.root(),
            &["init", "-q", "--bare", fixture.upstream().to_str().unwrap()],
        );
        fixture
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn upstream(&self) -> PathBuf {
        self.remote.repo("demo")
    }

    fn mirror(&self) -> PathBuf {
        self.root().join("repos/demo.git")
    }

    fn policy(&self, format: &str) -> PolicyConfig {
        PolicyConfig::from_yaml(&policy_yaml(
            &self.remote.url("demo"),
            "upstream-01",
            format,
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
            pinned: PinnedHosts::parse(&format!("{}\n", self.remote.known_hosts_line())).unwrap(),
            ca_certs: None,
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 64 << 20,
            scan_timeout: writ_mirror::scan::DEFAULT_HANDSHAKE_DEADLINE,
        }
    }

    fn signer(&self) -> Arc<dyn Signer> {
        Arc::new(
            SoftwareSigner::new(vec![("upstream-01".parse().unwrap(), self.key.clone())]).unwrap(),
        )
    }

    fn open_with(&self, config: MirrorConfig, format: &str) -> Result<Mirrors, MirrorError> {
        let policy = self.policy(format);
        self.runtime.block_on(Mirrors::open(
            config,
            policy.repos(),
            policy.proxies(),
            self.signer(),
            &BTreeMap::new(),
        ))
    }

    fn open(&self) -> Mirrors {
        self.open_with(self.config(), "sha1").unwrap()
    }

    fn sync(&self, mirrors: &Mirrors) -> Result<SyncReport, MirrorError> {
        self.runtime
            .block_on(async { mirrors.lock(&demo()).await?.sync().await })
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
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
            .unwrap()
    }

    fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A commit on upstream's `branch` (made in a scratch clone, pushed locally).
    fn upstream_commit(&self, branch: &str, file: &str) -> String {
        let work = self.root().join("work");
        if !work.exists() {
            self.git_ok(self.root(), &["init", "-q", work.to_str().unwrap()]);
        }
        std::fs::write(work.join(file), format!("{file}\n")).unwrap();
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

    /// Every ref of a repository, as `name id` lines.
    fn refs(&self, repo: &Path) -> Vec<String> {
        let out = self.git_ok(repo, &["for-each-ref", "--format=%(refname) %(objectname)"]);
        out.lines().map(str::to_owned).collect()
    }

    /// Files in the mirror's pack directory whose name starts with `tmp_`.
    fn partial_packs(&self) -> Vec<String> {
        std::fs::read_dir(self.mirror().join("objects/pack"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("tmp_"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn agent_sockets(&self) -> usize {
        std::fs::read_dir(self.root().join("mirror/sockets"))
            .unwrap()
            .count()
    }
}

fn demo() -> RepoName {
    "demo".parse().unwrap()
}

#[test]
fn a_sync_mirrors_branches_and_tags_only_and_follows_upstream() {
    let f = Fixture::new();
    let main = f.upstream_commit("main", "a");
    let gone = f.upstream_commit("gone", "b");
    let upstream = f.upstream();
    f.git_ok(&upstream, &["tag", "v1", &main]);
    f.git_ok(&upstream, &["update-ref", "refs/pull/1/head", &gone]);
    f.git_ok(&upstream, &["update-ref", "refs/notes/commits", &gone]);

    let mirrors = f.open();
    // The mirror the daemon made: bare, reftable, the registry's format.
    let formats = f.git_ok(
        &f.mirror(),
        &[
            "rev-parse",
            "--is-bare-repository",
            "--show-object-format",
            "--show-ref-format",
        ],
    );
    assert_eq!(formats, "true\nsha1\nreftable");
    let SyncReport::Synced { moved, more } = f.sync(&mirrors).unwrap() else {
        panic!("synced");
    };
    assert_eq!((moved.len(), more), (3, 0), "{moved:?}");
    let mut expected = vec![
        format!("refs/heads/gone {gone}"),
        format!("refs/heads/main {main}"),
        format!("refs/tags/v1 {main}"),
    ];
    assert_eq!(
        f.refs(&f.mirror()),
        expected,
        "branches and tags, nothing else"
    );
    assert_eq!(
        f.agent_sockets(),
        0,
        "the agent socket is gone after the sync"
    );
    // HEAD follows upstream's default branch, so a clone checks it out.
    let head = |repo: &Path| f.git_ok(repo, &["symbolic-ref", "HEAD"]);
    f.git_ok(&upstream, &["symbolic-ref", "HEAD", "refs/heads/gone"]);
    f.sync(&mirrors).unwrap();
    assert_eq!(head(&f.mirror()), "refs/heads/gone");
    f.git_ok(&upstream, &["symbolic-ref", "HEAD", "refs/heads/main"]);

    // Upstream moves on: a branch deleted, main rewritten (a force push), a new branch.
    f.git_ok(&upstream, &["update-ref", "-d", "refs/heads/gone"]);
    let rewritten = f.upstream_commit("main", "c");
    let new = f.upstream_commit("new", "d");
    let SyncReport::Synced { moved, .. } = f.sync(&mirrors).unwrap() else {
        panic!("synced");
    };
    let flags: Vec<(char, &str)> = moved.iter().map(|m| (m.flag, m.name.as_str())).collect();
    assert!(flags.contains(&('-', "refs/heads/gone")), "{flags:?}");
    assert!(flags.contains(&('*', "refs/heads/new")), "{flags:?}");
    expected = vec![
        format!("refs/heads/main {rewritten}"),
        format!("refs/heads/new {new}"),
        format!("refs/tags/v1 {main}"),
    ];
    assert_eq!(f.refs(&f.mirror()), expected, "the mirror follows upstream");
    assert_eq!(head(&f.mirror()), "refs/heads/main");

    // Fresh: no second fetch.
    let fetches = f.remote.upload_packs();
    let report = f.runtime.block_on(mirrors.sync_if_stale(&demo())).unwrap();
    assert_eq!(report, SyncReport::Fresh);
    assert_eq!(f.remote.upload_packs(), fetches);
}

#[test]
fn concurrent_syncs_of_a_stale_mirror_fetch_once() {
    let f = Fixture::new();
    f.upstream_commit("main", "a");
    let mirrors = f.open();
    let repo = demo();
    let reports = f.runtime.block_on(async {
        let (a, b, c) = tokio::join!(
            mirrors.sync_if_stale(&repo),
            mirrors.sync_if_stale(&repo),
            mirrors.sync_if_stale(&repo)
        );
        [a.unwrap(), b.unwrap(), c.unwrap()]
    });
    // One sync: its fetch and its look at upstream's HEAD.
    assert_eq!(f.remote.upload_packs(), 2);
    let fresh = reports.iter().filter(|r| **r == SyncReport::Fresh).count();
    assert_eq!(fresh, 2, "{reports:?}");
}

#[test]
fn an_upstream_in_another_object_format_is_refused() {
    let f = Fixture::new();
    f.upstream_commit("main", "a");
    let mirrors = f.open_with(f.config(), "sha256").unwrap();
    let formats = f.git_ok(&f.mirror(), &["rev-parse", "--show-object-format"]);
    assert_eq!(formats, "sha256");
    match f.sync(&mirrors) {
        Err(MirrorError::ObjectFormat { repo, expected }) => {
            assert_eq!((repo.as_str(), expected.as_str()), ("demo", "sha256"));
        }
        other => panic!("expected ObjectFormat, got {other:?}"),
    }
    assert!(f.refs(&f.mirror()).is_empty());
    // The same mirror reopened in the other format: refused, it isn't that mirror.
    match f.open_with(f.config(), "sha1") {
        Err(MirrorError::NotAMirror { why, .. }) => assert!(why.contains("sha256"), "{why}"),
        Err(other) => panic!("expected NotAMirror, got {other:?}"),
        Ok(_) => panic!("expected NotAMirror, got a mirror"),
    }
}

#[test]
fn another_host_key_or_an_unpinned_host_is_refused() {
    let f = Fixture::new();
    f.upstream_commit("main", "a");
    // The host is pinned, to another key: ssh refuses before authenticating.
    let mut config = f.config();
    let other = generate(KeyKind::Ed25519).unwrap();
    config.pinned = PinnedHosts::parse(&format!(
        "[127.0.0.1]:{} {}\n",
        f.remote.port,
        other.public_key().to_openssh().unwrap()
    ))
    .unwrap();
    let mirrors = f.open_with(config, "sha1").unwrap();
    assert!(
        matches!(f.sync(&mirrors), Err(MirrorError::HostKey { .. })),
        "a host key that isn't the pinned one"
    );
    assert_eq!(
        f.remote.upload_packs(),
        0,
        "nothing was asked of the remote"
    );
    assert!(f.refs(&f.mirror()).is_empty());

    // No pin for the host at all: the daemon refuses to start with this registry.
    let mut config = f.config();
    config.pinned = PinnedHosts::parse(&format!(
        "[127.0.0.1]:1 {}\n",
        other.public_key().to_openssh().unwrap()
    ))
    .unwrap();
    match f.open_with(config, "sha1") {
        Err(MirrorError::HostNotPinned { host, .. }) => {
            assert_eq!(host, format!("[127.0.0.1]:{}", f.remote.port));
        }
        Err(other) => panic!("expected HostNotPinned, got {other:?}"),
        Ok(_) => panic!("expected HostNotPinned, got mirrors"),
    }
    // And the right pin works: the refusals were the pins' doing.
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs(&f.mirror()).len(), 1);
}

#[test]
fn a_credential_the_remote_does_not_take_is_refused() {
    let f = Fixture::new();
    f.upstream_commit("main", "a");
    f.remote
        .authorize(generate(KeyKind::Ed25519).unwrap().public_key().clone());
    let mirrors = f.open();
    match f.sync(&mirrors) {
        Err(MirrorError::Git { what, stderr, .. }) => {
            assert_eq!(what, "sync");
            assert!(stderr.contains("Permission denied"), "{stderr}");
        }
        other => panic!("expected a refused sync, got {other:?}"),
    }
    assert!(f.refs(&f.mirror()).is_empty());
}

#[test]
fn malformed_or_dangerous_objects_from_upstream_never_land() {
    let f = Fixture::new();
    let main = f.upstream_commit("main", "a");
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    let upstream = f.upstream();

    // A tree with a `.git` entry (git only warns about it by default), on a new branch.
    let blob = f.git_ok(&upstream, &["hash-object", "-w", "/dev/null"]);
    let inner = mktree(&f, &upstream, &format!("100644 blob {blob}\tconfig\n"));
    let evil_tree = mktree(&f, &upstream, &format!("040000 tree {inner}\t.git\n"));
    let evil = f.git_ok(
        &upstream,
        &["commit-tree", &evil_tree, "-p", &main, "-m", "evil"],
    );
    f.git_ok(&upstream, &["update-ref", "refs/heads/evil", &evil]);
    // And a malformed commit (a bad committer line), on another.
    let bad = hash_literally(
        &f,
        &upstream,
        &format!("tree {inner}\nparent {main}\nauthor A <a@b> 1 +0000\ncommitter nobody\n\nbad\n"),
    );
    // And a directory with a mode git reads as one but never writes (`40755`), on a third.
    let mode_tree = mktree(&f, &upstream, &format!("40755 tree {inner}\t.github\n"));
    let mode = f.git_ok(
        &upstream,
        &["commit-tree", &mode_tree, "-p", &main, "-m", "mode"],
    );
    for (branch, id, check) in [
        ("evil", evil.as_str(), "hasDotgit"),
        ("bad", bad.as_str(), "error"),
        ("mode", mode.as_str(), "badFilemode"),
    ] {
        // One at a time: each refused on its own.
        for other in ["evil", "bad", "mode"] {
            let _ = f.git(
                &upstream,
                &["update-ref", "-d", &format!("refs/heads/{other}")],
            );
        }
        f.git_ok(
            &upstream,
            &["update-ref", &format!("refs/heads/{branch}"), id],
        );
        match f.sync(&mirrors) {
            Err(MirrorError::Git { stderr, .. }) => {
                assert!(stderr.contains(check), "{branch}: {stderr}");
            }
            other => panic!("{branch}: expected a refused sync, got {other:?}"),
        }
        assert_eq!(
            f.refs(&f.mirror()),
            [format!("refs/heads/main {main}")],
            "{branch}"
        );
        assert!(
            f.partial_packs().is_empty(),
            "{branch}: {:?}",
            f.partial_packs()
        );
        let present = f.git(&f.mirror(), &["cat-file", "-e", id]);
        assert_eq!(
            present.status.code(),
            Some(1),
            "{branch}: the object never landed"
        );
    }
}

#[test]
fn a_sync_past_the_byte_cap_is_refused_on_both_sides() {
    let f = Fixture::new();
    // 300 KB of random bytes: a pack that can't be compressed under it.
    let work = f.root().join("work");
    f.git_ok(f.root(), &["init", "-q", work.to_str().unwrap()]);
    let mut random = vec![0u8; 300_000];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").unwrap(),
        &mut random,
    )
    .unwrap();
    std::fs::write(work.join("big"), random).unwrap();
    f.git_ok(&work, &["add", "big"]);
    f.git_ok(&work, &["commit", "-q", "-m", "big"]);
    let upstream = f.upstream();
    f.git_ok(
        &work,
        &[
            "push",
            "-q",
            upstream.to_str().unwrap(),
            "HEAD:refs/heads/main",
        ],
    );

    let mut small = f.config();
    small.max_fetch_bytes = 100_000;
    let mirrors = f.open_with(small, "sha1").unwrap();
    match f.sync(&mirrors) {
        Err(MirrorError::TooLarge { max, .. }) => assert_eq!(max, 100_000),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(f.refs(&f.mirror()).is_empty());
    assert!(f.partial_packs().is_empty(), "{:?}", f.partial_packs());

    // A remote that floods: the same.
    f.remote.set_mode(Mode::Flood(500_000));
    assert!(matches!(
        f.sync(&mirrors),
        Err(MirrorError::TooLarge { .. })
    ));
    f.remote.set_mode(Mode::Serve);

    // Under a cap above it, the same sync passes.
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    assert_eq!(f.refs(&f.mirror()).len(), 1);
}

#[test]
fn an_upstream_that_never_answers_is_cut_at_the_deadline() {
    let f = Fixture::new();
    f.upstream_commit("main", "a");
    f.remote.set_mode(Mode::Hang);
    let mut config = f.config();
    config.timeout = Duration::from_secs(2);
    let mirrors = f.open_with(config, "sha1").unwrap();
    match f.sync(&mirrors) {
        Err(MirrorError::Timeout { seconds, .. }) => assert_eq!(seconds, 2),
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(f.refs(&f.mirror()).is_empty());
    assert_eq!(f.agent_sockets(), 0);
    // Stale after a failure: the next call syncs again (and works once upstream answers).
    f.remote.set_mode(Mode::Serve);
    let report = f.runtime.block_on(mirrors.sync_if_stale(&demo())).unwrap();
    assert!(matches!(report, SyncReport::Synced { .. }), "{report:?}");
}

#[test]
fn a_directory_that_is_not_a_daemon_mirror_is_refused() {
    let f = Fixture::new();
    let repos = f.root().join("repos");
    std::fs::create_dir_all(&repos).unwrap();
    // A plain bare repository (files ref format) where the mirror goes.
    f.git_ok(
        f.root(),
        &["init", "-q", "--bare", f.mirror().to_str().unwrap()],
    );
    match f.open_with(f.config(), "sha1") {
        Err(MirrorError::NotAMirror { why, .. }) => assert!(why.contains("files"), "{why}"),
        Err(other) => panic!("expected NotAMirror, got {other:?}"),
        Ok(_) => panic!("expected NotAMirror"),
    }
    // A link to a real mirror: refused too, whatever it points at.
    std::fs::remove_dir_all(f.mirror()).unwrap();
    let elsewhere = f.root().join("elsewhere.git");
    f.git_ok(
        f.root(),
        &[
            "init",
            "-q",
            "--bare",
            "--ref-format=reftable",
            elsewhere.to_str().unwrap(),
        ],
    );
    std::os::unix::fs::symlink(&elsewhere, f.mirror()).unwrap();
    match f.open_with(f.config(), "sha1") {
        Err(MirrorError::NotAMirror { why, .. }) => assert!(why.contains("link"), "{why}"),
        Err(other) => panic!("expected NotAMirror, got {other:?}"),
        Ok(_) => panic!("expected NotAMirror"),
    }
    // Nothing there: created, and opened again as the same mirror.
    std::fs::remove_file(f.mirror()).unwrap();
    f.open();
    f.open();
}

#[test]
fn an_upstream_the_daemon_cannot_reach_as_configured_is_refused_at_start_and_one_without_its_token_reaches_nothing()
 {
    let f = Fixture::new();
    let open = |upstream: &str, credential: &str| {
        let policy = PolicyConfig::from_yaml(&policy_yaml(upstream, credential, "sha1")).unwrap();
        f.runtime.block_on(Mirrors::open(
            f.config(),
            policy.repos(),
            policy.proxies(),
            f.signer(),
            &BTreeMap::new(),
        ))
    };
    // A credential the signer doesn't hold.
    match open(&f.remote.url("demo"), "upstream-02") {
        Err(MirrorError::UnknownCredential { key, .. }) => assert_eq!(key.as_str(), "upstream-02"),
        other => panic!("expected UnknownCredential, got {:?}", other.err()),
    }
    // An HTTPS upstream whose token the keystore doesn't hold yet (here: its id is an ssh
    // key's): served, but nothing reaches upstream, with the command that adds the token.
    let mirrors = open("https://example.org/demo.git", "upstream-01").unwrap();
    let demo: writ_core::names::RepoName = "demo".parse().unwrap();
    match f.runtime.block_on(mirrors.sync_if_stale(&demo)) {
        Err(error @ MirrorError::NoToken { .. }) => assert_eq!(
            error.to_string(),
            "repo demo: upstream credential upstream-01 has no token yet: an approver adds it \
             with `writ admin token upstream-01`"
        ),
        other => panic!("expected NoToken, got {other:?}"),
    }
    // Plain HTTP: never (the token would travel in clear); the registry refuses it already.
    let http = PolicyConfig::from_yaml(&policy_yaml("http://example.org/demo.git", "u-1", "sha1"));
    assert_eq!(
        http.unwrap_err().to_string(),
        "repos.demo.upstream: http:// would send the token in clear: use https://"
    );
    // As configured: opened.
    assert!(open(&f.remote.url("demo"), "upstream-01").is_ok());
}

/// A registry with one repo, `demo`, and a template for it: its credential declared for its
/// URL (an SSH key for `ssh://`, a token for `https://`), its host pinned (to a key that
/// doesn't matter: the mirrors here take their pins from the fixture's configuration).
fn policy_yaml(upstream: &str, credential: &str, format: &str) -> String {
    use writ_core::upstream::Upstream;
    let (declaration, pins) = match Upstream::parse(upstream) {
        Ok(Upstream::Https(url)) => (
            format!("{{ use: upstream, kind: token, host: \"{}\" }}", url.host()),
            String::new(),
        ),
        Ok(Upstream::Ssh(url)) => (
            "{ use: upstream, kind: ssh, algorithm: ed25519 }".to_owned(),
            format!(
                "upstream_hosts:\n  \"{}\": [\"ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"]\n",
                url.known_hosts_name()
            ),
        ),
        Err(_) => (
            "{ use: upstream, kind: ssh, algorithm: ed25519 }".to_owned(),
            String::new(),
        ),
    };
    format!(
        "keys:\n  {credential}: {declaration}\n{pins}\
         repos:\n  demo:\n    upstream: {upstream}\n    upstream_credential: {credential}\n    \
         templates: [t]\n    object_format: {format}\n\
         templates:\n  t:\n    operations: [fetch]\n    branches: [\"*\"]\n    \
         committer_emails: [\"a@b\"]\n    max_ttl: 1h\n    max_signatures: 1\n    \
         max_pushes: 1\n    max_ops_per_minute: 10\n    max_push_size: 1MB\n"
    )
}

fn mktree(f: &Fixture, repo: &Path, entries: &str) -> String {
    let mut child = Command::new("git")
        .args(["mktree", "--missing"])
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(entries.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "mktree in {}", f.root().display());
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn hash_literally(f: &Fixture, repo: &Path, content: &str) -> String {
    let path = f.root().join("object");
    std::fs::write(&path, content).unwrap();
    f.git_ok(
        repo,
        &[
            "hash-object",
            "-w",
            "--literally",
            "-t",
            "commit",
            path.to_str().unwrap(),
        ],
    )
}

#[test]
fn a_mirror_held_past_its_deadline_is_busy_never_waited_on_forever() {
    let f = Fixture::new();
    let mirrors = f.open();
    let deadline = mirrors.lock_deadline();
    assert_eq!(
        deadline,
        Duration::from_secs(120) + writ_mirror::LOCAL_WORK_DEADLINE,
        "a wait for a sync slot, one upstream operation and the local work around it"
    );
    // The clock is a fake from here: the mirror is open, nothing below starts a process.
    let paused = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    paused.block_on(async {
        // A second before the deadline the caller still waits, and gets the mirror once the
        // holder lets go.
        let held = mirrors.lock(&demo()).await.unwrap();
        let waiter = {
            let mirrors = mirrors.clone();
            tokio::spawn(async move { mirrors.lock(&demo()).await.map(drop) })
        };
        tokio::task::yield_now().await;
        tokio::time::advance(deadline - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "still waiting before the deadline");
        drop(held);
        assert!(matches!(waiter.await.unwrap(), Ok(())));

        // Held past the deadline: busy, with the reason.
        let held = mirrors.lock(&demo()).await.unwrap();
        match mirrors.lock(&demo()).await {
            Err(MirrorError::Busy { repo, seconds }) => {
                assert_eq!(repo, demo());
                assert_eq!(seconds, deadline.as_secs());
            }
            other => panic!("expected Busy, got {:?}", other.err()),
        }
        drop(held);
    });
}

// Notes (M4.7): written in the mirror, pushed upstream as a fast-forward, merged with
// upstream's when it moved.

fn note(commit: &str, text: &str) -> Note {
    Note {
        commit: commit.parse().unwrap(),
        text: text.to_owned(),
    }
}

impl Fixture {
    /// Notes under `refs/notes/writ`.
    fn push_notes(
        &self,
        mirrors: &Mirrors,
        credential: &str,
        notes: &[Note],
    ) -> Result<NotesPushed, MirrorError> {
        self.push_notes_to(mirrors, NotesRef::Writ, credential, notes)
    }

    fn push_notes_to(
        &self,
        mirrors: &Mirrors,
        notes_ref: NotesRef,
        credential: &str,
        notes: &[Note],
    ) -> Result<NotesPushed, MirrorError> {
        let credential = credential.parse().unwrap();
        self.runtime.block_on(async {
            mirrors
                .lock(&demo())
                .await?
                .push_notes(notes_ref, &credential, notes)
                .await
        })
    }

    /// The note of `commit` in `repo` under `refs/notes/writ`, or `None`.
    fn note_of(&self, repo: &Path, commit: &str) -> Option<String> {
        let out = self.git(repo, &["notes", "--ref=writ", "show", commit]);
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn notes_ref(&self, repo: &Path) -> Option<String> {
        let out = self.git(repo, &["rev-parse", "--verify", "-q", "refs/notes/writ"]);
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Makes `hooks/pre-receive` of the upstream repo say `words` and refuse, or removes it.
    fn upstream_refuses(&self, words: Option<&str>) {
        let hook = self.upstream().join("hooks/pre-receive");
        match words {
            Some(words) => {
                std::fs::write(&hook, format!("#!/bin/sh\necho '{words}' >&2\nexit 1\n")).unwrap();
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            None => std::fs::remove_file(&hook).unwrap(),
        }
    }
}

#[test]
fn notes_reach_upstream_as_a_fast_forward_the_commits_untouched() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let second = f.upstream_commit("main", "b");
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    let before = f.refs(&f.upstream());

    let pushed = f.push_notes(
        &mirrors,
        "upstream-01",
        &[
            note(&first, "Writ: wrt_A\n"),
            note(&second, "Writ: wrt_A\n"),
        ],
    );
    assert_eq!(pushed.unwrap(), NotesPushed::FastForward);
    let upstream = f.upstream();
    assert_eq!(
        f.note_of(&upstream, &first).as_deref(),
        Some("Writ: wrt_A\n")
    );
    assert_eq!(
        f.note_of(&upstream, &second).as_deref(),
        Some("Writ: wrt_A\n")
    );
    // Upstream's notes ref is the mirror's; every other ref as it was.
    let notes = f.notes_ref(&upstream).expect("a notes ref upstream");
    assert_eq!(f.notes_ref(&f.mirror()).as_deref(), Some(notes.as_str()));
    let after: Vec<String> = f
        .refs(&upstream)
        .into_iter()
        .filter(|r| !r.starts_with("refs/notes/writ "))
        .collect();
    assert_eq!(after, before);
    // Unsigned, by the daemon's fixed identity.
    let commit = f.git_ok(&upstream, &["cat-file", "commit", &notes]);
    assert!(!commit.contains("gpgsig"), "{commit}");
    assert!(
        commit.contains("committer writd <writd@writ.invalid>"),
        "{commit}"
    );
    assert_eq!(f.agent_sockets(), 0);

    // The next batch builds on it: one more fast-forward, a commit's note gains a line, after
    // a blank one (`union`, as `git notes append` writes it).
    let pushed = f.push_notes(&mirrors, "upstream-01", &[note(&second, "Writ: wrt_B\n")]);
    assert_eq!(pushed.unwrap(), NotesPushed::FastForward);
    assert_eq!(
        f.note_of(&upstream, &second).as_deref(),
        Some("Writ: wrt_A\n\nWrit: wrt_B\n")
    );
    assert_eq!(
        f.note_of(&upstream, &first).as_deref(),
        Some("Writ: wrt_A\n")
    );
    let parents = f.git_ok(
        &upstream,
        &["rev-list", "--parents", "-n1", "refs/notes/writ"],
    );
    assert!(parents.contains(&notes), "built on the last one: {parents}");
}

#[test]
fn a_notes_ref_upstream_moved_is_fetched_merged_and_pushed_once_more() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let second = f.upstream_commit("main", "b");
    let upstream = f.upstream();
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    // Notes someone else wrote upstream, on a ref of their own until the push comes.
    f.git_ok(
        &upstream,
        &["notes", "--ref=elsewhere", "add", "-m", "Theirs", &second],
    );
    let theirs = f.git_ok(&upstream, &["rev-parse", "refs/notes/elsewhere"]);
    f.remote
        .before_next_push(&["update-ref", "refs/notes/writ", &theirs]);

    let pushed = f.push_notes(
        &mirrors,
        "upstream-01",
        &[
            note(&first, "Writ: wrt_A\n"),
            note(&second, "Writ: wrt_A\n"),
        ],
    );
    assert_eq!(pushed.unwrap(), NotesPushed::Merged);
    // Theirs kept as written, ours after a blank line; a line both hold, once.
    assert_eq!(
        f.note_of(&upstream, &first).as_deref(),
        Some("Writ: wrt_A\n")
    );
    assert_eq!(
        f.note_of(&upstream, &second).as_deref(),
        Some("Theirs\n\nWrit: wrt_A\n")
    );
    let notes = f.notes_ref(&upstream).unwrap();
    assert_eq!(f.notes_ref(&f.mirror()).as_deref(), Some(notes.as_str()));
    let ancestor = f.git(
        &upstream,
        &["merge-base", "--is-ancestor", &theirs, "refs/notes/writ"],
    );
    assert!(ancestor.status.success(), "theirs is in the history");
    assert_eq!(f.remote.receive_packs(), 2, "one push, one retry");
    assert_eq!(f.agent_sockets(), 0);
}

#[test]
fn a_notes_ref_moved_again_before_the_retry_is_refused_after_one_retry() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let upstream = f.upstream();
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    f.git_ok(
        &upstream,
        &["notes", "--ref=elsewhere", "add", "-m", "1", &first],
    );
    let once = f.git_ok(&upstream, &["rev-parse", "refs/notes/elsewhere"]);
    f.git_ok(
        &upstream,
        &["notes", "--ref=elsewhere", "add", "-f", "-m", "2", &first],
    );
    let twice = f.git_ok(&upstream, &["rev-parse", "refs/notes/elsewhere"]);
    f.remote
        .before_next_push(&["update-ref", "refs/notes/writ", &once]);
    f.remote
        .before_next_push(&["update-ref", "refs/notes/writ", &twice]);

    match f.push_notes(&mirrors, "upstream-01", &[note(&first, "Writ: wrt_A\n")]) {
        Err(MirrorError::Rejected { reason, .. }) => {
            assert_eq!(
                reason,
                "refs/notes/writ moved again while the notes were merged"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(f.remote.receive_packs(), 2, "one retry, no more");
    assert_eq!(f.notes_ref(&upstream).as_deref(), Some(twice.as_str()));
    assert_eq!(f.agent_sockets(), 0);
}

#[test]
fn a_notes_push_the_remote_refuses_is_an_error_with_its_words_then_goes_through() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let upstream = f.upstream();
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    f.upstream_refuses(Some("no notes here"));

    match f.push_notes(&mirrors, "upstream-01", &[note(&first, "Writ: wrt_A\n")]) {
        Err(MirrorError::Rejected { reason, .. }) => {
            assert!(
                reason.contains("refs/notes/writ")
                    && reason.contains("pre-receive hook declined")
                    && reason.contains("no notes here"),
                "{reason}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(f.notes_ref(&upstream), None);
    assert_eq!(f.remote.receive_packs(), 1, "no retry for a refusal");

    // The remote takes notes again: the next batch carries what didn't go (the caller keeps
    // the notes waiting and sends them again).
    f.upstream_refuses(None);
    let second = f.upstream_commit("main", "b");
    f.sync(&mirrors).unwrap();
    let pushed = f.push_notes(
        &mirrors,
        "upstream-01",
        &[
            note(&first, "Writ: wrt_A\n"),
            note(&second, "Writ: wrt_B\n"),
        ],
    );
    assert_eq!(pushed.unwrap(), NotesPushed::FastForward);
    assert_eq!(
        f.note_of(&upstream, &first).as_deref(),
        Some("Writ: wrt_A\n")
    );
    assert_eq!(
        f.note_of(&upstream, &second).as_deref(),
        Some("Writ: wrt_B\n")
    );
}

/// The review after M7.6 (M-6): for a direct `ssh://` upstream each git of an operation had
/// its own relay and the whole `mirrors.max_fetch`, so a notes push (an `ls-remote`, then the
/// push) took twice the cap. The cap now holds for the operation: each git here gets about
/// 60 KB, under the 100 KB cap alone and over it together; at 30 KB each, the two pass it.
#[test]
fn the_byte_cap_holds_for_an_operation_s_gits_together() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let mut config = f.config();
    config.max_fetch_bytes = 100_000;
    let mirrors = f.open_with(config, "sha1").unwrap();
    f.sync(&mirrors).unwrap();

    f.remote.set_mode(Mode::Advertise(60_000));
    match f.push_notes(&mirrors, "upstream-01", &[note(&first, "Writ: wrt_A\n")]) {
        Err(MirrorError::TooLarge { max, .. }) => assert_eq!(max, 100_000),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    // Under the cap together: the push itself fails (this remote takes nothing), never as
    // too large.
    f.remote.set_mode(Mode::Advertise(30_000));
    match f.push_notes(&mirrors, "upstream-01", &[note(&first, "Writ: wrt_A\n")]) {
        Err(MirrorError::Rejected { .. } | MirrorError::Git { .. }) => {}
        other => panic!("expected the push to fail on its own, got {other:?}"),
    }
}

#[test]
fn a_batch_with_the_wrong_credential_or_malformed_is_refused_before_any_git() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    let good = note(&first, "Writ: wrt_A\n");

    match f.push_notes(&mirrors, "upstream-02", std::slice::from_ref(&good)) {
        Err(MirrorError::NotTheCredential { key, .. }) => assert_eq!(key.as_str(), "upstream-02"),
        other => panic!("expected the wrong credential, got {other:?}"),
    }
    let too_long = "x".repeat(MAX_NOTE_TEXT + 1);
    let longest = "x".repeat(MAX_NOTE_TEXT);
    for (notes, why) in [
        (vec![], format!("a batch holds from 1 to {MAX_NOTES} notes")),
        (
            vec![good.clone(); MAX_NOTES + 1],
            format!("a batch holds from 1 to {MAX_NOTES} notes"),
        ),
        (
            vec![note(&first, "")],
            format!("a note holds from 1 to {MAX_NOTE_TEXT} bytes"),
        ),
        (
            vec![note(&first, &too_long)],
            format!("a note holds from 1 to {MAX_NOTE_TEXT} bytes"),
        ),
        (
            vec![good.clone(), note(&first, "Writ: wrt_B\n")],
            format!("two notes for commit {first}"),
        ),
    ] {
        match f.push_notes(&mirrors, "upstream-01", &notes) {
            Err(MirrorError::Notes(reason)) => assert_eq!(reason, why),
            other => panic!("expected {why:?}, got {other:?}"),
        }
    }
    assert_eq!(f.notes_ref(&f.mirror()), None);
    assert_eq!(f.remote.receive_packs(), 0);

    // At the bounds: the longest note goes through.
    let pushed = f.push_notes(&mirrors, "upstream-01", &[note(&first, &longest)]);
    assert_eq!(pushed.unwrap(), NotesPushed::FastForward);
    assert_eq!(
        f.note_of(&f.upstream(), &first).map(|n| n.len()),
        Some(MAX_NOTE_TEXT)
    );
}

#[test]
fn a_malformed_notes_ref_upstream_never_lands_and_the_notes_push_fails() {
    let f = Fixture::new();
    let main = f.upstream_commit("main", "a");
    let upstream = f.upstream();
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    // Upstream's notes ref, just before the notes push, a malformed commit (a bad committer
    // line): the push is refused as behind, and the fetch that follows checks what it takes.
    let blob = f.git_ok(&upstream, &["hash-object", "-w", "/dev/null"]);
    let tree = mktree(&f, &upstream, &format!("100644 blob {blob}\t{main}\n"));
    let bad = hash_literally(
        &f,
        &upstream,
        &format!("tree {tree}\nauthor A <a@b> 1 +0000\ncommitter nobody\n\nbad\n"),
    );
    f.remote
        .before_next_push(&["update-ref", "refs/notes/writ", &bad]);

    match f.push_notes(&mirrors, "upstream-01", &[note(&main, "Writ: wrt_A\n")]) {
        Err(MirrorError::Git { what, stderr, .. }) => {
            assert_eq!(what, "notes fetch");
            assert!(
                stderr.contains("fsck") || stderr.contains("error"),
                "{stderr}"
            );
        }
        other => panic!("expected a refused notes fetch, got {other:?}"),
    }
    let present = f.git(&f.mirror(), &["cat-file", "-e", &bad]);
    assert_eq!(present.status.code(), Some(1), "the object never landed");
    assert_ne!(f.notes_ref(&f.mirror()).as_deref(), Some(bad.as_str()));
    assert!(f.partial_packs().is_empty(), "{:?}", f.partial_packs());
    assert_eq!(f.agent_sockets(), 0);
}

#[test]
fn notes_under_git_s_own_ref_keep_a_person_s_notes_there() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let upstream = f.upstream();
    // A person's note, under git's default notes ref, before the daemon writes any.
    f.git_ok(
        &upstream,
        &["notes", "add", "-m", "Reviewed by Sam", &first],
    );
    let theirs = f.git_ok(&upstream, &["rev-parse", "refs/notes/commits"]);
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();

    let pushed = f.push_notes_to(
        &mirrors,
        NotesRef::Commits,
        "upstream-01",
        &[note(&first, "Writ: wrt_A\n")],
    );
    // The mirror had no notes ref: upstream's is fetched, merged, pushed once more.
    assert_eq!(pushed.unwrap(), NotesPushed::Merged);
    let shown = f.git_ok(&upstream, &["notes", "show", &first]);
    assert_eq!(shown, "Reviewed by Sam\n\nWrit: wrt_A");
    let ancestor = f.git(
        &upstream,
        &["merge-base", "--is-ancestor", &theirs, "refs/notes/commits"],
    );
    assert!(
        ancestor.status.success(),
        "the person's notes are in the history"
    );
    // Nothing under refs/notes/writ: one ref per repo.
    assert_eq!(f.notes_ref(&upstream), None);
}

#[test]
fn the_mirror_says_which_commits_it_holds() {
    let f = Fixture::new();
    let first = f.upstream_commit("main", "a");
    let mirrors = f.open();
    f.sync(&mirrors).unwrap();
    let later = f.upstream_commit("main", "b");
    let tree = f.git_ok(&f.mirror(), &["rev-parse", &format!("{first}^{{tree}}")]);
    let held = |ids: &[&str]| -> Result<Vec<String>, MirrorError> {
        let ids: Vec<writ_core::names::CommitId> =
            ids.iter().map(|id| id.parse().unwrap()).collect();
        f.runtime.block_on(async {
            let set = mirrors.lock(&demo()).await?.held_commits(&ids).await?;
            Ok(set.iter().map(ToString::to_string).collect())
        })
    };
    // Synced: the first; upstream's later one not yet; a tree is no commit.
    assert_eq!(
        held(&[&first, &later, &tree]).unwrap(),
        std::slice::from_ref(&first)
    );
    assert!(held(&[]).unwrap().is_empty());
    f.sync(&mirrors).unwrap();
    let mut both = vec![first.clone(), later.clone()];
    both.sort();
    assert_eq!(held(&[&later, &first]).unwrap(), both);
    // The review after M7.6 (M-4): a commit in the mirror that no branch or tag reaches (an
    // accepted push's pack can bring one, never pushed upstream) is not held, even on top of
    // one that is; once a ref reaches it, it is.
    let dangling = f.git_ok(
        &f.mirror(),
        &["commit-tree", "-p", &later, &tree, "-m", "in no ref"],
    );
    assert_eq!(
        held(&[&dangling, &later]).unwrap(),
        std::slice::from_ref(&later)
    );
    f.git_ok(&f.mirror(), &["tag", "reached", &dangling]);
    assert_eq!(held(&[&dangling]).unwrap(), std::slice::from_ref(&dangling));
    f.git_ok(&f.mirror(), &["tag", "-d", "reached"]);
    // At most MAX_LOOKUPS at once, on both sides.
    let many: Vec<String> = (0..=MAX_LOOKUPS).map(|n| format!("{n:040x}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    match held(&refs) {
        Err(MirrorError::Notes(reason)) => {
            assert_eq!(
                reason,
                format!("at most {MAX_LOOKUPS} commits looked up at once")
            );
        }
        other => panic!("expected the bound, got {other:?}"),
    }
    assert!(held(&refs[..MAX_LOOKUPS]).unwrap().is_empty());
}

/// The review after M5.5 (S10): a registry change (here a repo's protected refs) opened the
/// changed repo again with a lock of its own, and made new sync slots: an operation holding
/// the old lock and one taking the new ran on the same mirror at once. The mirror keeps its
/// one lock across a change, and the daemon its sync slots.
#[test]
fn a_registry_change_keeps_one_lock_per_mirror() {
    let f = Fixture::new();
    let mirrors = f.open();
    let changed = PolicyConfig::from_yaml(
        &policy_yaml(&f.remote.url("demo"), "upstream-01", "sha1").replacen(
            "    object_format: sha1\n",
            "    object_format: sha1\n    protected_refs: [\"refs/heads/release\"]\n",
            1,
        ),
    )
    .unwrap();
    assert_ne!(
        changed.repos().get(&demo()),
        f.policy("sha1").repos().get(&demo()),
        "the entry changed, so the repo is opened again"
    );
    let held = f.runtime.block_on(mirrors.lock(&demo())).unwrap();
    let after = f
        .runtime
        .block_on(mirrors.with_registry(
            changed.repos(),
            changed.proxies(),
            f.config().pinned,
            f.signer(),
            &BTreeMap::new(),
        ))
        .unwrap();
    assert!(mirrors.shares_lock_with(&after, &demo()));
    drop(held);
    // Taken through the new `Mirrors` once the old guard is gone, as through the old.
    drop(f.runtime.block_on(after.lock(&demo())).unwrap());
}
