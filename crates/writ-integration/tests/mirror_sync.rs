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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use writ_core::config::PolicyConfig;
use writ_core::names::RepoName;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_integration::binaries::bin;
use writ_integration::remote::{Mode, TestRemote};
use writ_mirror::known_hosts::PinnedHosts;
use writ_mirror::{MirrorConfig, MirrorError, Mirrors, SyncReport};
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
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(&format!("{}\n", self.remote.known_hosts_line())).unwrap(),
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 64 << 20,
        }
    }

    fn signer(&self) -> Arc<dyn Signer> {
        Arc::new(
            SoftwareSigner::new(vec![("upstream-01".parse().unwrap(), self.key.clone())]).unwrap(),
        )
    }

    fn open_with(&self, config: MirrorConfig, format: &str) -> Result<Mirrors, MirrorError> {
        let policy = self.policy(format);
        self.runtime
            .block_on(Mirrors::open(config, policy.repos(), self.signer()))
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
        std::fs::read_dir(self.root().join("mirror/agent"))
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
    assert_eq!(f.remote.upload_packs(), 1);
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
    for (branch, id) in [("evil", evil.as_str()), ("bad", bad.as_str())] {
        // One at a time: each refused on its own.
        for other in ["evil", "bad"] {
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
                assert!(
                    stderr.contains("fsck") || stderr.contains("error"),
                    "{branch}: {stderr}"
                );
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
fn an_upstream_the_daemon_cannot_reach_as_configured_is_refused_at_start() {
    let f = Fixture::new();
    let open = |upstream: &str, credential: &str| {
        let policy = PolicyConfig::from_yaml(&policy_yaml(upstream, credential, "sha1")).unwrap();
        f.runtime
            .block_on(Mirrors::open(f.config(), policy.repos(), f.signer()))
    };
    // A credential the signer doesn't hold.
    match open(&f.remote.url("demo"), "upstream-02") {
        Err(MirrorError::UnknownCredential { key, .. }) => assert_eq!(key.as_str(), "upstream-02"),
        other => panic!("expected UnknownCredential, got {:?}", other.err()),
    }
    // An HTTPS upstream (M4.5).
    match open("https://example.org/demo.git", "upstream-01") {
        Err(MirrorError::Upstream { why, .. }) => assert!(why.contains("M4.5"), "{why}"),
        other => panic!("expected Upstream, got {:?}", other.err()),
    }
    // As configured: opened.
    assert!(open(&f.remote.url("demo"), "upstream-01").is_ok());
}

/// A registry with one repo, `demo`, and a template for it.
fn policy_yaml(upstream: &str, credential: &str, format: &str) -> String {
    format!(
        "repos:\n  demo:\n    upstream: {upstream}\n    upstream_credential: {credential}\n    \
         object_format: {format}\n\
         templates:\n  t:\n    repos: [demo]\n    operations: [fetch]\n    branches: [\"*\"]\n    \
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
