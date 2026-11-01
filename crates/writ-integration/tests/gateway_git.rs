//! The gateway with the real `git` and `ssh`: fetch and push through it, the pre-receive check
//! (and its audit lines), session certificates (only valid ones from a real lease get in), and
//! the same protocol over a Unix socket. Signing is in `signed_commits.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::path::Path;
use std::process::Command;

use writ_crypto::ca::CertificateAuthority;
use writ_crypto::keys::{KeyKind, generate};
use writ_integration::gateway::{GitGateway, Listen, now};
use writ_integration::{audit_events, stderr};

#[test]
fn fetch_and_push_through_the_gateway() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    assert_eq!(fs::read_to_string(work.join("README")).unwrap(), "demo\n");
    let main_before = gateway.bare_ref("refs/heads/main");

    fs::write(work.join("feature"), "x\n").unwrap();
    gateway.git_ok(&work, &["add", "feature"]);
    gateway.git_ok(&work, &["commit", "-q", "-m", "feature"]);
    gateway.git_ok(&work, &["push", "-q", "origin", "HEAD:refs/heads/agent/x"]);
    let head = gateway.git_ok(&work, &["rev-parse", "HEAD"]);
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/x").as_deref(),
        Some(head.trim())
    );

    // A protected ref: refused by the daemon through the pre-receive callback, with its
    // reason shown by git, and nothing lands.
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/main"), main_before);

    gateway.git_ok(&work, &["tag", "v1"]);
    let out = gateway.git(&work, &["push", "origin", "refs/tags/v1"]);
    assert!(
        stderr(&out).contains("writ: refs/tags/v1 is protected"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/tags/v1"), None);

    // Both refusals are in the audit log, written before git was answered.
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let refused = audit_events(&audit, "push", "denied");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[0]["reason"], "refs/heads/main is protected");
    assert_eq!(refused[0]["refs"][0], "refs/heads/main");
    assert_eq!(refused[0]["repo"], "demo");
    assert_eq!(refused[1]["reason"], "refs/tags/v1 is protected");

    // Fetch sees the pushed branch.
    let other = gateway.clone("other");
    gateway.git_ok(&other, &["fetch", "-q", "origin"]);
    let fetched = gateway.git_ok(&other, &["rev-parse", "origin/agent/x"]);
    assert_eq!(fetched.trim(), head.trim());
}

#[test]
fn malformed_objects_never_land() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    // Tree entries git's fsck only warns about by default, refused here at error level: a
    // `.GIT` blob and a `.git` tree (git's own directory, the family of checkout CVEs), `.`
    // and `..`. Made with plumbing, which doesn't check.
    let blob = gateway.git_ok(&work, &["hash-object", "-w", "README"]);
    let blob = blob.trim();
    let inner = mktree(&gateway, &work, &format!("100644 blob {blob}\tconfig\n"));
    for (listing, check) in [
        (format!("100644 blob {blob}\t.GIT\n"), "hasDotgit"),
        (format!("040000 tree {inner}\t.git\n"), "hasDotgit"),
        (format!("040000 tree {inner}\t..\n"), "hasDotdot"),
        (format!("040000 tree {inner}\t.\n"), "hasDot"),
    ] {
        let tree = mktree(&gateway, &work, &listing);
        let commit = gateway.git_ok(&work, &["commit-tree", &tree, "-p", "HEAD", "-m", "bad"]);
        let out = gateway.git(
            &work,
            &[
                "push",
                "origin",
                &format!("{}:refs/heads/agent/bad", commit.trim()),
            ],
        );
        assert_eq!(out.status.code(), Some(1), "{listing}: accepted");
        assert!(stderr(&out).contains(check), "{listing}: {}", stderr(&out));
        assert_eq!(
            gateway.bare_ref("refs/heads/agent/bad"),
            None,
            "{listing}: nothing landed"
        );
    }
    // A good commit still goes through, on the same connection setup.
    fs::write(work.join("feature"), "x\n").unwrap();
    gateway.git_ok(&work, &["add", "feature"]);
    gateway.git_ok(&work, &["commit", "-q", "-m", "feature"]);
    gateway.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/good"],
    );
}

#[test]
fn only_valid_session_certificates_get_in() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let url = format!("{}/demo.git", gateway.url);
    let ls_remote = |key: &Path, with_cert: bool| {
        gateway.git_with(
            &gateway.ssh_command(key, with_cert),
            gateway.root(),
            &["ls-remote", &url],
        )
    };
    let key = |name: &str| gateway.root().join("keys").join(name);

    assert!(ls_remote(&key("session"), true).status.success());

    let other_ca = CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap());
    gateway.forged_session(&other_ca, "foreign", 0, now() + 3600);
    assert!(
        !ls_remote(&key("foreign"), true).status.success(),
        "unknown CA"
    );

    gateway.forged_session(&gateway.ca, "expired", 0, now() - 10);
    assert!(
        !ls_remote(&key("expired"), true).status.success(),
        "expired"
    );

    gateway.forged_session(&gateway.ca, "early", now() + 600, now() + 3600);
    assert!(
        !ls_remote(&key("early"), true).status.success(),
        "not valid yet"
    );

    // Our own CA, valid dates, but no lease behind it: refused.
    gateway.forged_session(&gateway.ca, "leaseless", 0, now() + 3600);
    assert!(
        !ls_remote(&key("leaseless"), true).status.success(),
        "no lease"
    );

    assert!(
        !ls_remote(&key("session"), false).status.success(),
        "plain key"
    );

    let lease = gateway.session("revoked");
    assert!(ls_remote(&key("revoked"), true).status.success());
    gateway.revoke(&lease);
    assert!(
        !ls_remote(&key("revoked"), true).status.success(),
        "revoked"
    );

    // Commands other than git and writ-sign are refused with a reason.
    let ssh = gateway.ssh_command(&key("session"), true);
    let host = gateway.url.trim_start_matches("ssh://");
    let (destination, port) = host.rsplit_once(':').unwrap();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("{ssh} -p {port} {destination} id"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("writ: command not allowed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_same_protocol_works_over_a_unix_socket() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Unix);
    gateway.seed_repo();
    let work = gateway.clone("work");
    fs::write(work.join("f"), "x\n").unwrap();
    gateway.git_ok(&work, &["add", "f"]);
    gateway.git_ok(&work, &["commit", "-q", "-m", "over a unix socket"]);
    gateway.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/unix"],
    );
    assert!(gateway.bare_ref("refs/heads/agent/unix").is_some());
    let out = gateway.git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        stderr(&out).contains("writ: refs/heads/main is protected"),
        "{}",
        stderr(&out)
    );
}

/// A tree from `git mktree --missing` (plumbing: no check on the names).
fn mktree(gateway: &GitGateway, work: &Path, listing: &str) -> String {
    use std::io::Write as _;
    let mut child = Command::new("git")
        .args(["mktree", "--missing"])
        .current_dir(work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", gateway.root().join("gitconfig"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(listing.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "mktree: {listing}");
    let tree = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(tree.len(), 40, "mktree made the tree");
    tree
}

/// A lease that may push and sign, not fetch.
const NO_FETCH: &str = r#"
scope:
  repos: [demo]
  operations: [commit_sign, push]
  branches: ["agent/*"]
ticket:
  title: No fetch
  task: Push without fetching
"#;

/// A lease of two operations a minute.
const TWO_A_MINUTE: &str = r#"
scope:
  repos: [demo]
  operations: [fetch, commit_sign, push]
  branches: ["agent/*"]
ticket:
  title: Slow
  task: Fetch slowly
limits:
  max_ops_per_minute: 2
"#;

#[test]
fn a_fetch_goes_through_the_policy_and_counts_against_the_rate() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let audit = || fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();

    // A lease without `fetch`: refused by the policy, with its code in the log.
    gateway.session_with("no-fetch", NO_FETCH);
    let out = gateway.git_as("no-fetch", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("fetch not allowed"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&audit(), "fetch", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["code"], "operation");

    // Two operations a minute: two fetches pass, the third is refused for the rate.
    gateway.session_with("slow", TWO_A_MINUTE);
    for n in 0..2 {
        let out = gateway.git_as("slow", &work, &["fetch", "-q", "origin"]);
        assert!(out.status.success(), "fetch {n}: {}", stderr(&out));
    }
    let out = gateway.git_as("slow", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("over 2 operations per minute"),
        "{}",
        stderr(&out)
    );
    let denied = audit_events(&audit(), "fetch", "denied");
    assert_eq!(denied.len(), 2, "{denied:?}");
    assert_eq!(denied[1]["code"], "rate");
    // Every allowed fetch has its line: the clone, and the slow lease's two.
    assert_eq!(audit_events(&audit(), "fetch", "allowed").len(), 3);
}

#[test]
fn a_fetch_is_refused_when_upstream_refuses_the_sync() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    // The remote stops taking the daemon's credential before the mirror's first sync.
    gateway
        .remote
        .authorize(generate(KeyKind::Ed25519).unwrap().public_key().clone());
    let work = gateway.root().join("work");
    let out = gateway.git(
        gateway.root(),
        &[
            "clone",
            &format!("{}/demo.git", gateway.url),
            work.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: cannot sync from upstream: repo demo: sync failed"),
        "{}",
        stderr(&out)
    );
    let audit = fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    let denied = audit_events(&audit, "fetch", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("Permission denied"),
        "{denied:?}"
    );
    assert_eq!(gateway.bare_ref("refs/heads/main"), None, "nothing synced");
}
