//! The gateway with the real `git` and `ssh`: fetch and push through it, the pre-receive check
//! (and its audit lines), session certificates (only valid ones from a real lease get in),
//! commits signed by the daemon through `writ-sign` that `git verify-commit` accepts, and the
//! same protocol over a Unix socket.

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
use writ_integration::gateway::{GitGateway, Listen, now, writ_sign};
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
    assert!(!out.status.success());
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
    // A tree with a `.GIT` entry (git's own directory, under another case): fsck's
    // hasDotgit, the family of checkout CVEs. Made with plumbing, which doesn't check.
    let blob = gateway.git_ok(&work, &["hash-object", "-w", "README"]);
    let listing = format!("100644 blob {}\t.GIT\n", blob.trim());
    let mktree = Command::new("git")
        .args(["mktree"])
        .current_dir(&work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", gateway.root().join("gitconfig"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    let mut child = mktree;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(listing.as_bytes())
        .unwrap();
    let tree = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    assert_eq!(tree.trim().len(), 40, "mktree made the tree");
    let commit = gateway.git_ok(
        &work,
        &["commit-tree", tree.trim(), "-p", "HEAD", "-m", "bad"],
    );
    let out = gateway.git(
        &work,
        &[
            "push",
            "origin",
            &format!("{}:refs/heads/agent/bad", commit.trim()),
        ],
    );
    assert!(!out.status.success(), "a malformed tree was accepted");
    assert!(stderr(&out).contains("hasDotgit"), "{}", stderr(&out));
    assert_eq!(
        gateway.bare_ref("refs/heads/agent/bad"),
        None,
        "nothing landed"
    );
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
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writ: command not allowed"),
        "{}",
        stderr(&out)
    );
}

fn signed_commit_verifies(agent_kind: KeyKind) {
    let gateway = GitGateway::start(agent_kind, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    let agent_public = gateway.agent_key.public_key().to_openssh().unwrap();
    let allowed = gateway.root().join("allowed_signers");
    fs::write(&allowed, format!("agent@writ {agent_public}\n")).unwrap();
    let shim = writ_sign();
    for (key, value) in [
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", shim.to_str().unwrap()),
        ("user.signingkey", &format!("key::{agent_public}")),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
        ("writ.url", &gateway.url),
    ] {
        gateway.git_ok(&work, &["config", key, value]);
    }

    gateway.git_ok(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "signed"],
    );
    let out = gateway.git(&work, &["verify-commit", "HEAD"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Good \"git\" signature for agent@writ"),
        "{}",
        stderr(&out)
    );

    // Signed commits push like any other.
    gateway.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/signed"],
    );

    // No valid certificate, no signature.
    let leases = gateway.service.list(false).unwrap();
    gateway.revoke(&leases.tickets[0].id);
    let out = gateway.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "refused"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writ-sign: the daemon refused to sign"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn ed25519_commits_signed_by_the_daemon_verify_with_git() {
    signed_commit_verifies(KeyKind::Ed25519);
}

#[test]
fn p256_commits_signed_by_the_daemon_verify_with_git() {
    signed_commit_verifies(KeyKind::P256);
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
