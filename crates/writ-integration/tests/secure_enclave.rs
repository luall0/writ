//! Keys on the Secure Enclave (`backend: se-cryptokit`, M7.5) with the real `writd`, `writ`,
//! `writ-sign`, `writ-se`, `git` and `ssh`: on the Mac, an agent signing key and the upstream
//! credential made on this Mac's Secure Enclave, a commit signed with it that `git
//! verify-commit` accepts, then pushed upstream with the credential; the keystore holds each
//! key's framed blob, never a private key. Elsewhere, the backend refused by name.
//!
//! Only well-formed blobs reach the real Secure Enclave here (docs/testing.md, hardware is
//! never fuzzed): refusing a bad one before it reaches the device is tested against the fake
//! helper (`crates/writ-signer/tests/helper.rs`).

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
use std::process::{Command, Output, Stdio};

use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-se:
    use: signing
    format: ssh
    algorithm: p256
    backend: se-cryptokit
  upstream-se:
    use: upstream
    kind: ssh
    algorithm: p256
    backend: se-cryptokit
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-se
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-se
    max_ttl: 2h
    max_signatures: 10
    max_pushes: 10
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

const TICKET: &str = r#"
repos:
  demo:
    operations: [fetch, commit_sign, push]
    branches: ["agent/se"]
ticket:
  title: "Sign with the Secure Enclave"
  task: A commit signed by a key that never leaves the Mac
limits:
  ttl: 1h
"#;

fn git(daemon: &Daemon, cwd: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", daemon.root().join("home"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn git_ok(daemon: &Daemon, cwd: &Path, args: &[&str]) -> String {
    let out = git(daemon, cwd, args);
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
    stdout(&out)
}

fn writ_ok(daemon: &Daemon, cwd: &Path, args: &[&str]) -> String {
    let out = daemon
        .writ(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "writ {args:?}: {}", stderr(&out));
    stdout(&out)
}

#[test]
fn a_build_without_the_secure_enclave_refuses_its_backend_by_name() {
    if std::env::consts::OS == "macos" {
        return;
    }
    let error = Daemon::refused_policy(POLICY, POLICY);
    assert!(
        error.contains(
            "keys.agent-se.backend: this daemon has no backend se-cryptokit (it has: software)"
        ),
        "{error}"
    );
}

#[test]
fn secure_enclave_keys_sign_commits_git_verifies_and_push_upstream() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let root = daemon.root().to_owned();

    // The keystore keeps each key's framed blob and its public half, never a private key.
    for (dir, id) in [("signing", "agent-se"), ("upstream", "upstream-se")] {
        let file = fs::read_to_string(root.join("s/keys").join(dir).join(id)).unwrap();
        assert!(
            file.starts_with("writ-key/1\nformat: ssh\nbackend: se-cryptokit\n"),
            "{id}: {file}"
        );
        assert!(!file.contains("PRIVATE KEY"), "{id}: {file}");
        let public =
            fs::read_to_string(root.join("s/keys").join(dir).join(format!("{id}.pub"))).unwrap();
        assert!(public.contains("ecdsa-sha2-nistp256 "), "{id}: {public}");
    }

    // A lease on the Secure Enclave key.
    let request = daemon.request("se", TICKET);
    let id = request.id.clone();
    let out = daemon.run(&["sign", &id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    let agent_key = fs::read_to_string(daemon.session(&id).join("signing_key.pub")).unwrap();
    assert!(agent_key.starts_with("ecdsa-sha2-nistp256 "), "{agent_key}");
    assert_eq!(
        daemon.print("signing-keys"),
        format!("agent-se {} (templates: feature)", agent_key.trim())
    );

    // Upstream has a main branch; the agent's clone is wired for Writ.
    fs::write(
        root.join("home/.gitconfig"),
        "[user]\n\tname = Operator\n\temail = me@operator.example\n\
         [init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    let origin = daemon.remote.repo("demo");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&daemon, &repo, &["init", "-q"]);
    git_ok(
        &daemon,
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    fs::write(repo.join("README"), "demo\n").unwrap();
    git_ok(&daemon, &repo, &["add", "-A"]);
    git_ok(&daemon, &repo, &["commit", "-q", "-m", "seed"]);
    git_ok(
        &daemon,
        &repo,
        &["push", "-q", "origin", "HEAD:refs/heads/main"],
    );
    writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"]);

    // The agent's commit, signed on the Secure Enclave: git verifies it with the lease's key.
    git_ok(&daemon, &repo, &["checkout", "-q", "-b", "agent/se"]);
    fs::write(repo.join("se.txt"), "signed in the enclave\n").unwrap();
    writ_ok(&daemon, &repo, &["git", "add", "-A"]);
    let trailer = format!("Writ: {id}");
    writ_ok(
        &daemon,
        &repo,
        &["git", "commit", "-q", "-m", "SE", "--trailer", &trailer],
    );
    let allowed = root.join("allowed");
    fs::write(&allowed, format!("agent@writ {}\n", agent_key.trim())).unwrap();
    let option = format!("gpg.ssh.allowedSignersFile={}", allowed.display());
    let verified = git(&daemon, &repo, &["-c", &option, "verify-commit", "HEAD"]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(
        stderr(&verified).contains("Good \"git\" signature for agent@writ with ECDSA key"),
        "{}",
        stderr(&verified)
    );

    // Pushed upstream through the daemon, which authenticates with the Secure Enclave
    // credential (the test remote authorizes only that key).
    let head = git_ok(&daemon, &repo, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    writ_ok(&daemon, &repo, &["git", "fetch", "-q", "origin"]);
    writ_ok(
        &daemon,
        &repo,
        &["git", "push", "-q", "origin", "HEAD:refs/heads/agent/se"],
    );
    assert_eq!(
        git_ok(&daemon, &origin, &["rev-parse", "refs/heads/agent/se"]).trim(),
        head
    );
}

/// The fake `writ-se` `make test` builds beside the binaries: the protocol with software
/// keys, so a damaged blob is tried on it and never on the real Secure Enclave.
fn fake_helper() -> std::path::PathBuf {
    writ_integration::binaries::bin("writ-fake-se")
}

#[test]
fn a_damaged_blob_leaves_its_key_unusable_and_the_daemon_running() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let helper = fake_helper();
    let mut daemon = Daemon::start_with(POLICY, Approvals::Ssh, |yaml| {
        format!(
            "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
            helper.display()
        )
    });
    let root = daemon.root().to_owned();
    let request = daemon.request("se", TICKET);
    let id = request.id.clone();
    let out = daemon.run(&["sign", &id, "--yes"], "");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");

    // One hex digit of the agent key's stored blob changed on disk, then the daemon started
    // again: the frame no longer checks, so the blob never reaches the helper.
    let path = root.join("s/keys/signing/agent-se");
    let text = fs::read_to_string(&path).unwrap();
    let body_at = text.rfind('\n').unwrap() - 5;
    let mut bytes = text.into_bytes();
    bytes[body_at] = if bytes[body_at] == b'0' { b'1' } else { b'0' };
    fs::write(&path, &bytes).unwrap();
    daemon.restart();

    // Running: the key is listed, refuses to sign, and the audit log says it once.
    // Logged while it opened the keystore, before its listeners: there once restart returns.
    let log = daemon.log();
    let line = log
        .lines()
        .find(|l| l.contains("a key's stored bytes were refused"))
        .unwrap_or_else(|| panic!("{log}"));
    assert!(line.contains("key=agent-se"), "{line}");
    let audit = daemon.audit();
    assert!(
        audit.contains("key agent-se is unusable: its stored bytes were refused at unseal (its stored bytes don't match their digest (corrupted, or another key's))"),
        "{audit}"
    );
    assert_eq!(
        daemon.print("signing-keys").split_whitespace().next(),
        Some("agent-se")
    );

    // The agent's commit is refused by name. (The harness made the keys with the default
    // helper, the real Secure Enclave, before pointing the daemon at the fake: the fake then
    // refuses the upstream key's real blob, and no bad blob ever reaches the real device.)
    fs::write(
        root.join("home/.gitconfig"),
        "[user]\n\tname = Operator\n\temail = me@operator.example\n\
         [init]\n\tdefaultBranch = main\n",
    )
    .unwrap();
    let origin = daemon.remote.repo("demo");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).unwrap();
    git_ok(&daemon, &repo, &["init", "-q"]);
    git_ok(
        &daemon,
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    fs::write(repo.join("README"), "demo\n").unwrap();
    git_ok(&daemon, &repo, &["add", "-A"]);
    git_ok(&daemon, &repo, &["commit", "-q", "-m", "seed"]);
    git_ok(
        &daemon,
        &repo,
        &["push", "-q", "origin", "HEAD:refs/heads/main"],
    );
    writ_ok(&daemon, &repo, &["init", "demo", "--agents", "none"]);
    git_ok(&daemon, &repo, &["checkout", "-q", "-b", "agent/se"]);
    fs::write(repo.join("se.txt"), "x\n").unwrap();
    writ_ok(&daemon, &repo, &["git", "add", "-A"]);
    let trailer = format!("Writ: {id}");
    let refused = daemon
        .writ(&["git", "commit", "-q", "-m", "SE", "--trailer", &trailer])
        .current_dir(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(128), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("key agent-se is unusable")
            && stderr(&refused).contains("writ admin key rotate"),
        "{}",
        stderr(&refused)
    );
}

/// A software policy with two signing keys: Ed25519 (which the Secure Enclave doesn't make)
/// and P-256.
const SOFTWARE: &str = r#"
keys:
  agent-ed:
    use: signing
    format: ssh
    algorithm: ed25519
  agent-p256:
    use: signing
    format: ssh
    algorithm: p256
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [feature]
templates:
  feature:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-p256
    max_ttl: 2h
    max_signatures: 10
    max_pushes: 10
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

#[test]
fn a_key_moves_to_the_secure_enclave_and_back_from_the_cli_alone() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let daemon = Daemon::start(SOFTWARE, Approvals::Ssh);
    let root = daemon.root().to_owned();
    // The daemon says where a key may live.
    let out = daemon.run(&["admin", "key", "list"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "backends: software (ed25519, p256, p384, rsa3072, rsa4096); se-cryptokit (p256)"
        ),
        "{}",
        stderr(&out)
    );
    // What the Secure Enclave can't make is refused before any signature is asked for.
    let out = daemon.run(
        &[
            "admin",
            "key",
            "rotate",
            "agent-ed",
            "--backend",
            "se-cryptokit",
            "--yes",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("se-cryptokit makes p256 keys only: agent-ed is ed25519"),
        "{}",
        stderr(&out)
    );
    let out = daemon.run(
        &[
            "admin",
            "key",
            "rotate",
            "agent-p256",
            "--backend",
            "yubikey",
            "--yes",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("the daemon has no backend yubikey (it has: software, se-cryptokit)"),
        "{}",
        stderr(&out)
    );

    // To the Secure Enclave: a new key made there, the template switched to it.
    let out = daemon.run(
        &[
            "admin",
            "key",
            "rotate",
            "agent-p256",
            "--backend",
            "se-cryptokit",
            "--name",
            "agent-se",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out)
            .contains("New signing key agent-se (register it on the remote): ecdsa-sha2-nistp256 "),
        "{}",
        stdout(&out)
    );
    let file = fs::read_to_string(root.join("s/keys/signing/agent-se")).unwrap();
    assert!(file.contains("backend: se-cryptokit\n"), "{file}");
    assert!(
        daemon
            .print("signing-keys")
            .contains("agent-se ecdsa-sha2-nistp256 "),
        "the template signs with it now"
    );

    // And back to software: one more rotation, a policy change only.
    let out = daemon.run(
        &[
            "admin",
            "key",
            "rotate",
            "agent-se",
            "--backend",
            "software",
            "--name",
            "agent-back",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let file = fs::read_to_string(root.join("s/keys/signing/agent-back")).unwrap();
    let (back, meta) = writ_crypto::keyfile::decode_secret(file.as_bytes())
        .unwrap_or_else(|e| panic!("a software key again: {e}"));
    assert_eq!(meta.backend, None);
    assert_eq!(
        writ_crypto::algorithm::KeyAlgorithm::of_public(back.public_key().key_data()),
        Some(writ_crypto::algorithm::KeyAlgorithm::P256)
    );
    let printed = daemon.print("signing-keys");
    let back = printed
        .lines()
        .find(|l| l.starts_with("agent-back "))
        .unwrap_or_else(|| panic!("{printed}"));
    assert!(
        back.starts_with("agent-back ecdsa-sha2-nistp256 ")
            && back.ends_with("(templates: feature)"),
        "the template signs with the software key again: {printed}"
    );
}
