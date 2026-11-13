//! The SSH CA rotated live (M7.6, `writ admin ca rotate`) with the real `writd`, `writ`, `git`
//! and `ssh`, on a sealed keystore: the CA shown, rotated; a lease the old CA certified keeps
//! working, a new one is certified by the new CA; the old CA recorded as trusted until that
//! lease's end, kept across a restart; a replay, another daemon's, a backend the daemon lacks,
//! a non-approver's and not a `writ-ca/1` each refused and logged.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use writ_integration::daemon::{Approvals, Daemon, ssh_options};
use writ_integration::{stderr, stdout};

const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
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
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch]\n    branches: [\"agent/x\"]\n\
                      ticket:\n  title: \"CA\"\n  task: CA\nlimits:\n  ttl: 30m\n";

fn ls_remote(daemon: &Daemon, lease: &str) -> Output {
    let ssh = format!(
        "ssh {}",
        ssh_options(&daemon.root().join("known_hosts"), &daemon.session(lease)).join(" ")
    );
    Command::new("git")
        .args([
            "ls-remote",
            &format!("ssh://git@127.0.0.1:{}/demo.git", daemon.agents_port),
        ])
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", daemon.root().join("home"))
        .output()
        .unwrap()
}

fn ca_public(daemon: &Daemon) -> String {
    fs::read_to_string(daemon.root().join("s/keys/ca.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

fn fingerprint(line: &str) -> String {
    writ_crypto::ssh_key::PublicKey::from_openssh(line)
        .unwrap()
        .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string()
}

fn daemon_fingerprint(daemon: &Daemon) -> String {
    let line = daemon.print("host-key");
    let key = writ_crypto::ssh_key::PublicKey::from_openssh(&line).unwrap();
    key.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string()
}

/// `doc` signed by the approver (or by `key`, another one).
fn signed(daemon: &Daemon, doc: &str, key: Option<&std::path::Path>) -> String {
    let root = daemon.root();
    fs::write(root.join("ca-doc"), doc).unwrap();
    let _ = fs::remove_file(root.join("ca-doc.sig"));
    let mut sign = Command::new("ssh-keygen");
    sign.args(["-Y", "sign", "-q", "-n", "writ-approval"]);
    match key {
        Some(key) => {
            sign.arg("-f").arg(key);
        }
        None => {
            sign.arg("-U")
                .arg("-f")
                .arg(root.join("approver.pub"))
                .env("SSH_AUTH_SOCK", daemon.agent.socket());
        }
    }
    let out = sign.arg(root.join("ca-doc")).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    fs::read_to_string(root.join("ca-doc.sig")).unwrap()
}

/// `body` sent as `writ admin ca rotate` over the approval API's SSH, with the reader key.
fn sent(daemon: &Daemon, body: &str) -> Output {
    let root = daemon.root();
    let mut child = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentityAgent=none",
        ])
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ])
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            root.join("known_hosts").display()
        ))
        .arg("-i")
        .arg(root.join("writ/reader"))
        .args([
            "-p",
            &daemon.approvals_port.to_string(),
            "writ@127.0.0.1",
            "writ admin ca rotate",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    writ_integration::process::finish(child)
}

/// A `writ-ca/1` naming `daemon`, `replaces` and `backend`.
fn document(daemon: &str, replaces: &str, backend: &str) -> String {
    format!(
        r#"{{"kind":"writ-ca/1","daemon":"{daemon}","replaces":"{replaces}","backend":"{backend}"}}"#
    )
}

/// The error message of a refused reply.
fn refusal(out: &Output) -> String {
    assert_eq!(out.status.code(), Some(1), "{}{}", stdout(out), stderr(out));
    let reply: serde_json::Value = serde_json::from_str(&stdout(out)).unwrap();
    reply["error"]["message"].as_str().unwrap().to_owned()
}

#[test]
fn the_ca_is_rotated_live_and_a_lease_the_old_one_certified_keeps_working_to_its_end() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let old = ca_public(&daemon);
    let old_fingerprint = fingerprint(&old);
    let before = daemon.lease("before", TICKET);
    assert_eq!(ls_remote(&daemon, &before).status.code(), Some(0));

    let shown = daemon.run(&["admin", "ca", "show"], "");
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let said = stdout(&shown);
    assert!(said.contains(&old_fingerprint), "{said}");
    assert!(said.contains("backend: software"), "{said}");
    assert!(said.contains("no other CA is trusted"), "{said}");

    let out = daemon.run(&["admin", "ca", "rotate", "--yes"], "");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let new = ca_public(&daemon);
    assert_ne!(new, old);
    let new_fingerprint = fingerprint(&new);
    assert!(
        stdout(&out).contains(&format!(
            "SSH CA rotated: {new_fingerprint} (key on software), replacing {old_fingerprint}."
        )),
        "{}",
        stdout(&out)
    );
    // The lease the old CA certified works on; a new one is certified by the new CA.
    assert_eq!(
        ls_remote(&daemon, &before).status.code(),
        Some(0),
        "the old CA's lease"
    );
    let after = daemon.lease("after", TICKET);
    assert_eq!(
        ls_remote(&daemon, &after).status.code(),
        Some(0),
        "the new CA's lease"
    );
    let said = stdout(&daemon.run(&["admin", "ca", "show"], ""));
    assert!(said.contains(&new_fingerprint), "{said}");
    assert!(
        said.contains(&format!(
            "a CA it replaced, {old_fingerprint}, is trusted until"
        )),
        "{said}"
    );
    let retired = fs::read_to_string(daemon.root().join("s/keys/ca-retired.pub")).unwrap();
    assert!(retired.trim_end().ends_with(&old), "{retired}");
    // Kept across a restart.
    daemon.restart();
    assert_eq!(daemon.unseal().status.code(), Some(0));
    assert_eq!(
        ls_remote(&daemon, &before).status.code(),
        Some(0),
        "after a restart"
    );
    assert_eq!(ls_remote(&daemon, &after).status.code(), Some(0));
    assert!(daemon.audit().contains(&format!(
        "SSH CA rotated: {old_fingerprint} replaced by {new_fingerprint}, its key on backend software"
    )));
}

#[test]
fn a_replayed_stale_foreign_or_unsigned_ca_rotation_is_refused_and_logged() {
    let daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert_eq!(daemon.unseal().status.code(), Some(0));
    let me = daemon_fingerprint(&daemon);
    let current = fingerprint(&ca_public(&daemon));
    let doc = document(&me, &current, "software");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, None)}).to_string();
    let out = sent(&daemon, &body);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let rotated = fingerprint(&ca_public(&daemon));
    assert_ne!(rotated, current);
    // The same document again: it names a CA no longer in force.
    assert_eq!(
        refusal(&sent(&daemon, &body)),
        format!(
            "not rotated: it replaces CA {current}, but {rotated} is in force (rotated \
             meanwhile?): writ admin ca rotate again"
        )
    );
    // Another daemon's; a backend this daemon lacks; a non-approver; not a writ-ca/1.
    let other = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    let doc = document(other, &rotated, "software");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, None)}).to_string();
    assert_eq!(
        refusal(&sent(&daemon, &body)),
        format!("the rotation names daemon {other}, not this one ({me})")
    );
    let doc = document(&me, &rotated, "yubikey");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, None)}).to_string();
    assert!(
        refusal(&sent(&daemon, &body))
            .starts_with("not rotated: this daemon has no backend yubikey"),
    );
    let stranger = daemon.root().join("stranger");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(&stranger)
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0));
    let doc = document(&me, &rotated, "software");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, Some(&stranger))})
            .to_string();
    let why = refusal(&sent(&daemon, &body));
    assert!(why.ends_with(", which is not in approvers"), "{why}");
    let body = serde_json::json!({"document": document(&me, &rotated, "software").replace("writ-ca/1", "writ-tls/1"), "signature": "x"}).to_string();
    assert!(refusal(&sent(&daemon, &body)).starts_with("not a writ-ca/1 document: "));
    assert_eq!(fingerprint(&ca_public(&daemon)), rotated, "nothing rotated");
    let audit = daemon.audit();
    assert!(
        audit.contains(&format!(
            "SSH CA not rotated (CA {current}, backend software): it replaces"
        )),
        "{audit}"
    );
}

/// On the Mac, against the fake `writ-se`: the CA moved to the device by a rotation, and back
/// to software by another, each new lease certified by the CA in force.
#[test]
fn on_the_mac_the_ca_moves_to_the_secure_enclave_and_back() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let helper = writ_integration::binaries::bin("writ-fake-se");
    let daemon = Daemon::start_sealed_with(POLICY, Approvals::Ssh, |yaml| {
        format!(
            "{yaml}signers:\n  se_cryptokit:\n    helper: {}\n",
            helper.display()
        )
    });
    assert_eq!(daemon.unseal().status.code(), Some(0));
    let first = daemon.lease("first", TICKET);
    let out = daemon.run(
        &[
            "admin",
            "ca",
            "rotate",
            "--backend",
            "se-cryptokit",
            "--yes",
        ],
        "",
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(ca_public(&daemon).starts_with("ecdsa-sha2-nistp256 "));
    assert!(stdout(&daemon.run(&["admin", "ca", "show"], "")).contains("backend: se-cryptokit"));
    let lease = daemon.lease("on-device", TICKET);
    assert_eq!(
        ls_remote(&daemon, &lease).status.code(),
        Some(0),
        "the device's certificate"
    );
    let out = daemon.run(
        &["admin", "ca", "rotate", "--backend", "software", "--yes"],
        "",
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(ca_public(&daemon).starts_with("ssh-ed25519 "));
    let again = daemon.lease("back", TICKET);
    assert_eq!(ls_remote(&daemon, &again).status.code(), Some(0));
    assert_eq!(
        ls_remote(&daemon, &lease).status.code(),
        Some(0),
        "the device CA's lease"
    );
    // Two rotations later, the first CA's lease still works: every retired CA is kept.
    assert_eq!(
        ls_remote(&daemon, &first).status.code(),
        Some(0),
        "the first CA's lease"
    );
    let said = stdout(&daemon.run(&["admin", "ca", "show"], ""));
    assert_eq!(said.matches("a CA it replaced").count(), 2, "{said}");
}

/// The review after M7.6 (D-4): the CA's backend marker, which auto-unseal's check reads while
/// sealed, is checked against the key the unseal opens: one that says otherwise refuses the
/// unseal, naming the file.
#[test]
fn a_ca_marker_that_is_not_the_key_s_backend_stops_the_unseal() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert_eq!(daemon.unseal().status.code(), Some(0));
    daemon.stop();
    let marker = daemon.root().join("s/keys/ca.backend");
    fs::write(&marker, "se-cryptokit\n").unwrap();
    daemon.restart();
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains(&format!(
            "{}: the CA's backend marker says se-cryptokit, but its key is on software",
            marker.canonicalize().unwrap().display()
        )) || stderr(&out)
            .contains("the CA's backend marker says se-cryptokit, but its key is on software"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains("daemon sealed"));
}
