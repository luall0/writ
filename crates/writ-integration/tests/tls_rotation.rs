//! The HTTPS approval API's TLS key rotated by a signed admin change, live (M7.5, `writ admin
//! tls rotate`), with the real binaries: over HTTPS the client's pin is replaced and checked,
//! the old pin is refused from then on, the new certificate survives a restart; a replayed or
//! stale document, another daemon's, a backend the daemon lacks and a non-approver's signature
//! are refused, each in the audit log. On the Mac, the key moved to the Secure Enclave and
//! back; `writd init --tls-backend` refuses a backend this daemon lacks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{stderr, stdout};

const POLICY: &str = r#"
format: 2
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
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 60
    max_push_size: 10MB
"#;

/// The daemon's SSH host key fingerprint, as a `writ-tls/1` names it.
fn daemon_fingerprint(daemon: &Daemon) -> String {
    let line = daemon.print("host-key");
    let key = writ_crypto::ssh_key::PublicKey::from_openssh(&line).unwrap();
    key.fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string()
}

/// `doc` signed by the approver (or by `key`, another one).
fn signed(daemon: &Daemon, doc: &str, key: Option<&std::path::Path>) -> String {
    let root = daemon.root();
    fs::write(root.join("tls-doc"), doc).unwrap();
    let _ = fs::remove_file(root.join("tls-doc.sig"));
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
    let out = sign.arg(root.join("tls-doc")).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    fs::read_to_string(root.join("tls-doc.sig")).unwrap()
}

/// `body` sent as `writ admin tls rotate` over the approval API's SSH, with the reader key.
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
            "writ admin tls rotate",
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

/// A `writ-tls/1` naming `daemon`, `replaces` and `backend`.
fn document(daemon: &str, replaces: &str, backend: &str) -> String {
    format!(
        r#"{{"kind":"writ-tls/1","daemon":"{daemon}","replaces":"{replaces}","backend":"{backend}"}}"#
    )
}

/// The error message of a refused reply.
fn refusal(out: &Output) -> String {
    assert_eq!(out.status.code(), Some(1), "{}{}", stdout(out), stderr(out));
    let reply: serde_json::Value = serde_json::from_str(&stdout(out)).unwrap();
    reply["error"]["message"].as_str().unwrap().to_owned()
}

#[test]
fn the_tls_key_is_rotated_live_the_client_repinned_and_the_old_pin_refused() {
    let mut daemon = Daemon::start(POLICY, Approvals::Https);
    let root = daemon.root().to_owned();
    let old = daemon.print("tls-fingerprint");
    // Another approver's machine, still pinning the old certificate.
    fs::copy(root.join("tls_pins"), root.join("tls_pins.other")).unwrap();

    let out = daemon.run(&["admin", "tls", "rotate", "--yes"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let said = stdout(&out);
    assert!(
        said.contains(&format!(
            "The HTTPS approval API of daemon {}: certificate {old}, its key on software.",
            daemon_fingerprint(&daemon)
        )),
        "{said}"
    );
    let new = daemon.print("tls-fingerprint");
    assert_ne!(new, old);
    assert!(
        said.contains(&format!(
            "TLS key rotated: certificate {new} (key on software), replacing {old}."
        )),
        "{said}"
    );
    assert!(
        said.contains("Checked: the daemon answers with the new certificate."),
        "{said}"
    );
    // The client's pin replaced, only that line; the old pin refused at once.
    let pins = fs::read_to_string(root.join("tls_pins")).unwrap();
    assert!(pins.contains(&new) && !pins.contains(&old), "{pins}");
    let other = daemon
        .writ(&["ls"])
        .env("WRIT_TLS_PINS", root.join("tls_pins.other"))
        .output()
        .unwrap();
    assert_eq!(other.status.code(), Some(1), "{}", stderr(&other));
    assert!(
        stderr(&other).contains("the daemon's certificate doesn't match the pinned fingerprint"),
        "{}",
        stderr(&other)
    );
    // In the audit log, by the approver.
    let audit = daemon.audit();
    assert!(
        audit.contains(&format!(
            "TLS key rotated: certificate {old} replaced by {new}, its key on backend software"
        )),
        "{audit}"
    );
    // Kept: a restart serves the new certificate.
    daemon.restart();
    assert_eq!(daemon.print("tls-fingerprint"), new);
    let out = daemon.run(&["ls"], "");
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_replayed_stale_foreign_or_unsigned_rotation_is_refused_and_logged() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let me = daemon_fingerprint(&daemon);
    let current = daemon.print("tls-fingerprint");
    let doc = document(&me, &current, "software");
    let signature = signed(&daemon, &doc, None);
    let body = serde_json::json!({"document": doc, "signature": signature}).to_string();
    // Over SSH the reply is the protocol's: done once.
    let out = sent(&daemon, &body);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let rotated = daemon.print("tls-fingerprint");
    assert_ne!(rotated, current);
    // The same document again: it names a certificate no longer in force.
    assert_eq!(
        refusal(&sent(&daemon, &body)),
        format!(
            "not rotated: it replaces certificate {current}, but {rotated} is in force (rotated \
             meanwhile?): writ admin tls rotate again"
        )
    );
    assert_eq!(daemon.print("tls-fingerprint"), rotated, "nothing rotated");
    // Another daemon's.
    let other = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    let doc = document(other, &rotated, "software");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, None)}).to_string();
    assert_eq!(
        refusal(&sent(&daemon, &body)),
        format!("the rotation names daemon {other}, not this one ({me})")
    );
    // A backend this daemon lacks.
    let doc = document(&me, &rotated, "yubikey");
    let body =
        serde_json::json!({"document": doc, "signature": signed(&daemon, &doc, None)}).to_string();
    assert_eq!(
        refusal(&sent(&daemon, &body)),
        "not rotated: this daemon has no backend yubikey (writ admin key list names them)"
    );
    // Signed by a key that isn't an approver's.
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
    assert!(
        why.starts_with("the signature is by SHA256:")
            && why.ends_with(", which is not in approvers"),
        "a non-approver's signature: {why}"
    );
    // Not a writ-tls/1 document.
    let body =
        serde_json::json!({"document": "{\"kind\":\"writ-scan/1\"}", "signature": signature})
            .to_string();
    assert!(refusal(&sent(&daemon, &body)).starts_with("not a writ-tls/1 document: "));
    assert_eq!(daemon.print("tls-fingerprint"), rotated, "nothing rotated");
    // Each refusal after the document was read is an admin line, denied.
    let audit = daemon.audit();
    assert!(
        audit.contains(&format!(
            "TLS key not rotated (certificate {current}, backend software): it replaces"
        )),
        "{audit}"
    );
    assert!(
        audit.contains("TLS key not rotated: the rotation names daemon"),
        "{audit}"
    );
}

#[test]
fn on_the_mac_the_tls_key_moves_to_the_secure_enclave_and_back() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    let mut daemon = Daemon::start(POLICY, Approvals::Https);
    let root = daemon.root().to_owned();
    let out = daemon.run(
        &[
            "admin",
            "tls",
            "rotate",
            "--backend",
            "se-cryptokit",
            "--yes",
        ],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("(key on se-cryptokit)"),
        "{}",
        stdout(&out)
    );
    let key = fs::read_to_string(root.join("s/keys/tls-01")).unwrap();
    assert!(
        key.starts_with("writ-key/1\nformat: ssh\nbackend: se-cryptokit\n"),
        "{key}"
    );
    assert!(root.join("s/keys/tls-01.pub").exists());
    // Handshakes signed in the Secure Enclave, after a restart too.
    daemon.restart();
    let out = daemon.run(&["ls"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    // And back to software, the public half gone with the device key.
    let out = daemon.run(
        &["admin", "tls", "rotate", "--backend", "software", "--yes"],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!root.join("s/keys/tls-01.pub").exists());
    let key = fs::read(root.join("s/keys/tls-01")).unwrap();
    assert!(!key.starts_with(b"writ-key/1"), "a software key again");
}

#[test]
fn writd_init_refuses_a_tls_backend_it_lacks() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let have = if std::env::consts::OS == "macos" {
        "software, se-cryptokit"
    } else {
        "software"
    };
    for (backend, expected) in [
        (
            "yubikey",
            format!(
                "writd: --tls-backend yubikey: this daemon has no such backend (it has: {have})"
            ),
        ),
        (
            "SE",
            format!("writd: --tls-backend SE: this daemon has no such backend (it has: {have})"),
        ),
    ] {
        let out = Command::new(bin("writd"))
            .arg("init")
            .arg(daemon.root().join("writd.yaml"))
            .args(["--tls-backend", backend])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert_eq!(
            stderr(&out).lines().last(),
            Some(expected.as_str()),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn on_the_mac_writd_init_makes_the_tls_key_in_the_secure_enclave() {
    if !writ_integration::on_the_mac("this test") {
        return;
    }
    // The installer's way: the keystore made with its HTTPS key in the Secure Enclave, served
    // while sealed (the boot tier's), and after the unseal.
    let daemon = Daemon::start_sealed_tls(POLICY, Approvals::Https, "se-cryptokit");
    let key = fs::read_to_string(daemon.root().join("s/boot/tls-01")).unwrap();
    assert!(
        key.starts_with("writ-key/1\nformat: ssh\nbackend: se-cryptokit\n"),
        "{key}"
    );
    let out = daemon.unseal();
    assert!(out.status.success(), "{}", stderr(&out));
    let out = daemon.run(&["admin", "tls", "rotate", "--yes"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("its key on se-cryptokit.")
            && stdout(&out).contains("(key on se-cryptokit)"),
        "the current backend kept by default: {}",
        stdout(&out)
    );
}
