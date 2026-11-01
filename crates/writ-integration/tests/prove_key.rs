//! `writ prove-key` with the real binaries: the approver's proof signed by `ssh-keygen`
//! through a throwaway `ssh-agent`, sent over the approval API (SSH and HTTPS), and the
//! daemon's signature checked by the real `ssh-keygen -Y verify`, as a remote checks it. A
//! hostile request sent with plain `ssh` (a proof in namespace `git`, validly signed) is
//! refused on the wire, and logged.

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
use std::process::{Command, Stdio};

use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::{audit_events, stderr, stdout};
use writ_store::looks_secret;

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
templates:
  feature:
    repos: [demo]
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

/// Forgejo's challenge: a 64-hex token, signed without a trailing newline (`echo -n`).
const TOKEN: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// `ssh-keygen -Y verify` of `signature` over `message` by `key` in `namespace`.
fn remote_verifies(
    daemon: &Daemon,
    key: &str,
    namespace: &str,
    message: &str,
    signature: &str,
) -> bool {
    let root = daemon.root();
    fs::write(root.join("allowed"), format!("agent@writ {key}\n")).unwrap();
    fs::write(root.join("proof.sig"), signature).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(root.join("allowed"))
        .args(["-I", "agent@writ", "-n", namespace, "-s"])
        .arg(root.join("proof.sig"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(message.as_bytes())
        .unwrap();
    child.wait().unwrap().success()
}

#[test]
fn writ_prove_key_signs_the_remote_s_message_over_ssh_and_https() {
    for approvals in [Approvals::Https, Approvals::Ssh] {
        let daemon = Daemon::start(POLICY, approvals);
        let key = daemon.print("signing-keys");
        let key = key
            .strip_prefix("agent-01 ")
            .and_then(|rest| rest.strip_suffix(" (templates: feature)"))
            .unwrap_or_else(|| panic!("{key}"))
            .to_owned();
        let out = daemon.run(
            &["prove-key", "agent-01", "--namespace", "gitea", "--yes"],
            TOKEN,
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "{approvals:?}: {}",
            stderr(&out)
        );
        // The signature alone on stdout; the proof shown on stderr, before it was signed.
        let signature = stdout(&out);
        assert!(
            signature.starts_with("-----BEGIN SSH SIGNATURE-----\n"),
            "{signature}"
        );
        assert!(
            signature.ends_with("-----END SSH SIGNATURE-----\n"),
            "{signature}"
        );
        let shown = stderr(&out);
        assert!(shown.contains(&format!("│ {TOKEN}\n")), "{shown}");
        assert!(shown.contains("64 bytes"), "{shown}");
        assert!(shown.contains("Signed by agent-01 (SHA256:"), "{shown}");
        // What the remote checks: the key's signature over the token, in its namespace, and
        // nothing else (not with a newline, not in git's namespace).
        assert!(remote_verifies(&daemon, &key, "gitea", TOKEN, &signature));
        assert!(!remote_verifies(
            &daemon,
            &key,
            "gitea",
            &format!("{TOKEN}\n"),
            &signature
        ));
        assert!(!remote_verifies(&daemon, &key, "git", TOKEN, &signature));

        let audit = daemon.audit();
        let lines = audit_events(&audit, "prove", "allowed");
        assert_eq!(lines.len(), 1, "{audit}");
        assert_eq!(lines[0]["key"], "agent-01");
        assert_eq!(lines[0]["namespace"], "gitea");
        assert!(
            lines[0]["approver"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
        );
        assert!(!audit.contains(TOKEN), "{audit}");
        assert!(!looks_secret(&audit), "{audit}");
    }
}

#[test]
fn writ_prove_key_refuses_what_it_would_never_send() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    // A namespace that is git or Writ's own: refused by the parser (exit 2), nothing signed.
    for namespace in ["git", "writ-approval"] {
        let out = daemon.run(
            &["prove-key", "agent-01", "--namespace", namespace, "--yes"],
            TOKEN,
        );
        assert_eq!(out.status.code(), Some(2), "{namespace}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("invalid proof namespace"),
            "{}",
            stderr(&out)
        );
    }
    // A message over 4 KiB, or none: refused before anything is signed (exit 1).
    let over = "a".repeat(4097);
    for (message, why) in [(over.as_str(), "longer than 4096 bytes"), ("", "0 bytes")] {
        let out = daemon.run(
            &["prove-key", "agent-01", "--namespace", "gitea", "--yes"],
            message,
        );
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(stderr(&out).contains(why), "{}", stderr(&out));
    }
    // A key no template signs with: the daemon refuses (exit 1), with its reason.
    let out = daemon.run(
        &["prove-key", "upstream-01", "--namespace", "gitea", "--yes"],
        TOKEN,
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("upstream-01 is not a key a template signs commits with"),
        "{}",
        stderr(&out)
    );
    assert_eq!(audit_events(&daemon.audit(), "prove", "denied").len(), 1);
    assert!(audit_events(&daemon.audit(), "prove", "allowed").is_empty());
}

#[test]
fn a_hostile_proof_sent_over_the_wire_is_refused_and_logged() {
    // What a client that skips every check could send: a proof in git's namespace (it would
    // sign commits outside the lease and the ledger), validly signed by the approver.
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let root = daemon.root();
    let doc = format!(
        r#"{{"kind":"writ-proof/1","key":"agent-01","namespace":"git","message":"{TOKEN}"}}"#
    );
    fs::write(root.join("doc"), &doc).unwrap();
    let signed = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-U", "-q", "-n", "writ-approval", "-f"])
        .arg(root.join("approver.pub"))
        .arg(root.join("doc"))
        .env("SSH_AUTH_SOCK", daemon.agent.socket())
        .output()
        .unwrap();
    assert_eq!(signed.status.code(), Some(0), "{}", stderr(&signed));
    let signature = fs::read_to_string(root.join("doc.sig")).unwrap();
    let body = serde_json::json!({"proof": doc, "signature": signature}).to_string();
    // The approval API with the reader key, nothing from the user's SSH setup.
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
            "writ prove",
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
    let out = writ_integration::process::finish(child);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let reply: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("proof refused: "), "{message}");
    assert!(message.contains("commit signatures"), "{message}");
    let denied = audit_events(&daemon.audit(), "prove", "denied");
    assert_eq!(denied.len(), 1, "{}", daemon.audit());
    assert!(audit_events(&daemon.audit(), "prove", "allowed").is_empty());
}
