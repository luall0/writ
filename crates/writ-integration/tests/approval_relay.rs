//! The review after M7.6 (L-1): in local mode the approver's pins and settings are files of
//! the user every agent runs as, so an agent can point `writ` at a relay of its own, its own
//! host key pinned, which reaches the real daemon with the approver's reader key. `writ`
//! signs nothing such a relay could use: a reply naming a daemon other than the one whose
//! host key the connection checked is refused, and so is a text that isn't the one its digest
//! names (over HTTPS, where the client never sees the host key, and against a copy of the
//! boot tier, the digest is the check: the relay below holds the daemon's own host key to
//! stand for both). Nothing signed is sent: the real daemon logs no admin change, the version
//! stays.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;

use writ_core::authority::TextDigest;
use writ_integration::daemon::{Approvals, Daemon, private};
use writ_integration::relay::{Change, Relay};
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

/// The relay's own line in a `known_hosts` of its own, and `writ` pointed at it.
fn through(daemon: &Daemon, relay: &Relay, args: &[&str]) -> std::process::Output {
    let pins = daemon.root().join("relay_known_hosts");
    fs::write(&pins, format!("{}\n", relay.known_hosts_line())).unwrap();
    private(&pins);
    daemon
        .writ(args)
        .env(
            "WRIT_APPROVAL_URL",
            format!("ssh://127.0.0.1:{}", relay.port),
        )
        .env("WRIT_KNOWN_HOSTS", &pins)
        .output()
        .unwrap()
}

/// The policy in force on the real daemon: its version line (on stderr) and its text.
fn policy_in_force(daemon: &Daemon) -> (String, String) {
    let out = daemon.run(&["admin", "show", "policy"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    (stderr(&out), stdout(&out))
}

/// What the edits below would make: a template of the relay's own, beside the approver's.
const ADDED: &str = "templates:\n  relay:\n    operations: [fetch, commit_sign, push]\n    \
                     branches: [\"*\"]\n    committer_emails: [\"agent@writ\"]\n    signing_key: \
                     agent-01\n    max_ttl: 2h\n    max_signatures: 1000\n    max_pushes: 1000\n    \
                     max_ops_per_minute: 100\n    max_push_size: 10MB\n";

#[test]
fn a_relay_that_shows_another_text_under_the_daemon_s_digest_gets_nothing_signed() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let relay = Relay::start(
        &runtime,
        daemon.approvals_port,
        &daemon.root().join("writ/reader"),
        // The daemon's own host key: the name check passes, the digest is what is left.
        Some(
            writ_crypto::ssh_key::PrivateKey::from_openssh(
                fs::read_to_string(daemon.root().join("s/keys/host")).unwrap(),
            )
            .unwrap(),
        ),
        Change::AdminText {
            from: "templates:\n".to_owned(),
            to: ADDED.to_owned(),
        },
    );
    let (version, text) = policy_in_force(&daemon);
    let digest = TextDigest::of(&text);
    let sent = TextDigest::of(&text.replacen("templates:\n", ADDED, 1));
    let expected = format!(
        "writ: the policy the daemon sent is not the text its digest names (sha256 {digest}, the \
         text sent hashes to {sent}): something changed it on the way, so nothing was signed\n"
    );
    // A whole text applied, and one field edited: each refused before anything is signed.
    let file = daemon.root().join("edited-policy.yaml");
    fs::write(&file, text.replace("max_pushes: 20", "max_pushes: 5")).unwrap();
    for args in [
        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"][..],
        &[
            "admin",
            "template",
            "set",
            "feature",
            "max_pushes=5",
            "--yes",
        ][..],
    ] {
        let out = through(&daemon, &relay, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
        assert_eq!(stderr(&out), expected, "{args:?}");
    }
    let lines = relay.lines();
    assert!(!lines.is_empty());
    assert!(
        lines.iter().all(|l| l == "writ admin show policy"),
        "only the text in force was asked for: {lines:?}"
    );
    assert_eq!(daemon.audited("admin", "allowed"), 0);
    assert_eq!(daemon.audited("admin", "denied"), 0);
    assert_eq!(policy_in_force(&daemon), (version, text));
}

#[test]
fn a_relay_with_its_own_host_key_is_not_the_daemon_its_replies_name() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let relay = Relay::start(
        &runtime,
        daemon.approvals_port,
        &daemon.root().join("writ/reader"),
        None,
        Change::Nothing,
    );
    let (version, text) = policy_in_force(&daemon);
    let named = writ_crypto::keys::fingerprint(
        &writ_crypto::ssh_key::PublicKey::from_openssh(&daemon.print("host-key")).unwrap(),
    );
    let relays = writ_crypto::keys::fingerprint(relay.host_key.public_key());
    assert_ne!(named, relays);
    let expected = format!(
        "writ: the reply names daemon {named}, but the daemon that answered holds host key \
         {relays}, the key pinned for this address: it is not the daemon it says it is \
         (something stands between this client and the daemon), so nothing was signed\n"
    );
    let file = daemon.root().join("edited-policy.yaml");
    fs::write(&file, text.replace("max_pushes: 20", "max_pushes: 5")).unwrap();
    for args in [
        &["admin", "apply", "policy", file.to_str().unwrap(), "--yes"][..],
        &[
            "admin",
            "template",
            "set",
            "feature",
            "max_pushes=5",
            "--yes",
        ][..],
    ] {
        let out = through(&daemon, &relay, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
        assert_eq!(stderr(&out), expected, "{args:?}");
    }
    assert!(
        relay.lines().iter().all(|l| l == "writ admin show policy"),
        "{:?}",
        relay.lines()
    );
    assert_eq!(daemon.audited("admin", "allowed"), 0);
    assert_eq!(policy_in_force(&daemon), (version, text));
    // The same commands straight to the daemon: signed and applied (the refusals above were
    // the relay's, not the commands').
    let out = daemon.run(
        &[
            "admin",
            "template",
            "set",
            "feature",
            "max_pushes=5",
            "--yes",
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(daemon.audited("admin", "allowed"), 1);
}
