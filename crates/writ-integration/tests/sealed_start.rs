//! M5's sealed start with the real binaries: `writd init` (the passphrase on stdin), `writd
//! run` sealed, `writ unseal` through the throwaway ssh-agent over SSH and HTTPS. While
//! sealed every request fails closed with "daemon sealed" and is logged; unsealing needs the
//! passphrase and an approver's signature, either alone refused and logged; a restart keeps
//! the active leases, usable again once unsealed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;

use writ_crypto::keys::{KeyKind, generate};
use writ_integration::daemon::{Approvals, Daemon, PASSPHRASE};
use writ_integration::{audit_events, stderr, stdout};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main"]
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

const TICKET: &str = "repos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
                      branches: [\"agent/oauth\"]\nticket:\n  title: \"Add OAuth login\"\n  \
                      task: Add GitHub OAuth login\nlimits:\n  ttl: 1h\n";

/// Whether the audit log holds a request refused because the daemon was sealed.
fn crate_audit_has_sealed(audit: &str) -> bool {
    audit_events(audit, "command", "denied")
        .iter()
        .any(|e| e["reason"].as_str().is_some_and(|r| r.starts_with(SEALED)))
}

const SEALED: &str = "daemon sealed: an approver unseals it with `writ unseal`";

#[test]
fn while_sealed_every_request_fails_closed_with_daemon_sealed_and_is_logged() {
    let daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.log().contains("sealed=true"), "{}", daemon.log());
    // The approver is told at once (the token is in the boot tier).
    let told = daemon.telegram.wait_for(1);
    assert!(told[0].contains("writd started, sealed"), "{}", told[0]);

    for args in [
        &["ls"][..],
        &["ls", "--all"],
        &["revoke", "wrt_01K0000000000000000000000A"],
    ] {
        let out = daemon.run(args, "");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stdout(&out));
        assert!(stderr(&out).contains(SEALED), "{args:?}: {}", stderr(&out));
    }
    let file = daemon.root().join("ticket.yaml");
    fs::write(&file, TICKET).unwrap();
    let out = daemon.run(&["request", file.to_str().unwrap(), "--no-wait"], "");
    assert_ne!(out.status.code(), Some(0));
    assert!(stderr(&out).contains(SEALED), "{}", stderr(&out));

    // Logged, coalesced per source: one line, the others counted later.
    let audit = daemon.audit();
    assert_eq!(audit_events(&audit, "seal", "done").len(), 1, "{audit}");
    let refused = audit_events(&audit, "command", "denied");
    assert!(!refused.is_empty(), "{audit}");
    assert!(
        refused
            .iter()
            .all(|e| e["reason"].as_str().unwrap().starts_with(SEALED)),
        "{audit}"
    );
    // Nothing was opened: no unseal line, the keystore's secrets never read.
    assert_eq!(daemon.audited("unseal", "allowed"), 0);
}

#[test]
fn unsealing_needs_both_the_passphrase_and_an_approver_signature() {
    for approvals in [Approvals::Ssh, Approvals::Https] {
        let daemon = Daemon::start_sealed(POLICY, approvals);

        // The right signature, a wrong passphrase: refused after the signature, still sealed.
        let out = daemon.run(&["unseal"], "the wrong passphrase\n");
        assert_eq!(
            out.status.code(),
            Some(1),
            "{approvals:?}: {}",
            stdout(&out)
        );
        assert!(
            stdout(&out).contains("is sealed (start "),
            "{}",
            stdout(&out)
        );
        assert!(
            stderr(&out).contains("not unsealed: cannot unlock the keystore: wrong passphrase"),
            "{approvals:?}: {}",
            stderr(&out)
        );
        assert!(stderr(&daemon.run(&["ls"], "")).contains(SEALED));

        // The right passphrase, a key that isn't an approver's: refused before scrypt.
        let stranger = generate(KeyKind::Ed25519).unwrap();
        daemon.agent.add(&stranger);
        let stranger_pub = daemon.root().join("stranger.pub");
        fs::write(&stranger_pub, stranger.public_key().to_openssh().unwrap()).unwrap();
        let out = daemon.run(
            &["unseal", "--key", stranger_pub.to_str().unwrap()],
            &format!("{PASSPHRASE}\n"),
        );
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        assert!(
            stderr(&out).contains("which is not in approvers"),
            "{}",
            stderr(&out)
        );
        assert!(stderr(&daemon.run(&["ls"], "")).contains(SEALED));

        // Both: open.
        let out = daemon.unseal();
        assert!(
            out.status.success(),
            "{approvals:?}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).contains("Unsealed (signed by SHA256:"),
            "{}",
            stdout(&out)
        );
        let ls = daemon.run(&["ls"], "");
        assert!(ls.status.success(), "{}", stderr(&ls));
        let audit = daemon.audit();
        let denied = audit_events(&audit, "unseal", "denied");
        assert_eq!(denied.len(), 2, "{audit}");
        assert!(
            denied[0]["reason"]
                .as_str()
                .unwrap()
                .contains("wrong passphrase"),
            "{audit}"
        );
        assert!(
            denied[0]["approver"].is_string(),
            "the approver is named: {audit}"
        );
        assert!(
            denied[1]["reason"]
                .as_str()
                .unwrap()
                .contains("not in approvers"),
            "{audit}"
        );
        assert_eq!(
            audit_events(&audit, "unseal", "allowed").len(),
            1,
            "{audit}"
        );
        assert!(
            !audit.contains(PASSPHRASE),
            "the passphrase is never logged"
        );
        assert!(
            !daemon.log().contains(PASSPHRASE),
            "nor in the daemon's log"
        );
        let told = daemon.telegram.wait_for(2);
        assert!(told[1].contains("writd unsealed"), "{}", told[1]);

        // Open once: another unseal is told there is nothing to do.
        let out = daemon.unseal();
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("the daemon is not sealed: there is nothing to unseal"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn a_restart_keeps_active_leases_working_after_unseal() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Https);
    assert!(daemon.unseal().status.success());
    let lease = daemon.lease("a", TICKET);
    let session = daemon.session(&lease);
    let certificate = fs::read(session.join("key-cert.pub")).unwrap();
    assert!(daemon.ls_remote(&session).status.success());

    daemon.restart();
    // Sealed again: the certificate is refused until an approver unseals.
    let out = daemon.ls_remote(&session);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Permission denied"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains(SEALED));
    // The refused certificate is logged as sealed, not as a lease's denial.
    assert!(
        crate_audit_has_sealed(&daemon.audit()),
        "{}",
        daemon.audit()
    );
    assert_eq!(daemon.audited("seal", "done"), 2);

    assert!(daemon.unseal().status.success());
    let listed = stdout(&daemon.run(&["ls"], ""));
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with(&lease) && l.contains("active")),
        "{listed}"
    );
    // The same certificate, untouched, accepted again: it still expires when it did.
    assert_eq!(fs::read(session.join("key-cert.pub")).unwrap(), certificate);
    let out = daemon.ls_remote(&session);
    assert!(out.status.success(), "{}", stderr(&out));
}
