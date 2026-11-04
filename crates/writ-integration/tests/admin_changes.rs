//! M5's signed admin changes with the real binaries: `writ admin show` and `writ admin apply`
//! (the approval key in the throwaway ssh-agent), over SSH and HTTPS. A signed change of the
//! approvers, readers or policy applies at once and is written back to its file; a stranger's
//! signature is refused; a file edited by hand is set aside at the next start, never applied;
//! a version altered at rest keeps the daemon sealed; `writd recover` puts a file in force
//! with the passphrase only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::process::Command;

use writ_crypto::keys::{KeyKind, generate};
use writ_integration::binaries::bin;
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

const TICKET: &str = "scope:\n  repos: [demo]\n  operations: [fetch, commit_sign, push]\n  \
                      branches: [\"agent/oauth\"]\nticket:\n  title: \"Add OAuth login\"\n  \
                      task: Add GitHub OAuth login\nlimits:\n  ttl: 1h\n";

/// `writ admin apply <target> <file> --yes` with `extra` flags: its output.
fn apply(daemon: &Daemon, target: &str, text: &str, extra: &[&str]) -> std::process::Output {
    let file = daemon.root().join(format!("new-{target}"));
    fs::write(&file, text).unwrap();
    let mut args = vec!["admin", "apply", target, file.to_str().unwrap(), "--yes"];
    args.extend_from_slice(extra);
    daemon.run(&args, "")
}

/// A second approval key, in the agent, its public half in a file: the `approvers` line and
/// the file.
fn second_approver(daemon: &Daemon) -> (String, std::path::PathBuf) {
    let key = generate(KeyKind::Ed25519).unwrap();
    daemon.agent.add(&key);
    let public = daemon.root().join("second.pub");
    let line = key.public_key().to_openssh().unwrap();
    fs::write(&public, format!("{line}\n")).unwrap();
    (format!("second {line}\n"), public)
}

#[test]
fn a_signed_change_applies_at_once_and_is_written_back_to_its_file() {
    for approvals in [Approvals::Ssh, Approvals::Https] {
        let daemon = Daemon::start(POLICY, approvals);
        let shown = daemon.run(&["admin", "show", "approvers"], "");
        assert!(shown.status.success(), "{}", stderr(&shown));
        let before = stdout(&shown);
        assert_eq!(
            before,
            fs::read_to_string(daemon.root().join("approvers")).unwrap()
        );
        assert!(
            stderr(&shown).starts_with("approvers: version 1 (sha256 "),
            "{}",
            stderr(&shown)
        );

        // Approvers: the first key and a second one.
        let (line, second_pub) = second_approver(&daemon);
        let both = format!("{before}{line}");
        let out = apply(&daemon, "approvers", &both, &[]);
        assert!(
            out.status.success(),
            "{approvals:?}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        let said = stdout(&out);
        assert!(
            said.contains("+ second ssh-ed25519 "),
            "the change is shown: {said}"
        );
        assert!(
            said.contains("Applied: approvers is version 2 (sha256 "),
            "{said}"
        );
        assert_eq!(
            fs::read_to_string(daemon.root().join("approvers")).unwrap(),
            both
        );
        // At once: the second key signs a ticket.
        let request = daemon.request("by-second", TICKET);
        let request_id = request.id.clone();
        let out = daemon.run(
            &[
                "sign",
                &request.id,
                "--yes",
                "--key",
                second_pub.to_str().unwrap(),
            ],
            "",
        );
        assert!(out.status.success(), "{}", stderr(&out));
        let (status, _, err) = request.finish();
        assert_eq!(status.code(), Some(0), "{err}");
        let by_second = daemon.session(&request_id);
        assert!(daemon.ls_remote(&by_second).status.success());

        // Nothing to change: said, nothing signed.
        let out = apply(&daemon, "approvers", &both, &[]);
        assert!(stdout(&out).contains("already holds this text: nothing to change"));

        // The second key removed again: the lease it signed is revoked by the same change,
        // named in its output, and refused at once. Then the key is added back (version 4).
        let out = apply(&daemon, "approvers", &before, &[]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
        let said = stdout(&out);
        assert!(
            said.contains(&format!(
                "Revoked lease {request_id}: the approver key that signed it was removed."
            )),
            "{said}"
        );
        let refused = daemon.ls_remote(&by_second);
        assert_eq!(refused.status.code(), Some(128), "{}", stderr(&refused));
        let audit = daemon.audit();
        let revoked = audit_events(&audit, "revoke", "done");
        assert_eq!(revoked.len(), 1, "{audit}");
        assert_eq!(revoked[0]["lease"], request_id.as_str());
        assert!(
            revoked[0]["reason"]
                .as_str()
                .unwrap()
                .ends_with("was removed from approvers (version 3)"),
            "{}",
            revoked[0]
        );
        let out = apply(&daemon, "approvers", &both, &[]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));

        // A stranger's key: refused, nothing changed.
        let stranger = generate(KeyKind::Ed25519).unwrap();
        daemon.agent.add(&stranger);
        let stranger_pub = daemon.root().join("stranger.pub");
        fs::write(&stranger_pub, stranger.public_key().to_openssh().unwrap()).unwrap();
        let out = apply(
            &daemon,
            "approvers",
            "eve ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
            &["--key", stranger_pub.to_str().unwrap()],
        );
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        assert!(
            stderr(&out).contains("which is not in approvers"),
            "{}",
            stderr(&out)
        );
        assert_eq!(
            fs::read_to_string(daemon.root().join("approvers")).unwrap(),
            both
        );

        let audit = daemon.audit();
        assert_eq!(audit_events(&audit, "admin", "allowed").len(), 3, "{audit}");
        assert_eq!(audit_events(&audit, "admin", "denied").len(), 1, "{audit}");
    }
}

#[test]
fn a_reader_removed_is_turned_away_at_once_and_a_tightened_template_denies_its_leases() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    let lease = daemon.lease("a", TICKET);
    assert!(daemon.ls_remote(&daemon.session(&lease)).status.success());

    // Policy: `fetch` taken out of the template: the lease no longer fits it.
    let in_force = stdout(&daemon.run(&["admin", "show", "policy"], ""));
    let tight = in_force.replace(
        "operations: [fetch, commit_sign, push]",
        "operations: [commit_sign, push]",
    );
    let out = apply(&daemon, "policy", &tight, &[]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let out = daemon.ls_remote(&daemon.session(&lease));
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    let denied = audit_events(&daemon.audit(), "fetch", "denied");
    assert!(
        denied.iter().any(|e| e["code"] == "config"),
        "{}",
        daemon.audit()
    );
    assert_eq!(
        fs::read_to_string(daemon.root().join("policy.yaml")).unwrap(),
        tight
    );

    // Readers: a new reader key replaces the old one: the old is turned away at its next
    // request, over HTTPS (this connection) and SSH alike.
    let other_home = daemon.root().join("other-writ");
    let reader = Command::new(bin("writ"))
        .args(["reader", "other-mac"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", daemon.root().join("home"))
        .env("WRIT_HOME", &other_home)
        .output()
        .unwrap();
    assert!(reader.status.success());
    let line = String::from_utf8(reader.stdout).unwrap();
    let out = apply(&daemon, "readers", &line, &[]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let out = daemon.run(&["ls"], "");
    assert_eq!(out.status.code(), Some(1));
    let ssh = daemon.run(
        &[
            "ls",
            "--approval-url",
            &format!("ssh://127.0.0.1:{}", daemon.approvals_port),
        ],
        "",
    );
    assert_eq!(ssh.status.code(), Some(1), "{}", stdout(&ssh));
    // The new reader gets in.
    let out = daemon
        .writ(&[
            "--reader",
            other_home.join("reader").to_str().unwrap(),
            "ls",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_hand_edited_file_is_set_aside_at_the_next_start_and_never_applied() {
    let mut daemon = Daemon::start(POLICY, Approvals::Ssh);
    let path = daemon.root().join("approvers");
    let in_force = fs::read_to_string(&path).unwrap();
    daemon.stop();
    let (line, second_pub) = second_approver(&daemon);
    fs::write(&path, format!("{in_force}{line}")).unwrap();
    daemon.restart();
    // Set aside, the version in force written back, both logged.
    assert_eq!(fs::read_to_string(&path).unwrap(), in_force);
    let aside: Vec<_> = fs::read_dir(daemon.root())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("approvers.unapplied-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert!(
        fs::read_to_string(daemon.root().join(&aside[0]))
            .unwrap()
            .contains("second ssh-ed25519"),
        "the edit is kept"
    );
    let notes = audit_events(&daemon.audit(), "admin", "done");
    assert!(
        notes[0]["reason"]
            .as_str()
            .unwrap()
            .contains("never applied"),
        "{notes:?}"
    );
    // Never applied: the second key signs nothing.
    let request = daemon.request("edited", TICKET);
    let out = daemon.run(
        &[
            "sign",
            &request.id,
            "--yes",
            "--key",
            second_pub.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("which is not in approvers"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success());
    daemon.stop();

    // writd recover with a wrong passphrase: refused, nothing in force changed.
    let (line, second_pub) = second_approver(&daemon);
    let in_force = fs::read_to_string(daemon.root().join("approvers")).unwrap();
    let file = daemon.root().join("recovered-approvers");
    fs::write(&file, format!("{in_force}{line}")).unwrap();
    let recover = |passphrase: &str| {
        daemon.writd_with(
            &["recover", "writd.yaml", "approvers", file.to_str().unwrap()],
            &format!("{passphrase}\n"),
        )
    };
    let out = recover("not the passphrase");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("wrong passphrase"),
        "{}",
        stderr(&out)
    );
    // The right one: in force, written back, logged.
    let out = recover(PASSPHRASE);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("approvers: version 2 in force (recovered on the host)"));
    assert_eq!(
        fs::read_to_string(daemon.root().join("approvers")).unwrap(),
        format!("{in_force}{line}")
    );
    let recovered = audit_events(&daemon.audit(), "admin", "allowed");
    assert!(
        recovered[0]["reason"]
            .as_str()
            .unwrap()
            .contains("recovered on the host")
    );
    daemon.restart();
    let out = daemon.run(
        &["unseal", "--key", second_pub.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(
        out.status.success(),
        "the recovered key unseals: {}",
        stderr(&out)
    );
    daemon.stop();

    // The approvers changed in the store behind the daemon's back: it stays sealed.
    let conn = rusqlite::Connection::open(daemon.root().join("s/leases.db")).unwrap();
    let eve = generate(KeyKind::Ed25519).unwrap();
    daemon.agent.add(&eve);
    let eve_line = format!("eve {}\n", eve.public_key().to_openssh().unwrap());
    let digest = writ_core::authority::TextDigest::of(&eve_line);
    conn.execute(
        "UPDATE authority SET text = ?1, digest = ?2 WHERE target = 'approvers' AND version = 2",
        rusqlite::params![eve_line, digest.as_str()],
    )
    .unwrap();
    drop(conn);
    let eve_pub = daemon.root().join("eve.pub");
    fs::write(&eve_pub, eve.public_key().to_openssh().unwrap()).unwrap();
    daemon.restart();
    let out = daemon.run(
        &["unseal", "--key", eve_pub.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("were altered at rest"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains("daemon sealed"));
    daemon.stop();

    // What the unseal's refusal says to do: `writd recover` the file you trust (the review
    // after M5.5, S12). It shows the two others as the state holds them; answered no, nothing
    // changes; yes, all three are sealed again, the altered approvers replaced.
    let trusted = format!("{in_force}{line}");
    fs::write(&file, &trusted).unwrap();
    let recover_answering = |answer: &str| {
        daemon.writd_with(
            &["recover", "writd.yaml", "approvers", file.to_str().unwrap()],
            &format!("{PASSPHRASE}\n{answer}\n"),
        )
    };
    let out = recover_answering("n");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("--- policy") && stdout(&out).contains("--- readers"),
        "the other two shown: {}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("not recovered"), "{}", stderr(&out));
    let out = recover_answering("y");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("approvers: version 3 in force (recovered on the host)"),
        "{}",
        stdout(&out)
    );
    daemon.restart();
    let out = daemon.run(
        &["unseal", "--key", eve_pub.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "eve's key is out: {}",
        stdout(&out)
    );
    let out = daemon.run(
        &["unseal", "--key", second_pub.to_str().unwrap()],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(out.status.success(), "recovered: {}", stderr(&out));
}

/// The review after M5.5 (L6): the keystore's `recipient` file is what every key and token
/// sealed after an unseal is encrypted to, and what approvers encrypt tokens to (`writ info`).
/// One replaced at rest (by whoever can write the keys directory) is refused at the unseal:
/// it must be the identity the passphrase opened.
#[test]
fn a_recipient_file_that_isn_t_the_keystore_s_stops_the_unseal() {
    let mut daemon = Daemon::start_sealed(POLICY, Approvals::Ssh);
    assert!(daemon.unseal().status.success());
    daemon.stop();
    let path = daemon.root().join("s/keys/recipient");
    // Another X25519 recipient (age's own documentation's example): valid, and not this one.
    let theirs = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    assert_ne!(fs::read_to_string(&path).unwrap().trim(), theirs);
    fs::write(&path, format!("{theirs}\n")).unwrap();
    daemon.restart();
    let out = daemon.unseal();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("not this keystore's recipient"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&daemon.run(&["ls"], "")).contains("daemon sealed"));
}
