//! M2 end to end, with the real binaries: `writd run` on a temporary configuration, the `writ`
//! CLI on both sides, approver signatures made by `ssh-keygen` through a throwaway `ssh-agent`,
//! real `ssh` and `git` with the session certificates, and a fake Telegram Bot API receiving
//! the notifications. The approval API is used over SSH in one scenario and over HTTPS (pinned
//! certificate) in the others.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use writ_integration::binaries::bin;
use writ_integration::daemon::{Approvals, Daemon};
use writ_integration::process::ends_within;
use writ_integration::{stderr, stdout};
use writ_store::looks_secret;

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
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

fn ticket(extra_text: &str, ttl: &str) -> String {
    format!(
        "scope:\n  repos: [demo]\n  operations: [fetch, commit_sign, push]\n  branches: [\"agent/oauth\"]\n\
         ticket:\n  title: \"Add OAuth login\"\n  task: Add GitHub OAuth login behind a feature flag\n\
         {extra_text}limits:\n  ttl: {ttl}\n"
    )
}

#[test]
fn rejected_signed_narrowed_and_refused_tickets_end_to_end() {
    let daemon = Daemon::start(POLICY, Approvals::Ssh);

    // Outside every template: rejected before it reaches the approver, with the reason.
    let outside = daemon.root().join("outside.yaml");
    fs::write(&outside, ticket("", "1h").replace("agent/oauth", "main")).unwrap();
    let out = daemon.run(&["request", outside.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("branch main is not within"),
        "{}",
        stderr(&out)
    );

    // Submitted, notified, shown, narrowed and signed through the agent.
    let request = daemon.request("first", &ticket("", "1h"));
    let id = request.id.clone();
    let notification = daemon.telegram.wait_for(1)[0].clone();
    assert!(notification.contains("Ticket waiting"), "{notification}");
    // Agent-written text never goes to the third party.
    assert!(!notification.contains("Add OAuth login"), "{notification}");
    assert!(notification.contains(&id), "{notification}");
    assert!(notification.contains(r#""chat_id":42"#), "{notification}");

    let out = daemon.run(
        &["sign", &id, "--max-signatures", "5", "--drop-op", "push"],
        "y\n",
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let shown = stdout(&out);
    assert!(shown.contains("Narrowed by you"), "{shown}");
    assert!(shown.contains("│ Add OAuth login"), "{shown}");

    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(0), "{out}{err}");
    assert!(out.contains("The approver narrowed the ticket"), "{out}");
    let session = daemon.session(&id);
    let lease = fs::read_to_string(session.join("lease.json")).unwrap();
    assert!(lease.contains(r#""max_signatures":5"#), "{lease}");
    assert!(!lease.contains("\"push\""), "{lease}");
    assert_eq!(
        fs::metadata(session.join("key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_link(daemon.root().join("writ/sessions/current")).unwrap(),
        PathBuf::from(&id)
    );
    // The certificate works with the real ssh and git.
    let out = daemon.ls_remote(&session);
    assert!(out.status.success(), "{}", stderr(&out));

    // Refused with feedback (signed: decisions is `signed`); the agent gets it.
    let request = daemon.request("second", &ticket("", "1h"));
    let refused = request.id.clone();
    let out = daemon.run(&["refuse", &refused, "-m", "Don't touch billing"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let (status, out, err) = request.finish();
    assert_eq!(status.code(), Some(4), "{err}");
    assert!(out.contains("│ Don't touch billing"), "{out}");

    // Revision 2 shows my feedback and the diff, with its escape sequences neutralized.
    let revision = ticket(&format!("  revises: {refused}\n"), "1h")
        .replace("\"Add OAuth login\"", "\"Add OAuth \\e[2J\\e[31mlogin\"");
    // Only from the session that submitted the refused ticket: from another host (another
    // `writ` home), there's no key to revise it with.
    let elsewhere = daemon.root().join("revision-elsewhere.yaml");
    fs::write(&elsewhere, &revision).unwrap();
    let out = writ_integration::process::finish(
        daemon
            .writ(&["request", elsewhere.to_str().unwrap()])
            .env("WRIT_HOME", daemon.root().join("another-host"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("comes from the session that submitted it"),
        "{}",
        stderr(&out)
    );
    let request = daemon.request("third", &revision);
    let third = request.id.clone();
    let out = daemon.run(&["sign", &third], "n\n");
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    let shown = stdout(&out);
    assert!(shown.contains("revision 2"), "{shown}");
    assert!(shown.contains("Feedback on revision 1"), "{shown}");
    assert!(shown.contains("│ Don't touch billing"), "{shown}");
    assert!(shown.contains("Changes since revision 1"), "{shown}");
    assert!(shown.contains("\\u{1b}[2J"), "{shown}");
    assert!(
        !shown.contains('\x1b'),
        "an escape sequence reached the terminal"
    );

    // Withdrawn: the waiting agent is told.
    let out = daemon.run(&["revoke", &third], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(request.finish().0.code(), Some(5));

    for (event, result) in [
        ("submit", "denied"),
        ("submit", "allowed"),
        ("grant", "allowed"),
        ("refuse", "done"),
        ("revoke", "done"),
        ("connect", "allowed"),
    ] {
        assert!(
            daemon.audited(event, result) >= 1,
            "{event} {result}:\n{}",
            daemon.audit()
        );
    }
    assert!(!looks_secret(&daemon.audit()), "{}", daemon.audit());
    // Clients that come and go (writ, ssh, git) leave no error in the daemon's log.
    let log = daemon.log();
    assert!(!log.contains("ERROR") && !log.contains("WARN"), "{log}");
}

#[test]
fn revocation_and_expiry_drop_sessions_and_refuse_the_certificate() {
    // The approval API over HTTPS this time.
    let daemon = Daemon::start(POLICY, Approvals::Https);

    // Revocation: the open session is dropped, the next connection refused.
    let request = daemon.request("long", &ticket("", "1h"));
    let id = request.id.clone();
    assert!(daemon.run(&["sign", &id, "--yes"], "").status.success());
    assert!(request.finish().0.success());
    let session = daemon.session(&id);
    let mut open = daemon
        .ssh(&session)
        .arg("git-upload-pack 'demo.git'")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        !ends_within(&mut open, Duration::from_millis(500)),
        "the session should stay open"
    );
    let out = daemon.run(&["revoke", &id], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        ends_within(&mut open, Duration::from_secs(5)),
        "the open session was not dropped"
    );
    assert!(
        !daemon.ls_remote(&session).status.success(),
        "a revoked certificate got in"
    );

    // Expiry: the same, when expires_at passes. A ticket asks for at least 5 minutes; the
    // approver may narrow it below that when signing.
    let request = daemon.request("short", &ticket("", "1h"));
    let short = request.id.clone();
    assert!(
        daemon
            .run(&["sign", &short, "--yes", "--ttl", "4s"], "")
            .status
            .success()
    );
    assert!(request.finish().0.success());
    let session = daemon.session(&short);
    let mut open = daemon
        .ssh(&session)
        .arg("git-upload-pack 'demo.git'")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        ends_within(&mut open, Duration::from_secs(10)),
        "the session outlived the lease"
    );
    assert!(
        !daemon.ls_remote(&session).status.success(),
        "an expired certificate got in"
    );

    assert!(daemon.audited("revoke", "done") >= 1, "{}", daemon.audit());
    assert!(daemon.audited("expire", "done") >= 1, "{}", daemon.audit());
    assert!(
        daemon.audited("connect", "denied") >= 1,
        "{}",
        daemon.audit()
    );
    assert!(!looks_secret(&daemon.audit()));
}

#[test]
fn https_approval_clients_check_the_pin_and_both_transports_cannot_be_disabled() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    assert!(daemon.run(&["ls"], "").status.success());
    // A pin that doesn't match: refused before anything is sent.
    let other = daemon.root().join("other_pins");
    fs::write(
        &other,
        format!(
            "[127.0.0.1]:{} SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\n",
            daemon.https_port
        ),
    )
    .unwrap();
    let out = daemon.run(&["--tls-pins", other.to_str().unwrap(), "ls"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("TLS with the daemon failed"),
        "{}",
        stderr(&out)
    );
    // No pin at all: refused, saying how to pin.
    let out = daemon.run(&["--tls-pins", "/dev/null", "ls"], "");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("writd tls-fingerprint"),
        "{}",
        stderr(&out)
    );

    // Both approval transports disabled: the daemon refuses to start.
    let config = fs::read_to_string(daemon.root().join("writd.yaml")).unwrap();
    let start = config.find("  approvals:").unwrap();
    let end = config.find("attestor:").unwrap();
    let disabled = format!(
        "{}  approvals: {{ ssh: [], https: [] }}\n{}",
        &config[..start],
        &config[end..]
    );
    fs::write(daemon.root().join("disabled.yaml"), disabled).unwrap();
    let out = Command::new(bin("writd"))
        .arg("run")
        .arg(daemon.root().join("disabled.yaml"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("both disabled"), "{}", stderr(&out));
}

#[test]
fn only_a_key_in_approvers_can_sign() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    let request = daemon.request("ticket", &ticket("", "1h"));
    let id = request.id.clone();

    // A key in the approver's agent, but not in `approvers`.
    let stranger = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
    daemon.agent.add(&stranger);
    let stranger_pub = daemon.root().join("stranger.pub");
    fs::write(
        &stranger_pub,
        stranger.public_key().to_openssh().unwrap() + "\n",
    )
    .unwrap();
    let out = writ_integration::process::finish(
        daemon
            .writ(&[
                "sign",
                &id,
                "--yes",
                "--key",
                stranger_pub.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(!out.status.success(), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("which is not in approvers"),
        "{}",
        stderr(&out)
    );
    assert_eq!(daemon.audited("grant", "denied"), 1, "{}", daemon.audit());

    // Still waiting: the approver's own key signs it.
    assert!(daemon.run(&["sign", &id, "--yes"], "").status.success());
    assert!(request.finish().0.success());
    assert_eq!(daemon.audited("grant", "allowed"), 1);
}

#[test]
fn writ_sign_never_signs_with_a_private_key_file() {
    // Hard rule 8: the approval key lives in the agent. Here a stray key's private half sits
    // next to its .pub, and isn't in the agent: ssh-keygen must not fall back to the file.
    let daemon = Daemon::start(POLICY, Approvals::Ssh);
    let request = daemon.request("file-key", &ticket("", "1h"));
    let stray = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
    let private = daemon.root().join("stray");
    fs::write(
        &private,
        stray
            .to_openssh(writ_crypto::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    let public = daemon.root().join("stray.pub");
    fs::write(&public, stray.public_key().to_openssh().unwrap()).unwrap();

    let out = daemon.run(
        &[
            "sign",
            &request.id,
            "--yes",
            "--key",
            public.to_str().unwrap(),
        ],
        "",
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("ssh-keygen could not sign"),
        "refused by ssh-keygen itself, before the daemon: {}",
        stderr(&out)
    );
    assert_eq!(
        daemon.audited("grant", "denied"),
        0,
        "nothing reached the daemon"
    );
    let listing = stdout(&daemon.run(&["ls"], ""));
    assert!(
        listing.contains(&request.id) && listing.contains("pending"),
        "{listing}"
    );

    // The real approval key, in the agent, still signs (the refusal above was the file's).
    assert!(
        daemon
            .run(&["refuse", &request.id, "-m", "done"], "")
            .status
            .success()
    );
    assert_eq!(request.finish().0.code(), Some(4));
}
