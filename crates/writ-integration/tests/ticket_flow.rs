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
    assert_eq!(out.status.code(), Some(1));
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
    // Clients that come and go (writ, ssh, git) leave no error in the daemon's log. The one
    // warning a host may give, whatever the clients do: the memory lock not applied at start,
    // on Linux under a lock limit (a CI runner's `ulimit -l`); scenario 17 checks it end to end.
    let log = daemon.log();
    let host_s = "WARN writd::hardening: process hardening not applied step=memory locked";
    let unexpected: Vec<&str> = log
        .lines()
        .filter(|l| (l.contains("ERROR") || l.contains("WARN")) && !l.contains(host_s))
        .collect();
    assert!(unexpected.is_empty(), "{unexpected:#?}\n{log}");
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
    let out = daemon.ls_remote(&session);
    assert_eq!(out.status.code(), Some(128), "a revoked certificate got in");
    assert!(
        stderr(&out).contains("Permission denied (publickey)"),
        "refused at authentication: {}",
        stderr(&out)
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
    let out = daemon.ls_remote(&session);
    assert_eq!(
        out.status.code(),
        Some(128),
        "an expired certificate got in"
    );
    assert!(
        stderr(&out).contains("Permission denied (publickey)"),
        "refused at authentication: {}",
        stderr(&out)
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
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("TLS with the daemon failed"),
        "{}",
        stderr(&out)
    );
    // No pin at all: refused, saying how to pin.
    let out = daemon.run(&["--tls-pins", "/dev/null", "ls"], "");
    assert_eq!(out.status.code(), Some(1));
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
    assert_eq!(out.status.code(), Some(1));
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
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
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
    assert_eq!(out.status.code(), Some(1));
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

/// `writ` run to the end with nothing on stdin, from a configured command.
fn output(mut command: Command) -> std::process::Output {
    writ_integration::process::finish(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

/// `writ request --no-wait` with `text` in the file `<name>.yaml`.
fn submit(daemon: &Daemon, name: &str, text: &str) -> std::process::Output {
    let file = daemon.root().join(format!("{name}.yaml"));
    fs::write(&file, text).unwrap();
    daemon.run(&["request", "--no-wait", file.to_str().unwrap()], "")
}

/// The ticket was rejected before reaching the approver, with exactly these reasons.
fn assert_rejected(out: &std::process::Output, reasons: &[&str]) {
    assert_eq!(out.status.code(), Some(3), "{}", stdout(out));
    let listed: String = reasons.iter().map(|r| format!("  - {r}\n")).collect();
    assert_eq!(stderr(out), format!("writ: ticket rejected\n{listed}"));
}

/// The rejections here would pass the harness's submission rate.
fn more_submissions(yaml: &str) -> String {
    format!("{yaml}submissions: {{ per_source: 100, in_all: 100 }}\n")
}

#[test]
fn require_expected_paths_rejects_a_ticket_without_them() {
    let policy = format!("{POLICY}    require_expected_paths: true\n");
    let daemon = Daemon::start(&policy, Approvals::Https);
    let out = submit(&daemon, "without", &ticket("", "1h"));
    assert_rejected(
        &out,
        &[
            "the ticket fits no template",
            "feature: the template requires ticket.expected_paths",
        ],
    );
    let out = submit(
        &daemon,
        "with",
        &ticket("  expected_paths: [\"src/**\"]\n", "1h"),
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(daemon.audited("submit", "denied"), 1, "{}", daemon.audit());
    assert_eq!(daemon.audited("submit", "allowed"), 1, "{}", daemon.audit());
}

/// A registry of two repos, a template for one of them and without `push`.
const CAPPED: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
  other:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
templates:
  feature:
    repos: [demo]
    operations: [fetch, commit_sign]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

#[test]
fn a_ticket_past_its_template_is_rejected_with_each_reason() {
    let daemon = Daemon::start_with(CAPPED, Approvals::Https, more_submissions);
    let capped = |scope: &str, limits: &str| {
        format!(
            "scope:\n  repos: [demo]\n  operations: [fetch, commit_sign]\n  \
             branches: [\"agent/x\"]\n  committer_emails: [agent@writ]\n{scope}\
             ticket:\n  title: Capped\n  task: Ask for as much as the template allows\n\
             limits:\n{limits}"
        )
    };
    // Everything at the template's maximum: taken.
    let at = "  ttl: 2h\n  max_signatures: 40\n  max_pushes: 20\n  max_ops_per_minute: 100\n  \
              max_push_size: 10MB\n";
    let out = submit(&daemon, "at", &capped("", at));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // Nothing asked: the template's maxima, as the lease's limits.
    let out = submit(&daemon, "defaults", &capped("", "  {}\n"));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let id = stdout(&out)
        .strip_prefix("Ticket ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap()
        .to_owned();
    let terms: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(daemon.session(&id).join("ticket.json")).unwrap())
            .unwrap();
    let limits = &terms["limits"];
    assert_eq!(
        (
            &limits["max_signatures"],
            &limits["max_pushes"],
            &limits["max_ops_per_minute"],
            &limits["max_push_size"]
        ),
        (
            &serde_json::json!(40),
            &serde_json::json!(20),
            &serde_json::json!(100),
            &serde_json::json!(10_000_000)
        ),
        "{terms}"
    );

    // One past, each on its own: rejected with its reason.
    for (name, scope, limits, reason) in [
        (
            "ttl",
            "",
            at.replace("ttl: 2h", "ttl: 7201s"),
            "the lease would last 7201s, over the template's max_ttl (2h)",
        ),
        (
            "signatures",
            "",
            at.replace("max_signatures: 40", "max_signatures: 41"),
            "limits.max_signatures is 41, over the template's 40",
        ),
        (
            "pushes",
            "",
            at.replace("max_pushes: 20", "max_pushes: 21"),
            "limits.max_pushes is 21, over the template's 20",
        ),
        (
            "rate",
            "",
            at.replace("max_ops_per_minute: 100", "max_ops_per_minute: 101"),
            "limits.max_ops_per_minute is 101, over the template's 100",
        ),
        (
            "size",
            "",
            at.replace("max_push_size: 10MB", "max_push_size: 10000001"),
            "limits.max_push_size is 10000001, over the template's 10000000",
        ),
        (
            "force",
            "  force_push: true\n",
            at.to_owned(),
            "force_push is not allowed by the template",
        ),
    ] {
        assert_ne!(limits, at.to_owned() + scope, "{name}: the fixture changed");
        let out = submit(&daemon, name, &capped(scope, &limits));
        assert_rejected(
            &out,
            &["the ticket fits no template", &format!("feature: {reason}")],
        );
    }
    for (name, from, to, reason) in [
        (
            "repo",
            "repos: [demo]",
            "repos: [demo, other]",
            "repo other is not allowed by the template",
        ),
        (
            "operation",
            "operations: [fetch, commit_sign]",
            "operations: [fetch, commit_sign, push]",
            "operation push is not allowed by the template",
        ),
        (
            "branch",
            "branches: [\"agent/x\"]",
            "branches: [main]",
            "branch main is not within the template's branches (agent/*)",
        ),
        (
            "email",
            "committer_emails: [agent@writ]",
            "committer_emails: [agent@writ, me@personal.example]",
            "committer email me@personal.example is not allowed by the template",
        ),
    ] {
        let text = capped("", at);
        let past = text.replace(from, to);
        assert_ne!(past, text, "{name}: the fixture changed");
        let out = submit(&daemon, name, &past);
        assert_rejected(
            &out,
            &["the ticket fits no template", &format!("feature: {reason}")],
        );
    }
    // The review after M5.5's bounds (S8, L20): 50 branches and 16 KiB of expected_paths
    // taken, one more of either rejected with its reason.
    let task = "  task: Ask for as much as the template allows\n";
    let branches = |n: usize| {
        let list: Vec<String> = (0..n).map(|i| format!("\"agent/x{i}\"")).collect();
        capped("", at).replace(
            "branches: [\"agent/x\"]",
            &format!("branches: [{}]", list.join(", ")),
        )
    };
    let paths = |extra: bool| {
        let mut list: Vec<String> = (0..16)
            .map(|i| format!("\"d{i:02}/{}\"", "x".repeat(1020)))
            .collect();
        if extra {
            list.push("\"z\"".to_owned());
        }
        capped("", at).replace(
            task,
            &format!("{task}  expected_paths: [{}]\n", list.join(", ")),
        )
    };
    for (name, text) in [
        ("50 branches", branches(50)),
        ("16 KiB of paths", paths(false)),
    ] {
        let out = submit(&daemon, name, &text);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
    }
    for (name, text, reason) in [
        (
            "51 branches",
            branches(51),
            "scope.branches is too long (51, at most 50)",
        ),
        (
            "16 KiB and a byte of paths",
            paths(true),
            "ticket.expected_paths (bytes in all) is too long (16385, at most 16384)",
        ),
    ] {
        let out = submit(&daemon, name, &text);
        assert_rejected(
            &out,
            &["the ticket fits no template", &format!("feature: {reason}")],
        );
    }
    assert_eq!(daemon.audited("submit", "allowed"), 4, "{}", daemon.audit());
    assert_eq!(daemon.audited("submit", "denied"), 12, "{}", daemon.audit());
}

/// Two templates a plain ticket fits, one of them for any branch.
const TWO_TEMPLATES: &str = r#"
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
  wide:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 2h
    max_signatures: 40
    max_pushes: 20
    max_ops_per_minute: 100
    max_push_size: 10MB
"#;

#[test]
fn the_origin_hint_is_shown_and_a_caller_constraint_is_checked() {
    let daemon = Daemon::start(TWO_TEMPLATES, Approvals::Https);
    let template_of = |out: &std::process::Output| {
        assert_eq!(out.status.code(), Some(0), "{}", stderr(out));
        stdout(out)
            .split_once("(template ")
            .and_then(|(_, rest)| rest.split(',').next())
            .unwrap()
            .to_owned()
    };
    // `template`: fits both and none named, rejected; named, that one; fits one, that one.
    let out = submit(&daemon, "both", &ticket("", "1h"));
    assert_rejected(
        &out,
        &["the ticket fits several templates (feature, wide): name one with `template:`"],
    );
    let named = format!("template: wide\n{}", ticket("", "1h"));
    assert_eq!(template_of(&submit(&daemon, "named", &named)), "wide");
    let only = ticket("", "1h").replace("agent/oauth", "main");
    assert_eq!(template_of(&submit(&daemon, "only", &only)), "wide");
    let unknown = format!("template: nope\n{}", ticket("", "1h"));
    assert_rejected(
        &submit(&daemon, "unknown", &unknown),
        &["template nope does not exist"],
    );
    // A template the ticket doesn't fit, named: only its reasons.
    let misfit = format!("template: feature\n{only}");
    assert_rejected(
        &submit(&daemon, "misfit", &misfit),
        &[
            "the ticket fits no template",
            "feature: branch main is not within the template's branches (agent/*)",
        ],
    );

    // `origin_hint` is shown to the approver, as the agent's claim; `caller` as the process
    // the lease is bound to.
    let bound = format!(
        "template: feature\norigin_hint: \"build-host-7 / claude session 42\"\n\
         caller:\n  descends_from:\n    executable: /usr/local/bin/agent-harness\n    \
         pid: 4242\n    generation: 7\n    code_identity: {{ signing_id: com.example.harness, \
         team_id: ABCDE12345 }}\n{}",
        ticket(
            "  plan: [\"Read the OAuth spec\", \"Add the login route\"]\n",
            "1h"
        )
    );
    let request = daemon.request("bound", &bound);
    let id = request.id.clone();
    let out = daemon.run(&["sign", &id, "--full", "--yes"], "");
    let shown = stdout(&out);
    assert!(
        shown.contains(
            "origin hint (the agent's claim, not checked):\n    │ build-host-7 / claude session 42"
        ),
        "{shown}"
    );
    assert!(
        shown.contains(
            "descends from /usr/local/bin/agent-harness (pid 4242, generation 7, signed \
             com.example.harness team ABCDE12345)"
        ),
        "{shown}"
    );
    assert!(
        shown.contains("  plan\n    │ 1. Read the OAuth spec\n    │ 2. Add the login route\n"),
        "{shown}"
    );
    // The constraint is checked as soon as it would bind a lease: this daemon watches no
    // session (`session_watcher: none`, the only one this build has), so a lease bound to a
    // process is never granted (fail closed), whatever the approver signs.
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert_eq!(
        stderr(&out),
        "writ: approval refused: the lease is bound to a session the daemon can't watch: \
         session watching is not supported by this implementation\n"
    );
    let denied = writ_integration::audit_events(&daemon.audit(), "grant", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0]["reason"],
        "the lease is bound to a session the daemon can't watch: session watching is not \
         supported by this implementation",
        "{}",
        denied[0]
    );
    assert_eq!(daemon.audited("grant", "allowed"), 0, "{}", daemon.audit());
    let out = daemon.run(&["revoke", &id], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(request.finish().0.code(), Some(5));
    // The same lease without the constraint fetches.
    let free = daemon.lease("free", &format!("template: feature\n{}", ticket("", "1h")));
    let out = daemon.ls_remote(&daemon.session(&free));
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn writ_ssh_keygen_names_the_program_the_approver_signs_with() {
    let daemon = Daemon::start(POLICY, Approvals::Https);
    let request = daemon.request("keygen", &ticket("", "1h"));
    let id = request.id.clone();
    let with_keygen = |keygen: &str| {
        let mut command = daemon.writ(&["sign", &id, "--yes"]);
        command.env("WRIT_SSH_KEYGEN", keygen);
        output(command)
    };
    // Looked up in PATH it could be anything: refused before anything is signed.
    let out = with_keygen("ssh-keygen");
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert_eq!(
        stderr(&out).lines().last().unwrap(),
        "writ: WRIT_SSH_KEYGEN must be an absolute path"
    );
    assert_eq!(daemon.audited("grant", "allowed"), 0);
    // An absolute path: that program signs (a wrapper that records it ran, then runs the
    // real ssh-keygen).
    let wrapper = daemon.root().join("keygen-wrapper");
    let log = daemon.root().join("keygen.log");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec /usr/bin/ssh-keygen \"$@\"\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let out = with_keygen(wrapper.to_str().unwrap());
    assert!(out.status.success(), "{}", stderr(&out));
    let runs = fs::read_to_string(&log).unwrap();
    assert_eq!(runs.lines().count(), 1, "{runs}");
    assert!(
        runs.starts_with("-Y sign -U -n writ-approval -f "),
        "{runs}"
    );
    assert_eq!(request.finish().0.code(), Some(0));
    assert_eq!(daemon.audited("grant", "allowed"), 1);
}
