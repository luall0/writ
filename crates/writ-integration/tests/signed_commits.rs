//! M3 end to end: commits signed by the daemon through `writ-sign`, with the real `git` and
//! `ssh`, against the gateway in-process: every denial, with the reason the agent sees and
//! its audit line.

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
use std::process::Output;

use writ_core::names::TicketId;
use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen, TICKET, now};
use writ_integration::{audit_events, stderr};

/// git's status when the signing program fails.
const SIGNING_FAILED: i32 = 128;

/// One repo, `main` and tags protected, a template that refuses paths outside the ticket's.
const STRICT: &str = r#"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: ["refs/heads/main", "refs/tags/*"]
templates:
  strict:
    repos: [demo]
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 100
    max_pushes: 100
    max_ops_per_minute: 1000
    max_push_size: 50MB
    paths_check: deny
"#;

/// The harness's ticket with something more (YAML lines under the top level).
fn ticket(extra: &str) -> String {
    format!("{TICKET}{extra}")
}

/// `git commit -S` with a `Writ:` trailer for `lease`, as the session `key`.
fn commit(gw: &GitGateway, key: &str, work: &Path, lease: &str, extra: &[&str]) -> Output {
    let trailer = format!("Writ: {lease}");
    let mut args = vec!["commit", "-q", "-S", "--allow-empty", "-m", "change"];
    args.extend_from_slice(extra);
    args.extend(["--trailer", &trailer]);
    gw.git_as(key, work, &args)
}

/// The commit was refused: git's status, the reason the agent sees, the audit line's code.
fn assert_refused(gw: &GitGateway, out: &Output, reason: &str, code: Option<&str>) {
    assert_eq!(
        out.status.code(),
        Some(SIGNING_FAILED),
        "{reason}: {}",
        stderr(out)
    );
    assert!(
        stderr(out).contains(reason),
        "expected {reason:?} in:\n{}",
        stderr(out)
    );
    if let Some(code) = code {
        let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
        let denied = audit_events(&audit, "sign", "denied");
        let last = denied.last().expect("a denied sign line");
        assert_eq!(last["code"], code, "{last}");
    }
}

fn head(gw: &GitGateway, work: &Path) -> String {
    gw.git_ok(work, &["rev-parse", "HEAD"]).trim().to_owned()
}

fn signed_commits_verify_and_are_in_the_ledger(kind: KeyKind) {
    let gw = GitGateway::start(kind, Listen::Tcp);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();

    fs::write(work.join("feature"), "x\n").unwrap();
    gw.git_ok(&work, &["add", "feature"]);
    let out = commit(&gw, "session", &work, lease.as_str(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = gw.git(&work, &["verify-commit", "HEAD"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Good \"git\" signature for agent@writ"),
        "{}",
        stderr(&out)
    );
    // The ledger holds the commit git wrote (its signature in it), for this lease and repo,
    // with the template's key; the audit line names it.
    let id = head(&gw, &work);
    let ledger = gw.ledger(&lease);
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].commit.as_str(), id);
    assert_eq!(ledger[0].repo.as_str(), "demo");
    assert_eq!(ledger[0].key.as_str(), "agent-01");
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    let signed = audit_events(&audit, "sign", "allowed");
    assert_eq!(signed.len(), 1, "one line per signature: {signed:?}");
    assert_eq!(signed[0]["commit"], id.as_str());
    assert_eq!(signed[0]["committer"], "agent@writ");
    assert_eq!(signed[0]["lease"], lease.as_str());

    // Signed commits push like any other.
    gw.git_ok(
        &work,
        &["push", "-q", "origin", "HEAD:refs/heads/agent/signed"],
    );
}

#[test]
fn ed25519_commits_signed_by_the_daemon_verify_and_are_in_the_ledger() {
    signed_commits_verify_and_are_in_the_ledger(KeyKind::Ed25519);
}

#[test]
fn p256_commits_signed_by_the_daemon_verify_and_are_in_the_ledger() {
    signed_commits_verify_and_are_in_the_ledger(KeyKind::P256);
}

#[test]
fn what_the_commit_says_is_checked() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();
    let id = lease.as_str();

    // A committer email the lease doesn't allow.
    let out = commit(&gw, "session", &work, id, &[]);
    assert!(
        out.status.success(),
        "the allowed case signs: {}",
        stderr(&out)
    );
    let out = gw.git(
        &work,
        &[
            "-c",
            "user.email=me@personal.example",
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "-m",
            "x",
            "--trailer",
            &format!("Writ: {id}"),
        ],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: outside ticket {id}: committer email \"me@personal.example\" not allowed"),
        Some("committer"),
    );

    // The `Writ:` trailer: missing, another lease's, twice.
    let out = gw.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", "no trailer"],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: repo demo needs a `Writ: {id}` trailer in the commit message"),
        Some("ticket_link"),
    );
    let other = "wrt_01JD8X0000000000000000000Z";
    let out = commit(&gw, "session", &work, other, &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: the commit needs exactly one `Writ: {id}` trailer"),
        Some("ticket_link"),
    );
    // Written in the message: `--trailer` would fold two identical ones into one.
    let twice = format!("change\n\nWrit: {id}\nWrit: {id}\n");
    let out = gw.git(
        &work,
        &["commit", "-q", "-S", "--allow-empty", "-m", &twice],
    );
    assert_refused(
        &gw,
        &out,
        &format!("writ: the commit needs exactly one `Writ: {id}` trailer"),
        Some("ticket_link"),
    );

    // A tag: releases stay a human act.
    let out = gw.git(&work, &["tag", "-s", "v1", "-m", "release"]);
    assert_eq!(out.status.code(), Some(SIGNING_FAILED), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writ: only commits are signed (no tags: releases stay a human act)"),
        "{}",
        stderr(&out)
    );
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    assert_eq!(
        audit_events(&audit, "sign", "denied").last().unwrap()["code"],
        "object_type"
    );
    assert_eq!(gw.ledger(&lease).len(), 1, "only the allowed commit");
}

#[test]
fn paths_outside_the_ticket_are_refused_with_paths_check_deny() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.session_with("paths", &ticket("  expected_paths: [\"src/**\"]\n"));
    let id = lease.as_str();

    fs::create_dir_all(work.join("src/auth")).unwrap();
    fs::write(work.join("src/auth/login.rs"), "fn login() {}\n").unwrap();
    gw.git_ok(&work, &["add", "-A"]);
    let out = commit(&gw, "paths", &work, id, &[]);
    assert!(
        out.status.success(),
        "inside expected_paths: {}",
        stderr(&out)
    );

    fs::create_dir_all(work.join("docs")).unwrap();
    fs::write(work.join("docs/notes.md"), "notes\n").unwrap();
    fs::write(work.join("src/auth/login.rs"), "fn login() { todo!() }\n").unwrap();
    gw.git_ok(&work, &["add", "-A"]);
    let out = commit(&gw, "paths", &work, id, &[]);
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ: outside ticket {id}: files outside expected_paths: docs/notes.md. If needed, \
             submit an amendment (ticket.amends: {id})"
        ),
        Some("paths"),
    );
    assert_eq!(gw.ledger(&lease).len(), 1);
}

#[test]
fn signatures_stop_at_the_lease_s_count_and_rate() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);

    let few = gw.session_with("few", &ticket("limits:\n  max_signatures: 2\n"));
    for _ in 0..2 {
        let out = commit(&gw, "few", &work, few.as_str(), &[]);
        assert!(out.status.success(), "under the limit: {}", stderr(&out));
    }
    let out = commit(&gw, "few", &work, few.as_str(), &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: lease {few}: all 2 signatures used"),
        Some("limit"),
    );

    // Two a minute: the third within the minute is refused (the test takes seconds; were it
    // to take a minute, the third would sign and the test fail, never pass by luck).
    let slow = gw.session_with("slow", &ticket("limits:\n  max_ops_per_minute: 2\n"));
    for _ in 0..2 {
        let out = commit(&gw, "slow", &work, slow.as_str(), &[]);
        assert!(out.status.success(), "under the rate: {}", stderr(&out));
    }
    let out = commit(&gw, "slow", &work, slow.as_str(), &[]);
    assert_refused(
        &gw,
        &out,
        &format!("writ: lease {slow}: over 2 operations per minute, retry shortly"),
        Some("rate"),
    );
    assert_eq!(gw.ledger(&few).len(), 2);
    assert_eq!(gw.ledger(&slow).len(), 2);
}

#[test]
fn no_lease_an_expired_or_a_revoked_one_says_why() {
    let gw = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.service.list(false).unwrap().tickets[0].id.clone();
    let as_key = |name: &str, lease: &TicketId| {
        let key = gw.root().join("keys").join(name);
        let trailer = format!("Writ: {lease}");
        gw.git_with(
            &gw.ssh_command(&key, true),
            &work,
            &[
                "commit",
                "-q",
                "-S",
                "--allow-empty",
                "-m",
                "x",
                "--trailer",
                &trailer,
            ],
        )
    };

    // No session at all.
    let out = as_key("none", &lease);
    let missing = gw.root().join("keys/none-cert.pub");
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ-sign: cannot reach the daemon with this session: no lease: there is no \
             session certificate at {}",
            missing.display()
        ),
        None,
    );

    // A certificate past its end (its lease expired with it).
    gw.forged_session(&gw.ca, "expired", 0, now() - 10);
    let out = as_key("expired", &lease);
    assert_refused(
        &gw,
        &out,
        "writ-sign: cannot reach the daemon with this session: lease \
         wrt_01JD8X0000000000000000000 expired at",
        None,
    );

    // A revoked lease: the certificate is still valid in time, the daemon refuses it.
    let revoked = gw.session("revoked");
    assert!(
        as_key("revoked", &revoked).status.success(),
        "before the revocation"
    );
    gw.revoke(&revoked);
    let out = as_key("revoked", &revoked);
    assert_refused(
        &gw,
        &out,
        &format!(
            "writ-sign: cannot reach the daemon with this session: the daemon refused the \
             session certificate of lease {revoked}"
        ),
        None,
    );
}

#[test]
fn a_violation_revokes_a_lease_that_asks_for_it() {
    let gw = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, STRICT);
    gw.seed_repo();
    let work = gw.clone("work");
    gw.wire_signing(&work);
    let lease = gw.session_with("strict", &ticket("on_violation: revoke_lease\n"));
    let id = lease.as_str();

    // Running out of signatures is no violation; a wrong committer is one.
    let out = gw.git_as(
        "strict",
        &work,
        &[
            "-c",
            "user.email=me@personal.example",
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "-m",
            "x",
            "--trailer",
            &format!("Writ: {id}"),
        ],
    );
    assert_refused(
        &gw,
        &out,
        "committer email \"me@personal.example\" not allowed",
        Some("committer"),
    );
    let audit = fs::read_to_string(gw.root().join("audit.jsonl")).unwrap();
    let revoked = audit_events(&audit, "revoke", "done");
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0]["lease"], id);
    assert!(
        revoked[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("violation (committer): outside ticket"),
        "{}",
        revoked[0]
    );
    // The lease is over: even a good commit is refused now.
    let out = commit(&gw, "strict", &work, id, &[]);
    assert_refused(
        &gw,
        &out,
        "the daemon refused the session certificate",
        None,
    );
}
