//! M7.9.7: a fetch with no signature, through the gateway with the real `git` and `ssh`. A
//! repo naming an `unsigned_fetch` template is fetched under a lease granted when submitted;
//! that lease fetches and does nothing else, and is never pending, approved, amended or
//! renewed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::fs;

use writ_approval::RefusalCode;
use writ_approval::testing::sign_approval;
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::ticket::Ticket;
use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen, POLICY};
use writ_integration::{audit_events, stderr};

/// The gateway's policy with `demo` naming an unsigned_fetch template beside its signed one.
fn policy() -> String {
    POLICY
        .replacen("templates: [spike]", "templates: [spike, look]", 1)
        .replacen(
            "templates:\n  spike:",
            "templates:\n  look:\n    unsigned_fetch: true\n    operations: [fetch]\n    \
             max_ttl: 15m\n    max_signatures: 0\n    max_pushes: 0\n    max_ops_per_minute: 20\n    \
             max_push_size: 0\n  spike:",
            1,
        )
}

const FETCH: &str = r#"
repos:
  demo:
    template: look
    operations: [fetch]
ticket:
  title: Fetch demo
  task: Fetch before planning
limits:
  ttl: 10m
"#;

#[test]
fn an_unsigned_fetch_lease_is_granted_with_no_signature_and_only_fetches() {
    let gateway = GitGateway::start_with(KeyKind::Ed25519, Listen::Tcp, &policy());
    gateway.seed_repo();
    let work = gateway.clone("work");
    let audit = || fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();

    // Submitted, active at once: no approver, nothing waiting.
    let lease = gateway.unsigned_session("look", FETCH);
    assert_eq!(gateway.service.waiting(), 0);
    let listed = gateway.service.list(false).unwrap();
    let row = listed.tickets.iter().find(|t| t.id == lease).unwrap();
    assert_eq!(row.state, State::Active);
    assert!(row.unsigned);
    // One grant line, naming its template, with no approver.
    let grants: Vec<_> = audit_events(&audit(), "grant", "allowed")
        .into_iter()
        .filter(|e| e["lease"] == lease.as_str())
        .collect();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(
        grants[0]["reason"],
        "granted with no signature (unsigned_fetch): template look"
    );
    assert!(grants[0].get("approver").is_none(), "{grants:?}");

    // It fetches, upstream's new commit included.
    let seed = gateway.root().join("seed");
    gateway.git_ok(&seed, &["commit", "-q", "--allow-empty", "-m", "moved"]);
    let moved = gateway
        .git_ok(&seed, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    let bare = gateway.remote.repo("demo");
    gateway.git_ok(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    let out = gateway.git_as("look", &work, &["fetch", "-q", "origin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        gateway.git_ok(&work, &["rev-parse", "origin/main"]).trim(),
        moved
    );
    let fetched: Vec<_> = audit_events(&audit(), "fetch", "allowed")
        .into_iter()
        .filter(|e| e["lease"] == lease.as_str())
        .collect();
    assert_eq!(fetched.len(), 1, "{fetched:?}");

    // A push under it: refused for the operation, nothing lands.
    gateway.git_ok(&work, &["commit", "-q", "--allow-empty", "-m", "x"]);
    let out = gateway.git_as(
        "look",
        &work,
        &["push", "origin", "HEAD:refs/heads/agent/x"],
    );
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("push not allowed. This lease was granted with no signature"),
        "{}",
        stderr(&out)
    );
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    let denied = audit_events(&audit(), "push", "denied");
    assert!(
        denied
            .iter()
            .any(|e| e["lease"] == lease.as_str() && e["code"] == "operation"),
        "{denied:?}"
    );

    // Never approved: it isn't pending.
    let ticket =
        Ticket::from_canonical(gateway.service.show(&lease).unwrap().canonical.as_bytes()).unwrap();
    let refused = gateway
        .service
        .approve(
            &lease,
            &sign_approval(&gateway.approver, &ticket),
            &CallerFacts::default(),
        )
        .unwrap_err();
    assert_eq!(refused.code(), Some(RefusalCode::WrongState));

    // Its amendment is refused at submission, from its own session key too.
    let key = gateway.root().join("keys/look");
    let key = writ_crypto::ssh_key::PrivateKey::read_openssh_file(&key).unwrap();
    let amendment = format!(
        "{}  amends: {lease}\n",
        FETCH.replacen("limits:\n  ttl: 10m\n", "", 1)
    );
    let refused = gateway
        .service
        .submit(
            key.public_key(),
            amendment.as_bytes(),
            &CallerFacts::default(),
        )
        .unwrap_err();
    assert!(
        refused.reason_text().contains("never amended or renewed"),
        "{}",
        refused.reason_text()
    );

    // Revoked like any lease: its fetch refused after.
    gateway.revoke(&lease);
    let out = gateway.git_as("look", &work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
}
