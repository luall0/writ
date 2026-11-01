//! A revocation never waits for git or upstream (M4, the M3.6 review's Q2): with a fetch and
//! a push in flight, both stuck on an upstream that doesn't answer (holding the repo's
//! mirror), revoking the lease completes without them, ends both, and nothing of the push
//! lands, upstream or in the mirror.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::process::Stdio;
use std::time::Instant;

use writ_crypto::keys::KeyKind;
use writ_integration::gateway::{GitGateway, Listen};
use writ_integration::process::finish;
use writ_integration::remote::Mode;
use writ_integration::{audit_events, eventually, stderr};

#[test]
fn a_revocation_completes_at_once_with_fetches_and_pushes_in_flight() {
    let gateway = GitGateway::start(KeyKind::Ed25519, Listen::Tcp);
    gateway.seed_repo();
    let work = gateway.clone("work");
    gateway.commit_signed(&work, "f", "x\n");
    let key = gateway.root().join("keys/session");
    let ssh = gateway.ssh_command(&key, true);

    // Upstream stops answering: the fetch's sync hangs on it, holding the mirror; the push
    // waits for the mirror behind it.
    gateway.remote.set_mode(Mode::Hang);
    let before = gateway.remote.upload_packs();
    let spawn = |args: &[&str]| {
        gateway
            .git_command(&ssh, &work, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let fetch = spawn(&["fetch", "origin"]);
    eventually("the fetch's sync to reach upstream", || {
        gateway.remote.upload_packs() > before
    });
    let push = spawn(&["push", "origin", "HEAD:refs/heads/agent/x"]);

    // The revocation: under the state lock only, never behind git, a sync or upstream.
    let started = Instant::now();
    gateway.revoke(&gateway.lease);
    let took = started.elapsed();
    // Measured for the record (docs/history, M4); never asserted on time.
    eprintln!("revocation took {took:?} with a fetch and a push in flight");
    assert_eq!(
        gateway.remote.receive_packs(),
        0,
        "nothing was pushed upstream"
    );

    // Both end: their sessions are dropped (or refused), whatever upstream does.
    let fetched = finish(fetch);
    let pushed = finish(push);
    assert_eq!(fetched.status.code(), Some(128), "{}", stderr(&fetched));
    assert_eq!(pushed.status.code(), Some(128), "{}", stderr(&pushed));
    gateway.remote.set_mode(Mode::Serve);
    assert_eq!(gateway.upstream_ref("refs/heads/agent/x"), None);
    assert_eq!(gateway.bare_ref("refs/heads/agent/x"), None);
    // The lease is revoked for good: a new connection is turned away.
    let out = gateway.git(&work, &["fetch", "origin"]);
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    let audit = std::fs::read_to_string(gateway.root().join("audit.jsonl")).unwrap();
    assert_eq!(audit_events(&audit, "revoke", "done").len(), 1);
}
