//! docs/threat-model.md § What Writ guarantees, at the policy level: each test tries to break
//! one guarantee with the decisions alone. The end-to-end halves (real git, real ssh, the
//! daemon running) come with the milestones that wire them (M2–M4).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use writ_core::lease::{self, State, TicketRecord, Usage};
use writ_core::policy::{
    self, CertIdentity, Denial, DenyCode, LedgerRef, ObjectKind, PushedCommit,
};

/// The code of a denial; an allowed request fails the test.
fn code<T: std::fmt::Debug>(decision: Result<T, Denial>) -> DenyCode {
    match decision {
        Ok(allowed) => panic!("allowed: {allowed:?}"),
        Err(denial) => denial.code,
    }
}

#[test]
fn no_signature_or_push_outside_an_active_approver_signed_lease() {
    // Not a lease yet, or not any more: every operation is denied.
    for (state, expected) in [
        (State::Pending, DenyCode::NotActive),
        (State::Refused, DenyCode::NotActive),
        (State::Applied, DenyCode::NotActive),
        (State::Closed, DenyCode::NotActive),
        (State::Revoked, DenyCode::NotActive),
        (State::Exhausted, DenyCode::Exhausted),
        (State::Expired, DenyCode::Expired),
    ] {
        let mut world = World::new(lease());
        world.lease.state = state;
        let sign = policy::decide_sign(&world.ctx(), &sign_request(&world.lease));
        let push = policy::decide_push(&world.ctx(), &push_request(&world.lease));
        let fetch = policy::decide_fetch(&world.ctx(), &fetch_request());
        for (operation, denied) in [
            ("sign", code(sign)),
            ("push", code(push)),
            ("fetch", code(fetch)),
        ] {
            assert_eq!(denied, expected, "{operation} under a {state} lease");
        }
    }
    // The same requests under the active lease are allowed: the state alone denied them.
    let world = World::new(lease());
    assert!(policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).is_ok());
    assert!(policy::decide_push(&world.ctx(), &push_request(&world.lease)).is_ok());
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
    // A certificate that matches no lease.
    let lease = lease();
    let cert = CertIdentity {
        key_id: ticket_id(5).to_string(),
        serial: 7,
        session_key: fp('S'),
    };
    assert_eq!(
        code(policy::resolve_lease([&lease], &cert)),
        DenyCode::NoLease
    );
    // An approval under another namespace never activates a ticket.
    let ticket = submitted(REQUEST);
    let mut git_signature = approval();
    git_signature.namespace = "git".to_owned();
    let record = TicketRecord::pending(ticket.clone());
    assert_eq!(
        lease::activate(&config(), &record, ticket, git_signature, 1, later(5)).unwrap_err(),
        lease::LifecycleError::Namespace("git".to_owned())
    );
}

#[test]
fn pushes_only_to_allowed_repos_and_refs_no_force_push_unless_allowed() {
    let world = World::new(lease());
    type Attack = fn(&mut writ_core::policy::PushRequest);
    let attempts: Vec<(&str, Attack, DenyCode)> = vec![
        (
            "another repo",
            |r| r.repo = repo("homelab-scripts"),
            DenyCode::Repo,
        ),
        (
            "main",
            |r| r.updates[0].name = "refs/heads/main".to_owned(),
            DenyCode::ProtectedRef,
        ),
        (
            "a tag",
            |r| r.updates[0].name = "refs/tags/v9".to_owned(),
            DenyCode::ProtectedRef,
        ),
        (
            "a branch outside the lease",
            |r| r.updates[0].name = "refs/heads/agent/other".to_owned(),
            DenyCode::Ref,
        ),
        (
            "a path-like ref",
            |r| r.updates[0].name = "refs/heads/agent/oauth-x/../../main".to_owned(),
            DenyCode::Invalid,
        ),
        (
            "a force push",
            |r| r.updates[0].fast_forward = false,
            DenyCode::ForcePush,
        ),
        (
            "a deletion",
            |r| r.updates[0].new = None,
            DenyCode::ForcePush,
        ),
    ];
    assert!(policy::decide_push(&world.ctx(), &push_request(&world.lease)).is_ok());
    for (name, attack, expected) in attempts {
        let mut request = push_request(&world.lease);
        attack(&mut request);
        assert_eq!(
            code(policy::decide_push(&world.ctx(), &request)),
            expected,
            "{name}"
        );
    }
}

#[test]
fn only_commits_signed_under_the_same_lease_reach_upstream() {
    let world = World::new(lease());
    let other_lease = ticket_id(2);
    let attempts: Vec<(&str, Vec<LedgerRef>)> = vec![
        ("never signed", vec![]),
        (
            "signed under another lease",
            vec![LedgerRef {
                paths: None,
                lease: other_lease.clone(),
                repo: repo("omega-code"),
            }],
        ),
        (
            "signed under this lease for another repo",
            vec![LedgerRef {
                paths: None,
                lease: world.lease.id.clone(),
                repo: repo("homelab-scripts"),
            }],
        ),
    ];
    for (name, signed_under) in attempts {
        let mut request = push_request(&world.lease);
        request.commits.push(PushedCommit {
            paths: None,
            id: commit(9),
            signed_under,
        });
        assert_eq!(
            code(policy::decide_push(&world.ctx(), &request)),
            DenyCode::Unsigned,
            "{name}"
        );
    }
    // Signed under this lease for this repo: allowed.
    let mut request = push_request(&world.lease);
    request.commits.push(PushedCommit {
        paths: None,
        id: commit(9),
        signed_under: vec![LedgerRef {
            paths: None,
            lease: world.lease.id.clone(),
            repo: repo("omega-code"),
        }],
    });
    assert!(policy::decide_push(&world.ctx(), &request).is_ok());
}

#[test]
fn signatures_only_for_allowed_committer_identities() {
    let world = World::new(lease());
    for email in [
        "user@example.org",
        "USER+AGENT@example.org",
        "user+agent@example.org ",
        "",
        "user+fix@example.org",
    ] {
        let mut request = sign_request(&world.lease);
        request.committer_email = email.to_owned();
        assert_eq!(
            code(policy::decide_sign(&world.ctx(), &request)),
            DenyCode::Committer,
            "{email:?}"
        );
        // The same emails as the author, the committer allowed: the author is checked too.
        let mut request = sign_request(&world.lease);
        request.author_email = email.to_owned();
        assert_eq!(
            code(policy::decide_sign(&world.ctx(), &request)),
            DenyCode::Author,
            "author {email:?}"
        );
    }
    assert!(policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).is_ok());
    // And only commits: never a tag (a violation), a tree, a blob or anything else (a
    // malformed request, no violation), whoever the tagger.
    for (object, expected) in [
        (ObjectKind::Tag, DenyCode::ObjectType),
        (ObjectKind::Tree, DenyCode::Invalid),
        (ObjectKind::Blob, DenyCode::Invalid),
        (ObjectKind::Other, DenyCode::Invalid),
    ] {
        let mut request = sign_request(&world.lease);
        request.object = object;
        assert_eq!(
            code(policy::decide_sign(&world.ctx(), &request)),
            expected,
            "{object:?}"
        );
    }
    assert!(DenyCode::ObjectType.is_violation() && !DenyCode::Invalid.is_violation());
}

#[test]
fn leases_bounded_in_time_count_and_rate() {
    // Each limit: allowed one short of it, denied at it. (The test lease: max_signatures 3,
    // max_pushes 2, max_ops_per_minute 5.)
    let mut world = World::new(lease());
    let expires = world.lease.ticket.limits.expires_at;
    world.now = expires.saturating_sub_seconds(1);
    assert!(
        policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok(),
        "1 s before expiry"
    );
    world.now = expires;
    assert_eq!(
        code(policy::decide_fetch(&world.ctx(), &fetch_request())),
        DenyCode::Expired
    );
    world.now = later(60);

    let terms = om(&world.lease.ticket);
    let (signatures, pushes, rate) = (
        terms.limits.max_signatures,
        terms.limits.max_pushes,
        world.lease.ticket.limits.max_ops_per_minute,
    );
    let below = |used: u32| used.checked_sub(1).unwrap();
    world.usage = usage_in(below(signatures), 0, 0);
    assert!(policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).is_ok());
    used(&mut world.usage).signatures = signatures;
    assert_eq!(
        code(policy::decide_sign(
            &world.ctx(),
            &sign_request(&world.lease)
        )),
        DenyCode::Limit,
        "at max_signatures"
    );
    world.usage = usage_in(0, below(pushes), 0);
    assert!(policy::decide_push(&world.ctx(), &push_request(&world.lease)).is_ok());
    used(&mut world.usage).pushes = pushes;
    assert_eq!(
        code(policy::decide_push(
            &world.ctx(),
            &push_request(&world.lease)
        )),
        DenyCode::Limit,
        "at max_pushes"
    );
    world.usage = Usage {
        ops_last_minute: below(rate),
        ..Usage::default()
    };
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
    world.usage.ops_last_minute = rate;
    assert_eq!(
        code(policy::decide_fetch(&world.ctx(), &fetch_request())),
        DenyCode::Rate,
        "at the rate"
    );
    // Revocable: a revoked lease denies on the very next request.
    world.usage = Usage::default();
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
    world.lease.state = lease::transition(State::Active, State::Revoked).unwrap();
    assert_eq!(
        code(policy::decide_fetch(&world.ctx(), &fetch_request())),
        DenyCode::NotActive,
        "after revocation"
    );
}
