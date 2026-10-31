//! docs/threat-model.md § What Writ guarantees, at the policy level: each test tries to break
//! one guarantee with the decisions alone. The end-to-end halves (real git, real ssh, the
//! daemon running) come with the milestones that wire them (M2–M4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use writ_core::config::PushMode;
use writ_core::lease::{self, State, TicketRecord, Usage};
use writ_core::policy::{self, CertIdentity, LedgerRef, ObjectKind, PushedCommit};

#[test]
fn no_signature_or_push_outside_an_active_approver_signed_lease() {
    // Not a lease yet, or not any more: every operation is denied.
    for state in [
        State::Pending,
        State::Refused,
        State::Applied,
        State::Closed,
        State::Exhausted,
        State::Expired,
        State::Revoked,
    ] {
        let mut world = World::new(lease());
        world.lease.state = state;
        assert!(
            policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).is_err(),
            "{state}"
        );
        assert!(
            policy::decide_push(&world.ctx(), &push_request(&world.lease)).is_err(),
            "{state}"
        );
        assert!(
            policy::decide_fetch(&world.ctx(), &fetch_request()).is_err(),
            "{state}"
        );
    }
    // A certificate that matches no lease.
    let lease = lease();
    let cert = CertIdentity {
        key_id: ticket_id(5).to_string(),
        serial: 7,
        session_key: fp('S'),
    };
    assert!(policy::resolve_lease([&lease], &cert).is_err());
    // An approval under another namespace never activates a ticket.
    let ticket = submitted(REQUEST);
    let mut git_signature = approval();
    git_signature.namespace = "git".to_owned();
    let record = TicketRecord::pending(ticket.clone());
    assert!(lease::activate(&config(), &record, ticket, git_signature, 1, later(5)).is_err());
}

#[test]
fn pushes_only_to_allowed_repos_and_refs_no_force_push_unless_allowed() {
    let world = World::new(lease());
    type Attack = fn(&mut writ_core::policy::PushRequest);
    let attempts: Vec<(&str, Attack)> = vec![
        ("another repo", |r| r.repo = repo("homelab-scripts")),
        ("main", |r| r.updates[0].name = "refs/heads/main".to_owned()),
        ("a tag", |r| r.updates[0].name = "refs/tags/v9".to_owned()),
        ("a branch outside the lease", |r| {
            r.updates[0].name = "refs/heads/agent/other".to_owned()
        }),
        ("a path-like ref", |r| {
            r.updates[0].name = "refs/heads/agent/oauth-x/../../main".to_owned()
        }),
        ("a force push", |r| r.updates[0].fast_forward = false),
        ("a deletion", |r| r.updates[0].new = None),
        ("direct_ssh", |r| r.mode = PushMode::DirectSsh),
        ("proxy where the repo doesn't allow it", |r| {
            r.mode = PushMode::Proxy
        }),
    ];
    for (name, attack) in attempts {
        let mut request = push_request(&world.lease);
        attack(&mut request);
        assert!(
            policy::decide_push(&world.ctx(), &request).is_err(),
            "{name} was allowed"
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
                lease: other_lease.clone(),
                repo: repo("omega-code"),
            }],
        ),
        (
            "signed under this lease for another repo",
            vec![LedgerRef {
                lease: world.lease.id.clone(),
                repo: repo("homelab-scripts"),
            }],
        ),
    ];
    for (name, signed_under) in attempts {
        let mut request = push_request(&world.lease);
        request.commits.push(PushedCommit {
            id: commit(9),
            signed_under,
        });
        assert!(
            policy::decide_push(&world.ctx(), &request).is_err(),
            "{name} was allowed"
        );
    }
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
        assert!(
            policy::decide_sign(&world.ctx(), &request).is_err(),
            "{email:?} was signed"
        );
    }
    // And never a tag, whoever the tagger.
    let mut tag = sign_request(&world.lease);
    tag.object = ObjectKind::Tag;
    assert!(policy::decide_sign(&world.ctx(), &tag).is_err());
}

#[test]
fn leases_bounded_in_time_count_and_rate() {
    let mut world = World::new(lease());
    let expires = world.lease.ticket.limits.expires_at;
    world.now = expires;
    assert!(
        policy::decide_fetch(&world.ctx(), &fetch_request()).is_err(),
        "at expiry"
    );
    world.now = later(60);
    world.usage = Usage {
        signatures: 3,
        ..Usage::default()
    };
    assert!(
        policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).is_err(),
        "over max_signatures"
    );
    world.usage = Usage {
        pushes: 2,
        ..Usage::default()
    };
    assert!(
        policy::decide_push(&world.ctx(), &push_request(&world.lease)).is_err(),
        "over max_pushes"
    );
    world.usage = Usage {
        ops_last_minute: 5,
        ..Usage::default()
    };
    assert!(
        policy::decide_fetch(&world.ctx(), &fetch_request()).is_err(),
        "over the rate"
    );
    // Revocable: a revoked lease denies on the very next request.
    world.usage = Usage::default();
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
    world.lease.state = lease::transition(State::Active, State::Revoked).unwrap();
    assert!(
        policy::decide_fetch(&world.ctx(), &fetch_request()).is_err(),
        "after revocation"
    );
}
