//! One table per row of docs/lease-model.md § Constraints that the daemon checks, each case
//! allowed or denied with its code. (The `direct_ssh` rows are checked from M10, the LLM
//! plan check is in the backlog.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod common;

use std::path::PathBuf;

use common::*;
use writ_core::caller::{CallerConstraint, CodeIdentity, ProcessMatch, ProcessRef};
use writ_core::config::{ObjectFormat, PushMode};
use writ_core::lease::{Lease, State};
use writ_core::policy::{
    self, CertIdentity, DenyCode, LedgerRef, ObjectKind, PushRequest, PushedCommit, RefUpdate,
    SignRequest,
};

type Mutate<T> = fn(&mut World, &mut T);

fn check_sign(cases: &[(&str, Mutate<SignRequest>, Option<DenyCode>)]) {
    for (name, mutate, expected) in cases {
        let mut world = World::new(lease());
        let mut request = sign_request(&world.lease);
        mutate(&mut world, &mut request);
        let got = policy::decide_sign(&world.ctx(), &request)
            .err()
            .map(|d| d.code);
        assert_eq!(got, *expected, "sign case {name:?}");
    }
}

fn check_push(cases: &[(&str, Mutate<PushRequest>, Option<DenyCode>)]) {
    for (name, mutate, expected) in cases {
        let mut world = World::new(lease());
        let mut request = push_request(&world.lease);
        mutate(&mut world, &mut request);
        let got = policy::decide_push(&world.ctx(), &request)
            .err()
            .map(|d| d.code);
        assert_eq!(got, *expected, "push case {name:?}");
    }
}

fn check_fetch(cases: &[(&str, Mutate<()>, Option<DenyCode>)]) {
    for (name, mutate, expected) in cases {
        let mut world = World::new(lease());
        mutate(&mut world, &mut ());
        let got = policy::decide_fetch(&world.ctx(), &fetch_request())
            .err()
            .map(|d| d.code);
        assert_eq!(got, *expected, "fetch case {name:?}");
    }
}

fn update(name: &str) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        old: Some(commit(1)),
        new: Some(commit(3)),
        fast_forward: true,
        case_twin: false,
    }
}

// Row: TTL, counts, rate — daemon state.

#[test]
fn ttl_counts_and_rate() {
    check_sign(&[
        ("fresh lease", |_, _| {}, None),
        (
            "one second before expiry",
            |w, _| w.now = later(2 * 3600 - 1),
            None,
        ),
        (
            "at expiry",
            |w, _| w.now = later(2 * 3600),
            Some(DenyCode::Expired),
        ),
        (
            "after expiry",
            |w, _| w.now = later(10 * 3600),
            Some(DenyCode::Expired),
        ),
        (
            "marked expired",
            |w, _| w.lease.state = State::Expired,
            Some(DenyCode::Expired),
        ),
        (
            "revoked",
            |w, _| w.lease.state = State::Revoked,
            Some(DenyCode::NotActive),
        ),
        (
            "closed",
            |w, _| w.lease.state = State::Closed,
            Some(DenyCode::NotActive),
        ),
        (
            "still pending",
            |w, _| w.lease.state = State::Pending,
            Some(DenyCode::NotActive),
        ),
        ("last signature", |w, _| w.usage.signatures = 2, None),
        (
            "signatures used up",
            |w, _| w.usage.signatures = 3,
            Some(DenyCode::Limit),
        ),
        (
            "both counts used up (fetch keeps it alive)",
            |w, _| {
                w.usage.signatures = 3;
                w.usage.pushes = 2;
            },
            Some(DenyCode::Limit),
        ),
        ("under the rate", |w, _| w.usage.ops_last_minute = 4, None),
        (
            "at the rate",
            |w, _| w.usage.ops_last_minute = 5,
            Some(DenyCode::Rate),
        ),
    ]);
    check_push(&[
        ("last push", |w, _| w.usage.pushes = 1, None),
        (
            "pushes used up",
            |w, _| w.usage.pushes = 2,
            Some(DenyCode::Limit),
        ),
        (
            "signatures used up, pushes left",
            |w, _| w.usage.signatures = 3,
            None,
        ),
        (
            "at the rate",
            |w, _| w.usage.ops_last_minute = 5,
            Some(DenyCode::Rate),
        ),
        (
            "after expiry",
            |w, _| w.now = later(3 * 3600),
            Some(DenyCode::Expired),
        ),
    ]);
    check_fetch(&[
        ("fresh lease", |_, _| {}, None),
        (
            "signatures and pushes used up",
            |w, _| {
                w.usage.signatures = 3;
                w.usage.pushes = 2;
            },
            None,
        ),
        (
            "at the rate",
            |w, _| w.usage.ops_last_minute = 5,
            Some(DenyCode::Rate),
        ),
        (
            "after expiry",
            |w, _| w.now = later(3 * 3600),
            Some(DenyCode::Expired),
        ),
        (
            "exhausted",
            |w, _| w.lease.state = State::Exhausted,
            Some(DenyCode::Exhausted),
        ),
    ]);
}

#[test]
fn a_lease_without_fetch_is_exhausted_when_its_counts_are_used() {
    let lease = lease_of(submitted(
        &REQUEST.replace("[fetch, commit_sign, push]", "[commit_sign, push]"),
    ));
    let mut world = World::new(lease);
    world.usage.signatures = 3;
    let mut push = push_request(&world.lease);
    assert!(policy::decide_push(&world.ctx(), &push).is_ok());
    world.usage.pushes = 2;
    push = push_request(&world.lease);
    assert_eq!(
        policy::decide_push(&world.ctx(), &push).unwrap_err().code,
        DenyCode::Exhausted
    );
    let sign = sign_request(&world.lease);
    assert_eq!(
        policy::decide_sign(&world.ctx(), &sign).unwrap_err().code,
        DenyCode::Exhausted
    );
}

// Row: Repo — gateway endpoint.

#[test]
fn repo_endpoint() {
    check_sign(&[
        ("repo in the lease", |_, _| {}, None),
        (
            "registered repo outside the lease",
            |_, r| r.repo = repo("homelab-scripts"),
            Some(DenyCode::Repo),
        ),
        (
            "unknown repo",
            |_, r| r.repo = repo("someone-else"),
            Some(DenyCode::Repo),
        ),
    ]);
    check_push(&[(
        "repo outside the lease",
        |_, r| r.repo = repo("homelab-scripts"),
        Some(DenyCode::Repo),
    )]);
    check_fetch(&[(
        "repo removed from the registry",
        |w, _| {
            w.config = writ_core::config::PolicyConfig::from_yaml(
                &POLICY.replace("omega-code", "omega-two"),
            )
            .unwrap();
        },
        Some(DenyCode::Config),
    )]);
}

// Row: Destination ref, protected refs — push commands received by the gateway / proxy.

#[test]
fn destination_ref_and_protected_refs() {
    check_push(&[
        ("allowed branch", |_, _| {}, None),
        (
            "protected main",
            |_, r| r.updates = vec![update("refs/heads/main")],
            Some(DenyCode::ProtectedRef),
        ),
        (
            "protected tag",
            |_, r| r.updates = vec![update("refs/tags/v1")],
            Some(DenyCode::ProtectedRef),
        ),
        // On a case-insensitive file system (APFS) these are main's own ref file.
        (
            "protected main, in another case",
            |_, r| r.updates = vec![update("refs/heads/MAIN")],
            Some(DenyCode::ProtectedRef),
        ),
        (
            "protected main, one letter in another case",
            |_, r| r.updates = vec![update("refs/heads/Main")],
            Some(DenyCode::ProtectedRef),
        ),
        (
            "protected tag, prefix in another case",
            |_, r| r.updates = vec![update("refs/TAGS/v1")],
            Some(DenyCode::ProtectedRef),
        ),
        (
            "other branch under agent/",
            |_, r| r.updates = vec![update("refs/heads/agent/other")],
            Some(DenyCode::Ref),
        ),
        (
            "branch outside agent/",
            |_, r| r.updates = vec![update("refs/heads/feature/x")],
            Some(DenyCode::Ref),
        ),
        (
            "a note ref",
            |_, r| r.updates = vec![update("refs/notes/writ")],
            Some(DenyCode::Ref),
        ),
        (
            "one bad update among good ones",
            |_, r| r.updates.push(update("refs/heads/main")),
            Some(DenyCode::ProtectedRef),
        ),
        (
            "same ref twice",
            |_, r| r.updates.push(update("refs/heads/agent/oauth-login")),
            Some(DenyCode::Invalid),
        ),
        (
            "invalid ref name",
            |_, r| r.updates = vec![update("refs/heads/agent/oauth-..x")],
            Some(DenyCode::Invalid),
        ),
        (
            "not a full ref",
            |_, r| r.updates = vec![update("agent/oauth-login")],
            Some(DenyCode::Invalid),
        ),
        (
            "no updates",
            |_, r| r.updates.clear(),
            Some(DenyCode::Invalid),
        ),
        ("branch creation", |_, r| r.updates[0].old = None, None),
        (
            "proxy mode, not allowed for omega-code",
            |_, r| r.mode = PushMode::Proxy,
            Some(DenyCode::PushMode),
        ),
        (
            "direct_ssh never goes through here",
            |_, r| r.mode = PushMode::DirectSsh,
            Some(DenyCode::PushMode),
        ),
    ]);
}

#[test]
fn protected_refs_win_over_any_lease() {
    // A template and a lease that would allow every branch: main is still refused.
    let policy = POLICY.replace(r#"branches: ["agent/*"]"#, r#"branches: ["*"]"#);
    let config = writ_core::config::PolicyConfig::from_yaml(&policy).unwrap();
    let request = request(&REQUEST.replace(r#"["agent/oauth-*"]"#, r#"["*"]"#));
    let ticket = writ_core::fit::submit(&config, &request, &submission(1)).unwrap();
    let record = writ_core::lease::TicketRecord::pending(ticket.clone());
    let lease =
        writ_core::lease::activate(&config, &record, ticket, approval(), 7, later(1)).unwrap();
    let mut world = World::new(lease);
    world.config = config;
    let mut push = push_request(&world.lease);
    push.updates = vec![update("refs/heads/anything")];
    assert!(policy::decide_push(&world.ctx(), &push).is_ok());
    push.updates = vec![update("refs/heads/main")];
    let denial = policy::decide_push(&world.ctx(), &push).unwrap_err();
    assert_eq!(denial.code, DenyCode::ProtectedRef);
    assert!(
        denial.reason.contains("refs/heads/main is protected"),
        "{denial}"
    );
}

// Row: Force push — ref update (old → new).

#[test]
fn force_push() {
    check_push(&[
        ("fast-forward", |_, _| {}, None),
        (
            "non-fast-forward",
            |_, r| r.updates[0].fast_forward = false,
            Some(DenyCode::ForcePush),
        ),
        (
            "deletion",
            |_, r| {
                r.updates[0].new = None;
                r.commits.clear();
            },
            Some(DenyCode::ForcePush),
        ),
        (
            "empty update",
            |_, r| {
                r.updates[0].old = None;
                r.updates[0].new = None;
            },
            Some(DenyCode::Invalid),
        ),
        (
            "creation is never a force push",
            |_, r| {
                r.updates[0].old = None;
                r.updates[0].fast_forward = false;
            },
            None,
        ),
    ]);
}

#[test]
fn force_push_when_the_lease_allows_it() {
    let policy = POLICY.replacen(
        "    push_modes: [gateway, proxy]\n    committer_emails",
        "    push_modes: [gateway, proxy]\n    force_push: true\n    committer_emails",
        1,
    );
    let config = writ_core::config::PolicyConfig::from_yaml(&policy).unwrap();
    let request = request(&REQUEST.replace(
        "  branches: [\"agent/oauth-*\"]\n",
        "  branches: [\"agent/oauth-*\"]\n  force_push: true\n",
    ));
    // Without the template allowing it, the ticket doesn't fit.
    let rejection =
        writ_core::fit::submit(&common::config(), &request, &submission(1)).unwrap_err();
    assert!(
        rejection.reasons.iter().any(|r| r.contains("force_push")),
        "{rejection}"
    );
    let ticket = writ_core::fit::submit(&config, &request, &submission(1)).unwrap();
    let record = writ_core::lease::TicketRecord::pending(ticket.clone());
    let lease =
        writ_core::lease::activate(&config, &record, ticket, approval(), 7, later(1)).unwrap();
    let mut world = World::new(lease);
    world.config = config;
    let mut push = push_request(&world.lease);
    push.updates[0].fast_forward = false;
    assert!(policy::decide_push(&world.ctx(), &push).is_ok());
    push.updates[0].new = None;
    push.commits.clear();
    assert!(policy::decide_push(&world.ctx(), &push).is_ok());
    // Still never onto a protected ref.
    push.updates[0].name = "refs/heads/main".to_owned();
    assert_eq!(
        policy::decide_push(&world.ctx(), &push).unwrap_err().code,
        DenyCode::ProtectedRef
    );
}

// Row: Pushed commits signed under this lease — pack vs ledger.

#[test]
fn pushed_commits_signed_under_this_lease() {
    fn under(lease: &str, repo_name: &str) -> LedgerRef {
        LedgerRef {
            paths: None,
            lease: lease.parse().unwrap(),
            repo: repo(repo_name),
        }
    }
    check_push(&[
        ("every commit in the ledger", |_, _| {}, None),
        (
            "no new commits (branch moved to a known commit)",
            |_, r| r.commits.clear(),
            None,
        ),
        (
            "a commit not in the ledger",
            |_, r| r.commits[1].signed_under.clear(),
            Some(DenyCode::Unsigned),
        ),
        (
            "a commit signed under another lease",
            |_, r| {
                r.commits[0].signed_under = vec![under(ticket_id(99).as_str(), "omega-code")];
            },
            Some(DenyCode::Unsigned),
        ),
        (
            "a commit signed under this lease for another repo",
            |w, r| {
                r.commits[0].signed_under = vec![under(w.lease.id.as_str(), "homelab-scripts")];
            },
            Some(DenyCode::Unsigned),
        ),
        (
            "signed under another lease and this one",
            |w, r| {
                r.commits[0].signed_under = vec![
                    under(ticket_id(99).as_str(), "omega-code"),
                    under(w.lease.id.as_str(), "omega-code"),
                ];
            },
            None,
        ),
        (
            "an unsigned commit among many",
            |_, r| {
                r.commits.push(PushedCommit {
                    paths: None,
                    id: commit(4),
                    signed_under: vec![],
                });
            },
            Some(DenyCode::Unsigned),
        ),
        // A renewal pushes what the leases it renews signed, and nothing more.
        (
            "signed under the lease this one renews",
            |w, r| {
                w.lease.ticket.text.renews = Some(ticket_id(98));
                r.predecessors = vec![ticket_id(98)];
                r.commits[0].signed_under = vec![under(ticket_id(98).as_str(), "omega-code")];
            },
            None,
        ),
        (
            "signed under the lease that one renewed",
            |w, r| {
                w.lease.ticket.text.renews = Some(ticket_id(98));
                r.predecessors = vec![ticket_id(98), ticket_id(97)];
                r.commits[0].signed_under = vec![under(ticket_id(97).as_str(), "omega-code")];
            },
            None,
        ),
        (
            "signed under a predecessor for another repo",
            |w, r| {
                w.lease.ticket.text.renews = Some(ticket_id(98));
                r.predecessors = vec![ticket_id(98)];
                r.commits[0].signed_under = vec![under(ticket_id(98).as_str(), "homelab-scripts")];
            },
            Some(DenyCode::Unsigned),
        ),
        (
            "signed under a lease outside the chain",
            |w, r| {
                w.lease.ticket.text.renews = Some(ticket_id(98));
                r.predecessors = vec![ticket_id(98)];
                r.commits[0].signed_under = vec![under(ticket_id(99).as_str(), "omega-code")];
            },
            Some(DenyCode::Unsigned),
        ),
        (
            "a lease that renews nothing given a chain",
            |_, r| {
                r.predecessors = vec![ticket_id(98)];
                r.commits[0].signed_under = vec![under(ticket_id(98).as_str(), "omega-code")];
            },
            Some(DenyCode::Invalid),
        ),
        (
            "a chain that doesn't start with the lease renewed",
            |w, r| {
                w.lease.ticket.text.renews = Some(ticket_id(98));
                r.predecessors = vec![ticket_id(99), ticket_id(98)];
            },
            Some(DenyCode::Invalid),
        ),
        (
            "a renewal given no chain",
            |w, _| w.lease.ticket.text.renews = Some(ticket_id(98)),
            Some(DenyCode::Invalid),
        ),
    ]);
}

// Row: the paths a commit touches, signing vs push — evidence vs the objects git verified.

#[test]
fn a_pushed_commit_s_paths_must_be_the_ones_checked_at_signing() {
    fn signed_with(r: &mut PushRequest, lease: &str, paths: Option<&str>) {
        for commit in &mut r.commits {
            for entry in &mut commit.signed_under {
                if entry.lease.as_str() == lease {
                    entry.paths = paths.map(str::to_owned);
                }
            }
        }
    }
    check_push(&[
        (
            "the same paths",
            |w, r| {
                signed_with(r, w.lease.id.as_str(), Some("d1"));
                r.commits
                    .iter_mut()
                    .for_each(|c| c.paths = Some("d1".into()));
            },
            None,
        ),
        (
            "unknown at signing: nothing to compare",
            |_, r| {
                r.commits
                    .iter_mut()
                    .for_each(|c| c.paths = Some("d2".into()))
            },
            None,
        ),
        (
            "other paths at push",
            |w, r| {
                signed_with(r, w.lease.id.as_str(), Some("d1"));
                r.commits
                    .iter_mut()
                    .for_each(|c| c.paths = Some("d1".into()));
                r.commits[1].paths = Some("d2".into());
            },
            Some(DenyCode::PathsChanged),
        ),
        (
            "known at signing, not computable at push",
            |w, r| {
                signed_with(r, w.lease.id.as_str(), Some("d1"));
                r.commits
                    .iter_mut()
                    .for_each(|c| c.paths = Some("d1".into()));
                r.commits[0].paths = None;
            },
            Some(DenyCode::PathsChanged),
        ),
    ]);
}

// Row: refs that differ only in case — APFS folds them into one.

#[test]
fn refs_that_differ_only_in_case_are_refused() {
    check_push(&[
        ("a ref alone", |_, _| {}, None),
        (
            "a new ref with a twin in the repo",
            |_, r| r.updates[0].case_twin = true,
            Some(DenyCode::Invalid),
        ),
        (
            "two updates differing only in case",
            |_, r| {
                let mut twin = r.updates[0].clone();
                twin.name = twin
                    .name
                    .to_ascii_uppercase()
                    .replace("REFS/HEADS/", "refs/heads/");
                r.updates.push(twin);
            },
            Some(DenyCode::Invalid),
        ),
    ]);
}

#[test]
fn push_size() {
    check_push(&[
        ("at the limit", |_, r| r.pack_size = 1_000_000, None),
        (
            "over the limit",
            |_, r| r.pack_size = 1_000_001,
            Some(DenyCode::Size),
        ),
    ]);
}

// Row: Committer / author identity — commit bytes parsed by the daemon.

#[test]
fn committer_identity_and_object() {
    check_sign(&[
        ("agent email", |_, _| {}, None),
        (
            "personal email",
            |_, r| r.committer_email = "user@example.org".to_owned(),
            Some(DenyCode::Committer),
        ),
        (
            "case differs",
            |_, r| r.committer_email = "User+agent@example.org".to_owned(),
            Some(DenyCode::Committer),
        ),
        (
            "email allowed by the template, not by the ticket",
            |_, r| {
                r.committer_email = "user+fix@example.org".to_owned();
            },
            Some(DenyCode::Committer),
        ),
        (
            "empty email",
            |_, r| r.committer_email.clear(),
            Some(DenyCode::Committer),
        ),
        // The author is checked like the committer: a commit signed under the lease can't
        // name someone else (the user's personal identity) as its author.
        (
            "author: personal email",
            |_, r| r.author_email = "user@example.org".to_owned(),
            Some(DenyCode::Author),
        ),
        (
            "author: case differs",
            |_, r| r.author_email = "User+agent@example.org".to_owned(),
            Some(DenyCode::Author),
        ),
        (
            "author: allowed by the template, not by the ticket",
            |_, r| r.author_email = "user+fix@example.org".to_owned(),
            Some(DenyCode::Author),
        ),
        (
            "author: empty email",
            |_, r| r.author_email.clear(),
            Some(DenyCode::Author),
        ),
        (
            "a tag",
            |_, r| r.object = ObjectKind::Tag,
            Some(DenyCode::ObjectType),
        ),
        (
            "a tree",
            |_, r| r.object = ObjectKind::Tree,
            Some(DenyCode::Invalid),
        ),
        (
            "a blob",
            |_, r| r.object = ObjectKind::Blob,
            Some(DenyCode::Invalid),
        ),
        (
            "anything else",
            |_, r| r.object = ObjectKind::Other,
            Some(DenyCode::Invalid),
        ),
        (
            "a SHA-256 commit for a SHA-1 repo",
            |_, r| r.object_format = Some(ObjectFormat::Sha256),
            Some(DenyCode::ObjectFormat),
        ),
        (
            "a commit whose format is unknown",
            |_, r| r.object_format = None,
            Some(DenyCode::ObjectFormat),
        ),
    ]);
}

#[test]
fn ticket_link_trailer() {
    check_sign(&[
        ("trailer with the lease id", |_, _| {}, None),
        (
            "no trailer",
            |_, r| r.writ_trailers.clear(),
            Some(DenyCode::TicketLink),
        ),
        (
            "another lease's id",
            |_, r| r.writ_trailers = vec![ticket_id(99).to_string()],
            Some(DenyCode::TicketLink),
        ),
        (
            "two trailers",
            |w, r| r.writ_trailers.push(w.lease.id.to_string()),
            Some(DenyCode::TicketLink),
        ),
    ]);
    // homelab-scripts is ledger_only: no trailer needed.
    let lease = lease_of(submitted(
        &REQUEST.replace("[omega-code]", "[homelab-scripts]"),
    ));
    let world = World::new(lease);
    let mut request = sign_request(&world.lease);
    request.repo = repo("homelab-scripts");
    request.writ_trailers.clear();
    assert!(policy::decide_sign(&world.ctx(), &request).is_ok());
}

// Row: Caller = lease holder — session certificate.

#[test]
fn caller_is_the_lease_holder() {
    let lease = lease();
    let cert = CertIdentity {
        key_id: lease.id.to_string(),
        serial: lease.cert_serial,
        session_key: lease.ticket.subject.session_key.clone(),
    };
    let other =
        lease_of(writ_core::fit::submit(&config(), &request(REQUEST), &submission(2)).unwrap());
    let leases: Vec<Lease> = vec![other.clone(), lease.clone()];
    assert_eq!(policy::resolve_lease(&leases, &cert).unwrap().id, lease.id);

    let cases: Vec<(&str, CertIdentity, DenyCode)> = vec![
        (
            "another lease id",
            CertIdentity {
                key_id: ticket_id(42).to_string(),
                ..cert.clone()
            },
            DenyCode::NoLease,
        ),
        (
            "another serial",
            CertIdentity {
                serial: 8,
                ..cert.clone()
            },
            DenyCode::NoLease,
        ),
        (
            "another session key",
            CertIdentity {
                session_key: fp('X'),
                ..cert.clone()
            },
            DenyCode::NoLease,
        ),
        (
            "garbage key id",
            CertIdentity {
                key_id: "root".to_owned(),
                ..cert.clone()
            },
            DenyCode::NoLease,
        ),
    ];
    for (name, cert, code) in cases {
        assert_eq!(
            policy::resolve_lease(&leases, &cert).unwrap_err().code,
            code,
            "{name}"
        );
    }
    let twice = vec![lease.clone(), lease.clone()];
    assert_eq!(
        policy::resolve_lease(&twice, &cert).unwrap_err().code,
        DenyCode::AmbiguousLease
    );
    assert_eq!(
        policy::resolve_lease(&Vec::<Lease>::new(), &cert)
            .unwrap_err()
            .code,
        DenyCode::NoLease
    );
}

// Row: Origin host — advisory: never decides anything.

#[test]
fn origin_host_is_advisory() {
    let lease = lease_of(submitted(&format!("origin_hint: macbook-user\n{REQUEST}")));
    let mut world = World::new(lease);
    world.caller.source_addr = Some("203.0.113.9".parse().unwrap());
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
}

// Row: Process tree (local mode only) — CallerFacts.

fn process(pid: u32, generation: u64, exe: &str) -> ProcessRef {
    ProcessRef {
        pid,
        generation,
        executable: PathBuf::from(exe),
        code_identity: None,
    }
}

const OMEGA: &str = "/Applications/Omega Code.app/Contents/MacOS/omega";

fn bound_lease(code_identity: Option<CodeIdentity>) -> Lease {
    let mut ticket = submitted(REQUEST);
    ticket.subject.caller = Some(CallerConstraint {
        descends_from: ProcessMatch {
            executable: OMEGA.to_owned(),
            pid: 4242,
            generation: 118,
            code_identity,
        },
    });
    lease_of(ticket)
}

fn chain_with(root: ProcessRef) -> Vec<ProcessRef> {
    vec![
        process(5003, 1, "/usr/local/bin/writ-sign"),
        process(5002, 1, "/usr/bin/git"),
        process(5001, 1, "/usr/local/bin/claude"),
        root,
        process(1, 1, "/sbin/launchd"),
    ]
}

#[test]
fn process_tree() {
    type Chain = Option<Vec<ProcessRef>>;
    let cases: Vec<(&str, Chain, Option<DenyCode>)> = vec![
        (
            "descends from the session",
            Some(chain_with(process(4242, 118, OMEGA))),
            None,
        ),
        (
            "the session root itself",
            Some(vec![process(4242, 118, OMEGA)]),
            None,
        ),
        ("no process chain (TCP)", None, Some(DenyCode::Caller)),
        ("empty process chain", Some(vec![]), Some(DenyCode::Caller)),
        (
            "not in the session's tree",
            Some(chain_with(process(4000, 3, "/usr/bin/zsh"))),
            Some(DenyCode::Caller),
        ),
        (
            "pid reused (other generation)",
            Some(chain_with(process(4242, 119, OMEGA))),
            Some(DenyCode::Caller),
        ),
        (
            "same pid, other executable",
            Some(chain_with(process(4242, 118, "/tmp/omega"))),
            Some(DenyCode::Caller),
        ),
        (
            "same executable, other pid",
            Some(chain_with(process(4243, 118, OMEGA))),
            Some(DenyCode::Caller),
        ),
    ];
    for (name, chain, expected) in cases {
        let mut world = World::new(bound_lease(None));
        world.caller.process_chain = chain;
        let got = policy::decide_fetch(&world.ctx(), &fetch_request())
            .err()
            .map(|d| d.code);
        assert_eq!(got, expected, "{name}");
    }
}

#[test]
fn process_tree_with_code_identity() {
    let identity = CodeIdentity {
        signing_id: "com.omega.code".to_owned(),
        team_id: Some("TEAM123456".to_owned()),
    };
    let mut world = World::new(bound_lease(Some(identity.clone())));
    let mut root = process(4242, 118, OMEGA);
    world.caller.process_chain = Some(chain_with(root.clone()));
    assert_eq!(
        policy::decide_fetch(&world.ctx(), &fetch_request())
            .unwrap_err()
            .code,
        DenyCode::Caller,
        "unsigned process"
    );
    root.code_identity = Some(CodeIdentity {
        team_id: Some("OTHER".to_owned()),
        ..identity.clone()
    });
    world.caller.process_chain = Some(chain_with(root.clone()));
    assert_eq!(
        policy::decide_fetch(&world.ctx(), &fetch_request())
            .unwrap_err()
            .code,
        DenyCode::Caller,
        "other team"
    );
    root.code_identity = Some(identity);
    world.caller.process_chain = Some(chain_with(root));
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
}

// Row: Files touched vs expected_paths — commit trees.

#[test]
fn files_vs_expected_paths() {
    fn paths(list: &[&str]) -> Option<Vec<String>> {
        Some(list.iter().map(|p| p.to_string()).collect())
    }
    // feature-branch: paths_check warn.
    let world = World::new(lease());
    let mut request = sign_request(&world.lease);
    request.touched_paths = paths(&["src/auth/a.rs", "tests/auth/b.rs"]);
    assert!(
        policy::decide_sign(&world.ctx(), &request)
            .unwrap()
            .warnings
            .is_empty()
    );
    request.touched_paths = paths(&["src/auth/a.rs", "src/billing/b.rs"]);
    let allowed = policy::decide_sign(&world.ctx(), &request).unwrap();
    assert_eq!(
        allowed.warnings,
        vec!["files outside expected_paths: src/billing/b.rs"]
    );
    request.touched_paths = None;
    assert_eq!(
        policy::decide_sign(&world.ctx(), &request)
            .unwrap()
            .warnings,
        vec!["paths not checked"]
    );

    // quick-fix: paths_check deny.
    let quick = REQUEST
        .replace("template: feature-branch", "template: quick-fix")
        .replace("agent/oauth-*", "agent/fix-*")
        .replace("ttl: 2h", "ttl: 1h");
    let world = World::new(lease_of(submitted(&quick)));
    let mut request = sign_request(&world.lease);
    assert!(policy::decide_sign(&world.ctx(), &request).is_ok());
    request.touched_paths = paths(&["src/auth/a.rs", "src/billing/b.rs"]);
    let denial = policy::decide_sign(&world.ctx(), &request).unwrap_err();
    assert_eq!(denial.code, DenyCode::Paths);
    assert!(denial.reason.contains("src/billing/b.rs"), "{denial}");
    assert!(
        denial.hint.as_deref().unwrap_or("").contains("amendment"),
        "{denial}"
    );
    request.touched_paths = None;
    assert_eq!(
        policy::decide_sign(&world.ctx(), &request)
            .unwrap_err()
            .code,
        DenyCode::Paths
    );

    // No expected_paths: the check is skipped, even with deny.
    let no_paths = quick.replace(
        "  expected_paths: [\"src/auth/**\", \"tests/auth/**\"]\n",
        "",
    );
    let world = World::new(lease_of(submitted(&no_paths)));
    let mut request = sign_request(&world.lease);
    request.touched_paths = paths(&["anything/at/all"]);
    assert!(policy::decide_sign(&world.ctx(), &request).is_ok());
}

// Operations: each needs its own grant.

#[test]
fn operations() {
    let fetch_only = REQUEST
        .replace("template: feature-branch", "template: read-only")
        .replace(
            "operations: [fetch, commit_sign, push]",
            "operations: [fetch]",
        )
        .replace("  branches: [\"agent/oauth-*\"]\n", "")
        .replace(
            "  max_signatures: 3\n  max_pushes: 2\n",
            "  max_signatures: 0\n  max_pushes: 0\n",
        )
        .replace("  max_push_size: 1MB\n", "  max_push_size: 0\n");
    let world = World::new(lease_of(submitted(&fetch_only)));
    assert!(policy::decide_fetch(&world.ctx(), &fetch_request()).is_ok());
    let sign = policy::decide_sign(&world.ctx(), &sign_request(&world.lease)).unwrap_err();
    assert_eq!(sign.code, DenyCode::Operation);
    assert_eq!(
        sign.to_string(),
        format!(
            "outside ticket {id}: commit_sign not allowed. If needed, submit an amendment (ticket.amends: {id})",
            id = world.lease.id
        )
    );
    let push = policy::decide_push(&world.ctx(), &push_request(&world.lease)).unwrap_err();
    assert_eq!(push.code, DenyCode::Operation);
}

#[test]
fn violations_are_out_of_scope_denials_only() {
    for code in [
        DenyCode::Repo,
        DenyCode::Ref,
        DenyCode::ProtectedRef,
        DenyCode::ForcePush,
        DenyCode::Unsigned,
        DenyCode::Committer,
    ] {
        assert!(code.is_violation(), "{code}");
    }
    for code in [
        DenyCode::Expired,
        DenyCode::Limit,
        DenyCode::Rate,
        DenyCode::NoLease,
        DenyCode::Caller,
        DenyCode::Config,
        DenyCode::ObjectFormat,
        DenyCode::Sealed,
    ] {
        assert!(!code.is_violation(), "{code}");
    }
}

#[test]
fn a_lease_that_no_longer_fits_its_template_is_refused() {
    // The admin lowered the template's max_signatures below the lease's: fail closed.
    let mut world = World::new(lease());
    world.config = writ_core::config::PolicyConfig::from_yaml(&POLICY.replacen(
        "max_signatures: 50",
        "max_signatures: 2",
        1,
    ))
    .unwrap();
    let denial = policy::decide_fetch(&world.ctx(), &fetch_request()).unwrap_err();
    assert_eq!(denial.code, DenyCode::Config);
    // A removed template too.
    world.config =
        writ_core::config::PolicyConfig::from_yaml(&POLICY.replace("feature-branch:", "renamed:"))
            .unwrap();
    assert_eq!(
        policy::decide_fetch(&world.ctx(), &fetch_request())
            .unwrap_err()
            .code,
        DenyCode::Config
    );
}

#[test]
fn proxy_mode_where_allowed() {
    let lease = lease_of(submitted(
        &REQUEST.replace("[omega-code]", "[homelab-scripts]"),
    ));
    let world = World::new(lease);
    let mut push = push_request(&world.lease);
    push.repo = repo("homelab-scripts");
    push.mode = PushMode::Proxy;
    for commit in &mut push.commits {
        commit.signed_under[0].repo = repo("homelab-scripts");
    }
    assert!(policy::decide_push(&world.ctx(), &push).is_ok());
}
