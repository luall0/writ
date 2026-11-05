//! What an agent can read and check before it submits: `writ policy` (what a ticket for one
//! repo may ask, and nothing else of the policy) and `writ request --dry-run` (every check a
//! submission gets, nothing stored, nobody told).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use writ_approval::testing::{START, TestService, TestServiceBuilder};
use writ_approval::{RefusalCode, ServiceError, SubmissionLimits};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::config::{PathsCheck, TicketLink};
use writ_core::lease::State;
use writ_core::ticket::{Operation, Ticket};
use writ_crypto::keys::{KeyKind, generate};
use writ_platform::testing::{FakeClock, RecordingNotifier};

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// The terms of `omega-code` in a ticket.
fn om(ticket: &Ticket) -> &writ_core::ticket::RepoTerms {
    ticket.repos.get(&"omega-code".parse().unwrap()).unwrap()
}

fn ticket(branch: &str, more: &str) -> String {
    format!(
        r#"
limits:
  ttl: 2h
repos:
  omega-code:
    template: feature-branch
    operations: [fetch, commit_sign, push]
    branches: ["{branch}"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
{more}"#
    )
}

fn from(addr: &str) -> CallerFacts {
    CallerFacts {
        source_addr: Some(addr.parse().unwrap()),
        process_chain: None,
    }
}

fn service(
    edit: impl FnOnce(TestServiceBuilder) -> TestServiceBuilder,
) -> (tempfile::TempDir, TestService) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(START));
    let test = edit(TestServiceBuilder::new(POLICY).clock(clock)).build(dir.path());
    (dir, test)
}

fn refused(result: Result<impl std::fmt::Debug, ServiceError>, code: RefusalCode, text: &str) {
    match result {
        Err(error) => {
            assert_eq!(error.code(), Some(code), "{error}");
            assert!(
                error.reason_text().contains(text),
                "{text:?} not in {}",
                error.reason_text()
            );
        }
        Ok(value) => panic!("expected {code:?}, got {value:?}"),
    }
}

#[test]
fn writ_policy_shows_one_repo_and_nothing_else_of_the_policy() {
    let (_dir, h) = service(|b| b.max_active_per_source(2));
    let here = from("192.0.2.7");
    let omega = h
        .service
        .repo_policy(&"omega-code".parse().unwrap(), &here)
        .unwrap();
    assert_eq!(omega.repo.as_str(), "omega-code");
    assert_eq!(omega.protected_refs, ["refs/heads/main", "refs/tags/*"]);
    assert_eq!(omega.ticket_link, TicketLink::Trailer);
    assert_eq!(omega.min_ttl, writ_core::fit::DEFAULT_MIN_TTL);
    assert_eq!(omega.renew_grace, writ_core::fit::DEFAULT_RENEW_GRACE);
    assert_eq!(omega.max_active_per_source, Some(2));
    let names: Vec<&str> = omega.templates.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["feature-branch", "quick-fix", "read-only"]);
    let feature = &omega.templates[0];
    assert_eq!(
        feature.operations,
        [Operation::Fetch, Operation::CommitSign, Operation::Push]
    );
    assert_eq!(feature.branches, ["agent/*"]);
    assert_eq!(
        feature.committer_emails[0].as_str(),
        "user+agent@example.org"
    );
    assert_eq!(feature.max_ttl.seconds(), 4 * 3600);
    assert_eq!(
        (
            feature.max_signatures,
            feature.max_pushes,
            feature.max_ops_per_minute
        ),
        (50, 30, 20)
    );
    assert_eq!(feature.paths_check, PathsCheck::Warn);
    assert_eq!(omega.templates[1].paths_check, PathsCheck::Deny);
    // The signing key's id, to tell whether one lease can cover several repos.
    assert_eq!(
        feature.signing_key.as_ref().map(|k| k.as_str()),
        Some("agent-ed25519-01")
    );
    assert_eq!(
        omega.templates[2].signing_key, None,
        "read-only signs nothing"
    );

    // Another repo: only the templates that allow it.
    let dotfiles = h
        .service
        .repo_policy(&"dotfiles".parse().unwrap(), &here)
        .unwrap();
    let names: Vec<&str> = dotfiles.templates.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["quick-fix"]);
    assert!(dotfiles.protected_refs.is_empty());

    // Nothing of the upstream, the credential or the other repos; of the signing key, its id
    // alone (agents get its public key with each grant).
    let reply = String::from_utf8(writ_proto::encode_reply(&Ok::<_, writ_proto::ApiError>(
        omega,
    )))
    .unwrap();
    for hidden in [
        "github.com",
        "upstream-github-01",
        "homelab-scripts",
        "dotfiles",
        "gateway",
    ] {
        assert!(!reply.contains(hidden), "{hidden:?} in {reply}");
    }
    assert!(
        reply.contains(r#""signing_key":"agent-ed25519-01""#) && !reply.contains("ssh-ed25519"),
        "the key's id, never the key: {reply}"
    );

    // A repo not in the registry: refused, logged.
    refused(
        h.service.repo_policy(&"nowhere".parse().unwrap(), &here),
        RefusalCode::UnknownRepo,
        "repo nowhere is not in the registry",
    );
    let denied = h.events("policy", "denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["reason"], "repo nowhere is not in the registry");
    assert_eq!(denied[0]["source_addr"], "192.0.2.7");
    let allowed = h.events("policy", "allowed");
    assert_eq!(allowed.len(), 2);
    assert_eq!(allowed[0]["repo"], "omega-code");
    assert_eq!(allowed[1]["repo"], "dotfiles");
}

#[test]
fn policy_reads_and_dry_runs_count_against_the_submission_rate() {
    let (_dir, h) = service(|b| {
        b.submissions(SubmissionLimits {
            per_source: 2,
            in_all: 100,
        })
    });
    let here = from("192.0.2.7");
    let key = generate(KeyKind::Ed25519).unwrap();
    // One read and one dry run: the rate is used up, at its limit.
    h.service
        .repo_policy(&"omega-code".parse().unwrap(), &here)
        .unwrap();
    h.service
        .dry_run(key.public_key(), ticket("agent/a", "").as_bytes(), &here)
        .unwrap();
    refused(
        h.service.repo_policy(&"omega-code".parse().unwrap(), &here),
        RefusalCode::RateLimited,
        "more than 2 submissions a minute from this address",
    );
    refused(
        h.service
            .submit(key.public_key(), ticket("agent/a", "").as_bytes(), &here),
        RefusalCode::RateLimited,
        "more than 2 submissions a minute from this address",
    );
    // Another source has its own.
    h.service
        .repo_policy(&"omega-code".parse().unwrap(), &from("192.0.2.8"))
        .unwrap();
}

#[test]
fn a_dry_run_checks_like_a_submission_and_stores_nothing() {
    let notifier = Arc::new(RecordingNotifier::new());
    let (_dir, h) = service(|b| b.notifier(notifier.clone()));
    let here = from("192.0.2.7");
    let key = generate(KeyKind::Ed25519).unwrap();

    // Accepted: the ticket the daemon would build, nothing stored, nobody told.
    let checked = h
        .service
        .dry_run(key.public_key(), ticket("agent/a", "").as_bytes(), &here)
        .unwrap();
    let would = Ticket::from_canonical(checked.canonical.as_bytes()).unwrap();
    assert_eq!(om(&would).template.as_str(), "feature-branch");
    assert_eq!(would.limits.expires_at.unix(), START as i64 + 7200);
    assert!(h.service.list(true).unwrap().tickets.is_empty());
    let line = h.events("dry_run", "allowed");
    assert_eq!(line.len(), 1);
    assert_eq!(line[0]["reason"], "fits template feature-branch");
    assert!(line[0].get("ticket").is_none() && line[0].get("lease").is_none());
    assert!(h.audit().iter().all(|e| e["event"] != "submit"));
    // The first notification is the real submission's: the dry run queued none.
    let submitted = h
        .service
        .submit(key.public_key(), ticket("agent/a", "").as_bytes(), &here)
        .unwrap();
    let first = &notifier.wait_for(1)[0];
    assert!(
        first.message.starts_with(submitted.id.as_str()),
        "{}",
        first.message
    );
    assert_eq!(h.service.list(true).unwrap().tickets.len(), 1);

    // Rejected: the same reasons a submission gets, logged as a dry run.
    let main = ticket("main", "");
    let dry = h
        .service
        .dry_run(key.public_key(), main.as_bytes(), &here)
        .unwrap_err();
    let real = h
        .service
        .submit(key.public_key(), main.as_bytes(), &here)
        .unwrap_err();
    assert_eq!(dry.code(), Some(RefusalCode::Rejected));
    assert_eq!(dry.reason_text(), real.reason_text());
    assert_eq!(
        dry.reason_text(),
        "repos.omega-code fits no template: feature-branch: repos.omega-code: branch main is \
         not within the template's branches (agent/*)"
    );
    let denied = h.events("dry_run", "denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["reason"], dry.reason_text());

    // The checks around the templates too: an amendment from another session.
    let pending = &submitted.id;
    let stranger = generate(KeyKind::Ed25519).unwrap();
    refused(
        h.service.dry_run(
            stranger.public_key(),
            ticket("agent/a", &format!("  amends: {pending}\n")).as_bytes(),
            &here,
        ),
        RefusalCode::Rejected,
        &format!("ticket {pending} (amends) does not exist"),
    );
    assert_eq!(h.service.show(pending).unwrap().state, State::Pending);
}

#[test]
fn a_dry_run_is_refused_where_a_submission_would_be() {
    let (_dir, h) = service(|b| b.max_active_per_source(1));
    let here = from("192.0.2.7");
    let key = generate(KeyKind::Ed25519).unwrap();
    let submitted = h
        .service
        .submit(key.public_key(), ticket("agent/a", "").as_bytes(), &here)
        .unwrap();
    let pending = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    h.service
        .approve(&pending.id, &h.approval(&pending), &CallerFacts::default())
        .unwrap();
    // At the limit: refused with its code, as a submission is.
    let other = generate(KeyKind::Ed25519).unwrap();
    refused(
        h.service
            .dry_run(other.public_key(), ticket("agent/b", "").as_bytes(), &here),
        RefusalCode::TooManyActive,
        "(max_active_per_source: 1)",
    );
    // Not a ticket: refused before any template is read.
    refused(
        h.service
            .dry_run(other.public_key(), b"\xff\xfe", &from("192.0.2.8")),
        RefusalCode::NotUtf8,
        "the ticket file is not UTF-8",
    );
    refused(
        h.service
            .dry_run(other.public_key(), b"scope: [", &from("192.0.2.8")),
        RefusalCode::Rejected,
        "",
    );
    // An amendment from the lease's session: it would be accepted, and names its lease.
    h.service
        .dry_run(
            key.public_key(),
            ticket("agent/a", &format!("  amends: {}\n", pending.id)).as_bytes(),
            &here,
        )
        .unwrap();
    let allowed = h.events("dry_run", "allowed");
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0]["lease"], pending.id.as_str());
    assert_eq!(h.service.list(false).unwrap().tickets.len(), 1);
}
