//! The leases of a source and the end of a lease: `max_active_per_source` at submission and at
//! signing, the other active leases `writ sign` shows, an amendment that keeps its lease's
//! end, and `writ close` with its activity report.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use writ_approval::testing::{START, TestService, TestServiceBuilder};
use writ_approval::{RefusalCode, ServiceError};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::policy::CertIdentity;
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg, PrivateKey};
use writ_platform::testing::FakeClock;
use writ_proto::{CloseRequest, Decision};

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// A feature-branch ticket on omega-code, `branch` its one branch pattern, `more` lines in
/// its `ticket:` section.
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

fn feature(branch: &str) -> String {
    ticket(branch, "")
}

fn from(addr: &str) -> CallerFacts {
    CallerFacts {
        source_addr: Some(addr.parse().unwrap()),
        process_chain: None,
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    test: TestService,
    clock: Arc<FakeClock>,
}

impl std::ops::Deref for Harness {
    type Target = TestService;
    fn deref(&self) -> &TestService {
        &self.test
    }
}

impl Harness {
    fn new(edit: impl FnOnce(TestServiceBuilder) -> TestServiceBuilder) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::at_unix(START));
        let test = edit(TestServiceBuilder::new(POLICY).clock(clock.clone())).build(dir.path());
        Self {
            _dir: dir,
            test,
            clock,
        }
    }

    fn submit(
        &self,
        key: &PrivateKey,
        yaml: &str,
        caller: &CallerFacts,
    ) -> Result<Ticket, ServiceError> {
        let submitted = self
            .service
            .submit(key.public_key(), yaml.as_bytes(), caller)?;
        Ok(Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap())
    }

    fn approve(&self, ticket: &Ticket) -> Result<State, ServiceError> {
        self.service
            .approve(&ticket.id, &self.approval(ticket), &CallerFacts::default())
            .map(|ack| ack.state)
    }

    /// A granted lease from `caller`: its id, session key and certificate.
    fn lease(&self, yaml: &str, caller: &CallerFacts) -> (TicketId, PrivateKey, CertIdentity) {
        let key = generate(KeyKind::Ed25519).unwrap();
        let ticket = self.submit(&key, yaml, caller).unwrap();
        self.approve(&ticket).unwrap();
        let decision = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.service.wait(&ticket.id, key.public_key()))
            .unwrap();
        let Decision::Active { certificate, .. } = decision else {
            panic!("expected an active lease, got {decision:?}");
        };
        let cert = Certificate::from_openssh(&certificate).unwrap();
        let identity = CertIdentity {
            key_id: cert.key_id().to_owned(),
            serial: cert.serial(),
            session_key: cert
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
                .parse()
                .unwrap(),
        };
        (ticket.id, key, identity)
    }

    fn state(&self, id: &TicketId) -> State {
        self.service.show(id).unwrap().state
    }
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
fn max_active_per_source_counts_the_active_leases_of_one_source() {
    let h = Harness::new(|b| b.max_active_per_source(2));
    let here = from("192.0.2.7");
    let (first, first_key, _) = h.lease(&feature("agent/a-*"), &here);
    // One below the limit: accepted and granted.
    let (_, _, _) = h.lease(&feature("agent/b-*"), &here);
    // At the limit: refused at submission, with its code and the limit named.
    refused(
        h.submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/c-*"),
            &here,
        ),
        RefusalCode::TooManyActive,
        "this source (192.0.2.7) already holds 2 active leases (max_active_per_source: 2)",
    );
    assert_eq!(h.events("submit", "denied").len(), 1);
    // Another source has its own slots; an IPv4 address seen as IPv6 is the same source.
    h.lease(&feature("agent/c-*"), &from("192.0.2.8"));
    refused(
        h.submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/c-*"),
            &from("::ffff:192.0.2.7"),
        ),
        RefusalCode::TooManyActive,
        "already holds 2",
    );
    // An amendment adds no lease; a renewal of an active lease replaces it.
    let amendment = ticket("agent/a-*", &format!("  amends: {first}\n"));
    let amendment = h.submit(&first_key, &amendment, &here).unwrap();
    assert_eq!(h.approve(&amendment).unwrap(), State::Applied);
    let renewal = ticket("agent/a-*", &format!("  renews: {first}\n"));
    let renewal = h.submit(&first_key, &renewal, &here).unwrap();
    assert_eq!(h.approve(&renewal).unwrap(), State::Active);
    assert_eq!(h.state(&first), State::Renewed);
    // A lease ending frees its slot.
    h.service
        .revoke(
            &renewal.id,
            &h.revocation(&renewal.id),
            &CallerFacts::default(),
        )
        .unwrap();
    h.lease(&feature("agent/d-*"), &here);
}

#[test]
fn a_lease_granted_meanwhile_makes_the_signature_refused() {
    let h = Harness::new(|b| b.max_active_per_source(1));
    let here = from("192.0.2.7");
    // Two tickets wait while the source holds nothing: both accepted.
    let first = h
        .submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/a-*"),
            &here,
        )
        .unwrap();
    let second = h
        .submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/b-*"),
            &here,
        )
        .unwrap();
    assert_eq!(h.approve(&first).unwrap(), State::Active);
    // The second's slot was taken meanwhile: its signature is refused, and it stays pending.
    refused(
        h.approve(&second),
        RefusalCode::TooManyActive,
        "max_active_per_source: 1",
    );
    assert_eq!(h.state(&second.id), State::Pending);
    let denied = h.events("grant", "denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["ticket"], second.id.as_str());
    // Once the first ends, the same signature is taken.
    h.service
        .revoke(&first.id, &h.revocation(&first.id), &CallerFacts::default())
        .unwrap();
    assert_eq!(h.approve(&second).unwrap(), State::Active);
}

/// The review after M7.6 (A-10): a ticket whose source the store doesn't hold skipped
/// `max_active_per_source` at signing, a missing fact that allowed. Refused now; the same
/// ticket with its source back is granted (the refusal is the missing fact's).
#[test]
fn a_ticket_without_its_source_is_refused_where_the_limit_needs_one() {
    let h = Harness::new(|b| b.max_active_per_source(5));
    let here = from("192.0.2.7");
    let ticket = h
        .submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/a-*"),
            &here,
        )
        .unwrap();
    let set_source = |source: Option<&str>| {
        let conn = rusqlite::Connection::open(h._dir.path().join("leases.db")).unwrap();
        let changed = conn
            .execute(
                "UPDATE tickets SET source = ?1 WHERE id = ?2",
                rusqlite::params![source, ticket.id.as_str()],
            )
            .unwrap();
        assert_eq!(changed, 1, "the fixture changed");
    };
    set_source(None);
    refused(
        h.approve(&ticket),
        RefusalCode::TooManyActive,
        &format!(
            "ticket {} has no source recorded: max_active_per_source can't be checked",
            ticket.id
        ),
    );
    assert_eq!(h.state(&ticket.id), State::Pending);
    set_source(Some("192.0.2.7"));
    assert_eq!(h.approve(&ticket).unwrap(), State::Active);
}

#[test]
fn writ_sign_sees_the_source_s_other_active_leases() {
    let h = Harness::new(|b| {
        b.submissions(writ_approval::SubmissionLimits {
            per_source: 100,
            in_all: 1_000,
        })
    });
    let here = from("192.0.2.7");
    // Eleven leases from the source: one overlapping, ten not.
    h.lease(&feature("agent/oauth-*"), &here);
    for n in 0..10 {
        h.lease(&feature(&format!("agent/other-{n}")), &here);
    }
    // A lease from another source, and one ended: never listed.
    h.lease(&feature("agent/oauth-l*"), &from("192.0.2.8"));
    let (ended, _, _) = h.lease(&feature("agent/oauth-y"), &here);
    h.service
        .revoke(&ended, &h.revocation(&ended), &CallerFacts::default())
        .unwrap();
    let ticket = h
        .submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/oauth-login"),
            &here,
        )
        .unwrap();
    let shown = h.service.show(&ticket.id).unwrap();
    assert_eq!(shown.others.shown.len(), 10);
    assert_eq!(shown.others.more, 1);
    let overlapping: Vec<_> = shown.others.shown.iter().filter(|l| l.overlap).collect();
    assert_eq!(overlapping.len(), 1);
    assert_eq!(overlapping[0].branches, ["agent/oauth-*"]);
    // Listed first, so never the one left out (the test clock gives every id the same time:
    // without that, which ten are shown would be the ids' random parts).
    assert!(shown.others.shown[0].overlap);
    assert!(shown.others.shown.iter().all(|l| l.id != ended));
    // From the other source, only its own lease is there.
    let elsewhere = h
        .submit(
            &generate(KeyKind::Ed25519).unwrap(),
            &feature("agent/oauth-login"),
            &from("192.0.2.8"),
        )
        .unwrap();
    let shown = h.service.show(&elsewhere.id).unwrap();
    assert_eq!(shown.others.shown.len(), 1);
    assert_eq!(shown.others.more, 0);
    assert!(shown.others.shown[0].overlap);
}

#[test]
fn an_amendment_minutes_before_the_end_keeps_the_end() {
    let h = Harness::new(|b| b);
    let here = from("192.0.2.7");
    let (lease, key, _) = h.lease(&feature("agent/a-*"), &here);
    let end = writ_core::units::Timestamp::from_unix(i64::try_from(START).unwrap() + 7200).unwrap();
    // Ten minutes before the end, it asks for four hours: it ends with its lease.
    h.clock.advance(7200 - 600);
    let amendment =
        ticket("agent/a-*", &format!("  amends: {lease}\n")).replace("ttl: 2h", "ttl: 4h");
    let amendment = h.submit(&key, &amendment, &here).unwrap();
    assert_eq!(amendment.limits.expires_at, end);
    assert_eq!(h.approve(&amendment).unwrap(), State::Applied);
    let listed = h.service.list(false).unwrap();
    let entry = listed.tickets.iter().find(|t| t.id == lease).unwrap();
    assert_eq!(entry.expires_at, end);
}

#[test]
fn closing_ends_the_lease_and_reports_what_it_did() {
    let h = Harness::new(|b| b);
    let here = from("192.0.2.7");
    let estimate = ticket("agent/a-*", "  estimate:\n    coding: 30m\n    ci: 15m\n");
    let (lease, key, cert) = h.lease(&estimate, &here);
    h.clock.advance(120);
    // A fetch, and a denied fetch of another repo (a violation counted by its code).
    h.service
        .fetch(
            &cert,
            &CallerFacts::default(),
            &"omega-code".parse().unwrap(),
        )
        .unwrap();
    let denial = h
        .service
        .fetch(
            &cert,
            &CallerFacts::default(),
            &"homelab-scripts".parse().unwrap(),
        )
        .unwrap_err();
    assert_eq!(denial.code, writ_core::policy::DenyCode::Repo);
    // Another session can't close it; an empty summary is refused.
    let close = |key: &PrivateKey, summary: &str| {
        h.service.close(
            &lease,
            key.public_key(),
            &CloseRequest {
                summary: summary.to_owned(),
            },
            &CallerFacts::default(),
        )
    };
    assert!(matches!(
        close(&generate(KeyKind::Ed25519).unwrap(), "done"),
        Err(ServiceError::NotFound(id)) if id == lease
    ));
    refused(
        close(&key, "  "),
        RefusalCode::Summary,
        "the summary is empty",
    );
    refused(
        close(&key, &"x".repeat(4_001)),
        RefusalCode::Summary,
        "the summary is too long (4001, at most 4000)",
    );
    assert_eq!(h.state(&lease), State::Active, "nothing closed yet");
    h.clock.advance(60);
    let report = close(&key, &"x".repeat(4_000)).unwrap();
    assert_eq!(report.state, State::Closed);
    assert_eq!(h.state(&lease), State::Closed);
    assert!(h.service.is_revoked(cert.serial));
    assert_eq!(report.fetches, 1);
    assert_eq!(report.denials.len(), 1);
    assert_eq!(report.denials[0].code, "repo");
    assert_eq!(report.denials[0].count, 1);
    assert_eq!(report.chain.len(), 1);
    assert_eq!(report.used_seconds, 180);
    assert_eq!(report.granted_seconds, 7200);
    assert_eq!(report.estimate.unwrap().coding.unwrap().seconds(), 1800);
    assert_eq!(report.phases.approval_wait_seconds, Some(0));
    assert_eq!(report.phases.coding_seconds, None, "nothing signed");
    assert_eq!(report.summary.as_deref().map(str::len), Some(4_000));
    let line = h.events("close", "done");
    assert_eq!(line.len(), 1);
    assert_eq!(line[0]["lease"], lease.as_str());
    // Closed once: a second close is answered with the same report, its summary the first
    // one, and writes no line (the review after M7.6, A-1); the approver reads it too.
    assert_eq!(close(&key, "again").unwrap(), report);
    assert_eq!(h.events("close", "done").len(), 1, "no second line");
    assert_eq!(h.service.report(&lease).unwrap(), report);
    // An expired lease is closed too, to get its report: it keeps its state.
    let (expired, key, _) = h.lease(&feature("agent/b-*"), &here);
    h.clock.advance(7200);
    let report = h
        .service
        .close(
            &expired,
            key.public_key(),
            &CloseRequest {
                summary: "ran out".to_owned(),
            },
            &CallerFacts::default(),
        )
        .unwrap();
    assert_eq!(report.state, State::Expired);
    assert_eq!(report.used_seconds, 7200);
    assert_eq!(h.events("close", "done")[1]["reason"], "already expired");
    // An ended lease takes one summary too: a second close neither rewrites it nor logs.
    let again = h
        .service
        .close(
            &expired,
            key.public_key(),
            &CloseRequest {
                summary: "rewritten after the approver read it".to_owned(),
            },
            &CallerFacts::default(),
        )
        .unwrap();
    assert_eq!(again.summary.as_deref(), Some("ran out"));
    assert_eq!(again, report);
    assert_eq!(h.events("close", "done").len(), 2);
}

/// The review after M7.6, A-1: `writ close` had no rate, and its denial carried the id the
/// caller chose, so a flood of fresh `wrt_…` ids was never coalesced: one line and one fsync
/// under the state lock each. It counts against the submission rates now, and a denial for a
/// lease the caller doesn't hold names no lease.
#[test]
fn closes_count_against_the_submission_rates_and_a_flood_of_unknown_ids_is_bounded() {
    let h = Harness::new(|b| {
        b.submissions(writ_approval::SubmissionLimits {
            per_source: 10,
            in_all: 1_000,
        })
    });
    let (lease, key, _) = h.lease(&feature("agent/a-*"), &from("192.0.2.9"));
    let flooder = from("192.0.2.7");
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let unknown = |n: u32| -> TicketId { format!("wrt_01JD8X{n:020}").parse().unwrap() };
    let close = |id: &TicketId, key: &PrivateKey, caller: &CallerFacts| {
        h.service.close(
            id,
            key.public_key(),
            &CloseRequest {
                summary: "done".to_owned(),
            },
            caller,
        )
    };
    // At the source's rate: each is refused as unknown, with its own line.
    for n in 0..10 {
        assert!(matches!(
            close(&unknown(n), &stranger, &flooder),
            Err(ServiceError::NotFound(_))
        ));
    }
    // One past it: refused over the rate; a flood after that only counted.
    for n in 10..500 {
        refused(
            close(&unknown(n), &stranger, &flooder),
            RefusalCode::RateLimited,
            "",
        );
    }
    let denied = h.events("close", "denied");
    assert_eq!(denied.len(), 10, "the flood's lines are the rate's bound");
    assert!(
        denied.iter().all(|line| line.get("lease").is_none()),
        "no caller-chosen lease id: {denied:?}"
    );
    assert_eq!(
        denied[0]["reason"],
        format!("no lease {} for this session", unknown(0))
    );
    let over = h.events("submit", "denied");
    assert_eq!(
        over.len(),
        1,
        "one line for the burst over the rate: {over:?}"
    );
    // The holder of a real lease, from its own source, is not held back by the flood.
    let report = close(&lease, &key, &from("192.0.2.9")).unwrap();
    assert_eq!(report.state, State::Closed);
    // Its source's rate is its own: past it, even its own close waits.
    h.clock.advance(60);
    let quiet = from("192.0.2.10");
    for _ in 0..10 {
        close(&lease, &key, &quiet).unwrap();
    }
    refused(close(&lease, &key, &quiet), RefusalCode::RateLimited, "");
}

/// The review after M7.6 (A-2): with the CA on a device, a certificate signed under the state
/// lock held every revocation, sweep and decision behind it. It is signed with no lock held:
/// a revocation of another lease completes while it waits, and what changed meanwhile is
/// decided again before the lease is recorded (a refusal by another approver: discarded, the
/// reason logged; a CA rotated: signed again by the new one).
#[test]
fn a_certificate_is_signed_outside_the_state_lock_and_decided_again_before_its_lease() {
    let h = Harness::new(|b| b);
    let caller = from("10.0.0.1");
    let (other, _, _) = h.lease(&feature("agent/a-*"), &caller);
    let held = |branch: &str| {
        let key = generate(KeyKind::Ed25519).unwrap();
        let ticket = h.submit(&key, &feature(branch), &caller).unwrap();
        (ticket, key)
    };

    // A revocation of another lease completes while a certificate waits at the CA.
    let (ticket, _) = held("agent/b-*");
    h.ca_gate.close();
    std::thread::scope(|scope| {
        let approving = scope.spawn(|| h.approve(&ticket));
        h.ca_gate.wait_entered();
        h.service
            .revoke(&other, &h.revocation(&other), &CallerFacts::default())
            .unwrap();
        assert_eq!(h.state(&other), State::Revoked);
        // Meanwhile the waiting ticket is refused: its certificate is discarded.
        h.service
            .refuse(
                &ticket.id,
                &h.refusal(&ticket.id, "not now"),
                &CallerFacts::default(),
            )
            .unwrap();
        h.ca_gate.open();
        refused(
            approving.join().unwrap(),
            RefusalCode::WrongState,
            &format!(
                "ticket {} became refused while its certificate was signed: the certificate is \
                 discarded",
                ticket.id
            ),
        );
    });
    assert_eq!(h.state(&ticket.id), State::Refused);
    let denied = h.events("grant", "denied");
    assert!(
        denied.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains("became refused while its certificate was signed"),
        "{denied:?}"
    );

    // The CA rotated while a certificate waits: the lease gets one from the new CA.
    let (ticket, key) = held("agent/c-*");
    let rotation = {
        let replaces = writ_crypto::keys::fingerprint(h.ca_key.public_key())
            .parse()
            .unwrap();
        let document = writ_core::signed::CaRotation::new(
            h.daemon.clone(),
            replaces,
            "software".to_owned().try_into().unwrap(),
        )
        .canonical_bytes()
        .unwrap();
        let request = writ_proto::CaRequest {
            signature: writ_crypto::sshsig::sign(
                &h.approver,
                writ_core::lease::APPROVAL_NAMESPACE,
                &document,
            )
            .unwrap(),
            document: String::from_utf8(document).unwrap(),
        };
        h.service
            .check_ca(&request, &CallerFacts::default())
            .unwrap()
    };
    h.ca_gate.close();
    let rotated = generate(KeyKind::Ed25519).unwrap();
    std::thread::scope(|scope| {
        let approving = scope.spawn(|| h.approve(&ticket));
        h.ca_gate.wait_entered();
        h.service
            .replace_ca(
                &rotation,
                Arc::new(writ_approval::testing::GatedCa::new(
                    &rotated,
                    Arc::new(writ_approval::testing::CaGate::default()),
                )),
            )
            .unwrap();
        h.ca_gate.open();
        assert_eq!(approving.join().unwrap().unwrap(), State::Active);
    });
    let decision = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(h.service.wait(&ticket.id, key.public_key()))
        .unwrap();
    let Decision::Active { certificate, .. } = decision else {
        panic!("expected an active lease, got {decision:?}");
    };
    let cert = Certificate::from_openssh(&certificate).unwrap();
    assert_eq!(cert.signature_key(), rotated.public_key().key_data());
}

/// The review after M7.6 (A-9): an approver's revocation or an agent's close that the store
/// couldn't record barred the certificate in memory only: after a restart the lease was
/// active again. Each is now retried by the sweep, like the daemon's own revocations.
#[test]
fn a_revocation_or_close_the_store_can_t_record_is_recorded_by_the_next_sweep() {
    let h = Harness::new(|b| b);
    let caller = from("10.0.0.1");
    let (revoked, _, _) = h.lease(&feature("agent/r-*"), &caller);
    let (closed, key, _) = h.lease(&feature("agent/c-*"), &caller);
    h.store_breaker.fail_state_changes(1);
    // any error: the store the test broke answers an internal error; what is checked is what
    // the sweep does next.
    assert!(
        h.service
            .revoke(&revoked, &h.revocation(&revoked), &CallerFacts::default())
            .is_err()
    );
    let request = CloseRequest {
        summary: "done".to_owned(),
    };
    // The close's own sweep tries the revocation again (it fails too), then the close.
    h.store_breaker.fail_state_changes(2);
    // any error: as above.
    assert!(
        h.service
            .close(&closed, key.public_key(), &request, &caller)
            .is_err()
    );
    // The next request's sweep records both.
    assert_eq!(h.state(&revoked), State::Revoked);
    assert_eq!(h.state(&closed), State::Revoked);
    let revokes = h.events("revoke", "done");
    assert!(
        revokes.iter().any(|e| e["lease"] == closed.as_str()
            && e["reason"] == "closed by its agent (the close couldn't be recorded)"),
        "{revokes:?}"
    );
}
