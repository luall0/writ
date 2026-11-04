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
template: feature-branch
limits:
  ttl: 2h
scope:
  repos: [omega-code]
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
    // Closed once; the approver reads the same report.
    refused(
        close(&key, "again"),
        RefusalCode::WrongState,
        "is closed: nothing to close",
    );
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
}
