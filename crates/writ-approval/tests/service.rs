//! The approval service on the platform fakes: submission, approval (and every approval that
//! must be refused), narrowing, refusal and revision, revocation, expiry, session binding,
//! and the audit log of all of it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use writ_approval::testing::{START, TestService, TestServiceBuilder, sign_approval_in};
use writ_approval::{RefusalCode, ServiceError};
use writ_core::caller::{CallerFacts, ProcessRef};
use writ_core::canonical::Canonical;
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::names::TicketId;
use writ_core::policy::{CertIdentity, DenyCode};
use writ_core::signed::Refusal;
use writ_core::ticket::Operation;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::ca::validate_user_certificate;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg, PrivateKey};
use writ_crypto::sshsig;
use writ_platform::testing::{FakeClock, FakeWatcher, RecordingNotifier, WAIT_LIMIT, eventually};
use writ_proto::{ApproveRequest, Decision, Decisions, RefuseRequest, Relation, RevokeRequest};
use writ_store::looks_secret;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// The terms of `omega-code` in a ticket.
fn om(ticket: &Ticket) -> &writ_core::ticket::RepoTerms {
    ticket.repos.get(&"omega-code".parse().unwrap()).unwrap()
}

/// The terms of `omega-code` in a ticket (mutable, for a test to change them).
fn omega(ticket: &mut Ticket) -> &mut writ_core::ticket::RepoTerms {
    ticket
        .repos
        .get_mut(&"omega-code".parse().unwrap())
        .unwrap()
}

const REQUEST: &str = r#"
repos:
  omega-code:
    template: feature-branch
    operations: [fetch, commit_sign, push]
    branches: ["agent/oauth-*"]
    limits:
      max_signatures: 30
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
  plan: [Add the callback route, Tests]
limits:
  ttl: 2h
"#;

struct Harness {
    dir: tempfile::TempDir,
    test: TestService,
    clock: Arc<FakeClock>,
    notifier: RecordingNotifier,
    watcher: FakeWatcher,
}

/// The service, the approver, the CA fingerprint and the audit log, as in every crate's tests.
impl std::ops::Deref for Harness {
    type Target = TestService;

    fn deref(&self) -> &TestService {
        &self.test
    }
}

fn facts() -> CallerFacts {
    CallerFacts {
        source_addr: Some("192.0.2.7".parse().unwrap()),
        process_chain: None,
    }
}

impl Harness {
    fn new(decisions: Decisions) -> Self {
        Self::with(decisions, FakeWatcher::new(), 20)
    }

    fn with(decisions: Decisions, watcher: FakeWatcher, max_pending: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::at_unix(START));
        let notifier = RecordingNotifier::new();
        let test = TestServiceBuilder::new(POLICY)
            .decisions(decisions)
            .max_pending(max_pending)
            .watcher(Arc::new(watcher.clone()))
            .notifier(Arc::new(notifier.clone()))
            .clock(clock.clone())
            .build(dir.path());
        Self {
            dir,
            test,
            clock,
            notifier,
            watcher,
        }
    }

    fn events(&self, event: &str, result: &str) -> usize {
        self.test.events(event, result).len()
    }

    /// Submits a request with a fresh session key.
    fn submit(&self, yaml: &str) -> (Ticket, PrivateKey) {
        let key = generate(KeyKind::Ed25519).unwrap();
        let submitted = self
            .service
            .submit(key.public_key(), yaml.as_bytes(), &facts())
            .unwrap();
        (
            Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap(),
            key,
        )
    }

    fn signed(&self, ticket: &Ticket) -> ApproveRequest {
        self.approval(ticket)
    }

    fn approve(&self, ticket: &Ticket) -> Result<State, ServiceError> {
        self.service
            .approve(&ticket.id, &self.signed(ticket), &facts())
            .map(|ack| ack.state)
    }

    fn wait(&self, id: &TicketId, key: &PrivateKey) -> Decision {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.service.wait(id, key.public_key()))
            .unwrap()
    }

    fn sign_doc(&self, bytes: &[u8]) -> String {
        sshsig::sign(&self.approver, APPROVAL_NAMESPACE, bytes).unwrap()
    }

    fn refuse_signed(&self, id: &TicketId, feedback: &str) -> Result<State, ServiceError> {
        let request = self.refusal(id, feedback);
        self.service.refuse(id, &request, &facts()).map(|a| a.state)
    }

    fn revoke_signed(&self, id: &TicketId) -> Result<State, ServiceError> {
        let request = self.revocation(id);
        self.service.revoke(id, &request, &facts()).map(|a| a.state)
    }

    /// An active lease: the ticket, the session key and the certificate.
    fn lease(&self) -> (Ticket, PrivateKey, Certificate) {
        let (ticket, key) = self.submit(REQUEST);
        assert_eq!(self.approve(&ticket).unwrap(), State::Active);
        let Decision::Active { certificate, .. } = self.wait(&ticket.id, &key) else {
            panic!("expected an active lease");
        };
        (
            ticket,
            key,
            Certificate::from_openssh(&certificate).unwrap(),
        )
    }
}

/// Turned down with exactly this code, and a message containing `expected`.
fn refused_as<T: std::fmt::Debug>(
    result: Result<T, ServiceError>,
    code: RefusalCode,
    expected: &str,
) {
    match result {
        Err(ServiceError::Refused {
            code: found,
            message,
            ..
        }) => {
            assert_eq!(found, code, "{message}");
            assert!(
                message.contains(expected),
                "{expected:?} not in {message:?}"
            );
        }
        other => panic!("expected a refusal with {expected:?}, got {other:?}"),
    }
}

/// Failed because the audit log can't be written, and for no other reason.
fn audit_log_down<T: std::fmt::Debug>(result: Result<T, ServiceError>) {
    assert!(
        matches!(result, Err(ServiceError::AuditLog(_))),
        "expected an audit log failure, got {result:?}"
    );
}

fn identity(cert: &Certificate) -> CertIdentity {
    CertIdentity {
        key_id: cert.key_id().to_owned(),
        serial: cert.serial(),
        session_key: cert
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            .parse()
            .unwrap(),
    }
}

#[test]
fn a_ticket_outside_every_template_is_rejected_before_reaching_the_approver() {
    let h = Harness::new(Decisions::Signed);
    let key = generate(KeyKind::Ed25519).unwrap();
    let outside = REQUEST.replace("agent/oauth-*", "main");
    let error = h
        .service
        .submit(key.public_key(), outside.as_bytes(), &facts())
        .unwrap_err();
    assert!(
        matches!(&error, ServiceError::Refused { reasons, .. }
            if reasons.iter().any(|r| r.contains("branch main"))),
        "{error:?}"
    );
    let unparsable = h
        .service
        .submit(key.public_key(), b"scope: {repos: [x]", &facts())
        .unwrap_err();
    assert!(
        matches!(&unparsable, ServiceError::Refused { message, .. } if message == "ticket rejected"),
        "{unparsable:?}"
    );
    assert!(h.service.list(true).unwrap().tickets.is_empty());
    assert_eq!(h.events("submit", "denied"), 2);
    // Notifications are delivered in order: if a rejected ticket had queued one, it would
    // arrive before the valid ticket's.
    let (valid, _) = h.submit(REQUEST);
    let delivered = h.notifier.wait_for(1);
    assert_eq!(delivered.len(), 1, "rejected tickets never notify");
    assert!(delivered[0].message.contains(valid.id.as_str()));
}

#[test]
fn a_signed_ticket_becomes_a_lease_with_a_certificate_until_it_expires() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    assert_eq!(ticket.text.revision, 1);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);
    let notification = &h.notifier.wait_for(1)[0];
    assert_eq!(notification.title, "Ticket waiting");
    assert!(notification.message.contains(ticket.id.as_str()));
    // No agent-written text goes to a notification sink.
    for text in [&notification.title, &notification.message] {
        assert!(!text.contains("Add OAuth login"), "{text}");
    }

    assert_eq!(h.approve(&ticket).unwrap(), State::Active);
    let Decision::Active {
        lease,
        certificate,
        signing_key,
        signing_certificate,
    } = h.wait(&ticket.id, &key)
    else {
        panic!("expected an active lease");
    };
    assert_eq!(Ticket::from_canonical(lease.as_bytes()).unwrap(), ticket);
    // The public key commits are signed with, for the agent's git config.
    let expected = h.signing_key("agent-ed25519-01").to_openssh().unwrap();
    assert_eq!(signing_key.as_deref(), Some(expected.as_str()));
    // An SSH key: no OpenPGP certificate.
    assert_eq!(signing_certificate, None);
    let cert = Certificate::from_openssh(&certificate).unwrap();
    assert_eq!(cert.key_id(), ticket.id.as_str());
    assert_eq!(cert.public_key(), key.public_key().key_data());
    assert_eq!(
        cert.valid_before(),
        u64::try_from(ticket.limits.expires_at.unix()).unwrap()
    );
    validate_user_certificate(
        &cert,
        std::slice::from_ref(&h.ca_fingerprint),
        |_| false,
        "git",
        START,
    )
    .unwrap();
    let lease = h
        .service
        .authorize(&identity(&cert), &facts(), None)
        .unwrap();
    assert_eq!(lease.id, ticket.id);
    h.service
        .authorize(&identity(&cert), &facts(), Some(Operation::CommitSign))
        .unwrap();
    assert_eq!(h.events("grant", "allowed"), 1);
    assert_eq!(h.events("connect", "allowed"), 1);
    assert_eq!(h.events("sign", "allowed"), 1);
}

#[test]
fn approvals_by_other_keys_namespaces_or_bytes_and_widenings_are_refused() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key) = h.submit(REQUEST);
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let mut narrowed = ticket.clone();
    omega(&mut narrowed).limits.max_signatures = 5;
    let mut widened = ticket.clone();
    omega(&mut widened).limits.max_signatures = 40;
    let mut other_bytes = h.signed(&ticket);
    other_bytes.signed = String::from_utf8(narrowed.canonical_bytes().unwrap()).unwrap();
    let mut not_canonical = h.signed(&ticket);
    not_canonical.signed = not_canonical.signed.replacen(':', ": ", 1);

    let cases = [
        (
            "a key not in approvers",
            sign_approval_in(&stranger, &ticket, APPROVAL_NAMESPACE),
            RefusalCode::Signature,
            "not in approvers",
        ),
        (
            "another namespace",
            sign_approval_in(&h.approver, &ticket, "git"),
            RefusalCode::Signature,
            "namespace",
        ),
        (
            "other bytes",
            other_bytes,
            RefusalCode::Signature,
            "does not match",
        ),
        (
            "a widening",
            h.signed(&widened),
            RefusalCode::Lifecycle,
            "max_signatures raised",
        ),
        (
            "non-canonical bytes",
            not_canonical,
            RefusalCode::Signature,
            "canonical",
        ),
    ];
    for (case, request, code, expected) in cases {
        let error = h.service.approve(&ticket.id, &request, &facts());
        refused_as(error, code, expected);
        assert_eq!(
            h.service.show(&ticket.id).unwrap().state,
            State::Pending,
            "{case}"
        );
    }
    assert_eq!(h.events("grant", "denied"), 5);
    // A key that never signed anything isn't an approval either: nothing is active.
    assert!(
        h.service
            .list(false)
            .unwrap()
            .tickets
            .iter()
            .all(|t| t.state == State::Pending)
    );
}

#[test]
fn a_narrowed_approval_is_the_lease_and_bounds_the_certificate() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    let mut narrowed = ticket.clone();
    omega(&mut narrowed).operations.remove(&Operation::Push);
    narrowed.limits.expires_at =
        Timestamp::from_unix(i64::try_from(START).unwrap() + 1800).unwrap();
    omega(&mut narrowed).limits.max_signatures = 5;
    h.service
        .approve(&ticket.id, &h.signed(&narrowed), &facts())
        .unwrap();
    let Decision::Active {
        lease, certificate, ..
    } = h.wait(&ticket.id, &key)
    else {
        panic!("expected an active lease");
    };
    assert_eq!(Ticket::from_canonical(lease.as_bytes()).unwrap(), narrowed);
    let cert = Certificate::from_openssh(&certificate).unwrap();
    assert_eq!(cert.valid_before(), START + 1800);
    let denial = h
        .service
        .authorize(&identity(&cert), &facts(), Some(Operation::Push))
        .unwrap_err();
    assert_eq!(denial.code, DenyCode::Operation);
    assert_eq!(h.events("push", "denied"), 1);
}

#[test]
fn a_refusal_reaches_the_agent_and_the_next_revision_shows_it() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    let unsigned = RefuseRequest {
        feedback: "no".into(),
        signature: None,
    };
    refused_as(
        h.service.refuse(&ticket.id, &unsigned, &facts()),
        RefusalCode::Signature,
        "refusal not accepted: this daemon requires an approver signature",
    );
    let forged = RefuseRequest {
        feedback: "different words".into(),
        signature: Some(
            h.sign_doc(
                &Refusal::new(ticket.id.clone(), "no".into())
                    .canonical_bytes()
                    .unwrap(),
            ),
        ),
    };
    refused_as(
        h.service.refuse(&ticket.id, &forged, &facts()),
        RefusalCode::Signature,
        "refusal not accepted: the signature does not match the signed bytes",
    );
    assert_eq!(h.events("refuse", "denied"), 2);

    assert_eq!(
        h.refuse_signed(&ticket.id, "Don't touch billing").unwrap(),
        State::Refused
    );
    assert_eq!(
        h.wait(&ticket.id, &key),
        Decision::Refused {
            feedback: "Don't touch billing".into(),
            signed_by: Some(
                h.approver
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string()
                    .parse()
                    .unwrap()
            ),
        }
    );
    refused_as(
        h.approve(&ticket),
        RefusalCode::WrongState,
        "is refused, not pending",
    );

    let revision = REQUEST.replace(
        "  plan: [Add the callback route, Tests]",
        &format!(
            "  plan: [Add the callback route, Tests]\n  revises: {}",
            ticket.id
        ),
    );
    // From another session: rejected, and the feedback stays with the session it was for.
    let other = generate(KeyKind::Ed25519).unwrap();
    match h
        .service
        .submit(other.public_key(), revision.as_bytes(), &facts())
    {
        Err(ServiceError::Refused { reasons, .. }) => {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.contains("(revises) does not exist")),
                "{reasons:?}"
            );
            assert!(
                !reasons.iter().any(|r| r.contains("billing")),
                "{reasons:?}"
            );
        }
        other => panic!("a revision from another session was accepted: {other:?}"),
    }
    // From the session that submitted the refused ticket.
    let submitted = h
        .service
        .submit(key.public_key(), revision.as_bytes(), &facts())
        .unwrap();
    let revised = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    assert_eq!(revised.text.revision, 2);
    assert_eq!(
        revised.text.previous_feedback.as_deref(),
        Some("Don't touch billing")
    );
    let shown = h.service.show(&revised.id).unwrap();
    let previous = shown.previous.unwrap();
    assert_eq!(previous.relation, Relation::Revises);
    assert_eq!(
        Ticket::from_canonical(previous.canonical.as_bytes())
            .unwrap()
            .id,
        ticket.id
    );
    assert_eq!(h.events("refuse", "done"), 1);
}

#[test]
fn a_revocation_puts_the_certificate_on_the_deny_list_and_announces_it() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    let mut revocations = h.service.subscribe_revocations();
    refused_as(
        h.service
            .revoke(&ticket.id, &RevokeRequest::default(), &facts()),
        RefusalCode::Signature,
        "revocation not accepted: this daemon requires an approver signature",
    );
    assert_eq!(h.revoke_signed(&ticket.id).unwrap(), State::Revoked);
    assert_eq!(revocations.try_recv().unwrap(), cert.serial());
    assert!(h.service.is_revoked(cert.serial()));
    let denial = h
        .service
        .authorize(&identity(&cert), &facts(), None)
        .unwrap_err();
    assert_eq!(denial.code, DenyCode::NotActive);
    refused_as(
        h.revoke_signed(&ticket.id),
        RefusalCode::WrongState,
        "nothing to revoke",
    );
    assert_eq!(h.events("revoke", "done"), 1);
    assert_eq!(h.events("revoke", "denied"), 2);
    assert_eq!(h.events("connect", "denied"), 1);
}

#[test]
fn open_decisions_need_no_signature_but_check_one_given() {
    let h = Harness::new(Decisions::Open);
    let (pending, key) = h.submit(REQUEST);
    let bad = RefuseRequest {
        feedback: "no".into(),
        signature: Some(
            sshsig::sign(
                &generate(KeyKind::Ed25519).unwrap(),
                APPROVAL_NAMESPACE,
                b"x",
            )
            .unwrap(),
        ),
    };
    refused_as(
        h.service.refuse(&pending.id, &bad, &facts()),
        RefusalCode::Signature,
        "refusal not accepted: the signature",
    );
    let open = RefuseRequest {
        feedback: "no".into(),
        signature: None,
    };
    h.service.refuse(&pending.id, &open, &facts()).unwrap();
    assert_eq!(
        h.wait(&pending.id, &key),
        // `decisions: open`, no signature: the agent is told nobody signed it.
        Decision::Refused {
            feedback: "no".into(),
            signed_by: None,
        }
    );
    let (ticket, _, cert) = h.lease();
    h.service
        .revoke(&ticket.id, &RevokeRequest::default(), &facts())
        .unwrap();
    assert!(h.service.is_revoked(cert.serial()));
    // An approval is always signed, whatever `decisions` says.
    let (other, _) = h.submit(REQUEST);
    let unsigned = ApproveRequest {
        signed: String::from_utf8(other.canonical_bytes().unwrap()).unwrap(),
        signature: String::new(),
    };
    refused_as(
        h.service.approve(&other.id, &unsigned, &facts()),
        RefusalCode::Signature,
        "approval refused: unreadable signature",
    );
}

#[test]
fn expiry_ends_pending_tickets_and_leases() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    let (pending, pending_key) = h.submit(REQUEST);
    let mut revocations = h.service.subscribe_revocations();
    h.clock.advance(2 * 3600);
    h.service.sweep();
    assert_eq!(revocations.try_recv().unwrap(), cert.serial());
    assert!(h.service.is_revoked(cert.serial()));
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Expired);
    assert_eq!(h.wait(&pending.id, &pending_key), Decision::Expired);
    refused_as(
        h.approve(&pending),
        RefusalCode::WrongState,
        "is expired, not pending",
    );
    assert_eq!(h.events("expire", "done"), 2);
}

#[test]
fn only_the_submitting_session_can_wait() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key) = h.submit(REQUEST);
    let other = generate(KeyKind::Ed25519).unwrap();
    let error = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(h.service.wait(&ticket.id, other.public_key()))
        .unwrap_err();
    assert!(
        matches!(&error, ServiceError::NotFound(id) if id == &ticket.id),
        "{error:?}"
    );
}

#[test]
fn waiting_returns_when_the_approver_decides() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let service = h.service.clone();
    let id = ticket.id.clone();
    let public = key.public_key().clone();
    let mut waiting = runtime.spawn(async move { service.wait(&id, &public).await });
    // Pending: no decision to return, however long it waits (the bound only stops looking).
    let early = runtime
        .block_on(async { tokio::time::timeout(Duration::from_millis(50), &mut waiting).await });
    // any error: a timeout's Elapsed is the only error `timeout` returns.
    assert!(early.is_err(), "returned before any decision: {early:?}");
    h.approve(&ticket).unwrap();
    // Woken by the decision itself, well before the 30 s re-check.
    let decision = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), waiting).await })
        .expect("the decision wakes the waiting client")
        .unwrap()
        .unwrap();
    assert!(matches!(decision, Decision::Active { .. }));
}

const BOUND: &str = r#"
caller:
  descends_from: { executable: /usr/local/bin/harness, pid: 4242, generation: 7 }
repos:
  omega-code:
    template: feature-branch
    operations: [fetch]
ticket:
  title: Bound to a session
  task: Read only
"#;

#[test]
fn a_lease_bound_to_a_session_needs_a_watcher_and_ends_with_it() {
    let unwatched = Harness::with(Decisions::Signed, FakeWatcher::unsupported(), 20);
    let (ticket, _) = unwatched.submit(BOUND);
    let error = unwatched.approve(&ticket).unwrap_err();
    assert!(
        matches!(&error, ServiceError::Refused { code: RefusalCode::Session, message, .. } if message.contains("can't watch")),
        "{error:?}"
    );

    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(BOUND);
    h.approve(&ticket).unwrap();
    assert_eq!(h.watcher.active_watches(), 1);
    let Decision::Active { certificate, .. } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    let cert = Certificate::from_openssh(&certificate).unwrap();
    // Over the network there is no process chain: the lease can't be used.
    let denial = h
        .service
        .authorize(&identity(&cert), &facts(), None)
        .unwrap_err();
    assert_eq!(denial.code, DenyCode::Caller);
    let inside = CallerFacts {
        source_addr: None,
        process_chain: Some(vec![ProcessRef {
            pid: 4242,
            generation: 7,
            executable: PathBuf::from("/usr/local/bin/harness"),
            code_identity: None,
        }]),
    };
    h.service
        .authorize(&identity(&cert), &inside, None)
        .unwrap();

    let mut revocations = h.service.subscribe_revocations();
    h.watcher.exit(4242, 7);
    // The revocation is announced once done: wait for that signal, not for time to pass.
    let revoked = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { tokio::time::timeout(WAIT_LIMIT, revocations.recv()).await })
        .expect("the ended session's lease is revoked")
        .unwrap();
    assert_eq!(revoked, cert.serial());
    assert!(h.service.is_revoked(cert.serial()));
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Revoked);
}

/// Waits for the next revocation announced by `service` (the signal that the lease's state
/// change was made).
fn next_revocation(revocations: &mut tokio::sync::broadcast::Receiver<u64>) -> u64 {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { tokio::time::timeout(WAIT_LIMIT, revocations.recv()).await })
        .expect("a revocation is announced")
        .unwrap()
}

/// A lease bound to the session process 4242 (generation 7), and its certificate's serial.
fn bound_lease(h: &Harness) -> (Ticket, u64) {
    let (ticket, key) = h.submit(BOUND);
    h.approve(&ticket).unwrap();
    let Decision::Active { certificate, .. } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    let serial = Certificate::from_openssh(&certificate).unwrap().serial();
    (ticket, serial)
}

/// The second review after M5.5 (R4): the retry of the revocations the store couldn't record
/// took them all, and a store error part way dropped the ones not reached yet: those leases
/// stayed active in the store (their certificates refused only until a restart).
#[test]
fn revocations_left_unrecorded_survive_a_retry_that_fails_part_way() {
    let h = Harness::new(Decisions::Signed);
    let bound = |pid: u32| {
        let (ticket, key) = h.submit(&BOUND.replace("pid: 4242", &format!("pid: {pid}")));
        h.approve(&ticket).unwrap();
        let Decision::Active { certificate, .. } = h.wait(&ticket.id, &key) else {
            panic!("expected an active lease");
        };
        (
            ticket,
            Certificate::from_openssh(&certificate).unwrap().serial(),
        )
    };
    let (first, first_serial) = bound(4242);
    let (second, second_serial) = bound(4243);
    // Both sessions end; the store fails both revocations' lookups, so neither is recorded
    // (their certificates are refused all the same).
    h.store_breaker.fail_lease_lookups_after(0, 2);
    let mut revocations = h.service.subscribe_revocations();
    h.watcher.exit(4242, 7);
    h.watcher.exit(4243, 7);
    // A lease is announced once its recording was tried: both tried, then the log mended.
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < 2 {
        let serial = next_revocation(&mut revocations);
        assert!([first_serial, second_serial].contains(&serial), "{serial}");
        seen.insert(serial);
    }
    assert!(h.service.is_revoked(first_serial) && h.service.is_revoked(second_serial));
    // The next request's retry fails at its first lookup, whichever lease that is.
    h.store_breaker.fail_lease_lookup_after(0);
    let shown = h.service.show(&first.id);
    assert!(
        matches!(shown, Err(ServiceError::Internal(_))),
        "the retry's store error fails the request: {:?}",
        shown.map(|s| s.state)
    );
    // The request after records both: the one not reached was kept.
    for ticket in [&first, &second] {
        assert_eq!(
            h.service.show(&ticket.id).unwrap().state,
            State::Revoked,
            "{}",
            ticket.id
        );
    }
    assert_eq!(h.events("revoke", "done"), 2);
}

#[test]
fn a_restart_watches_bound_sessions_again() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, serial) = bound_lease(&h);
    let watcher = FakeWatcher::new();
    let restarted = TestServiceBuilder::new(POLICY)
        .clock(h.clock.clone())
        .watcher(Arc::new(watcher.clone()))
        .build(h.dir.path());
    assert_eq!(watcher.active_watches(), 1, "watched again");
    assert!(!restarted.service.is_revoked(serial));

    let mut revocations = restarted.service.subscribe_revocations();
    watcher.exit(4242, 7);
    assert_eq!(next_revocation(&mut revocations), serial);
    assert!(restarted.service.is_revoked(serial));
    assert_eq!(
        restarted.service.show(&ticket.id).unwrap().state,
        State::Revoked
    );
    let revoked = restarted.events("revoke", "done");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0]["reason"], "the session's process ended");
}

#[test]
fn a_session_that_ended_while_the_daemon_was_down_revokes_at_restart() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, serial) = bound_lease(&h);
    let watcher = FakeWatcher::new();
    watcher.exit(4242, 7);
    let restarted = TestServiceBuilder::new(POLICY)
        .clock(h.clock.clone())
        .watcher(Arc::new(watcher.clone()))
        .build(h.dir.path());
    // The watcher calls back at once, on its own thread, while the service is being built:
    // there is nothing to subscribe to in time, so the revocation is polled for.
    eventually("the lease of the ended session is revoked", || {
        restarted.service.show(&ticket.id).unwrap().state == State::Revoked
    });
    assert!(restarted.service.is_revoked(serial));
    assert_eq!(restarted.events("revoke", "done").len(), 1);
}

#[test]
fn a_restart_without_a_watcher_revokes_bound_leases() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, serial) = bound_lease(&h);
    let restarted = TestServiceBuilder::new(POLICY)
        .clock(h.clock.clone())
        .watcher(Arc::new(FakeWatcher::unsupported()))
        .build(h.dir.path());
    assert!(restarted.service.is_revoked(serial));
    assert_eq!(
        restarted.service.show(&ticket.id).unwrap().state,
        State::Revoked
    );
    let revoked = restarted.events("revoke", "done");
    assert_eq!(revoked.len(), 1);
    assert!(
        revoked[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("after a restart: the lease is bound to a session the daemon can't watch"),
        "{:?}",
        revoked[0]
    );
}

#[test]
fn an_ended_session_revokes_even_with_the_audit_log_down() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, serial) = bound_lease(&h);
    let mut revocations = h.service.subscribe_revocations();
    h.audit_breaker.set_broken(true);
    h.watcher.exit(4242, 7);
    assert_eq!(next_revocation(&mut revocations), serial);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Revoked);
    h.audit_breaker.set_broken(false);
    h.service.sweep();
    assert_eq!(h.events("revoke", "done"), 1);
}

#[test]
fn too_many_waiting_tickets_are_turned_away() {
    let h = Harness::with(Decisions::Signed, FakeWatcher::new(), 2);
    h.submit(REQUEST);
    h.submit(REQUEST);
    let key = generate(KeyKind::Ed25519).unwrap();
    let error = h
        .service
        .submit(key.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap_err();
    assert!(
        matches!(&error, ServiceError::Refused { code: RefusalCode::TooManyPending, message, .. } if message.contains("already waiting")),
        "{error:?}"
    );
}

fn from(source: &str) -> CallerFacts {
    CallerFacts {
        source_addr: Some(source.parse().unwrap()),
        process_chain: None,
    }
}

#[test]
fn one_session_has_at_most_two_tickets_waiting() {
    let h = Harness::new(Decisions::Signed);
    let key = generate(KeyKind::Ed25519).unwrap();
    let submit = |source: &str| {
        h.service
            .submit(key.public_key(), REQUEST.as_bytes(), &from(source))
    };
    submit("192.0.2.1").unwrap();
    submit("192.0.2.2").unwrap();
    // The same key from another address is the same session.
    refused_as(
        submit("192.0.2.3"),
        RefusalCode::TooManyPending,
        "this session already has 2 tickets waiting for the approver",
    );
    // Another session isn't held back.
    let other = generate(KeyKind::Ed25519).unwrap();
    h.service
        .submit(other.public_key(), REQUEST.as_bytes(), &from("192.0.2.3"))
        .unwrap();
}

#[test]
fn one_address_submits_at_most_ten_tickets_a_minute() {
    let h = Harness::with(Decisions::Signed, FakeWatcher::new(), 100);
    let submit = |source: &str| {
        let key = generate(KeyKind::Ed25519).unwrap();
        h.service
            .submit(key.public_key(), REQUEST.as_bytes(), &from(source))
    };
    // Rejected tickets count too: the rate bounds what one address writes to the audit log.
    let bad = generate(KeyKind::Ed25519).unwrap();
    refused_as(
        h.service
            .submit(bad.public_key(), b"not: [yaml", &from("192.0.2.1")),
        RefusalCode::Rejected,
        "ticket rejected",
    );
    for _ in 1..10 {
        submit("192.0.2.1").unwrap();
    }
    let lines = h.events("submit", "denied");
    for _ in 0..3 {
        refused_as(
            submit("192.0.2.1"),
            RefusalCode::RateLimited,
            "more than 10 submissions a minute from this address; try again later",
        );
    }
    assert_eq!(
        h.events("submit", "denied"),
        lines + 1,
        "one line for the burst"
    );
    // Another address has its own rate.
    submit("192.0.2.2").unwrap();
    // A minute after the first, one slot frees; the burst's count is logged with it.
    h.clock.advance(59);
    refused_as(
        submit("192.0.2.1"),
        RefusalCode::RateLimited,
        "more than 10 submissions a minute",
    );
    h.clock.advance(1);
    submit("192.0.2.1").unwrap();
    let denied = h.test.events("submit", "denied");
    assert_eq!(
        denied.last().unwrap()["reason"],
        "3 more submissions from this address were refused over the rate"
    );
}

#[test]
fn a_burst_s_refusals_are_counted_even_when_its_source_goes_quiet() {
    let h = Harness::with(Decisions::Signed, FakeWatcher::new(), 100);
    let submit = |source: &str| {
        let key = generate(KeyKind::Ed25519).unwrap();
        h.service
            .submit(key.public_key(), REQUEST.as_bytes(), &from(source))
    };
    for _ in 0..10 {
        submit("192.0.2.1").unwrap();
    }
    for _ in 0..4 {
        refused_as(
            submit("192.0.2.1"),
            RefusalCode::RateLimited,
            "more than 10 submissions a minute from this address",
        );
    }
    let counted = "3 more submissions from this address were refused over the rate";
    let count_lines = || {
        h.test
            .events("submit", "denied")
            .into_iter()
            .filter(|e| e["reason"] == counted)
            .collect::<Vec<_>>()
    };
    // The source never submits again: the sweep writes the count once its window is over.
    h.clock.advance(59);
    h.service.sweep();
    assert!(count_lines().is_empty(), "the window isn't over yet");
    h.clock.advance(1);
    h.service.sweep();
    let lines = count_lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["source_addr"], "192.0.2.1");
    h.service.sweep();
    assert_eq!(count_lines().len(), 1, "written once");
}

#[test]
fn all_sources_together_submit_at_most_the_operator_s_rate() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(START));
    let test = TestServiceBuilder::new(POLICY)
        .max_pending(100)
        .submissions(writ_approval::SubmissionLimits {
            per_source: 10,
            in_all: 3,
        })
        .clock(clock.clone())
        .build(dir.path());
    let submit = |source: &str| {
        let key = generate(KeyKind::Ed25519).unwrap();
        test.service
            .submit(key.public_key(), REQUEST.as_bytes(), &from(source))
    };
    // At the rate, from three addresses; one more, from a fourth, is refused.
    for source in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        submit(source).unwrap();
    }
    let before = test.events("submit", "denied").len();
    for source in ["192.0.2.4", "192.0.2.5"] {
        refused_as(
            submit(source),
            RefusalCode::RateLimited,
            "more than 3 submissions a minute from all sources; try again later",
        );
    }
    let denied = test.events("submit", "denied");
    assert_eq!(denied.len(), before + 1, "one line for the burst");
    assert_eq!(
        denied.last().unwrap()["reason"],
        "more than 3 submissions a minute from all sources"
    );
    // A minute on, the next passes and the burst's count is logged with it.
    clock.advance(60);
    submit("192.0.2.4").unwrap();
    assert_eq!(
        test.events("submit", "denied").last().unwrap()["reason"],
        "1 more submissions were refused over the rate for all sources"
    );
}

#[test]
fn rates_out_of_bounds_are_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let start = |per_source: usize, in_all: usize| {
        TestServiceBuilder::new(POLICY)
            .submissions(writ_approval::SubmissionLimits { per_source, in_all })
            .try_build(dir.path())
    };
    match start(0, 60) {
        Err(ServiceError::Config(message)) => {
            assert_eq!(message, "submissions.per_source: 0, must be from 1 to 1000");
        }
        Err(other) => panic!("expected a configuration error, got {other}"),
        Ok(_) => panic!("started with a rate of 0"),
    }
    match start(10, 10_001) {
        Err(ServiceError::Config(message)) => {
            assert_eq!(
                message,
                "submissions.in_all: 10001, must be from 1 to 10000"
            );
        }
        Err(other) => panic!("expected a configuration error, got {other}"),
        Ok(_) => panic!("started with a rate over its bound"),
    }
}

/// A notifier that holds the worker inside `notify` until released.
struct Gated {
    state: std::sync::Mutex<(bool, bool, Vec<String>)>,
    changed: std::sync::Condvar,
}

impl Gated {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new((false, false, Vec::new())),
            changed: std::sync::Condvar::new(),
        })
    }

    /// Waits until the worker is inside `notify`.
    fn wait_entered(&self) {
        let state = self.state.lock().unwrap();
        let (_state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |s| !s.0)
            .unwrap();
        assert!(!timeout.timed_out(), "the worker never called the notifier");
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }

    fn wait_for(&self, count: usize) -> Vec<String> {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |s| s.2.len() < count)
            .unwrap();
        assert!(!timeout.timed_out(), "only {} notifications", state.2.len());
        state.2.clone()
    }
}

impl writ_platform::Notifier for Gated {
    fn notify(&self, notification: &writ_platform::Notification) -> writ_platform::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
        state.2.push(notification.title.clone());
        self.changed.notify_all();
        Ok(())
    }
}

#[test]
fn a_slow_notifier_never_queues_without_bound() {
    let dir = tempfile::tempdir().unwrap();
    let gated = Gated::new();
    let test = TestServiceBuilder::new(POLICY)
        .max_pending(100)
        .notifier(gated.clone())
        .clock(Arc::new(FakeClock::at_unix(START)))
        .build(dir.path());
    let submit = |n: usize| {
        let key = generate(KeyKind::Ed25519).unwrap();
        test.service
            .submit(
                key.public_key(),
                REQUEST.as_bytes(),
                &from(&format!("192.0.2.{n}")),
            )
            .unwrap();
    };
    submit(0);
    gated.wait_entered();
    // One in delivery, 32 queued, 7 counted.
    for n in 1..=39 {
        submit(n);
    }
    gated.release();
    let titles = gated.wait_for(34);
    assert_eq!(titles.len(), 34);
    assert!(titles[0].starts_with("Ticket waiting"));
    assert_eq!(titles[1], "7 more notifications were dropped");
    assert!(titles[2..].iter().all(|t| t.starts_with("Ticket waiting")));
}

#[test]
fn a_session_key_is_ed25519_or_p256() {
    let h = Harness::new(Decisions::Signed);
    let p256 = generate(KeyKind::P256).unwrap();
    h.service
        .submit(p256.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    // A throwaway P-384 public key, made by ssh-keygen for this test (no private half kept).
    let p384 = writ_crypto::ssh_key::PublicKey::from_openssh(
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIhnxfvj+u7EF\
         RXssN2rQZohx2pWI+XiNzjnSMq4bByNKtDaffJYic8mEAkPqQU/aks8oEeBWCO869LX2G6xqmNUZ86iX+mUmI\
         EtiEStNWoL1F719qPYG0HjGq6ncl13Sg==",
    )
    .unwrap();
    refused_as(
        h.service.submit(&p384, REQUEST.as_bytes(), &facts()),
        RefusalCode::SessionKey,
        "it must be ssh-ed25519 or ecdsa-sha2-nistp256",
    );
    assert_eq!(h.events("submit", "denied"), 1, "logged");
}

#[test]
fn the_deny_list_survives_a_restart() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    h.revoke_signed(&ticket.id).unwrap();
    // Another service on the same store, with another CA and approver.
    let restarted = TestServiceBuilder::new(POLICY)
        .clock(h.clock.clone())
        .build(h.dir.path());
    assert!(restarted.service.is_revoked(cert.serial()));
}

#[test]
fn the_audit_log_holds_every_decision_and_no_secret() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, _cert) = h.lease();
    let (refused, _) = h.submit(REQUEST);
    h.refuse_signed(&refused.id, "no").unwrap();
    h.revoke_signed(&ticket.id).unwrap();
    let text = std::fs::read_to_string(&h.audit_path).unwrap();
    assert!(!looks_secret(&text), "{text}");
    for (event, result) in [
        ("submit", "allowed"),
        ("grant", "allowed"),
        ("refuse", "done"),
        ("revoke", "done"),
    ] {
        assert!(h.events(event, result) >= 1, "{event} {result}");
    }
    let grant = h
        .audit()
        .into_iter()
        .find(|e| e["event"] == "grant")
        .unwrap();
    assert_eq!(
        grant["approver"],
        h.approver
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    assert_eq!(grant["source_addr"], "192.0.2.7");
}

#[test]
fn nothing_is_granted_without_its_audit_line() {
    let h = Harness::new(Decisions::Signed);
    let audit_lines = || h.audit().len();

    // Submission: no pending ticket.
    h.audit_breaker.set_broken(true);
    let key = generate(KeyKind::Ed25519).unwrap();
    let error = h
        .service
        .submit(key.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "the audit log can't be written; nothing was done"
    );
    assert!(h.service.list(true).unwrap().tickets.is_empty());
    h.audit_breaker.set_broken(false);

    // Grant: the ticket stays pending, no certificate.
    let (ticket, key) = h.submit(REQUEST);
    let before = audit_lines();
    h.audit_breaker.set_broken(true);
    audit_log_down(h.approve(&ticket));
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);
    assert_eq!(audit_lines(), before, "a broken log holds nothing");

    // Refusal: still pending (a refusal reduces nothing granted; it waits for its line).
    h.audit_breaker.set_broken(true);
    audit_log_down(h.refuse_signed(&ticket.id, "no"));
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);

    // With the log back, the same approval goes through.
    assert_eq!(h.approve(&ticket).unwrap(), State::Active);
    let Decision::Active { certificate, .. } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    let cert = Certificate::from_openssh(&certificate).unwrap();

    // Amendment: the lease keeps its terms.
    let amendment = REQUEST
        .replace("max_signatures: 30", "max_signatures: 40")
        .replace(
            "  plan: [Add the callback route, Tests]",
            &format!(
                "  plan: [Add the callback route, Tests]\n  amends: {}",
                ticket.id
            ),
        );
    let submitted = h
        .service
        .submit(key.public_key(), amendment.as_bytes(), &facts())
        .unwrap();
    let amendment = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    h.audit_breaker.set_broken(true);
    audit_log_down(h.approve(&amendment));
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&amendment.id).unwrap().state, State::Pending);
    let Decision::Active { lease, .. } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    let terms = Ticket::from_canonical(lease.as_bytes()).unwrap();
    assert_eq!(
        om(&terms).limits.max_signatures,
        30,
        "the amendment was not applied"
    );

    // Each step that went through has its line.
    assert_eq!(h.events("submit", "allowed"), 2);
    assert_eq!(h.events("grant", "allowed"), 1);
    assert_eq!(h.events("amend", "allowed"), 0);
    assert_eq!(h.events("refuse", "done"), 0);
    let _ = cert;
}

#[test]
fn a_revocation_never_waits_for_the_audit_log() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    let (pending, _) = h.submit(REQUEST);

    // A full disk must not keep a lease alive: revoked, refused at once, sessions dropped.
    let mut revocations = h.service.subscribe_revocations();
    h.audit_breaker.set_broken(true);
    assert_eq!(h.revoke_signed(&ticket.id).unwrap(), State::Revoked);
    assert_eq!(revocations.try_recv().unwrap(), cert.serial());
    assert!(h.service.is_revoked(cert.serial()));
    assert_eq!(
        h.service
            .authorize(&identity(&cert), &facts(), None)
            .unwrap_err()
            .code,
        DenyCode::NotActive
    );
    // A pending ticket is withdrawn the same way.
    assert_eq!(h.revoke_signed(&pending.id).unwrap(), State::Revoked);
    assert_eq!(
        h.events("revoke", "done"),
        0,
        "nothing reached the broken log"
    );

    // The lines are written, in order, as soon as the log can take them.
    h.audit_breaker.set_broken(false);
    h.service.sweep();
    let revoked: Vec<_> = h
        .test
        .events("revoke", "done")
        .into_iter()
        .map(|e| e["lease"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(revoked, [ticket.id.to_string(), pending.id.to_string()]);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Revoked);
}

#[test]
fn expiry_never_waits_for_the_audit_log() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    h.audit_breaker.set_broken(true);
    h.clock.advance(2 * 3600);
    h.service.sweep();
    assert!(h.service.is_revoked(cert.serial()));
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Expired);
    h.service.sweep();
    assert_eq!(h.events("expire", "done"), 1);
}

#[test]
fn an_unknown_ticket_is_logged_as_denied() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _) = h.submit(REQUEST);
    let unknown: TicketId = "wrt_01JD8X0000000000000000000Z".parse().unwrap();
    let mut other = ticket.clone();
    other.id = unknown.clone();
    for (result, event) in [
        (
            h.service
                .approve(&unknown, &h.signed(&other), &facts())
                .map(|a| a.state),
            "grant",
        ),
        (h.refuse_signed(&unknown, "no"), "refuse"),
        (h.revoke_signed(&unknown), "revoke"),
    ] {
        assert!(
            matches!(&result, Err(ServiceError::NotFound(id)) if *id == unknown),
            "{result:?}"
        );
        let denied = h.test.events(event, "denied");
        assert_eq!(denied.len(), 1, "{event}");
        assert_eq!(denied[0]["reason"], "no such ticket");
        assert_eq!(denied[0]["ticket"], unknown.as_str());
    }
}

#[test]
fn a_refused_amendment_approval_is_logged_as_amend() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key, _) = h.lease();
    let amendment = REQUEST.replace(
        "  plan: [Add the callback route, Tests]",
        &format!(
            "  plan: [Add the callback route, Tests]\n  amends: {}",
            ticket.id
        ),
    );
    let submitted = h
        .service
        .submit(key.public_key(), amendment.as_bytes(), &facts())
        .unwrap();
    let amendment = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    let other = generate(KeyKind::Ed25519).unwrap();
    let forged = sign_approval_in(&other, &amendment, APPROVAL_NAMESPACE);
    let error = h
        .service
        .approve(&amendment.id, &forged, &facts())
        .unwrap_err();
    assert!(
        matches!(&error, ServiceError::Refused { code: RefusalCode::Signature, message, .. } if message.contains("not in approvers")),
        "{error:?}"
    );
    assert_eq!(h.events("amend", "denied"), 1);
    assert_eq!(h.events("grant", "denied"), 0);
    assert_eq!(h.approve(&amendment).unwrap(), State::Applied);
    assert_eq!(h.events("amend", "allowed"), 1);
}
