//! The approval service on the platform fakes: submission, approval (and every approval that
//! must be refused), narrowing, refusal and revision, revocation, expiry, session binding,
//! and the audit log of all of it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use writ_approval::{Service, ServiceConfig, ServicePlatform};
use writ_core::caller::{CallerFacts, ProcessRef};
use writ_core::canonical::Canonical;
use writ_core::config::PolicyConfig;
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::names::TicketId;
use writ_core::policy::{CertIdentity, DenyCode};
use writ_core::signed::{Refusal, Revocation};
use writ_core::ticket::Operation;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::{CertificateAuthority, validate_user_certificate};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg, PrivateKey};
use writ_crypto::sshsig;
use writ_platform::testing::{FakeClock, FakeWatcher, RecordingNotifier};
use writ_proto::{ApproveRequest, Decision, Decisions, RefuseRequest, Relation, RevokeRequest};
use writ_store::{AuditBreaker, AuditLog, Store, looks_secret};

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");
const START: u64 = 1_800_000_000;

const REQUEST: &str = r#"
template: feature-branch
scope:
  repos: [omega-code]
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth-*"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
  plan: [Add the callback route, Tests]
limits:
  ttl: 2h
  max_signatures: 30
"#;

struct Harness {
    dir: tempfile::TempDir,
    service: Arc<Service>,
    clock: Arc<FakeClock>,
    notifier: RecordingNotifier,
    watcher: FakeWatcher,
    approver: PrivateKey,
    ca_fingerprint: writ_crypto::ssh_key::Fingerprint,
    audit_breaker: AuditBreaker,
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
        let approver = generate(KeyKind::Ed25519).unwrap();
        let ca_key = generate(KeyKind::Ed25519).unwrap();
        let ca_fingerprint = ca_key.public_key().fingerprint(HashAlg::Sha256);
        let clock = Arc::new(FakeClock::at_unix(START));
        let notifier = RecordingNotifier::new();
        let (audit, audit_breaker) =
            AuditLog::open_breakable(&dir.path().join("audit.jsonl")).unwrap();
        let service = Service::new(
            ServiceConfig {
                policy: PolicyConfig::from_yaml(POLICY).unwrap(),
                approvers: vec![AllowedSigner {
                    principals: "me".into(),
                    key: approver.public_key().clone(),
                }],
                decisions,
                max_pending,
            },
            CertificateAuthority::new(ca_key),
            Store::open(&dir.path().join("leases.db")).unwrap(),
            audit,
            ServicePlatform {
                notifier: Arc::new(notifier.clone()),
                watcher: Arc::new(watcher.clone()),
                clock: clock.clone(),
            },
        )
        .unwrap();
        Self {
            dir,
            service,
            clock,
            notifier,
            watcher,
            approver,
            ca_fingerprint,
            audit_breaker,
        }
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn events(&self, event: &str, result: &str) -> usize {
        self.audit()
            .iter()
            .filter(|e| e["event"] == event && e["result"] == result)
            .count()
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
        sign_with(&self.approver, ticket, APPROVAL_NAMESPACE)
    }

    fn approve(&self, ticket: &Ticket) -> Result<State, writ_proto::ApiError> {
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

    fn refuse_signed(&self, id: &TicketId, feedback: &str) -> Result<State, writ_proto::ApiError> {
        let doc = Refusal::new(id.clone(), feedback.into())
            .canonical_bytes()
            .unwrap();
        let request = RefuseRequest {
            feedback: feedback.into(),
            signature: Some(self.sign_doc(&doc)),
        };
        self.service.refuse(id, &request, &facts()).map(|a| a.state)
    }

    fn revoke_signed(&self, id: &TicketId) -> Result<State, writ_proto::ApiError> {
        let doc = Revocation::new(id.clone()).canonical_bytes().unwrap();
        let request = RevokeRequest {
            signature: Some(self.sign_doc(&doc)),
        };
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

fn sign_with(key: &PrivateKey, ticket: &Ticket, namespace: &str) -> ApproveRequest {
    let bytes = ticket.canonical_bytes().unwrap();
    ApproveRequest {
        signature: sshsig::sign(key, namespace, &bytes).unwrap(),
        signed: String::from_utf8(bytes).unwrap(),
    }
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

/// Waits for something that happens on another thread.
fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("condition never became true");
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
        error.reasons.iter().any(|r| r.contains("branch main")),
        "{error}"
    );
    let unparsable = h
        .service
        .submit(key.public_key(), b"scope: {repos: [x]", &facts())
        .unwrap_err();
    assert_eq!(unparsable.message, "ticket rejected");
    assert!(h.service.list(true).unwrap().tickets.is_empty());
    assert_eq!(h.events("submit", "denied"), 2);
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        h.notifier.notifications().is_empty(),
        "rejected tickets never notify"
    );
}

#[test]
fn a_signed_ticket_becomes_a_lease_with_a_certificate_until_it_expires() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    assert_eq!(ticket.text.revision, 1);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);
    eventually(|| h.notifier.notifications().len() == 1);
    let notification = &h.notifier.notifications()[0];
    assert!(notification.title.contains("Add OAuth login"));
    assert!(notification.message.contains(ticket.id.as_str()));

    assert_eq!(h.approve(&ticket).unwrap(), State::Active);
    let Decision::Active { lease, certificate } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    assert_eq!(Ticket::from_canonical(lease.as_bytes()).unwrap(), ticket);
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
    narrowed.limits.max_signatures = 5;
    let mut widened = ticket.clone();
    widened.limits.max_signatures = 40;
    let mut other_bytes = h.signed(&ticket);
    other_bytes.signed = String::from_utf8(narrowed.canonical_bytes().unwrap()).unwrap();
    let mut not_canonical = h.signed(&ticket);
    not_canonical.signed = not_canonical.signed.replacen(':', ": ", 1);

    let cases = [
        (
            "a key not in approvers",
            sign_with(&stranger, &ticket, APPROVAL_NAMESPACE),
            "not in approvers",
        ),
        (
            "another namespace",
            sign_with(&h.approver, &ticket, "git"),
            "namespace",
        ),
        ("other bytes", other_bytes, "does not match"),
        ("a widening", h.signed(&widened), "max_signatures raised"),
        ("non-canonical bytes", not_canonical, "canonical"),
    ];
    for (case, request, expected) in cases {
        let error = h
            .service
            .approve(&ticket.id, &request, &facts())
            .unwrap_err();
        assert!(error.message.contains(expected), "{case}: {error}");
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
    narrowed.scope.operations.remove(&Operation::Push);
    narrowed.limits.expires_at =
        Timestamp::from_unix(i64::try_from(START).unwrap() + 1800).unwrap();
    narrowed.limits.max_signatures = 5;
    h.service
        .approve(&ticket.id, &h.signed(&narrowed), &facts())
        .unwrap();
    let Decision::Active { lease, certificate } = h.wait(&ticket.id, &key) else {
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
    assert!(h.service.refuse(&ticket.id, &unsigned, &facts()).is_err());
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
    assert!(h.service.refuse(&ticket.id, &forged, &facts()).is_err());
    assert_eq!(h.events("refuse", "denied"), 2);

    assert_eq!(
        h.refuse_signed(&ticket.id, "Don't touch billing").unwrap(),
        State::Refused
    );
    assert_eq!(
        h.wait(&ticket.id, &key),
        Decision::Refused {
            feedback: "Don't touch billing".into()
        }
    );
    assert!(
        h.approve(&ticket).is_err(),
        "a refused ticket can't be signed"
    );

    let revision = REQUEST.replace(
        "  plan: [Add the callback route, Tests]",
        &format!(
            "  plan: [Add the callback route, Tests]\n  revises: {}",
            ticket.id
        ),
    );
    let (revised, _) = h.submit(&revision);
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
    assert!(
        h.service
            .revoke(&ticket.id, &RevokeRequest::default(), &facts())
            .is_err()
    );
    assert_eq!(h.revoke_signed(&ticket.id).unwrap(), State::Revoked);
    assert_eq!(revocations.try_recv().unwrap(), cert.serial());
    assert!(h.service.is_revoked(cert.serial()));
    let denial = h
        .service
        .authorize(&identity(&cert), &facts(), None)
        .unwrap_err();
    assert_eq!(denial.code, DenyCode::NotActive);
    assert!(
        h.revoke_signed(&ticket.id).is_err(),
        "nothing left to revoke"
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
    assert!(h.service.refuse(&pending.id, &bad, &facts()).is_err());
    let open = RefuseRequest {
        feedback: "no".into(),
        signature: None,
    };
    h.service.refuse(&pending.id, &open, &facts()).unwrap();
    assert_eq!(
        h.wait(&pending.id, &key),
        Decision::Refused {
            feedback: "no".into()
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
    assert!(h.service.approve(&other.id, &unsigned, &facts()).is_err());
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
    assert!(
        h.approve(&pending).is_err(),
        "an expired ticket can't be signed"
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
    assert!(error.message.contains("does not exist"));
}

#[test]
fn waiting_returns_when_the_approver_decides() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, key) = h.submit(REQUEST);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let service = h.service.clone();
    let id = ticket.id.clone();
    let public = key.public_key().clone();
    let waiting = runtime.spawn(async move { service.wait(&id, &public).await });
    std::thread::sleep(Duration::from_millis(100));
    assert!(!waiting.is_finished());
    h.approve(&ticket).unwrap();
    let decision = runtime.block_on(waiting).unwrap().unwrap();
    assert!(matches!(decision, Decision::Active { .. }));
}

const BOUND: &str = r#"
template: feature-branch
caller:
  descends_from: { executable: /usr/local/bin/harness, pid: 4242, generation: 7 }
scope:
  repos: [omega-code]
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
    assert!(error.message.contains("can't watch"), "{error}");

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

    h.watcher.exit(4242, 7);
    eventually(|| h.service.is_revoked(cert.serial()));
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Revoked);
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
    assert!(error.message.contains("already waiting"), "{error}");
}

#[test]
fn the_deny_list_survives_a_restart() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, cert) = h.lease();
    h.revoke_signed(&ticket.id).unwrap();
    let dir = h.dir.path().to_owned();
    let restarted = Service::new(
        ServiceConfig {
            policy: PolicyConfig::from_yaml(POLICY).unwrap(),
            approvers: vec![],
            decisions: Decisions::Signed,
            max_pending: 20,
        },
        CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap()),
        Store::open(&dir.join("leases.db")).unwrap(),
        AuditLog::open(&dir.join("audit.jsonl")).unwrap(),
        ServicePlatform {
            notifier: Arc::new(RecordingNotifier::new()),
            watcher: Arc::new(FakeWatcher::new()),
            clock: h.clock.clone(),
        },
    )
    .unwrap();
    assert!(restarted.is_revoked(cert.serial()));
}

#[test]
fn the_audit_log_holds_every_decision_and_no_secret() {
    let h = Harness::new(Decisions::Signed);
    let (ticket, _key, _cert) = h.lease();
    let (refused, _) = h.submit(REQUEST);
    h.refuse_signed(&refused.id, "no").unwrap();
    h.revoke_signed(&ticket.id).unwrap();
    let text = std::fs::read_to_string(h.dir.path().join("audit.jsonl")).unwrap();
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
fn nothing_changes_without_its_audit_line() {
    let h = Harness::new(Decisions::Signed);
    let audit_lines = || h.audit().len();

    // Submission: no pending ticket.
    h.audit_breaker.set_broken(true);
    let key = generate(KeyKind::Ed25519).unwrap();
    let error = h
        .service
        .submit(key.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap_err();
    assert_eq!(
        error.message,
        "the audit log can't be written; nothing was done"
    );
    assert!(h.service.list(true).unwrap().tickets.is_empty());
    h.audit_breaker.set_broken(false);

    // Grant: the ticket stays pending, no certificate.
    let (ticket, key) = h.submit(REQUEST);
    let before = audit_lines();
    h.audit_breaker.set_broken(true);
    assert!(h.approve(&ticket).is_err());
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);
    assert_eq!(audit_lines(), before, "a broken log holds nothing");

    // Refusal and withdrawal: still pending.
    h.audit_breaker.set_broken(true);
    assert!(h.refuse_signed(&ticket.id, "no").is_err());
    assert!(h.revoke_signed(&ticket.id).is_err());
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
    assert!(h.approve(&amendment).is_err());
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.show(&amendment.id).unwrap().state, State::Pending);
    let Decision::Active { lease, .. } = h.wait(&ticket.id, &key) else {
        panic!("expected an active lease");
    };
    let terms = Ticket::from_canonical(lease.as_bytes()).unwrap();
    assert_eq!(
        terms.limits.max_signatures, 30,
        "the amendment was not applied"
    );

    // Revocation: the certificate still works.
    h.audit_breaker.set_broken(true);
    assert!(h.revoke_signed(&ticket.id).is_err());
    h.audit_breaker.set_broken(false);
    assert!(!h.service.is_revoked(cert.serial()));
    assert!(
        h.service
            .authorize(&identity(&cert), &facts(), None)
            .is_ok()
    );

    // Each step that went through has its line.
    assert_eq!(h.events("submit", "allowed"), 2);
    assert_eq!(h.events("grant", "allowed"), 1);
    assert_eq!(h.events("amend", "allowed"), 0);
    assert_eq!(h.events("refuse", "done"), 0);
    assert_eq!(h.events("revoke", "done"), 0);
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
    let forged = sign_with(&other, &amendment, APPROVAL_NAMESPACE);
    let error = h
        .service
        .approve(&amendment.id, &forged, &facts())
        .unwrap_err();
    assert!(error.message.contains("not in approvers"), "{error}");
    assert_eq!(h.events("amend", "denied"), 1);
    assert_eq!(h.events("grant", "denied"), 0);
    assert_eq!(h.approve(&amendment).unwrap(), State::Applied);
    assert_eq!(h.events("amend", "allowed"), 1);
}
