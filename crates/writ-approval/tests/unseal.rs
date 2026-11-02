//! The sealed service on the platform fakes: every request but `info` and an unseal fails
//! with "daemon sealed" (its own code); an unseal needs an approver's signature over this
//! daemon's and this boot's `writ-unseal/1` document, then the keystore's CA and a signer
//! holding every template's key; every attempt is one `unseal` line, the sealed start one
//! `seal` line, and the approver is told of both.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use writ_approval::testing::{NONCE, TestService, TestServiceBuilder};
use writ_approval::{Opened, RefusalCode, ServiceError};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::policy::{CertIdentity, DenyCode, SEALED};
use writ_core::signed::{BootNonce, Unseal};
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::sshsig;
use writ_platform::testing::RecordingNotifier;
use writ_proto::{PassphraseText, ProveRequest, RevokeRequest, UnsealRequest};

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

const REQUEST: &str = r#"
template: feature-branch
scope:
  repos: [omega-code]
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth-*"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
limits:
  ttl: 2h
"#;

fn facts() -> CallerFacts {
    CallerFacts {
        source_addr: Some("192.0.2.7".parse().unwrap()),
        process_chain: None,
    }
}

fn sealed(dir: &std::path::Path) -> (TestService, Arc<RecordingNotifier>) {
    let notifier = Arc::new(RecordingNotifier::new());
    let h = TestServiceBuilder::new(POLICY)
        .notifier(notifier.clone())
        .sealed()
        .build(dir);
    (h, notifier)
}

fn refused<T: std::fmt::Debug>(result: Result<T, ServiceError>, code: RefusalCode) -> String {
    match result {
        Err(error) => {
            assert_eq!(error.code(), Some(code), "{error}");
            error.to_string()
        }
        Ok(value) => panic!("expected a refusal ({code:?}), got {value:?}"),
    }
}

fn opened(h: &TestService) -> Opened {
    Opened {
        ca: h.ca(),
        signer: h.signer.clone(),
    }
}

/// The `writ-unseal/1` document as canonical text, with what a test chooses.
fn document(daemon: &KeyFingerprint, nonce: [u8; 16]) -> String {
    let bytes = Unseal::new(daemon.clone(), BootNonce::from_bytes(nonce))
        .canonical_bytes()
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn request(
    signer: &writ_crypto::ssh_key::PrivateKey,
    namespace: &str,
    unseal: String,
) -> UnsealRequest {
    UnsealRequest {
        passphrase: PassphraseText::new("correct horse battery staple".to_owned()),
        signature: sshsig::sign(signer, namespace, unseal.as_bytes()).unwrap(),
        unseal,
    }
}

#[test]
fn while_sealed_every_request_fails_closed_with_daemon_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let (h, _) = sealed(dir.path());
    let s = &h.service;
    assert!(s.is_sealed());
    let session = generate(KeyKind::Ed25519).unwrap();
    let id: TicketId = TicketId::from_parts(1_800_000_000_000, [7; 10])
        .to_string()
        .parse()
        .unwrap();
    for (what, error) in [
        (
            "submit",
            s.submit(session.public_key(), REQUEST.as_bytes(), &facts())
                .map(|_| ()),
        ),
        ("ls", s.list(false).map(|_| ())),
        ("show", s.show(&id).map(|_| ())),
        (
            "approve",
            s.approve(
                &id,
                &writ_proto::ApproveRequest {
                    signed: "{}".into(),
                    signature: "x".into(),
                },
                &facts(),
            )
            .map(|_| ()),
        ),
        (
            "revoke",
            s.revoke(&id, &RevokeRequest::default(), &facts())
                .map(|_| ()),
        ),
        (
            "prove",
            s.prove(
                &ProveRequest {
                    proof: "{}".into(),
                    signature: "x".into(),
                },
                &facts(),
            )
            .map(|_| ()),
        ),
    ] {
        assert_eq!(refused(error, RefusalCode::Sealed), SEALED, "{what}");
    }
    // The gateway's side: its own code, never a violation.
    let cert = CertIdentity {
        key_id: id.to_string(),
        serial: 1,
        session_key: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            .parse()
            .unwrap(),
    };
    let denial = s.authorize(&cert, &facts(), None).unwrap_err();
    assert_eq!(
        (denial.code, denial.reason.as_str()),
        (DenyCode::Sealed, SEALED)
    );
    assert!(!DenyCode::Sealed.is_violation());
    let repo = "omega-code".parse().unwrap();
    assert_eq!(
        s.fetch(&cert, &facts(), &repo).unwrap_err().code,
        DenyCode::Sealed
    );
    assert_eq!(
        s.may_push(&cert, &facts(), &repo).unwrap_err().code,
        DenyCode::Sealed
    );
    // `info` names this daemon and this boot; once open, it doesn't.
    let boot = s.info().sealed.unwrap();
    assert_eq!(boot.daemon, h.daemon);
    assert_eq!(boot.nonce, BootNonce::from_bytes(NONCE));
    h.open().unwrap();
    assert_eq!(s.info().sealed, None);
    assert!(s.list(false).is_ok());
}

#[test]
fn an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot() {
    let dir = tempfile::tempdir().unwrap();
    let (h, _) = sealed(dir.path());
    let s = &h.service;
    let this = document(&h.daemon, NONCE);
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let other_daemon: KeyFingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        .parse()
        .unwrap();
    for (what, request, code, reason) in [
        (
            "another start",
            request(
                &h.approver,
                APPROVAL_NAMESPACE,
                document(&h.daemon, [8; 16]),
            ),
            RefusalCode::Unseal,
            "another start of this daemon",
        ),
        (
            "another daemon",
            request(
                &h.approver,
                APPROVAL_NAMESPACE,
                document(&other_daemon, NONCE),
            ),
            RefusalCode::Unseal,
            "not this one",
        ),
        (
            "not an approver",
            request(&stranger, APPROVAL_NAMESPACE, this.clone()),
            RefusalCode::Signature,
            "which is not in approvers",
        ),
        (
            "git's namespace",
            request(&h.approver, "git", this.clone()),
            RefusalCode::Signature,
            "namespace \"git\"",
        ),
        (
            "not canonical",
            UnsealRequest {
                unseal: this.replace(':', ": "),
                ..request(&h.approver, APPROVAL_NAMESPACE, this.clone())
            },
            RefusalCode::Unseal,
            "not a writ-unseal/1 document",
        ),
        (
            "a revocation's document",
            request(
                &h.approver,
                APPROVAL_NAMESPACE,
                String::from_utf8(
                    writ_core::signed::Revocation::new(
                        TicketId::from_parts(1_800_000_000_000, [7; 10])
                            .to_string()
                            .parse()
                            .unwrap(),
                    )
                    .canonical_bytes()
                    .unwrap(),
                )
                .unwrap(),
            ),
            RefusalCode::Unseal,
            "not a writ-unseal/1 document",
        ),
    ] {
        let message = refused(s.check_unseal(&request, &facts()), code);
        assert!(message.contains(reason), "{what}: {message}");
        assert!(s.is_sealed(), "{what}");
    }
    let denied = h.events("unseal", "denied");
    assert_eq!(denied.len(), 6, "every refused unseal is logged");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("another start")
    );
    assert_eq!(denied[0]["source_addr"], "192.0.2.7");
    // Never the passphrase in a line.
    let log = std::fs::read_to_string(&h.audit_path).unwrap();
    assert!(!log.contains("horse"), "{log}");

    // The approver's signature over this boot: accepted, the approver named.
    let fingerprint = s
        .check_unseal(&request(&h.approver, APPROVAL_NAMESPACE, this), &facts())
        .unwrap();
    assert_eq!(
        fingerprint.as_str(),
        h.approver
            .public_key()
            .fingerprint(Default::default())
            .to_string()
    );
    assert!(s.is_sealed(), "a checked signature alone opens nothing");
}

#[test]
fn an_unseal_opens_only_with_the_daemon_s_ca_and_is_logged_once() {
    let dir = tempfile::tempdir().unwrap();
    let (h, notifier) = sealed(dir.path());
    let s = &h.service;
    s.announce_sealed();
    let seal = h.events("seal", "done");
    assert_eq!(seal.len(), 1);
    let told = notifier.wait_for(1);
    assert_eq!(told[0].title, "writd started, sealed");
    assert!(
        told[0].message.contains(h.daemon.as_str()),
        "{}",
        told[0].message
    );

    let approver: KeyFingerprint = h
        .approver
        .public_key()
        .fingerprint(Default::default())
        .to_string()
        .parse()
        .unwrap();
    // Another CA key (a keystore swapped under the daemon): refused, still sealed.
    let foreign = Opened {
        ca: writ_crypto::ca::CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap()),
        signer: h.signer.clone(),
    };
    let message = refused(
        s.unseal(foreign, Some(&approver), &facts()),
        RefusalCode::Unseal,
    );
    assert_eq!(
        message,
        "the keystore's CA key is not the one the daemon started with"
    );
    assert!(s.is_sealed());
    s.unseal_failed(Some(&approver), "wrong passphrase", &facts());

    s.unseal(opened(&h), Some(&approver), &facts()).unwrap();
    assert!(!s.is_sealed());
    let allowed = h.events("unseal", "allowed");
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0]["approver"], approver.as_str());
    // A refused unseal is the caller's to log, once (the gateway does).
    let denied = h.events("unseal", "denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["reason"], "wrong passphrase");
    assert_eq!(denied[0]["approver"], approver.as_str());
    let told = notifier.wait_for(2);
    assert_eq!(told[1].title, "writd unsealed");

    // Open once: a second unseal, or its check, is refused as such and changes nothing.
    refused(
        s.unseal(opened(&h), Some(&approver), &facts()),
        RefusalCode::WrongState,
    );
    let again = h.unseal_request(&h.approver, "correct horse battery staple");
    let message = refused(s.check_unseal(&again, &facts()), RefusalCode::WrongState);
    assert_eq!(message, "the daemon is not sealed");
    assert_eq!(h.events("unseal", "allowed").len(), 1);

    // Open: tickets flow as before.
    let session = generate(KeyKind::Ed25519).unwrap();
    let submitted = s
        .submit(session.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    let ack = s
        .approve(&ticket.id, &h.approval(&ticket), &facts())
        .unwrap();
    assert_eq!(ack.state, State::Active);
}

#[test]
fn an_unseal_the_audit_log_cannot_take_keeps_the_daemon_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let (h, _) = sealed(dir.path());
    h.audit_breaker.set_broken(true);
    let error = h.service.unseal(opened(&h), None, &facts()).unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error}");
    assert!(h.service.is_sealed());
    h.audit_breaker.set_broken(false);
    h.service.unseal(opened(&h), None, &facts()).unwrap();
    assert!(!h.service.is_sealed());
}
