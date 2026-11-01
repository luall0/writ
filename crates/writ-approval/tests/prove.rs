//! Proofs (`writ prove-key`) on the platform fakes: an agent signing key signs a remote's
//! message only with an approver's signature over exactly the `writ-proof/1` document; a
//! namespace that is `git` or Writ's own, a message over 4 KiB, a key no template signs
//! with, a reader without an approver, a proof passed off as a ticket approval or the other
//! way round: each refused with its code, and logged.

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
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::signed::{MAX_PROOF_MESSAGE_BYTES, Proof};
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::HashAlg;
use writ_crypto::sshsig;
use writ_platform::testing::FakeClock;
use writ_proto::{ApproveRequest, Decisions, ProveRequest};
use writ_store::looks_secret;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// The fixture policy's agent signing key (both templates name it).
const KEY: &str = "agent-ed25519-01";

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

fn service(dir: &std::path::Path, decisions: Decisions) -> TestService {
    TestServiceBuilder::new(POLICY)
        .decisions(decisions)
        .clock(Arc::new(FakeClock::at_unix(START)))
        .build(dir)
}

/// A `writ-proof/1` document as canonical text, built by hand so a test can write what the
/// type would refuse to build.
fn document(key: &str, namespace: &str, message: &str) -> String {
    let text = |value: &str| serde_json::to_string(value).unwrap();
    format!(
        r#"{{"kind":"writ-proof/1","key":{},"namespace":{},"message":{}}}"#,
        text(key),
        text(namespace),
        text(message)
    )
}

/// A proof request: the document, signed by `signer` in `namespace`.
fn signed_by(
    signer: &writ_crypto::ssh_key::PrivateKey,
    namespace: &str,
    doc: &str,
) -> ProveRequest {
    ProveRequest {
        signature: sshsig::sign(signer, namespace, doc.as_bytes()).unwrap(),
        proof: doc.to_owned(),
    }
}

fn code(result: Result<writ_proto::Proved, ServiceError>) -> (RefusalCode, String) {
    match result {
        Ok(proved) => panic!("expected a refusal, got {proved:?}"),
        Err(e) => (e.code().expect("a refusal with a code"), e.to_string()),
    }
}

#[test]
fn a_proof_signs_exactly_the_message_with_the_named_key() {
    let dir = tempfile::tempdir().unwrap();
    let h = service(dir.path(), Decisions::Signed);
    let message = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let doc = document(KEY, "gitea", message);
    // What the client builds is the same document, byte for byte.
    let built = Proof::new(
        KEY.parse().unwrap(),
        "gitea".parse().unwrap(),
        message.to_owned().try_into().unwrap(),
    );
    assert_eq!(built.canonical_bytes().unwrap(), doc.as_bytes());

    let proved = h
        .service
        .prove(&signed_by(&h.approver, APPROVAL_NAMESPACE, &doc), &facts())
        .unwrap();
    let key = h.signing_key(KEY);
    assert_eq!(proved.public_key, key.to_openssh().unwrap());
    // The remote's check: the key's signature over the message, in its namespace.
    let signer = sshsig::verify(
        std::slice::from_ref(&key),
        "gitea",
        message.as_bytes(),
        &proved.signature,
    )
    .unwrap();
    assert_eq!(signer, &key);
    // In no other namespace, over no other message.
    assert!(matches!(
        sshsig::verify(
            std::slice::from_ref(&key),
            "git",
            message.as_bytes(),
            &proved.signature
        ),
        Err(writ_crypto::CryptoError::Namespace { .. })
    ));
    assert!(matches!(
        sshsig::verify(
            std::slice::from_ref(&key),
            "gitea",
            b"other",
            &proved.signature
        ),
        Err(writ_crypto::CryptoError::BadSignature)
    ));

    // One line: the key, the namespace, the message's digest, the approver; never the message.
    let lines = h.events("prove", "allowed");
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(line["key"], KEY);
    assert_eq!(line["namespace"], "gitea");
    assert_eq!(
        line["message_sha256"],
        sshsig::message_digest(message.as_bytes())
    );
    assert_eq!(
        line["approver"],
        h.approver
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    let audit = std::fs::read_to_string(&h.audit_path).unwrap();
    assert!(!audit.contains(message), "{audit}");
    assert!(!looks_secret(&audit), "{audit}");
}

#[test]
fn a_proof_needs_an_approver_signature_over_exactly_that_document() {
    // With `decisions: open` too: a reader key alone never has a key sign anything.
    for decisions in [Decisions::Signed, Decisions::Open] {
        let dir = tempfile::tempdir().unwrap();
        let h = service(dir.path(), decisions);
        let doc = document(KEY, "gitea", "token");
        let stranger = generate(KeyKind::Ed25519).unwrap();
        let other_doc = document(KEY, "gitea", "another token");
        let cases = [
            // A key that isn't in approvers (a reader's, say).
            (
                signed_by(&stranger, APPROVAL_NAMESPACE, &doc),
                "not in approvers",
            ),
            // The approver's signature over another document.
            (
                ProveRequest {
                    proof: doc.clone(),
                    signature: signed_by(&h.approver, APPROVAL_NAMESPACE, &other_doc).signature,
                },
                "does not match",
            ),
            // The approver's signature in another namespace (a git signature, say).
            (signed_by(&h.approver, "git", &doc), "namespace \"git\""),
            // No signature at all.
            (
                ProveRequest {
                    proof: doc.clone(),
                    signature: String::new(),
                },
                "unreadable signature",
            ),
        ];
        for (request, why) in cases {
            let (code, message) = code(h.service.prove(&request, &facts()));
            assert_eq!(
                code,
                RefusalCode::Signature,
                "{decisions:?} {why}: {message}"
            );
            assert!(message.starts_with("proof refused: "), "{message}");
            assert!(message.contains(why), "{decisions:?} {why}: {message}");
        }
        let denied = h.events("prove", "denied");
        assert_eq!(denied.len(), 4, "{denied:?}");
        assert!(
            denied
                .iter()
                .all(|line| line["key"] == KEY && line["namespace"] == "gitea")
        );
        assert!(h.events("prove", "allowed").is_empty());
        // The allowed case beside them: the same document, signed by the approver.
        let ok = signed_by(&h.approver, APPROVAL_NAMESPACE, &doc);
        assert!(h.service.prove(&ok, &facts()).is_ok());
    }
}

#[test]
fn a_proof_in_git_or_writ_s_namespaces_or_over_4_kib_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let h = service(dir.path(), Decisions::Signed);
    let longest = "a".repeat(MAX_PROOF_MESSAGE_BYTES);
    let over = "a".repeat(MAX_PROOF_MESSAGE_BYTES + 1);
    for (doc, why) in [
        (document(KEY, "git", "token"), "commit signatures"),
        (document(KEY, "Git", "token"), "commit signatures"),
        (document(KEY, "writ-approval", "token"), "Writ's own"),
        (document(KEY, "writ-proof", "token"), "Writ's own"),
        (document(KEY, "gitea", &over), "4097 bytes"),
        (document(KEY, "gitea", ""), "0 bytes"),
        // Not canonical: the same document with a space.
        (
            document(KEY, "gitea", "token").replacen(':', ": ", 1),
            "canonical",
        ),
        (document(KEY, "gitea\u{1b}[2J", "token"), "only letters"),
        ("not json".to_owned(), "writ-proof/1"),
    ] {
        // Signed by the approver: refused for what it says, not for who signed it.
        let request = signed_by(&h.approver, APPROVAL_NAMESPACE, &doc);
        let (code, message) = code(h.service.prove(&request, &facts()));
        assert_eq!(code, RefusalCode::Proof, "{why}: {message}");
        assert!(message.contains(why), "{why}: {message}");
    }
    assert_eq!(h.events("prove", "denied").len(), 9);
    // At the bound: signed.
    let request = signed_by(
        &h.approver,
        APPROVAL_NAMESPACE,
        &document(KEY, "gitea", &longest),
    );
    let proved = h.service.prove(&request, &facts()).unwrap();
    let key = h.signing_key(KEY);
    sshsig::verify(
        std::slice::from_ref(&key),
        "gitea",
        longest.as_bytes(),
        &proved.signature,
    )
    .unwrap();
}

#[test]
fn a_proof_for_a_key_no_template_signs_with_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let h = service(dir.path(), Decisions::Signed);
    for key in ["upstream-01", "ca", "host"] {
        let request = signed_by(
            &h.approver,
            APPROVAL_NAMESPACE,
            &document(key, "gitea", "t"),
        );
        let (code, message) = code(h.service.prove(&request, &facts()));
        assert_eq!(code, RefusalCode::Proof, "{message}");
        assert!(
            message.contains("is not a key a template signs commits with"),
            "{message}"
        );
    }
    let denied = h.events("prove", "denied");
    assert_eq!(denied.len(), 3);
    // The approver is known by then, and logged.
    assert!(
        denied.iter().all(|line| line["approver"].is_string()),
        "{denied:?}"
    );
}

#[test]
fn a_proof_and_a_ticket_approval_never_pass_for_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let h = service(dir.path(), Decisions::Signed);
    let session = generate(KeyKind::Ed25519).unwrap();
    let submitted = h
        .service
        .submit(session.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();

    // A ticket approval sent as a proof: not a proof.
    let approval = h.approval(&ticket);
    let replayed = ProveRequest {
        proof: approval.signed.clone(),
        signature: approval.signature.clone(),
    };
    let (code, message) = code(h.service.prove(&replayed, &facts()));
    assert_eq!(code, RefusalCode::Proof, "{message}");

    // A proof sent as the ticket's approval: not a ticket; the ticket stays pending.
    let proof = signed_by(
        &h.approver,
        APPROVAL_NAMESPACE,
        &document(KEY, "gitea", "t"),
    );
    let as_approval = ApproveRequest {
        signed: proof.proof.clone(),
        signature: proof.signature.clone(),
    };
    let error = h
        .service
        .approve(&ticket.id, &as_approval, &facts())
        .unwrap_err();
    assert_eq!(error.code(), Some(RefusalCode::Signature), "{error}");
    // The proof's signature beside the ticket's own bytes: it signs other bytes.
    let mixed = ApproveRequest {
        signed: approval.signed.clone(),
        signature: proof.signature,
    };
    let error = h.service.approve(&ticket.id, &mixed, &facts()).unwrap_err();
    assert_eq!(error.code(), Some(RefusalCode::Signature), "{error}");
    assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Pending);
    // The real approval still grants it.
    assert_eq!(
        h.service
            .approve(&ticket.id, &approval, &facts())
            .unwrap()
            .state,
        State::Active
    );
}

#[test]
fn a_proof_the_signer_or_the_audit_log_fails_is_never_handed_out() {
    let dir = tempfile::tempdir().unwrap();
    let h = service(dir.path(), Decisions::Signed);
    let request = signed_by(
        &h.approver,
        APPROVAL_NAMESPACE,
        &document(KEY, "gitea", "t"),
    );
    // The signer refuses: a refusal with the kind of failure, logged.
    h.signer.set_failing(true);
    let (code, message) = code(h.service.prove(&request, &facts()));
    assert_eq!(code, RefusalCode::Proof, "{message}");
    assert!(message.contains("the signer failed"), "{message}");
    assert_eq!(h.events("prove", "denied").len(), 1);
    h.signer.set_failing(false);
    // The audit log can't take the line: no signature leaves the daemon.
    h.audit_breaker.set_broken(true);
    let error = h.service.prove(&request, &facts()).unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error:?}");
    h.audit_breaker.set_broken(false);
    assert!(h.events("prove", "allowed").is_empty());
    // Once it can: signed, one line.
    assert!(h.service.prove(&request, &facts()).is_ok());
    assert_eq!(h.events("prove", "allowed").len(), 1);
}
