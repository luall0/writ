//! Sealed tokens on the platform fakes: an approver's `writ-token/2` signature, against the
//! token file in force, is logged and answered (the daemon writes the file); unsigned,
//! wrongly signed, malformed, stale or replayed changes are refused and logged; a sealed
//! service takes none; no line ever holds the token or its ciphertext.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_approval::testing::{TestService, TestServiceBuilder};
use writ_approval::{RefusalCode, ServiceError};
use writ_core::authority::{PreviousToken, SealedToken, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_core::signed::{Admin, Token};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_crypto::sshsig;
use writ_proto::TokenRequest;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

/// What the ciphertext stands for here: the service never opens it (the daemon does).
const SEALED: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBmYWtl";

fn facts() -> CallerFacts {
    CallerFacts {
        source_addr: Some("192.0.2.9".parse().unwrap()),
        process_chain: None,
    }
}

fn token(h: &TestService, previous: PreviousToken) -> Token {
    Token::new(
        h.service.daemon().clone(),
        "token-01".parse().unwrap(),
        previous,
        SealedToken::try_from(SEALED.to_owned()).unwrap(),
    )
}

fn signed(signer: &PrivateKey, document: &[u8]) -> TokenRequest {
    TokenRequest {
        signature: sshsig::sign(signer, APPROVAL_NAMESPACE, document).unwrap(),
        document: String::from_utf8(document.to_vec()).unwrap(),
    }
}

fn request(h: &TestService, previous: PreviousToken) -> TokenRequest {
    signed(&h.approver, &token(h, previous).canonical_bytes().unwrap())
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

/// No audit line holds the ciphertext.
fn nothing_sealed_logged(h: &TestService) {
    for line in h.audit() {
        assert!(!line.to_string().contains(&SEALED[..24]), "{line}");
    }
}

#[test]
fn a_signed_token_against_the_file_in_force_is_logged_and_a_replay_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let first = request(&h, PreviousToken::None);
    let checked = h.service.check_token(&first, &facts()).unwrap();
    assert_eq!(checked.token().id.as_str(), "token-01");
    let file = TextDigest::of_bytes(b"the new age file");
    let applied = h
        .service
        .commit_token(&checked, &PreviousToken::None, &file, &facts())
        .unwrap();
    assert_eq!(
        (&applied.digest, &applied.replaced, &applied.signed_by),
        (&file, &PreviousToken::None, checked.approver())
    );
    let lines = h.events("admin", "allowed");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["approver"], checked.approver().as_str());
    assert_eq!(
        lines[0]["reason"],
        format!("token token-01: sha256 {file} replaces none")
    );

    // Replayed once the file exists: against a file no longer in force.
    let replayed = h.service.check_token(&first, &facts()).unwrap();
    let message = refused(
        h.service.commit_token(
            &replayed,
            &PreviousToken::File(file.clone()),
            &TextDigest::of_bytes(b"another"),
            &facts(),
        ),
        RefusalCode::Admin,
    );
    assert!(
        message.contains(&format!(
            "the token in force is {file}, not the one this change replaces (none)"
        )),
        "{message}"
    );
    // A rotation against the file in force: fine.
    let rotation = request(&h, PreviousToken::File(file.clone()));
    let checked = h.service.check_token(&rotation, &facts()).unwrap();
    let next = TextDigest::of_bytes(b"the next age file");
    h.service
        .commit_token(
            &checked,
            &PreviousToken::File(file.clone()),
            &next,
            &facts(),
        )
        .unwrap();
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), 1, "the stale replay");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("token token-01: the token in force is "),
        "{}",
        denied[0]
    );
    assert_eq!(h.events("admin", "allowed").len(), 2);
    nothing_sealed_logged(&h);
}

#[test]
fn an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let document = token(&h, PreviousToken::None).canonical_bytes().unwrap();
    let mut no_signature = signed(&h.approver, &document);
    no_signature.signature = String::new();
    let mut other_bytes = signed(&h.approver, &document);
    other_bytes.document = String::from_utf8(
        token(&h, PreviousToken::File(TextDigest::of_bytes(b"x")))
            .canonical_bytes()
            .unwrap(),
    )
    .unwrap();
    let in_git = TokenRequest {
        signature: sshsig::sign(&h.approver, "git", &document).unwrap(),
        document: String::from_utf8(document.clone()).unwrap(),
    };
    let admin = Admin::new(
        h.service.daemon().clone(),
        writ_core::authority::AdminTarget::Readers,
        writ_core::signed::Replaced {
            version: 1,
            digest: TextDigest::of(""),
        },
        writ_core::authority::AdminText::try_from(String::new()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    let text = String::from_utf8(document.clone()).unwrap();
    let hostile = [
        text.replace(SEALED, "not base64!"),
        text.replace("\"token-01\"", "\"../../etc/x\""),
        text.replace("}", r#","plaintext":"x"}"#),
        format!(" {text}"),
    ];
    let mut cases = vec![
        (
            "a stranger's key",
            signed(&stranger, &document),
            RefusalCode::Signature,
        ),
        ("no signature", no_signature, RefusalCode::Signature),
        (
            "other bytes than signed",
            other_bytes,
            RefusalCode::Signature,
        ),
        ("git's namespace", in_git, RefusalCode::Signature),
        (
            "an admin change",
            signed(&h.approver, &admin),
            RefusalCode::Admin,
        ),
    ];
    for bad in &hostile {
        cases.push((
            "a hostile document",
            signed(&h.approver, bad.as_bytes()),
            RefusalCode::Admin,
        ));
    }
    // Signed for another daemon (one with the same approver): refused before anything else.
    let elsewhere = Token::new(
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            .parse()
            .unwrap(),
        "token-01".parse().unwrap(),
        PreviousToken::None,
        SealedToken::try_from(SEALED.to_owned()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    let message = refused(
        h.service
            .check_token(&signed(&h.approver, &elsewhere), &facts()),
        RefusalCode::Admin,
    );
    assert!(
        message.contains(
            "the token change names daemon SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU, not this one"
        ),
        "{message}"
    );
    let count = cases.len() + 1;
    for (what, request, code) in cases {
        let message = refused(h.service.check_token(&request, &facts()), code);
        if code == RefusalCode::Admin {
            assert!(
                message.contains("not a writ-token/2 document"),
                "{what}: {message}"
            );
        }
    }
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), count, "one line each");
    for line in &denied {
        assert!(
            line["reason"].as_str().unwrap().starts_with("token: "),
            "{line}"
        );
    }
    assert!(h.events("admin", "allowed").is_empty());
    nothing_sealed_logged(&h);
}

#[test]
fn a_sealed_service_takes_no_token() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).sealed().build(dir.path());
    let message = refused(
        h.service
            .check_token(&request(&h, PreviousToken::None), &facts()),
        RefusalCode::Sealed,
    );
    assert_eq!(message, writ_core::policy::SEALED);
}
