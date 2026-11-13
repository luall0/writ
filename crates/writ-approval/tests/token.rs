//! Sealed tokens on the platform fakes: an approver's `writ-token/3` signature, against the
//! id's change count and the token file in force, is logged, counted and answered (the
//! daemon's write runs under the same lock); unsigned, wrongly signed, malformed, stale or
//! replayed changes are refused and logged, a replay even once the id's file is gone; a
//! sealed service takes none; no line ever holds the token or its ciphertext.

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
use writ_core::signed::{Admin, Token, TokenReplaced};
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

fn token(h: &TestService, version: u64, previous: PreviousToken) -> Token {
    Token::new(
        h.service.daemon().clone(),
        "token-01".parse().unwrap(),
        TokenReplaced { version, previous },
        SealedToken::try_from(SEALED.to_owned()).unwrap(),
    )
}

fn signed(signer: &PrivateKey, document: &[u8]) -> TokenRequest {
    TokenRequest {
        signature: sshsig::sign(signer, APPROVAL_NAMESPACE, document).unwrap(),
        document: String::from_utf8(document.to_vec()).unwrap(),
    }
}

fn request(h: &TestService, version: u64, previous: PreviousToken) -> TokenRequest {
    signed(
        &h.approver,
        &token(h, version, previous).canonical_bytes().unwrap(),
    )
}

/// The daemon's write of the file, as `commit_token` runs it: counted in `writes`.
fn written(writes: &std::cell::Cell<u32>) -> impl FnOnce() -> Result<(), String> + '_ {
    move || {
        writes.set(writes.get() + 1);
        Ok(())
    }
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
    let id = "token-01".parse().unwrap();
    let writes = std::cell::Cell::new(0);
    assert_eq!(h.service.token_version(&id).unwrap(), 0);
    let first = request(&h, 0, PreviousToken::None);
    let checked = h.service.check_token(&first, &facts()).unwrap();
    assert_eq!(checked.token().id.as_str(), "token-01");
    let file = TextDigest::of_bytes(b"the new age file");
    let applied = h
        .service
        .commit_token(
            &checked,
            &PreviousToken::None,
            &file,
            &facts(),
            written(&writes),
        )
        .unwrap();
    assert_eq!(
        (
            applied.version,
            &applied.digest,
            &applied.replaced,
            &applied.signed_by
        ),
        (1, &file, &PreviousToken::None, checked.approver())
    );
    assert_eq!(writes.get(), 1, "written once, under the commit");
    assert_eq!(h.service.token_version(&id).unwrap(), 1);
    let lines = h.events("admin", "allowed");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["approver"], checked.approver().as_str());
    assert_eq!(
        lines[0]["reason"],
        format!("token token-01: version 1 (sha256 {file}) replaces version 0 (no token)")
    );

    // Replayed once the file exists: its count is spent.
    let replayed = h.service.check_token(&first, &facts()).unwrap();
    let message = refused(
        h.service.commit_token(
            &replayed,
            &PreviousToken::File(file.clone()),
            &TextDigest::of_bytes(b"another"),
            &facts(),
            written(&writes),
        ),
        RefusalCode::Admin,
    );
    assert!(
        message.contains(
            "token token-01: 1 changes of it were applied, not the 0 this change replaces"
        ),
        "{message}"
    );
    // The right count against another file than the one in force: stale too.
    let elsewhere = request(&h, 1, PreviousToken::File(TextDigest::of_bytes(b"x")));
    let checked = h.service.check_token(&elsewhere, &facts()).unwrap();
    let message = refused(
        h.service.commit_token(
            &checked,
            &PreviousToken::File(file.clone()),
            &TextDigest::of_bytes(b"another"),
            &facts(),
            written(&writes),
        ),
        RefusalCode::Admin,
    );
    assert!(
        message.contains(&format!(
            "the token in force is {file}, not the one this change replaces"
        )),
        "{message}"
    );
    assert_eq!(writes.get(), 1, "nothing written for either");
    // A rotation against the count and the file in force: fine.
    let rotation = request(&h, 1, PreviousToken::File(file.clone()));
    let checked = h.service.check_token(&rotation, &facts()).unwrap();
    let next = TextDigest::of_bytes(b"the next age file");
    let applied = h
        .service
        .commit_token(
            &checked,
            &PreviousToken::File(file.clone()),
            &next,
            &facts(),
            written(&writes),
        )
        .unwrap();
    assert_eq!(applied.version, 2);
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), 2, "the two stale changes");
    assert!(
        denied.iter().all(|line| line["reason"]
            .as_str()
            .unwrap()
            .starts_with("token token-01: ")),
        "{denied:?}"
    );
    assert_eq!(h.events("admin", "allowed").len(), 2);
    nothing_sealed_logged(&h);
}

/// The review after M7.6 (A-6): removing a key deletes its token file, so the file in force
/// said `none` again once the id was declared again, and the id's first change, replayed by
/// anyone who read it, put an old token back with no fresh signature. The count outlives the
/// file: the replay is refused, on both sides of the count, and only a change signed for the
/// count in force applies.
#[test]
fn a_token_replayed_once_its_file_was_deleted_is_refused_by_its_count() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let writes = std::cell::Cell::new(0);
    let first = request(&h, 0, PreviousToken::None);
    let checked = h.service.check_token(&first, &facts()).unwrap();
    let file = TextDigest::of_bytes(b"the first age file");
    h.service
        .commit_token(
            &checked,
            &PreviousToken::None,
            &file,
            &facts(),
            written(&writes),
        )
        .unwrap();
    // The key removed (its file deleted with it) and declared again: no file in force.
    let gone = PreviousToken::None;
    let commit = |request: &TokenRequest| {
        let checked = h.service.check_token(request, &facts()).unwrap();
        h.service.commit_token(
            &checked,
            &gone,
            &TextDigest::of_bytes(b"replayed"),
            &facts(),
            written(&writes),
        )
    };
    let message = refused(commit(&first), RefusalCode::Admin);
    assert_eq!(
        message,
        "token token-01: 1 changes of it were applied, not the 0 this change replaces: it was \
         applied already, or another came first (run writ admin token token-01 again)"
    );
    // One past the count: refused too.
    let message = refused(commit(&request(&h, 2, gone.clone())), RefusalCode::Admin);
    assert!(
        message.contains("not the 2 this change replaces"),
        "{message}"
    );
    assert_eq!(writes.get(), 1, "nothing written for the replays");
    // At the count: a new signature, taken.
    let applied = commit(&request(&h, 1, gone.clone())).unwrap();
    assert_eq!(applied.version, 2);
    assert_eq!(writes.get(), 2);
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), 2, "{denied:?}");
}

/// No line, no change: a log that can't take the line counts and writes nothing; a write
/// that fails is refused and logged, its count spent (the document can't apply again).
#[test]
fn a_token_change_is_counted_and_written_only_after_its_line() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let id = "token-01".parse().unwrap();
    let writes = std::cell::Cell::new(0);
    let first = request(&h, 0, PreviousToken::None);
    let checked = h.service.check_token(&first, &facts()).unwrap();
    let file = TextDigest::of_bytes(b"an age file");
    h.audit_breaker.set_broken(true);
    let error = h
        .service
        .commit_token(
            &checked,
            &PreviousToken::None,
            &file,
            &facts(),
            written(&writes),
        )
        .unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error:?}");
    h.audit_breaker.set_broken(false);
    assert_eq!(h.service.token_version(&id).unwrap(), 0, "nothing counted");
    assert_eq!(writes.get(), 0, "nothing written");

    let message = refused(
        h.service
            .commit_token(&checked, &PreviousToken::None, &file, &facts(), || {
                Err("no space left on the device".to_owned())
            }),
        RefusalCode::Admin,
    );
    assert_eq!(
        message,
        "token token-01: not written: no space left on the device"
    );
    assert_eq!(
        h.service.token_version(&id).unwrap(),
        1,
        "the document is spent"
    );
    let denied = h.events("admin", "denied");
    assert_eq!(
        denied.last().unwrap()["reason"],
        "not applied: token token-01: not written: no space left on the device"
    );
    let replayed = h.service.check_token(&first, &facts()).unwrap();
    refused(
        h.service.commit_token(
            &replayed,
            &PreviousToken::None,
            &file,
            &facts(),
            written(&writes),
        ),
        RefusalCode::Admin,
    );
    assert_eq!(writes.get(), 0);
}

#[test]
fn an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let document = token(&h, 0, PreviousToken::None).canonical_bytes().unwrap();
    let mut no_signature = signed(&h.approver, &document);
    no_signature.signature = String::new();
    let mut other_bytes = signed(&h.approver, &document);
    other_bytes.document = String::from_utf8(
        token(&h, 0, PreviousToken::File(TextDigest::of_bytes(b"x")))
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
        // The format before (the review after M7.6, A-6): no count, refused.
        text.replace("writ-token/3", "writ-token/2")
            .replace(r#""version":0,"#, ""),
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
        TokenReplaced {
            version: 0,
            previous: PreviousToken::None,
        },
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
    let count = cases.len() + 2;
    for (what, request, code) in cases {
        let message = refused(h.service.check_token(&request, &facts()), code);
        if code == RefusalCode::Admin {
            assert!(
                message.contains("not a writ-token/3 document"),
                "{what}: {message}"
            );
        }
    }
    // The format before, refused with its exact reason.
    let message = refused(
        h.service
            .check_token(&signed(&h.approver, hostile[4].as_bytes()), &facts()),
        RefusalCode::Admin,
    );
    assert!(
        message.starts_with(
            "not a writ-token/3 document: not a canonical writ-token/3 document: unknown \
             variant `writ-token/2`, expected `writ-token/3`"
        ),
        "{message}"
    );
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
            .check_token(&request(&h, 0, PreviousToken::None), &facts()),
        RefusalCode::Sealed,
    );
    assert_eq!(message, writ_core::policy::SEALED);
}
