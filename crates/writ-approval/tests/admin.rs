//! Admin changes on the platform fakes: an approver's `writ-admin/1` signature over a change
//! against the version in force applies it at once (a new approver key signs, the old one no
//! longer; a tightened template denies its leases), recorded under the keystore's MAC and
//! logged; unsigned, wrongly signed, stale or replayed changes, a policy naming a key the
//! signer lacks, or a log that can't take the line change nothing; versions altered at rest
//! keep the daemon sealed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_approval::testing::{TestService, TestServiceBuilder};
use writ_approval::{AdminParsed, CheckedAdmin, Opened, RefusalCode, ServiceError};
use writ_core::authority::{AdminTarget, AdminText, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::config::PolicyConfig;
use writ_core::lease::{APPROVAL_NAMESPACE, State};
use writ_core::policy::DenyCode;
use writ_core::signed::Admin;
use writ_core::ticket::Ticket;
use writ_crypto::allowed_signers;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_crypto::sshsig;
use writ_proto::AdminRequest;

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
        source_addr: Some("192.0.2.9".parse().unwrap()),
        process_chain: None,
    }
}

/// A change of `target` to `text`, against `previous`, signed by `signer`.
fn change(
    signer: &PrivateKey,
    target: AdminTarget,
    previous: TextDigest,
    text: &str,
) -> AdminRequest {
    let document = Admin::new(
        target,
        previous,
        AdminText::try_from(text.to_owned()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    AdminRequest {
        signature: sshsig::sign(signer, APPROVAL_NAMESPACE, &document).unwrap(),
        document: String::from_utf8(document).unwrap(),
    }
}

fn current(h: &TestService, target: AdminTarget) -> TextDigest {
    h.service.admin_show(target).unwrap().digest
}

fn parsed_approvers(text: &str) -> AdminParsed {
    AdminParsed::Approvers(allowed_signers::parse(text, APPROVAL_NAMESPACE).unwrap())
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

/// A pending ticket's id and bytes.
fn pending(h: &TestService) -> Ticket {
    let session = generate(KeyKind::Ed25519).unwrap();
    let submitted = h
        .service
        .submit(session.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap()
}

/// An active lease (submitted, approved, waited for) and its certificate's identity.
fn lease(h: &TestService) -> writ_core::policy::CertIdentity {
    use writ_crypto::ssh_key::{Certificate, HashAlg};
    let key = generate(KeyKind::Ed25519).unwrap();
    let submitted = h
        .service
        .submit(key.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    h.service
        .approve(&ticket.id, &h.approval(&ticket), &facts())
        .unwrap();
    let decision = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(h.service.wait(&ticket.id, key.public_key()))
        .unwrap();
    let writ_proto::Decision::Active { certificate, .. } = decision else {
        panic!("expected an active lease, got {decision:?}");
    };
    let cert = Certificate::from_openssh(&certificate).unwrap();
    writ_core::policy::CertIdentity {
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
fn a_signed_change_of_the_approvers_applies_at_once_and_is_logged() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let shown = h.service.admin_show(AdminTarget::Approvers).unwrap();
    assert_eq!(shown.version, 1);
    assert!(shown.text.starts_with("me ssh-ed25519 "), "{}", shown.text);

    let next = generate(KeyKind::Ed25519).unwrap();
    let text = format!("next {}\n", next.public_key().to_openssh().unwrap());
    let request = change(
        &h.approver,
        AdminTarget::Approvers,
        shown.digest.clone(),
        &text,
    );
    let checked: CheckedAdmin = h.service.check_admin(&request, &facts()).unwrap();
    let applied = h
        .service
        .commit_admin(&checked, parsed_approvers(&text), vec![], &facts())
        .unwrap();
    assert_eq!(
        (applied.target, applied.version),
        (AdminTarget::Approvers, 2)
    );
    assert_eq!(applied.digest, TextDigest::of(&text));
    let shown = h.service.admin_show(AdminTarget::Approvers).unwrap();
    assert_eq!((shown.version, shown.text.as_str()), (2, text.as_str()));
    let lines = h.events("admin", "allowed");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["approver"], checked.approver.as_str());
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("approvers: version 2 (sha256 "),
        "{}",
        lines[0]
    );

    // At once: the old key no longer approves, the new one does.
    let ticket = pending(&h);
    let error = h
        .service
        .approve(&ticket.id, &h.approval(&ticket), &facts())
        .unwrap_err();
    assert_eq!(error.code(), Some(RefusalCode::Signature), "{error}");
    let by_next = writ_approval::testing::sign_approval(&next, &ticket);
    let ack = h.service.approve(&ticket.id, &by_next, &facts()).unwrap();
    assert_eq!(ack.state, State::Active);

    // Replayed, the same change is against a version no longer in force.
    let message = refused(
        h.service.check_admin(&request, &facts()),
        RefusalCode::Signature,
    );
    assert!(message.contains("which is not in approvers"), "{message}");
    let again = change(
        &next,
        AdminTarget::Approvers,
        TextDigest::of(&shown.text).clone(),
        &text,
    );
    // Signed by the key in force, but against version 1's digest: stale.
    let stale = change(
        &next,
        AdminTarget::Approvers,
        checked.admin.previous.clone(),
        &text,
    );
    let message = refused(h.service.check_admin(&stale, &facts()), RefusalCode::Admin);
    assert!(
        message.contains("is version 2, not the one this change replaces"),
        "{message}"
    );
    // Against the version in force: fine (the same text again, version 3). The keys the
    // daemon made for a change are in the reply and the line.
    let checked = h.service.check_admin(&again, &facts()).unwrap();
    let made = writ_proto::CreatedKey {
        id: "agent-02".parse().unwrap(),
        role: writ_proto::KeyRole::Signing,
        public_key: next.public_key().to_openssh().unwrap(),
    };
    let applied = h
        .service
        .commit_admin(
            &checked,
            parsed_approvers(&text),
            vec![made.clone()],
            &facts(),
        )
        .unwrap();
    assert_eq!((applied.version, applied.created), (3, vec![made.clone()]));
    let lines = h.events("admin", "allowed");
    assert!(
        lines.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .ends_with(&format!(
                "; created signing key agent-02: {}",
                made.public_key
            )),
        "{}",
        lines.last().unwrap()
    );
}

#[test]
fn an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let previous = current(&h, AdminTarget::Readers);
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let ok = change(
        &h.approver,
        AdminTarget::Readers,
        previous.clone(),
        "mac ssh-ed25519 X\n",
    );
    for (what, request, code, reason) in [
        (
            "a stranger's key",
            change(&stranger, AdminTarget::Readers, previous.clone(), "eve\n"),
            RefusalCode::Signature,
            "which is not in approvers",
        ),
        (
            "another namespace",
            AdminRequest {
                signature: sshsig::sign(&h.approver, "git", ok.document.as_bytes()).unwrap(),
                ..ok.clone()
            },
            RefusalCode::Signature,
            "namespace \"git\"",
        ),
        (
            "no signature",
            AdminRequest {
                signature: String::new(),
                ..ok.clone()
            },
            RefusalCode::Signature,
            "unreadable signature",
        ),
        (
            "another file's bytes",
            AdminRequest {
                document: ok.document.replace("\"readers\"", "\"approvers\""),
                ..ok.clone()
            },
            RefusalCode::Signature,
            "does not match",
        ),
        (
            "not canonical",
            AdminRequest {
                document: ok.document.replace(':', ": "),
                ..ok.clone()
            },
            RefusalCode::Admin,
            "not a writ-admin/1 document",
        ),
        (
            "stale",
            change(
                &h.approver,
                AdminTarget::Readers,
                TextDigest::of("old\n"),
                "x\n",
            ),
            RefusalCode::Admin,
            "not the one this change replaces",
        ),
    ] {
        let message = refused(h.service.check_admin(&request, &facts()), code);
        assert!(message.contains(reason), "{what}: {message}");
    }
    assert_eq!(h.events("admin", "denied").len(), 6);
    assert_eq!(h.events("admin", "allowed").len(), 0);
    assert_eq!(
        current(&h, AdminTarget::Readers),
        previous,
        "nothing changed"
    );
}

#[test]
fn a_tightened_template_denies_its_leases_and_a_key_the_signer_lacks_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let cert = lease(&h);
    let repo = "omega-code".parse().unwrap();
    assert!(h.service.fetch(&cert, &facts(), &repo).is_ok());
    let previous = current(&h, AdminTarget::Policy);

    // A template naming a signing key the signer doesn't hold: refused, nothing changed.
    let unknown = POLICY.replace("agent-ed25519-01", "agent-unknown-01");
    assert_ne!(unknown, POLICY);
    let request = change(&h.approver, AdminTarget::Policy, previous.clone(), &unknown);
    let checked = h.service.check_admin(&request, &facts()).unwrap();
    let parsed = AdminParsed::Policy(PolicyConfig::from_yaml(&unknown).unwrap());
    let message = refused(
        h.service.commit_admin(&checked, parsed, vec![], &facts()),
        RefusalCode::Admin,
    );
    assert!(
        message.contains("which the signer doesn't hold"),
        "{message}"
    );
    assert_eq!(current(&h, AdminTarget::Policy), previous);

    // The template tightened below the lease: its lease is denied (`config`) at once.
    let tight = POLICY.replacen("max_signatures: 50", "max_signatures: 1", 1);
    assert_ne!(tight, POLICY, "the fixture changed");
    let request = change(&h.approver, AdminTarget::Policy, previous, &tight);
    let checked = h.service.check_admin(&request, &facts()).unwrap();
    let parsed = AdminParsed::Policy(PolicyConfig::from_yaml(&tight).unwrap());
    h.service
        .commit_admin(&checked, parsed, vec![], &facts())
        .unwrap();
    let denial = h.service.fetch(&cert, &facts(), &repo).unwrap_err();
    assert_eq!(denial.code, DenyCode::Config, "{denial:?}");
}

#[test]
fn a_change_the_audit_log_cannot_take_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let previous = current(&h, AdminTarget::Readers);
    let request = change(
        &h.approver,
        AdminTarget::Readers,
        previous.clone(),
        "mac ssh-ed25519 X\n",
    );
    let checked = h.service.check_admin(&request, &facts()).unwrap();
    h.audit_breaker.set_broken(true);
    let error = h
        .service
        .commit_admin(&checked, AdminParsed::Readers, vec![], &facts())
        .unwrap_err();
    assert!(matches!(error, ServiceError::AuditLog(_)), "{error}");
    h.audit_breaker.set_broken(false);
    assert_eq!(current(&h, AdminTarget::Readers), previous);
}

#[test]
fn versions_whose_mac_is_not_the_keystore_s_keep_the_daemon_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).sealed().build(dir.path());
    // Another keystore's key: the versions in force aren't its.
    let foreign = Opened {
        authority: writ_crypto::authority::AuthorityKey::generate().unwrap(),
        ..h.opened()
    };
    let message = refused(
        h.service.unseal(foreign, None, &facts()),
        RefusalCode::Unseal,
    );
    assert!(
        message.starts_with("the policy, approvers and readers in force were altered at rest"),
        "{message}"
    );
    assert!(h.service.is_sealed());
    h.open().unwrap();

    // The approvers in force, changed in the store behind the daemon's back: the next start
    // refuses to unseal.
    drop(h);
    let conn = rusqlite::Connection::open(dir.path().join("leases.db")).unwrap();
    let eve = generate(KeyKind::Ed25519).unwrap();
    let text = format!("eve {}\n", eve.public_key().to_openssh().unwrap());
    conn.execute(
        "UPDATE authority SET text = ?1, digest = ?2 WHERE target = 'approvers'",
        rusqlite::params![text, TextDigest::of(&text).as_str()],
    )
    .unwrap();
    drop(conn);
    let h = TestServiceBuilder::new(POLICY).sealed().build(dir.path());
    let message = refused(h.open(), RefusalCode::Unseal);
    assert!(message.contains("altered at rest"), "{message}");
}
