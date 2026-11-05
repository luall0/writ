//! Admin changes on the platform fakes: an approver's `writ-admin/2` signature over a change
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
use writ_core::names::KeyFingerprint;
use writ_core::policy::DenyCode;
use writ_core::signed::{Admin, Replaced};
use writ_core::ticket::Ticket;
use writ_crypto::allowed_signers;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::PrivateKey;
use writ_crypto::sshsig;
use writ_proto::AdminRequest;
use writ_proto::AdminShown;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

const REQUEST: &str = r#"
repos:
  omega-code:
    template: feature-branch
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

/// The version a change replaces, on the daemon that shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Base {
    daemon: KeyFingerprint,
    version: u64,
    digest: TextDigest,
}

fn base(shown: &AdminShown) -> Base {
    Base {
        daemon: shown.daemon.clone(),
        version: shown.version,
        digest: shown.digest.clone(),
    }
}

/// A change of `target` to `text`, against `previous`, signed by `signer`.
fn change(signer: &PrivateKey, target: AdminTarget, previous: Base, text: &str) -> AdminRequest {
    let document = Admin::new(
        previous.daemon,
        target,
        Replaced {
            version: previous.version,
            digest: previous.digest,
        },
        AdminText::try_from(text.to_owned()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    AdminRequest {
        signature: sshsig::sign(signer, APPROVAL_NAMESPACE, &document).unwrap(),
        document: String::from_utf8(document).unwrap(),
    }
}

fn current(h: &TestService, target: AdminTarget) -> Base {
    base(&h.service.admin_show(target).unwrap())
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
    lease_by(h, &h.approver)
}

/// An active lease approved by `approver`, and its certificate's identity.
fn lease_by(h: &TestService, approver: &PrivateKey) -> writ_core::policy::CertIdentity {
    use writ_crypto::ssh_key::{Certificate, HashAlg};
    let key = generate(KeyKind::Ed25519).unwrap();
    let submitted = h
        .service
        .submit(key.public_key(), REQUEST.as_bytes(), &facts())
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    h.service
        .approve(
            &ticket.id,
            &writ_approval::testing::sign_approval(approver, &ticket),
            &facts(),
        )
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
    let request = change(&h.approver, AdminTarget::Approvers, base(&shown), &text);
    let checked: CheckedAdmin = h.service.check_admin(&request, &facts()).unwrap();
    let applied = h
        .service
        .commit_admin(
            &checked,
            parsed_approvers(&text),
            vec![],
            Default::default(),
            &facts(),
        )
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
    assert_eq!(lines[0]["approver"], checked.approver().as_str());
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
    let again = change(&next, AdminTarget::Approvers, base(&shown), &text);
    // Signed by the key in force, but against version 1: stale.
    let stale = change(
        &next,
        AdminTarget::Approvers,
        Base {
            version: 1,
            digest: checked.admin().previous.clone(),
            ..base(&shown)
        },
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
            Default::default(),
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

/// The ABA replay: approvers go from A to B and back to A, a text whose digest is the one the
/// first change named. That change, replayed (its document and signature are in the state's
/// history, and in every backup of it), must not apply again: a change names the version it
/// replaces, and versions only grow.
#[test]
fn a_change_replayed_after_the_text_came_back_never_applies_again() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let a = h.service.admin_show(AdminTarget::Approvers).unwrap();
    let lost = generate(KeyKind::Ed25519).unwrap();
    let b = format!(
        "{}lost {}\n",
        a.text,
        lost.public_key().to_openssh().unwrap()
    );
    let apply = |request: &AdminRequest, text: &str| {
        let checked = h.service.check_admin(request, &facts()).unwrap();
        h.service
            .commit_admin(
                &checked,
                parsed_approvers(text),
                vec![],
                Default::default(),
                &facts(),
            )
            .unwrap()
    };
    // A → B (version 2), then B → A again (version 3): the lost key is out.
    let first = change(&h.approver, AdminTarget::Approvers, base(&a), &b);
    assert_eq!(apply(&first, &b).version, 2);
    let back = change(
        &h.approver,
        AdminTarget::Approvers,
        current(&h, AdminTarget::Approvers),
        &a.text,
    );
    assert_eq!(apply(&back, &a.text).version, 3);
    let now = h.service.admin_show(AdminTarget::Approvers).unwrap();
    assert_eq!(now.digest, a.digest, "the text in force is A's again");

    // The first change, replayed: its digest matches the text in force, its version doesn't.
    let message = refused(h.service.check_admin(&first, &facts()), RefusalCode::Admin);
    assert!(
        message.contains(
            "the approvers in force is version 3, not the one this change replaces (version 1)"
        ),
        "{message}"
    );
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("not the one this change replaces (version 1)"),
        "{}",
        denied[0]
    );
    // Nothing changed: the lost key approves nothing.
    let shown = h.service.admin_show(AdminTarget::Approvers).unwrap();
    assert_eq!((shown.version, shown.digest), (3, a.digest.clone()));
    let ticket = pending(&h);
    let by_lost = writ_approval::testing::sign_approval(&lost, &ticket);
    let error = h
        .service
        .approve(&ticket.id, &by_lost, &facts())
        .unwrap_err();
    assert_eq!(error.code(), Some(RefusalCode::Signature), "{error}");
}

/// Removing an approver takes back what it granted: every active lease its key signed is
/// revoked by the same change (one `revoke` line each, named in the reply), and its
/// certificate refused at once; a lease another approver signed keeps working.
#[test]
fn removing_an_approver_revokes_the_leases_it_signed() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let shown = h.service.admin_show(AdminTarget::Approvers).unwrap();
    let other = generate(KeyKind::Ed25519).unwrap();
    let both = format!(
        "{}other {}\n",
        shown.text,
        other.public_key().to_openssh().unwrap()
    );
    let apply = |text: &str| {
        let request = change(
            &h.approver,
            AdminTarget::Approvers,
            current(&h, AdminTarget::Approvers),
            text,
        );
        let checked = h.service.check_admin(&request, &facts()).unwrap();
        h.service
            .commit_admin(
                &checked,
                parsed_approvers(text),
                vec![],
                Default::default(),
                &facts(),
            )
            .unwrap()
    };
    // Adding a key revokes nothing.
    assert_eq!(apply(&both).revoked, vec![]);
    let by_other = lease_by(&h, &other);
    let by_me = lease(&h);
    let repo = "omega-code".parse().unwrap();
    assert!(h.service.fetch(&by_other, &facts(), &repo).is_ok());

    // `other` removed: its lease is revoked by the change, mine is not.
    let applied = apply(&shown.text);
    assert_eq!(applied.revoked.len(), 1, "{:?}", applied.revoked);
    let revoked = &applied.revoked[0];
    assert_eq!(revoked.as_str(), by_other.key_id);
    let denial = h.service.fetch(&by_other, &facts(), &repo).unwrap_err();
    assert_eq!(denial.code, DenyCode::NotActive, "{denial:?}");
    assert!(h.service.fetch(&by_me, &facts(), &repo).is_ok());
    let lines = h.events("revoke", "done");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["lease"], revoked.as_str());
    let other_fp = other
        .public_key()
        .fingerprint(writ_crypto::ssh_key::HashAlg::Sha256)
        .to_string();
    assert_eq!(
        lines[0]["reason"],
        format!("its approver {other_fp} was removed from approvers (version 3)")
    );
}

/// The second review after M5.5 (R3): the leases a removed approver signed were listed after
/// the change was in force, and a list the store couldn't give left them running. Listed
/// under the change's lock now, before anything is written: the change is refused instead.
#[test]
fn a_removal_whose_leases_can_t_be_listed_is_refused_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).build(dir.path());
    let shown = h.service.admin_show(AdminTarget::Approvers).unwrap();
    let other = generate(KeyKind::Ed25519).unwrap();
    let both = format!(
        "{}other {}\n",
        shown.text,
        other.public_key().to_openssh().unwrap()
    );
    let apply = |text: &str, broken: bool| {
        let request = change(
            &h.approver,
            AdminTarget::Approvers,
            current(&h, AdminTarget::Approvers),
            text,
        );
        let checked = h.service.check_admin(&request, &facts()).unwrap();
        if broken {
            // The change's sweep lists the active leases first; the second list is the
            // change's own.
            h.store_breaker.fail_lease_list_after(1);
        }
        h.service.commit_admin(
            &checked,
            parsed_approvers(text),
            vec![],
            Default::default(),
            &facts(),
        )
    };
    assert_eq!(apply(&both, false).unwrap().revoked, vec![]);
    let by_other = lease_by(&h, &other);
    let repo = "omega-code".parse().unwrap();
    let version = h
        .service
        .admin_show(AdminTarget::Approvers)
        .unwrap()
        .version;
    // Removing it, the list fails: refused, the version and the lease as they were.
    let refused = apply(&shown.text, true);
    assert!(
        matches!(refused, Err(ServiceError::Internal(_))),
        "{:?}",
        refused.map(|a| a.version)
    );
    assert_eq!(
        h.service
            .admin_show(AdminTarget::Approvers)
            .unwrap()
            .version,
        version
    );
    assert!(h.service.fetch(&by_other, &facts(), &repo).is_ok());
    let denied = h.events("admin", "denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0]["reason"],
        "approvers: internal error (see the daemon's log)"
    );
    // The store back: the same removal applies, and revokes the lease.
    assert_eq!(apply(&shown.text, false).unwrap().revoked.len(), 1);
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
            "not a writ-admin/2 document",
        ),
        (
            "stale",
            change(
                &h.approver,
                AdminTarget::Readers,
                Base {
                    digest: TextDigest::of("old\n"),
                    ..previous.clone()
                },
                "x\n",
            ),
            RefusalCode::Admin,
            "not the one this change replaces",
        ),
        (
            "the text in force, under another version number",
            change(
                &h.approver,
                AdminTarget::Readers,
                Base {
                    version: previous.version + 1,
                    ..previous.clone()
                },
                "x\n",
            ),
            RefusalCode::Admin,
            "not the one this change replaces (version 2)",
        ),
        (
            "another daemon",
            change(
                &h.approver,
                AdminTarget::Readers,
                Base {
                    daemon: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
                        .parse()
                        .unwrap(),
                    ..previous.clone()
                },
                "x\n",
            ),
            RefusalCode::Admin,
            "the change names daemon SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU, not this one",
        ),
    ] {
        let message = refused(h.service.check_admin(&request, &facts()), code);
        assert!(message.contains(reason), "{what}: {message}");
    }
    assert_eq!(h.events("admin", "denied").len(), 8);
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
        h.service
            .commit_admin(&checked, parsed, vec![], Default::default(), &facts()),
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
        .commit_admin(&checked, parsed, vec![], Default::default(), &facts())
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
        .commit_admin(
            &checked,
            AdminParsed::Readers,
            vec![],
            Default::default(),
            &facts(),
        )
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

#[test]
fn a_user_id_needs_an_approver_s_signature_and_a_signed_one_is_certified_and_logged() {
    use writ_crypto::algorithm::{Hash, KeyAlgorithm};
    let one = "uids: [\"Agent <user+agent@example.org>\"]";
    let policy = format!("{POLICY}\nsigning_keys:\n  agent-ed25519-01:\n    {one}\n");
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(&policy)
        .openpgp(KeyAlgorithm::Ed25519, Hash::Sha512)
        .build(dir.path());
    let id = "agent-ed25519-01".parse().unwrap();
    let before = h.service.openpgp_certificate(&id).unwrap();
    let previous = current(&h, AdminTarget::Policy);
    let two = policy.replace(
        one,
        "uids: [\"Agent <user+agent@example.org>\", \"Fix <user+fix@example.org>\"]",
    );

    // Signed by a key that isn't an approver's: refused, logged, the certificate unchanged.
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let message = refused(
        h.service.check_admin(
            &change(&stranger, AdminTarget::Policy, previous.clone(), &two),
            &facts(),
        ),
        RefusalCode::Signature,
    );
    assert!(message.contains("which is not in approvers"), "{message}");
    assert_eq!(h.service.openpgp_certificate(&id).unwrap(), before);
    assert_eq!(current(&h, AdminTarget::Policy), previous);

    // Signed by the approver: the new user id certified at once, in the change's line.
    let request = change(&h.approver, AdminTarget::Policy, previous, &two);
    let checked = h.service.check_admin(&request, &facts()).unwrap();
    let parsed = AdminParsed::Policy(PolicyConfig::from_yaml(&two).unwrap());
    h.service
        .commit_admin(&checked, parsed, vec![], Default::default(), &facts())
        .unwrap();
    let after = h.service.openpgp_certificate(&id).unwrap();
    assert_ne!(after, before);
    let audit = std::fs::read_to_string(&h.audit_path).unwrap();
    let line = audit
        .lines()
        .rev()
        .find(|l| l.contains("\"event\":\"admin\"") && l.contains("\"result\":\"allowed\""))
        .unwrap();
    assert!(
        line.contains("; certified OpenPGP key agent-ed25519-01 (")
            && line.contains("): Agent <user+agent@example.org>, Fix <user+fix@example.org>"),
        "{line}"
    );
    // The same user ids again: the same certificate, and nothing certified in the line.
    let previous = current(&h, AdminTarget::Policy);
    let same = format!("{two}\n# a comment\n");
    let request = change(&h.approver, AdminTarget::Policy, previous, &same);
    let checked = h.service.check_admin(&request, &facts()).unwrap();
    let parsed = AdminParsed::Policy(PolicyConfig::from_yaml(&same).unwrap());
    h.service
        .commit_admin(&checked, parsed, vec![], Default::default(), &facts())
        .unwrap();
    assert_eq!(h.service.openpgp_certificate(&id).unwrap(), after);
    let audit = std::fs::read_to_string(&h.audit_path).unwrap();
    let last = audit
        .lines()
        .rev()
        .find(|l| l.contains("\"event\":\"admin\""))
        .unwrap();
    assert!(!last.contains("certified"), "{last}");
}
