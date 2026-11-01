//! The software backend: the `Signer` contract (alone and behind a `QueuedSigner`), keys it
//! refuses, and nothing of a key in its `Debug` or its errors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_core::names::KeyId;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::LineEnding;
use writ_signer::contract::{queued_signer_contract, signer_contract};
use writ_signer::queue::{QueueConfig, QueuedSigner};
use writ_signer::software::SoftwareSigner;
use writ_signer::testing::{FailingSigner, software_signer};
use writ_signer::{Signer, SignerError, sshsig};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

#[test]
fn the_software_backend_passes_the_contract() {
    signer_contract(&software_signer(&["agent-01"], KeyKind::Ed25519));
    signer_contract(&software_signer(&["agent-p256"], KeyKind::P256));
    let mixed = SoftwareSigner::new([
        (id("a"), generate(KeyKind::Ed25519).unwrap()),
        (id("b"), generate(KeyKind::P256).unwrap()),
    ])
    .unwrap();
    signer_contract(&mixed);
    assert_eq!(mixed.capabilities().algorithms.len(), 2);
    assert!(mixed.capabilities().exportable);
    assert!(!mixed.capabilities().needs_touch);
}

#[test]
fn the_software_backend_passes_the_contract_behind_a_queue() {
    queued_signer_contract(software_signer(&["agent-01"], KeyKind::Ed25519));
    queued_signer_contract(software_signer(&["agent-p256", "other"], KeyKind::P256));
}

#[test]
fn the_failing_signer_passes_the_contract_until_it_fails() {
    let signer = FailingSigner::new(software_signer(&["agent-01"], KeyKind::Ed25519));
    signer_contract(&signer);
    signer.set_failing(true);
    assert!(matches!(
        sshsig(&signer, &id("agent-01"), "git", b"x"),
        Err(SignerError::Failed(k)) if k == id("agent-01")
    ));
}

#[test]
fn keys_it_refuses() {
    let key = generate(KeyKind::Ed25519).unwrap();
    assert!(matches!(
        SoftwareSigner::new([(id("a"), key.clone()), (id("a"), key.clone())]),
        Err(SignerError::DuplicateKey(k)) if k == id("a")
    ));
    // A security key: its private half is a handle on a device, never a software key.
    use writ_crypto::ssh_key::{private, public};
    let inner = key.key_data().ed25519().unwrap().public;
    let sk =
        private::SkEd25519::new(public::SkEd25519::new(inner, "ssh:"), 0x01, [7u8; 32]).unwrap();
    let sk =
        writ_crypto::ssh_key::PrivateKey::new(private::KeypairData::SkEd25519(sk), "").unwrap();
    assert!(matches!(
        SoftwareSigner::new([(id("sk"), sk)]),
        Err(SignerError::Unsupported { id: k, algorithm }) if k == id("sk")
            && algorithm == "sk-ssh-ed25519@openssh.com"
    ));
}

#[test]
fn no_key_in_debug_or_errors() {
    let key = generate(KeyKind::Ed25519).unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let signer = SoftwareSigner::new([(id("agent-01"), key)]).unwrap();
    let debug = format!("{signer:?}");
    assert_eq!(debug, r#"SoftwareSigner { keys: [KeyId("agent-01")] }"#);
    let queued = QueuedSigner::new(
        SoftwareSigner::new([(id("agent-02"), generate(KeyKind::Ed25519).unwrap())]).unwrap(),
        QueueConfig {
            name: "writ-sign-test".to_owned(),
            capacity: 1,
            deadline: std::time::Duration::from_secs(60),
        },
    )
    .unwrap();
    assert_eq!(
        format!("{queued:?}"),
        r#"QueuedSigner { keys: [KeyId("agent-02")], deadline: 60s, .. }"#
    );
    let error = signer.sign(&id("other"), b"x").unwrap_err().to_string();
    assert_eq!(error, "the signer has no key other");
    for text in [&debug, &error] {
        assert!(!text.contains(&body[..20]), "{text}");
    }
}
