//! `Routed`: several backends behind one `Signer`, each key on one of them. The contract over
//! a software backend and a device together; keys added and made on the backend named; an id
//! on two backends refused; and a stuck device never holding up a software key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::time::Duration;

use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_crypto::keys::KeyKind;
use writ_signer::contract::{add_key_contract, create_key_contract, signer_contract};
use writ_signer::queue::{QueueConfig, QueuedSigner};
use writ_signer::route::{Backends, Routed};
use writ_signer::testing::{FakeDevice, GatedSigner, keypair, software_signer};
use writ_signer::{Signer, SignerError};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

fn backends(list: Vec<(&str, Arc<dyn Signer>)>) -> Backends {
    list.into_iter().map(|(n, s)| (n.to_owned(), s)).collect()
}

fn both() -> Routed {
    let (device, _) = FakeDevice::with_keys(&["se-01"]);
    Routed::new(backends(vec![
        (
            "software",
            Arc::new(software_signer(&["sw-01"], KeyKind::Ed25519)),
        ),
        ("se-cryptokit", Arc::new(device)),
    ]))
    .unwrap()
}

#[test]
fn a_software_backend_and_a_device_together_pass_the_contract() {
    let routed = both();
    let ids: Vec<KeyId> = routed
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(ids, [id("se-01"), id("sw-01")]);
    signer_contract(&routed);
    let capabilities = routed.capabilities();
    assert!(capabilities.takes_keys && capabilities.makes_keys && capabilities.exportable);
    // Through the trait: added to the one that takes keys, made on the one that makes them.
    add_key_contract(&routed);
    create_key_contract(&routed, None);
    assert_eq!(routed.list_keys().unwrap().len(), 2);
}

#[test]
fn keys_land_on_the_backend_named() {
    let routed = both();
    let added = routed
        .add_key_on("software", id("sw-02"), keypair(KeyKind::P256))
        .unwrap();
    let on_software = routed.on("software").unwrap().list_keys().unwrap();
    assert!(on_software.contains(&added));
    let made = routed
        .create_key_on("se-cryptokit", id("se-02"), KeyAlgorithm::P256)
        .unwrap();
    let on_device = routed.on("se-cryptokit").unwrap().list_keys().unwrap();
    assert!(on_device.contains(&made.info));
    // Signed by the backend that holds each.
    for key in ["sw-02", "se-02"] {
        writ_signer::sshsig(&routed, &id(key), "git", Hash::Sha256, b"m").unwrap();
    }
    // An id another backend holds: refused by name, on either verb.
    assert!(matches!(
        routed.create_key_on("se-cryptokit", id("sw-02"), KeyAlgorithm::P256),
        Err(SignerError::DuplicateKey(k)) if k == id("sw-02")
    ));
    assert!(matches!(
        routed.add_key_on("software", id("se-02"), keypair(KeyKind::P256)),
        Err(SignerError::DuplicateKey(k)) if k == id("se-02")
    ));
    // The verb a backend doesn't have, on it: its own refusal.
    assert!(matches!(
        routed.create_key_on("software", id("x"), KeyAlgorithm::P256),
        Err(SignerError::MakesNoKeys(k)) if k == id("x")
    ));
    assert!(matches!(
        routed.add_key_on("se-cryptokit", id("x"), keypair(KeyKind::P256)),
        Err(SignerError::CannotTakeKeys(k)) if k == id("x")
    ));
    // A backend it doesn't have.
    let refused = routed
        .create_key_on("yubikey", id("x"), KeyAlgorithm::P256)
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        "key x: the backend yubikey is not supported by this backend"
    );
    // Removed from the backend that holds it.
    routed.remove_key(&id("se-02")).unwrap();
    assert!(matches!(
        routed.sign(&id("se-02"), b"m", Some(Hash::Sha256)),
        Err(SignerError::UnknownKey(k)) if k == id("se-02")
    ));
}

#[test]
fn an_id_on_two_backends_is_refused() {
    let shared = || -> Arc<dyn Signer> { Arc::new(software_signer(&["same"], KeyKind::P256)) };
    assert!(matches!(
        Routed::new(backends(vec![("a", shared()), ("b", shared())])),
        Err(SignerError::DuplicateKey(k)) if k == id("same")
    ));
    // Two backends that both make keys: the trait's verb names none, so it is refused.
    let routed = Routed::new(backends(vec![
        ("a", Arc::new(FakeDevice::new([]).unwrap())),
        ("b", Arc::new(FakeDevice::new([]).unwrap())),
    ]))
    .unwrap();
    assert!(matches!(
        routed.create_key(id("k"), KeyAlgorithm::P256),
        Err(SignerError::Unsupported { id: k, .. }) if k == id("k")
    ));
    assert!(matches!(
        routed.add_key(id("k"), keypair(KeyKind::P256)),
        Err(SignerError::CannotTakeKeys(k)) if k == id("k")
    ));
}

#[test]
fn a_stuck_device_never_holds_up_a_software_key() {
    let (device, _) = FakeDevice::with_keys(&["se-01"]);
    let gated = Arc::new(GatedSigner::new(device));
    let queue = |name: &str, deadline| QueueConfig {
        name: name.to_owned(),
        capacity: 4,
        deadline,
    };
    let device_queue = QueuedSigner::new(
        Arc::clone(&gated),
        queue("writ-sign-se", Duration::from_secs(60)),
    )
    .unwrap();
    let software_queue = QueuedSigner::new(
        software_signer(&["sw-01"], KeyKind::Ed25519),
        queue("writ-sign-sw", Duration::from_secs(60)),
    )
    .unwrap();
    let routed = Routed::new(backends(vec![
        ("se-cryptokit", Arc::new(device_queue)),
        ("software", Arc::new(software_queue)),
    ]))
    .unwrap();
    let closed = gated.close();
    std::thread::scope(|scope| {
        let stuck = scope.spawn(|| routed.sign(&id("se-01"), b"held", Some(Hash::Sha256)));
        gated.wait_entered();
        // The device holds its job; the software key signs all the same, and both are listed.
        routed.sign(&id("sw-01"), b"through", None).unwrap();
        assert_eq!(routed.list_keys().unwrap().len(), 2);
        closed.open();
        stuck.join().unwrap().unwrap();
    });
}
