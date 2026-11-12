//! A backend that makes its own keys (`testing::FakeDevice`, a stand-in for a Secure Enclave):
//! the whole `Signer` contract, alone and behind a queue; built again from what it stored;
//! bytes it didn't hand out refused; nothing of what it stores in `Debug`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_core::names::KeyId;
use writ_crypto::algorithm::{Hash, KeyAlgorithm};
use writ_signer::contract::{
    add_key_contract, create_key_contract, queued_signer_contract, signer_contract,
};
use writ_signer::testing::FakeDevice;
use writ_signer::{Signer, SignerError, Stored};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

fn rebuild(stored: Vec<(KeyId, Stored, writ_crypto::ssh_key::PublicKey)>) -> Box<dyn Signer> {
    Box::new(FakeDevice::new(stored.into_iter().map(|(id, s, _)| (id, s))).unwrap())
}

#[test]
fn a_device_passes_the_contract_alone_and_behind_a_queue() {
    let (device, _) = FakeDevice::with_keys(&["agent-01", "agent-02"]);
    signer_contract(&device);
    let capabilities = device.capabilities();
    assert!(capabilities.makes_keys && !capabilities.takes_keys);
    assert!(!capabilities.exportable);
    add_key_contract(&device);
    create_key_contract(&device, Some(&rebuild));
    // A device holding no key yet makes one too.
    let empty = FakeDevice::new([]).unwrap();
    create_key_contract(&empty, Some(&rebuild));
    assert!(empty.list_keys().unwrap().is_empty());
    let (device, _) = FakeDevice::with_keys(&["agent-01"]);
    queued_signer_contract(device);
}

#[test]
fn built_again_from_what_it_stored_it_holds_the_same_keys() {
    let (device, stored) = FakeDevice::with_keys(&["a", "b"]);
    let again = FakeDevice::new(stored).unwrap();
    assert_eq!(again.list_keys().unwrap(), device.list_keys().unwrap());
    let msg = b"signed by the device built again";
    let sig = writ_signer::sshsig(&again, &id("a"), "git", Hash::Sha256, msg).unwrap();
    let public = writ_signer::public_key(&device, &id("a")).unwrap();
    writ_crypto::sshsig::verify(&[public], "git", msg, &sig).unwrap();
}

#[test]
fn bytes_it_did_not_hand_out_are_refused_by_name() {
    for bytes in [
        b"".to_vec(),
        b"writ-fake-device/1\nnot a key".to_vec(),
        b"another device's blob".to_vec(),
    ] {
        assert!(matches!(
            FakeDevice::new([(id("k"), Stored::new(bytes))]),
            Err(SignerError::Failed(k)) if k == id("k")
        ));
    }
    let (_, mut stored) = FakeDevice::with_keys(&["k"]);
    let (_, bytes) = stored.pop().unwrap();
    let twice = vec![
        (id("k"), Stored::new(bytes.as_bytes().to_vec())),
        (id("k"), bytes),
    ];
    assert!(matches!(
        FakeDevice::new(twice),
        Err(SignerError::DuplicateKey(k)) if k == id("k")
    ));
}

#[test]
fn what_it_stores_is_never_printed() {
    let device = FakeDevice::new([]).unwrap();
    let created = device.create_key(id("k"), KeyAlgorithm::P256).unwrap();
    let len = created.stored.as_bytes().len();
    let debug = format!("{created:?}");
    assert!(debug.contains(&format!("Stored({len} bytes)")), "{debug}");
    let text = String::from_utf8_lossy(created.stored.as_bytes()).into_owned();
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .skip(1)
        .collect();
    assert!(!debug.contains(&body[..20]), "{debug}");
}
