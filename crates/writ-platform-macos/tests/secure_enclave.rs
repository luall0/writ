//! `se-cryptokit` on this Mac's real Secure Enclave, through the `writ-se` this build
//! compiled: the whole `Signer` contract, alone and behind a queue. A Mac without a Secure
//! Enclave fails here, naming why.
//!
//! **Only well-formed blobs reach the real Secure Enclave here, never a corrupted, cut or
//! random one** (docs/testing.md#hardware-is-never-fuzzed): one made a SEP firmware panic that
//! crashed the Mac (2026-11-12). Refusing such blobs before they reach the device is tested
//! against the fake helper (`crates/writ-signer/tests/helper.rs`).

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;

use writ_core::names::KeyId;
use writ_crypto::algorithm::KeyAlgorithm;
use writ_crypto::ssh_key::PublicKey;
use writ_platform_macos::secure_enclave::{BACKEND, BUILT_HELPER, DEADLINE};
use writ_signer::contract::{
    add_key_contract, create_key_contract, queued_signer_contract, signer_contract,
};
use writ_signer::helper::{HelperConfig, HelperSigner, Load, check};
use writ_signer::{Signer, Stored};

fn id(text: &str) -> KeyId {
    text.parse().unwrap()
}

fn config() -> HelperConfig {
    HelperConfig {
        backend: BACKEND.to_owned(),
        program: PathBuf::from(BUILT_HELPER),
        args: Vec::new(),
        deadline: DEADLINE,
    }
}

fn enclave() -> HelperSigner {
    check(&config()).unwrap_or_else(|e| {
        panic!("this Mac's Secure Enclave can't be used by writ-se ({e}): these tests need one")
    });
    HelperSigner::new(config(), []).unwrap()
}

fn loads(keys: Vec<(KeyId, Stored, PublicKey)>) -> Vec<Load> {
    keys.into_iter()
        .map(|(id, stored, public)| Load { id, stored, public })
        .collect()
}

fn rebuild(keys: Vec<(KeyId, Stored, PublicKey)>) -> Box<dyn Signer> {
    Box::new(HelperSigner::new(config(), loads(keys)).unwrap())
}

/// Keys made on the Secure Enclave: their blobs and public halves.
fn made(ids: &[&str]) -> Vec<(KeyId, Stored, PublicKey)> {
    let maker = enclave();
    ids.iter()
        .map(|k| {
            let created = maker.create_key(id(k), KeyAlgorithm::P256).unwrap();
            (id(k), created.stored, created.info.public_key)
        })
        .collect()
}

#[test]
fn the_secure_enclave_passes_the_contract_alone_and_behind_a_queue() {
    let held = HelperSigner::new(config(), loads(made(&["se-01", "se-02"]))).unwrap();
    assert!(held.refused().is_empty());
    signer_contract(&held);
    add_key_contract(&held);
    create_key_contract(&held, Some(&rebuild));
    queued_signer_contract(HelperSigner::new(config(), loads(made(&["se-01"]))).unwrap());
}

/// M7.6: the keystore's hardware recipient on this Mac's real Secure Enclave: a key-agreement
/// key made through `writ-se`, loaded again from what the daemon keeps, and the unwrap
/// contract through the `piv-p256` way. Only stanzas this crate wrapped reach the device here
/// (the contract changes a stanza's body, never its point nor the blob); hostile stanzas and
/// blobs are tested against the fake helper (`crates/writ-signer/tests/agreement.rs`).
#[test]
fn the_secure_enclave_key_agreement_passes_the_unwrap_contract() {
    use std::sync::Arc;
    use writ_crypto::piv_p256::{P256Recipient, SHARED_BYTES, UNCOMPRESSED_BYTES};
    use writ_platform::unlock::piv::{KeyAgreement, PivUnwrap};
    use writ_signer::helper::agreement::HelperAgreement;

    struct Device(HelperAgreement);
    impl KeyAgreement for Device {
        fn agree(
            &self,
            peer: &[u8; UNCOMPRESSED_BYTES],
        ) -> writ_platform::Result<zeroize::Zeroizing<[u8; SHARED_BYTES]>> {
            self.0
                .agree(peer)
                .map_err(|e| writ_platform::PlatformError::Unlock(e.to_string()))
        }
    }
    let way = |name: &str, agreement: HelperAgreement| {
        let recipient = P256Recipient::from_sec1(agreement.point(), "age1se").unwrap();
        PivUnwrap::new(name, recipient, Arc::new(Device(agreement)))
    };

    check(&config()).unwrap_or_else(|e| panic!("this Mac's Secure Enclave can't be used ({e})"));
    let (_, made) = HelperAgreement::create(&config()).unwrap();
    // Loaded from what the daemon keeps, as at each start: its frame, point and probe checked.
    let loaded = HelperAgreement::load(&config(), &made.stored, &made.point).unwrap();
    let se = way("se-01", loaded);
    let (other, _) = HelperAgreement::create(&config()).unwrap();
    let other = way("se-02", other);
    let fake = writ_platform::testing::FakeUnwrap::new("fake", [1; 16]).recipient();
    writ_platform::contract::keystore_unwrap(
        &se,
        se.recipient(),
        &[other.recipient(), &fake],
        &[&other],
        true,
        &[],
    );
    assert!(se.recipient().to_string().starts_with("age1se1"));
}
