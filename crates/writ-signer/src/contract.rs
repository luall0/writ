//! The contract every [`Signer`] backend passes (feature `testing`), so a hardware backend
//! is held to what the software one is: its signatures verify as SSHSIGs with the public key
//! it lists, only for the bytes signed, and an unknown key is refused by name.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use writ_core::names::KeyId;
use writ_crypto::CryptoError;

use crate::{Signer, SignerError, public_key, sshsig};

/// Runs the contract on a backend holding at least one key.
pub fn signer_contract(signer: &dyn Signer) {
    let keys = signer.list_keys().unwrap();
    assert!(!keys.is_empty(), "the backend under test holds no key");
    assert_eq!(signer.list_keys().unwrap(), keys, "the list is stable");
    let capabilities = signer.capabilities();
    for key in &keys {
        assert!(
            capabilities
                .algorithms
                .contains(&key.public_key.algorithm()),
            "{}: its algorithm is in the capabilities",
            key.id
        );
        assert_eq!(public_key(signer, &key.id).unwrap(), key.public_key);
        let msg = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n";
        let armored = sshsig(signer, &key.id, "git", msg).unwrap();
        let allowed = [key.public_key.clone()];
        writ_crypto::sshsig::verify(&allowed, "git", msg, &armored)
            .unwrap_or_else(|e| panic!("{}: its signature doesn't verify: {e}", key.id));
        assert!(
            matches!(
                writ_crypto::sshsig::verify(&allowed, "git", b"other bytes", &armored),
                Err(CryptoError::BadSignature)
            ),
            "{}: a signature verifies only for the bytes signed",
            key.id
        );
        // Another key's public half never verifies it.
        for other in keys.iter().filter(|o| o.id != key.id) {
            assert!(
                writ_crypto::sshsig::verify(
                    std::slice::from_ref(&other.public_key),
                    "git",
                    msg,
                    &armored
                )
                .is_err_and(|e| matches!(e, CryptoError::UnknownSigner(_))),
                "{} verified as {}",
                key.id,
                other.id
            );
        }
    }
    let unknown: KeyId = "no-such-key-for-the-contract".parse().unwrap();
    assert!(matches!(
        signer.sign(&unknown, b"data"),
        Err(SignerError::UnknownKey(id)) if id == unknown
    ));
    assert!(matches!(
        public_key(signer, &unknown),
        Err(SignerError::UnknownKey(id)) if id == unknown
    ));
}
