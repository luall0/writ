//! The contract every [`Signer`] backend passes (feature `testing`), so a hardware backend
//! is held to what the software one is: its signatures verify as SSHSIGs with the public key
//! it lists, only for the bytes signed, and an unknown key is refused by name. And the
//! decorator section: behind a [`QueuedSigner`], the backend passes the same contract, a full
//! queue refuses at once, a stuck backend times out, and its keys are still listed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::time::Duration;

use writ_core::names::KeyId;
use writ_crypto::CryptoError;

use crate::queue::{QueueConfig, QueuedSigner};
use crate::testing::GatedSigner;
use crate::{Signer, SignerError, public_key, sshsig};

/// A deadline no signature of a working backend comes near, for the jobs that must succeed.
const GENEROUS: Duration = Duration::from_secs(60);

/// A deadline for the jobs a closed gate holds: they time out whatever its length.
const SHORT: Duration = Duration::from_millis(20);

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

/// The decorator section: `backend` behind a [`QueuedSigner`] (with a [`GatedSigner`] between
/// them, to hold the backend stuck on a signal):
/// - the whole [`signer_contract`] passes through the queue;
/// - while the backend is stuck, `list_keys` and `capabilities` still answer, from the cache;
/// - a full queue refuses at once with [`SignerError::Busy`];
/// - a job the stuck backend doesn't answer returns [`SignerError::Timeout`] with its key;
/// - once the backend answers again, a job whose caller gave up is skipped (never signed for
///   nobody), the late result is thrown away, and the next job signs.
pub fn queued_signer_contract<S: Signer + 'static>(backend: S) {
    let keys = backend.list_keys().unwrap();
    let capabilities = backend.capabilities();
    let key = keys
        .first()
        .expect("the backend under test holds no key")
        .id
        .clone();
    let gated = std::sync::Arc::new(GatedSigner::new(backend));
    let queued = QueuedSigner::new(
        std::sync::Arc::clone(&gated),
        QueueConfig {
            name: "writ-sign-contract".to_owned(),
            capacity: 1,
            deadline: GENEROUS,
        },
    )
    .unwrap();
    signer_contract(&queued);
    let before = gated.calls();

    gated.close();
    // Taken by the worker, which is now stuck in the backend.
    let stuck = queued.submit(&key, b"first", SHORT).unwrap();
    gated.wait_entered();
    assert_eq!(queued.list_keys().unwrap(), keys, "listed while stuck");
    assert_eq!(queued.capabilities(), capabilities);
    // One job waits in the queue; the next one is refused at once.
    let waiting = queued.submit(&key, b"second", SHORT).unwrap();
    assert!(matches!(
        queued.submit(&key, b"third", GENEROUS),
        Err(SignerError::Busy)
    ));
    assert!(matches!(
        queued.sign(&key, b"third"),
        Err(SignerError::Busy)
    ));
    assert!(matches!(stuck.wait(), Err(SignerError::Timeout(k)) if k == key));
    assert!(matches!(waiting.wait(), Err(SignerError::Timeout(k)) if k == key));

    // The backend answers again: the first job's late result is dropped, the second one
    // (its caller gone) is skipped, the next one signs.
    gated.open();
    // The worker drains the queue on its own: wait for room (a condition, not a delay).
    let pending = loop {
        match queued.submit(&key, b"after the queue drained", GENEROUS) {
            Err(SignerError::Busy) => std::thread::yield_now(),
            other => break other.unwrap(),
        }
    };
    pending.wait().unwrap();
    let msg = b"and through the trait";
    let armored = sshsig(&queued, &key, "git", msg).unwrap();
    let public = public_key(&queued, &key).unwrap();
    writ_crypto::sshsig::verify(&[public], "git", msg, &armored).unwrap();
    assert_eq!(
        gated.calls() - before,
        3,
        "the abandoned job was never signed"
    );
}
