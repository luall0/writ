//! The contract every [`Signer`] backend passes (feature `testing`), so a hardware backend
//! is held to what the software one is: its signatures verify as SSHSIGs with the public key
//! it lists, only for the bytes signed, and an unknown key is refused by name. And the
//! decorator section: behind a [`QueuedSigner`], the backend passes the same contract, a full
//! queue refuses at once, a stuck backend times out, and its keys are still listed. And
//! [`add_key_contract`]: a backend that takes keys made outside it lists and signs with one at
//! once and refuses its id twice; one that doesn't says so, and holds nothing new.

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
use writ_crypto::keys::{KeyKind, generate, random_hex};

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

/// Runs the key-adding contract on a backend (it adds a key with a fresh id):
/// - one that says it takes keys ([`crate::Capabilities::takes_keys`]) answers the key's
///   [`crate::KeyInfo`], lists it at once, signs with it (verified as an SSHSIG), has its
///   algorithm in its capabilities, and refuses the same id again by name;
/// - one that doesn't answers [`SignerError::CannotTakeKeys`] with the id, and lists nothing
///   new.
pub fn add_key_contract(signer: &dyn Signer) {
    let before = signer.list_keys().unwrap();
    let id: KeyId = format!("contract-added-{}", random_hex(4).unwrap())
        .parse()
        .unwrap();
    let key = generate(KeyKind::Ed25519).unwrap();
    let public = key.public_key().clone();
    if !signer.capabilities().takes_keys {
        assert!(matches!(
            signer.add_key(id.clone(), key),
            Err(SignerError::CannotTakeKeys(refused)) if refused == id
        ));
        assert_eq!(signer.list_keys().unwrap(), before, "nothing new is listed");
        return;
    }
    let info = signer.add_key(id.clone(), key).unwrap();
    assert_eq!((&info.id, &info.public_key), (&id, &public));
    let listed = signer.list_keys().unwrap();
    assert_eq!(listed.len(), before.len() + 1);
    assert!(listed.contains(&info), "listed at once");
    assert!(
        signer
            .capabilities()
            .algorithms
            .contains(&public.algorithm())
    );
    let msg = b"signed with a key added while it runs";
    let armored = sshsig(signer, &id, "git", msg).unwrap();
    writ_crypto::sshsig::verify(std::slice::from_ref(&public), "git", msg, &armored).unwrap();
    // The same id again: refused by name, the first key kept.
    let again = generate(KeyKind::Ed25519).unwrap();
    assert!(matches!(
        signer.add_key(id.clone(), again),
        Err(SignerError::DuplicateKey(refused)) if refused == id
    ));
    assert_eq!(public_key(signer, &id).unwrap(), public);
}

/// The decorator section: `backend` behind a [`QueuedSigner`] (with a [`GatedSigner`] between
/// them, to hold the backend stuck on a signal):
/// - the whole [`signer_contract`] passes through the queue;
/// - while the backend is stuck, `list_keys` and `capabilities` still answer, from the cache;
/// - a full queue refuses at once with [`SignerError::Busy`];
/// - a job the stuck backend doesn't answer returns [`SignerError::Timeout`] with its key;
/// - once the backend answers again, a job whose caller gave up is skipped (never signed for
///   nobody), the late result is thrown away, and the next job signs;
/// - a key added while the backend is stuck waits its turn behind the job before it (not
///   listed until the backend took it), then lands; and the whole [`add_key_contract`]
///   passes through the queue.
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

    let closed = gated.close();
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
    closed.open();
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

    if capabilities.takes_keys {
        // A key added while the backend is stuck: it waits behind the stuck job.
        let closed = gated.close();
        let stuck = queued.submit(&key, b"held", GENEROUS).unwrap();
        gated.wait_entered();
        let id: KeyId = "contract-added-behind".parse().unwrap();
        let added = generate(KeyKind::Ed25519).unwrap();
        let public = added.public_key().clone();
        std::thread::scope(|scope| {
            let adding = scope.spawn(|| queued.add_key(id.clone(), added));
            // Whether or not the add is queued yet, the backend can't have taken it.
            assert!(
                queued.list_keys().unwrap().iter().all(|k| k.id != id),
                "listed before the backend took it"
            );
            closed.open();
            stuck.wait().unwrap();
            let info = adding.join().unwrap().unwrap();
            assert_eq!(info.public_key, public);
        });
        assert_eq!(public_key(&queued, &id).unwrap(), public);
    }
    add_key_contract(&queued);
}
