//! The contract every [`Signer`] backend passes (feature `testing`), so a hardware backend
//! is held to what the software one is: for each key it holds, every (algorithm, hash) pair
//! it declares for that key's algorithm signs, and the signature verifies with the public key
//! it lists, only for the bytes signed; a pair it doesn't declare is refused by name, never
//! signed with something else; its SSHSIGs verify; an unknown key is refused by name. And the
//! decorator section: behind a [`QueuedSigner`], the backend passes the same contract, a full
//! queue refuses at once, a stuck backend times out, and its keys are still listed. And
//! [`add_key_contract`]: a backend that takes keys made outside it lists and signs with one at
//! once and refuses its id twice; one that doesn't says so, and holds nothing new. And
//! [`create_key_contract`]: a backend that makes its own keys lists and signs with one at
//! once, refuses its id twice and an algorithm it doesn't make, and, built again from what it
//! stored, signs with the same key; one that doesn't says so, and holds nothing new.

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
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat, SignerHash};
use writ_crypto::keypair::{KeyPair, verify};
use writ_crypto::keys::random_hex;

use crate::queue::{QueueConfig, QueuedSigner};
use crate::testing::GatedSigner;
use crate::{Signer, SignerError, Stored, key_algorithm, public_key, sshsig};

/// Every signer hash a pair may carry, to try the ones a backend doesn't declare.
const HASHES: [SignerHash; 4] = [
    None,
    Some(Hash::Sha256),
    Some(Hash::Sha384),
    Some(Hash::Sha512),
];

/// The message hash of the key-adding sections' SSHSIGs.
const SSHSIG_HASH: Hash = Hash::Sha512;

/// A fresh Ed25519 key for the key-adding sections.
fn new_key() -> KeyPair {
    KeyPair::generate(KeyAlgorithm::Ed25519).unwrap()
}

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
        assert_eq!(public_key(signer, &key.id).unwrap(), key.public_key);
        let algorithm = key_algorithm(signer, &key.id).unwrap();
        let declared: Vec<SignerHash> = capabilities
            .pairs
            .iter()
            .filter(|(a, _)| *a == algorithm)
            .map(|(_, hash)| *hash)
            .collect();
        assert!(
            !declared.is_empty(),
            "{}: its algorithm {algorithm} is in the capabilities",
            key.id
        );
        let data = b"the bytes the daemon built";
        for hash in HASHES {
            let signed = signer.sign(&key.id, data, hash);
            if declared.contains(&hash) {
                let signature = signed
                    .unwrap_or_else(|e| panic!("{}: a declared pair didn't sign: {e}", key.id));
                assert_eq!(
                    (signature.algorithm(), signature.hash()),
                    (algorithm, hash),
                    "{}: signed with what was asked",
                    key.id
                );
                verify(&key.public_key, data, &signature).unwrap_or_else(|e| {
                    panic!(
                        "{}: its signature with {hash:?} doesn't verify: {e}",
                        key.id
                    )
                });
                assert!(
                    matches!(
                        verify(&key.public_key, b"other bytes", &signature),
                        Err(CryptoError::BadSignature)
                    ),
                    "{}: a signature verifies only for the bytes signed",
                    key.id
                );
            } else {
                assert!(
                    matches!(&signed, Err(SignerError::Unsupported { id, .. }) if id == &key.id),
                    "{}: an undeclared pair ({hash:?}) is refused by name: {signed:?}",
                    key.id
                );
            }
        }
        // SSHSIGs with each message hash SSH takes and the backend can sign for this key.
        let msg = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n";
        let allowed = [key.public_key.clone()];
        let mut armored = None;
        for &hash in writ_crypto::algorithm::hashes(SignatureFormat::Ssh, algorithm) {
            let signer_hash =
                writ_crypto::algorithm::signer_hash(SignatureFormat::Ssh, algorithm, hash);
            if !declared.contains(&signer_hash) {
                continue;
            }
            let sig = sshsig(signer, &key.id, "git", hash, msg).unwrap();
            writ_crypto::sshsig::verify(&allowed, "git", msg, &sig).unwrap_or_else(|e| {
                panic!("{}: its SSHSIG with {hash} doesn't verify: {e}", key.id)
            });
            assert!(
                matches!(
                    writ_crypto::sshsig::verify(&allowed, "git", b"other bytes", &sig),
                    Err(CryptoError::BadSignature)
                ),
                "{}: an SSHSIG verifies only for the bytes signed",
                key.id
            );
            armored = Some(sig);
        }
        let armored = armored.unwrap_or_else(|| panic!("{}: no SSHSIG it can make", key.id));
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
        signer.sign(&unknown, b"data", None),
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
    let key = new_key();
    let public = key.public_key();
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
            .pairs
            .contains(&(KeyAlgorithm::Ed25519, None))
    );
    let msg = b"signed with a key added while it runs";
    let armored = sshsig(signer, &id, "git", SSHSIG_HASH, msg).unwrap();
    writ_crypto::sshsig::verify(std::slice::from_ref(&public), "git", msg, &armored).unwrap();
    // The same id again: refused by name, the first key kept.
    let again = new_key();
    assert!(matches!(
        signer.add_key(id.clone(), again),
        Err(SignerError::DuplicateKey(refused)) if refused == id
    ));
    assert_eq!(public_key(signer, &id).unwrap(), public);
    // Removed: no longer listed nor signed with, the others untouched; removed again, or
    // signed with after, refused by name; then the same id takes a new key, never the old one.
    signer.remove_key(&id).unwrap();
    assert_eq!(
        signer.list_keys().unwrap(),
        before,
        "removed: only the others listed"
    );
    assert!(matches!(
        sshsig(signer, &id, "git", SSHSIG_HASH, msg),
        Err(SignerError::UnknownKey(refused)) if refused == id
    ));
    assert!(matches!(
        signer.remove_key(&id),
        Err(SignerError::UnknownKey(refused)) if refused == id
    ));
    let fresh = new_key();
    let fresh_public = fresh.public_key();
    signer.add_key(id.clone(), fresh).unwrap();
    assert_eq!(public_key(signer, &id).unwrap(), fresh_public);
    assert_ne!(fresh_public, public, "a new key under the old id");
    signer.remove_key(&id).unwrap();
}

/// Builds a backend again from what its keys stored (a daemon's next start).
pub type Rebuild<'a> = &'a dyn Fn(Vec<(KeyId, Stored)>) -> Box<dyn Signer>;

/// Runs the key-making contract on a backend (it makes keys with fresh ids):
/// - one that says it makes keys ([`crate::Capabilities::makes_keys`]) makes a key of the
///   first algorithm it declares, answers its [`crate::KeyInfo`], lists it at once, signs
///   with it (verified as an SSHSIG); refuses the same id again by name, the first key kept;
///   refuses an algorithm it declares no pair for ([`SignerError::Unsupported`], named), with
///   nothing new listed; with `rebuild`, a backend built again from the stored bytes lists
///   the same public half and signs with it; removed, the key is no longer listed nor signed
///   with, removed again is refused by name, and the id then makes a new key;
/// - one that doesn't answers [`SignerError::MakesNoKeys`] with the id, and lists nothing
///   new.
pub fn create_key_contract(signer: &dyn Signer, rebuild: Option<Rebuild<'_>>) {
    let before = signer.list_keys().unwrap();
    let id: KeyId = format!("contract-made-{}", random_hex(4).unwrap())
        .parse()
        .unwrap();
    let capabilities = signer.capabilities();
    let Some(&(algorithm, _)) = capabilities.pairs.first() else {
        panic!("the backend declares no pair");
    };
    if !capabilities.makes_keys {
        assert!(matches!(
            signer.create_key(id.clone(), algorithm),
            Err(SignerError::MakesNoKeys(refused)) if refused == id
        ));
        assert_eq!(signer.list_keys().unwrap(), before, "nothing new is listed");
        return;
    }
    let created = signer.create_key(id.clone(), algorithm).unwrap();
    assert_eq!(created.info.id, id);
    let public = created.info.public_key.clone();
    assert_eq!(KeyAlgorithm::of_public(public.key_data()), Some(algorithm));
    assert!(!created.stored.as_bytes().is_empty(), "something to keep");
    let listed = signer.list_keys().unwrap();
    assert_eq!(listed.len(), before.len() + 1);
    assert!(listed.contains(&created.info), "listed at once");
    let msg = b"signed with a key the backend made while it runs";
    let hash = *writ_crypto::algorithm::hashes(SignatureFormat::Ssh, algorithm)
        .first()
        .unwrap();
    let armored = sshsig(signer, &id, "git", hash, msg).unwrap();
    writ_crypto::sshsig::verify(std::slice::from_ref(&public), "git", msg, &armored).unwrap();
    // The same id again: refused by name, the first key kept.
    assert!(matches!(
        signer.create_key(id.clone(), algorithm),
        Err(SignerError::DuplicateKey(refused)) if refused == id
    ));
    assert_eq!(public_key(signer, &id).unwrap(), public);
    // An algorithm it declares no pair for: refused by name, nothing new.
    if let Some(other) = KeyAlgorithm::ALL
        .into_iter()
        .find(|a| capabilities.pairs.iter().all(|(held, _)| held != a))
    {
        let refused: KeyId = format!("{id}-other").parse().unwrap();
        let answer = signer.create_key(refused.clone(), other);
        assert!(
            matches!(&answer, Err(SignerError::Unsupported { id, .. }) if id == &refused),
            "an algorithm it doesn't make ({other}) is refused by name: {answer:?}"
        );
        assert_eq!(signer.list_keys().unwrap().len(), before.len() + 1);
    }
    // Built again from what it stored: the same key.
    if let Some(rebuild) = rebuild {
        let again = rebuild(vec![(id.clone(), created.stored)]);
        assert_eq!(public_key(&*again, &id).unwrap(), public);
        let armored = sshsig(&*again, &id, "git", hash, msg).unwrap();
        writ_crypto::sshsig::verify(std::slice::from_ref(&public), "git", msg, &armored).unwrap();
    }
    // Removed: no longer listed nor signed with; removed again refused; the id makes a new key.
    signer.remove_key(&id).unwrap();
    assert_eq!(
        signer.list_keys().unwrap(),
        before,
        "removed: only the others"
    );
    assert!(matches!(
        sshsig(signer, &id, "git", hash, msg),
        Err(SignerError::UnknownKey(refused)) if refused == id
    ));
    assert!(matches!(
        signer.remove_key(&id),
        Err(SignerError::UnknownKey(refused)) if refused == id
    ));
    let fresh = signer.create_key(id.clone(), algorithm).unwrap();
    assert_ne!(fresh.info.public_key, public, "a new key under the old id");
    signer.remove_key(&id).unwrap();
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
///   and [`create_key_contract`] pass through the queue.
pub fn queued_signer_contract<S: Signer + 'static>(backend: S) {
    let keys = backend.list_keys().unwrap();
    let capabilities = backend.capabilities();
    let key = keys
        .first()
        .expect("the backend under test holds no key")
        .id
        .clone();
    // A pair the backend declares for that key's algorithm.
    let algorithm = key_algorithm(&backend, &key).unwrap();
    let hash = capabilities
        .pairs
        .iter()
        .find(|(a, _)| *a == algorithm)
        .expect("the key's algorithm is declared")
        .1;
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
    let stuck = queued.submit(&key, b"first", hash, SHORT).unwrap();
    gated.wait_entered();
    assert_eq!(queued.list_keys().unwrap(), keys, "listed while stuck");
    assert_eq!(queued.capabilities(), capabilities);
    // One job waits in the queue; the next one is refused at once.
    let waiting = queued.submit(&key, b"second", hash, SHORT).unwrap();
    assert!(matches!(
        queued.submit(&key, b"third", hash, GENEROUS),
        Err(SignerError::Busy)
    ));
    assert!(matches!(
        queued.sign(&key, b"third", hash),
        Err(SignerError::Busy)
    ));
    assert!(matches!(stuck.wait(), Err(SignerError::Timeout(k)) if k == key));
    assert!(matches!(waiting.wait(), Err(SignerError::Timeout(k)) if k == key));

    // The backend answers again: the first job's late result is dropped, the second one
    // (its caller gone) is skipped, the next one signs.
    closed.open();
    // The worker drains the queue on its own: wait for room (a condition, not a delay).
    let pending = loop {
        match queued.submit(&key, b"after the queue drained", hash, GENEROUS) {
            Err(SignerError::Busy) => std::thread::yield_now(),
            other => break other.unwrap(),
        }
    };
    pending.wait().unwrap();
    let msg = b"and through the trait";
    let signature = queued.sign(&key, msg, hash).unwrap();
    let public = public_key(&queued, &key).unwrap();
    verify(&public, msg, &signature).unwrap();
    assert_eq!(
        gated.calls() - before,
        3,
        "the abandoned job was never signed"
    );

    if capabilities.takes_keys {
        // A key added while the backend is stuck: it waits behind the stuck job.
        let closed = gated.close();
        let stuck = queued.submit(&key, b"held", hash, GENEROUS).unwrap();
        gated.wait_entered();
        let id: KeyId = "contract-added-behind".parse().unwrap();
        let added = new_key();
        let public = added.public_key();
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
    create_key_contract(&queued, None);
}
