//! Test support (feature `testing`): a signer that fails on demand, to check that a backend
//! failure is refused and logged, never turned into a signature; one that blocks each
//! signature until the test releases it, to drive what happens while a device signs without
//! ever sleeping; and a fake device that makes its own keys, as a Secure Enclave does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, RwLock};
use std::time::Duration;

use writ_core::names::KeyId;
use writ_crypto::algorithm::{KeyAlgorithm, SignerHash};
use writ_crypto::keypair::{KeyPair, RawSignature};
use writ_crypto::keys::{KeyKind, generate};

use crate::software::SoftwareSigner;
use crate::{Capabilities, Created, KeyInfo, Signer, SignerError, Stored};

/// A software signer with a fresh key of `kind` for each id.
pub fn software_signer(ids: &[&str], kind: KeyKind) -> SoftwareSigner {
    SoftwareSigner::new(
        ids.iter()
            .map(|id| (id.parse::<KeyId>().unwrap(), keypair(kind))),
    )
    .unwrap()
}

/// A fresh [`KeyPair`] of `kind`.
pub fn keypair(kind: KeyKind) -> KeyPair {
    KeyPair::from_ssh(generate(kind).unwrap()).unwrap()
}

/// The error a [`FailingSigner`] answers, made from the key asked for.
pub type Failure = fn(&KeyId) -> SignerError;

/// Wraps a signer; while failing, every signature is refused, with [`SignerError::Failed`] or
/// the error set by [`FailingSigner::fail_with`] (the keys are still listed, like a device
/// that is present but refuses).
pub struct FailingSigner<S> {
    inner: S,
    failure: Mutex<Option<Failure>>,
}

impl<S: Signer> FailingSigner<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            failure: Mutex::new(None),
        }
    }

    pub fn set_failing(&self, failing: bool) {
        let failed: Failure = |id| SignerError::Failed(id.clone());
        *self.failure.lock().unwrap() = failing.then_some(failed);
    }

    /// Every signature is refused with `failure` (a queue's `Busy`, `Timeout`…).
    pub fn fail_with(&self, failure: Failure) {
        *self.failure.lock().unwrap() = Some(failure);
    }
}

impl<S: Signer> Signer for FailingSigner<S> {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        self.inner.list_keys()
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        if let Some(failure) = *self.failure.lock().unwrap() {
            return Err(failure(id));
        }
        self.inner.sign(id, data, hash)
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        self.inner.add_key(id, key)
    }

    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError> {
        self.inner.create_key(id, algorithm)
    }

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.inner.remove_key(id)
    }
}

/// How long a test waits for a signature to reach a [`GatedSigner`] before failing: a bound
/// on a hang, never a pause (every wait ends on a signal well before it).
const GATE_PATIENCE: Duration = Duration::from_secs(60);

/// What a [`GatedSigner`] calls when a signature reaches its closed gate.
pub type OnEnter = Box<dyn Fn(u64) + Send + Sync>;

#[derive(Default)]
struct Gate {
    closed: bool,
    /// Signatures that reached the gate so far (each call's number is its rank).
    calls: u64,
    /// Calls waiting at the gate that [`GatedSigner::wait_entered`] hasn't handed out yet.
    unseen: VecDeque<u64>,
    /// Calls let through one by one.
    released: HashSet<u64>,
}

/// Wraps a signer; while the gate is closed, each signature waits until the test releases it
/// (one call, or all by opening the gate). A test learns that a call is waiting from
/// [`GatedSigner::wait_entered`] or an [`OnEnter`] callback: a signal, never a sleep.
/// Dereferences to the wrapped signer.
pub struct GatedSigner<S> {
    inner: S,
    gate: Mutex<Gate>,
    changed: Condvar,
    on_enter: Mutex<Option<OnEnter>>,
}

impl<S: Signer> GatedSigner<S> {
    /// An open gate: signatures pass until [`GatedSigner::close`].
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            gate: Mutex::new(Gate::default()),
            changed: Condvar::new(),
            on_enter: Mutex::new(None),
        }
    }

    /// Signatures from now on wait at the gate, until the returned guard is opened or
    /// dropped: a test that fails while a signature waits unwinds instead of hanging.
    #[must_use = "the gate opens again when the guard is dropped"]
    pub fn close(&self) -> Closed<'_, S> {
        self.gate.lock().unwrap().closed = true;
        Closed { signer: self }
    }

    /// Lets every waiting signature through, and the next ones.
    pub fn open(&self) {
        self.gate.lock().unwrap().closed = false;
        self.changed.notify_all();
    }

    /// Lets the waiting call `call` through.
    pub fn release(&self, call: u64) {
        self.gate.lock().unwrap().released.insert(call);
        self.changed.notify_all();
    }

    /// Waits until a signature is waiting at the closed gate, and returns its call number
    /// (each one once). Panics if none comes within a minute: the test hangs otherwise.
    pub fn wait_entered(&self) -> u64 {
        let gate = self.gate.lock().unwrap();
        let (mut gate, timeout) = self
            .changed
            .wait_timeout_while(gate, GATE_PATIENCE, |g| g.unseen.is_empty())
            .unwrap();
        assert!(!timeout.timed_out(), "no signature reached the gate");
        gate.unseen.pop_front().unwrap()
    }

    /// Calls `on_enter` with its number when a signature reaches the closed gate (from the
    /// signing thread, before it waits).
    pub fn on_enter(&self, on_enter: OnEnter) {
        *self.on_enter.lock().unwrap() = Some(on_enter);
    }

    /// How many signatures reached the gate (each one is let through, now or later).
    pub fn calls(&self) -> u64 {
        self.gate.lock().unwrap().calls
    }
}

/// A closed [`GatedSigner`]: opens it when dropped.
pub struct Closed<'a, S: Signer> {
    signer: &'a GatedSigner<S>,
}

impl<S: Signer> Closed<'_, S> {
    /// Lets every waiting signature through, and the next ones.
    pub fn open(self) {}
}

impl<S: Signer> Drop for Closed<'_, S> {
    fn drop(&mut self) {
        self.signer.open();
    }
}

impl<S> std::ops::Deref for GatedSigner<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.inner
    }
}

impl<S: Signer> Signer for GatedSigner<S> {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        self.inner.list_keys()
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        let mut gate = self.gate.lock().unwrap();
        let call = gate.calls;
        gate.calls += 1;
        if gate.closed {
            gate.unseen.push_back(call);
            drop(gate);
            self.changed.notify_all();
            if let Some(on_enter) = &*self.on_enter.lock().unwrap() {
                on_enter(call);
            }
            gate = self.gate.lock().unwrap();
            gate = self
                .changed
                .wait_while(gate, |g| g.closed && !g.released.contains(&call))
                .unwrap();
            gate.released.remove(&call);
        }
        drop(gate);
        self.inner.sign(id, data, hash)
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        self.inner.add_key(id, key)
    }

    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError> {
        self.inner.create_key(id, algorithm)
    }

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.inner.remove_key(id)
    }
}

/// What a [`FakeDevice`]'s stored bytes start with.
const FAKE_DEVICE: &[u8] = b"writ-fake-device/1\n";

/// A backend that makes its own keys and takes none from outside, as a device does (a Secure
/// Enclave): P-256 keys only, its stored bytes the key itself behind a header (a fake: a real
/// device's are useless off the device). Built again from what it handed out, it signs with
/// the same keys.
pub struct FakeDevice {
    keys: RwLock<BTreeMap<KeyId, KeyPair>>,
}

impl FakeDevice {
    /// A device holding the keys `stored` gives back (each from an earlier
    /// [`Signer::create_key`]); bytes it didn't hand out are [`SignerError::Failed`].
    pub fn new(stored: impl IntoIterator<Item = (KeyId, Stored)>) -> Result<Self, SignerError> {
        let mut keys = BTreeMap::new();
        for (id, bytes) in stored {
            let pem = bytes
                .as_bytes()
                .strip_prefix(FAKE_DEVICE)
                .ok_or_else(|| SignerError::Failed(id.clone()))?;
            let key = KeyPair::from_pem(pem).map_err(|_| SignerError::Failed(id.clone()))?;
            if keys.insert(id.clone(), key).is_some() {
                return Err(SignerError::DuplicateKey(id));
            }
        }
        Ok(Self {
            keys: RwLock::new(keys),
        })
    }

    /// A device holding one fresh key under each id; answers what each one stored, to build
    /// it again.
    pub fn with_keys(ids: &[&str]) -> (Self, Vec<(KeyId, Stored)>) {
        let device = Self::new([]).unwrap();
        let stored = ids
            .iter()
            .map(|id| {
                let id: KeyId = id.parse().unwrap();
                let created = device.create_key(id.clone(), KeyAlgorithm::P256).unwrap();
                (id, created.stored)
            })
            .collect();
        (device, stored)
    }
}

impl Signer for FakeDevice {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self
            .keys
            .read()
            .unwrap()
            .iter()
            .map(|(id, key)| KeyInfo {
                id: id.clone(),
                public_key: key.public_key(),
            })
            .collect())
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(id)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))?;
        if hash != Some(writ_crypto::algorithm::Hash::Sha256) {
            return Err(SignerError::Unsupported {
                id: id.clone(),
                what: writ_crypto::keypair::pair(KeyAlgorithm::P256, hash),
            });
        }
        key.sign(data, hash)
            .map_err(|_| SignerError::Failed(id.clone()))
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            pairs: vec![(
                KeyAlgorithm::P256,
                Some(writ_crypto::algorithm::Hash::Sha256),
            )],
            exportable: false,
            needs_touch: false,
            takes_keys: false,
            makes_keys: true,
        }
    }

    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError> {
        if algorithm != KeyAlgorithm::P256 {
            return Err(SignerError::Unsupported {
                id,
                what: format!("making a {algorithm} key"),
            });
        }
        let mut keys = self.keys.write().unwrap();
        if keys.contains_key(&id) {
            return Err(SignerError::DuplicateKey(id));
        }
        let key = KeyPair::generate(algorithm).unwrap();
        let mut stored = FAKE_DEVICE.to_vec();
        stored.extend_from_slice(key.to_pem().unwrap().as_bytes());
        let info = KeyInfo {
            id: id.clone(),
            public_key: key.public_key(),
        };
        keys.insert(id, key);
        Ok(Created {
            info,
            stored: Stored::new(stored),
        })
    }

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.keys
            .write()
            .unwrap()
            .remove(id)
            .map(drop)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))
    }
}
