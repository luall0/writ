//! Test support (feature `testing`): a signer that fails on demand, to check that a backend
//! failure is refused and logged, never turned into a signature; and one that blocks each
//! signature until the test releases it, to drive what happens while a device signs without
//! ever sleeping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::collections::{HashSet, VecDeque};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use writ_core::names::KeyId;
use writ_crypto::algorithm::SignerHash;
use writ_crypto::keypair::{KeyPair, RawSignature};
use writ_crypto::keys::{KeyKind, generate};

use crate::software::SoftwareSigner;
use crate::{Capabilities, KeyInfo, Signer, SignerError};

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

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.inner.remove_key(id)
    }
}
