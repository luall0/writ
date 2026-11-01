//! Test support (feature `testing`): a signer that fails on demand, to check that a backend
//! failure is refused and logged, never turned into a signature.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::{AtomicBool, Ordering};

use writ_core::names::KeyId;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::Signature;

use crate::software::SoftwareSigner;
use crate::{Capabilities, KeyInfo, Signer, SignerError};

/// A software signer with a fresh key of `kind` for each id.
pub fn software_signer(ids: &[&str], kind: KeyKind) -> SoftwareSigner {
    SoftwareSigner::new(
        ids.iter()
            .map(|id| (id.parse::<KeyId>().unwrap(), generate(kind).unwrap())),
    )
    .unwrap()
}

/// Wraps a signer; while failing, every signature is refused with [`SignerError::Failed`]
/// (the keys are still listed, like a device that is present but refuses).
pub struct FailingSigner<S> {
    inner: S,
    failing: AtomicBool,
}

impl<S: Signer> FailingSigner<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            failing: AtomicBool::new(false),
        }
    }

    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

impl<S: Signer> Signer for FailingSigner<S> {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        self.inner.list_keys()
    }

    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(SignerError::Failed(id.clone()));
        }
        self.inner.sign(id, data)
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
}
