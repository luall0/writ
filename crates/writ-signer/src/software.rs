//! The software backend: Ed25519 and P-256 keys held in memory (`ssh-key` wipes them on
//! drop), handed over by whoever loaded them (the daemon's keystore). Nothing here reads a
//! file or prints a key.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{PoisonError, RwLock};

use signature::Signer as _;
use writ_core::names::KeyId;
use writ_crypto::ssh_key::{Algorithm, EcdsaCurve, PrivateKey, Signature};

use crate::{Capabilities, KeyInfo, Signer, SignerError};

/// Keys in memory, by id. Keys may be added while it runs ([`Signer::add_key`]).
pub struct SoftwareSigner {
    keys: RwLock<BTreeMap<KeyId, PrivateKey>>,
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The ids only: never a key.
        let keys = self.read();
        f.debug_struct("SoftwareSigner")
            .field("keys", &keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Whether the software backend holds keys of `key`'s kind: Ed25519 and P-256, unencrypted.
fn supported(key: &PrivateKey) -> bool {
    matches!(
        key.algorithm(),
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
    ) && !key.is_encrypted()
}

impl SoftwareSigner {
    /// Takes the keys (moved in: no other copy is kept). Two keys with one id, an encrypted
    /// key or another algorithm than Ed25519 and P-256 are refused.
    pub fn new(keys: impl IntoIterator<Item = (KeyId, PrivateKey)>) -> Result<Self, SignerError> {
        let mut held = BTreeMap::new();
        for (id, key) in keys {
            insert(&mut held, id, key)?;
        }
        Ok(Self {
            keys: RwLock::new(held),
        })
    }

    // poisoned: a key map is changed by one insert, whole or not at all; the map stands.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<KeyId, PrivateKey>> {
        self.keys.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Puts `key` in `held` under `id`, if the backend takes its kind and the id is free.
fn insert(
    held: &mut BTreeMap<KeyId, PrivateKey>,
    id: KeyId,
    key: PrivateKey,
) -> Result<KeyInfo, SignerError> {
    if !supported(&key) {
        return Err(SignerError::Unsupported {
            algorithm: key.algorithm().to_string(),
            id,
        });
    }
    if held.contains_key(&id) {
        return Err(SignerError::DuplicateKey(id));
    }
    let info = KeyInfo {
        id: id.clone(),
        public_key: key.public_key().clone(),
    };
    held.insert(id, key);
    Ok(info)
}

impl Signer for SoftwareSigner {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self
            .read()
            .iter()
            .map(|(id, key)| KeyInfo {
                id: id.clone(),
                public_key: key.public_key().clone(),
            })
            .collect())
    }

    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError> {
        let keys = self.read();
        let key = keys
            .get(id)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))?;
        key.try_sign(data)
            .map_err(|_| SignerError::Failed(id.clone()))
    }

    fn capabilities(&self) -> Capabilities {
        let mut algorithms: Vec<Algorithm> = Vec::new();
        for key in self.read().values() {
            if !algorithms.contains(&key.algorithm()) {
                algorithms.push(key.algorithm());
            }
        }
        Capabilities {
            algorithms,
            exportable: true,
            needs_touch: false,
            takes_keys: true,
        }
    }

    fn add_key(&self, id: KeyId, key: PrivateKey) -> Result<KeyInfo, SignerError> {
        let mut held = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        insert(&mut held, id, key)
    }
}
