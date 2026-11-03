//! The software backend: keys held in memory as [`KeyPair`]s (wiped on drop), handed over by
//! whoever loaded them (the daemon's keystore). It supports every pair Writ signs with
//! ([`writ_crypto::algorithm::every_pair`] less what this build can't make). Nothing here
//! reads a file or prints a key.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{PoisonError, RwLock};

use writ_core::names::KeyId;
use writ_crypto::CryptoError;
use writ_crypto::algorithm::{KeyAlgorithm, SignerHash};
use writ_crypto::keypair::{IntoKeyPair, KeyPair, RawSignature, pair};

use crate::{Capabilities, KeyInfo, Signer, SignerError};

/// Keys in memory, by id. Keys may be added while it runs ([`Signer::add_key`]).
pub struct SoftwareSigner {
    keys: RwLock<BTreeMap<KeyId, KeyPair>>,
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

/// The pairs the software backend signs with: every one [`KeyPair`] signs.
pub fn pairs() -> Vec<(KeyAlgorithm, SignerHash)> {
    writ_crypto::algorithm::every_pair()
        .into_iter()
        .filter(|(algorithm, _)| supported(*algorithm))
        .collect()
}

/// Whether this build's software backend holds keys of `algorithm`.
fn supported(algorithm: KeyAlgorithm) -> bool {
    !algorithm.is_rsa()
}

impl SoftwareSigner {
    /// Takes the keys (moved in: no other copy is kept). Two keys with one id, or an
    /// algorithm this build doesn't hold, are refused.
    pub fn new<K: IntoKeyPair>(
        keys: impl IntoIterator<Item = (KeyId, K)>,
    ) -> Result<Self, SignerError> {
        let mut held = BTreeMap::new();
        for (id, key) in keys {
            let key = key.into_keypair().map_err(|e| SignerError::Unsupported {
                what: match e {
                    CryptoError::Unsupported(what) => what,
                    other => other.to_string(),
                },
                id: id.clone(),
            })?;
            insert(&mut held, id, key)?;
        }
        Ok(Self {
            keys: RwLock::new(held),
        })
    }

    /// A backend holding no key yet (they are added while it runs, [`Signer::add_key`]).
    pub fn empty() -> Self {
        Self {
            keys: RwLock::new(BTreeMap::new()),
        }
    }

    // poisoned: a key map is changed by one insert, whole or not at all; the map stands.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<KeyId, KeyPair>> {
        self.keys.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Puts `key` in `held` under `id`, if the backend takes its kind and the id is free.
fn insert(
    held: &mut BTreeMap<KeyId, KeyPair>,
    id: KeyId,
    key: KeyPair,
) -> Result<KeyInfo, SignerError> {
    if !supported(key.algorithm()) {
        return Err(SignerError::Unsupported {
            what: key.algorithm().to_string(),
            id,
        });
    }
    if held.contains_key(&id) {
        return Err(SignerError::DuplicateKey(id));
    }
    let info = KeyInfo {
        id: id.clone(),
        public_key: key.public_key(),
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
                public_key: key.public_key(),
            })
            .collect())
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        let keys = self.read();
        let key = keys
            .get(id)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))?;
        key.sign(data, hash).map_err(|e| match e {
            CryptoError::Unsupported(_) => SignerError::Unsupported {
                id: id.clone(),
                what: pair(key.algorithm(), hash),
            },
            _ => SignerError::Failed(id.clone()),
        })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            pairs: pairs(),
            exportable: true,
            needs_touch: false,
            takes_keys: true,
        }
    }

    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        let mut held = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        insert(&mut held, id, key)
    }
}
