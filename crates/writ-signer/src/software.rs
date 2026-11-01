//! The software backend: Ed25519 and P-256 keys held in memory (`ssh-key` wipes them on
//! drop), handed over by whoever loaded them (the daemon's keystore). Nothing here reads a
//! file or prints a key.

use std::collections::BTreeMap;
use std::fmt;

use signature::Signer as _;
use writ_core::names::KeyId;
use writ_crypto::ssh_key::{Algorithm, EcdsaCurve, PrivateKey, Signature};

use crate::{Capabilities, KeyInfo, Signer, SignerError};

/// Keys in memory, by id.
pub struct SoftwareSigner {
    keys: BTreeMap<KeyId, PrivateKey>,
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The ids only: never a key.
        f.debug_struct("SoftwareSigner")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SoftwareSigner {
    /// Takes the keys (moved in: no other copy is kept). Two keys with one id, an encrypted
    /// key or another algorithm than Ed25519 and P-256 are refused.
    pub fn new(keys: impl IntoIterator<Item = (KeyId, PrivateKey)>) -> Result<Self, SignerError> {
        let mut held = BTreeMap::new();
        for (id, key) in keys {
            let supported = matches!(
                key.algorithm(),
                Algorithm::Ed25519
                    | Algorithm::Ecdsa {
                        curve: EcdsaCurve::NistP256
                    }
            );
            if !supported || key.is_encrypted() {
                return Err(SignerError::Unsupported {
                    algorithm: key.algorithm().to_string(),
                    id,
                });
            }
            if held.contains_key(&id) {
                return Err(SignerError::DuplicateKey(id));
            }
            held.insert(id, key);
        }
        Ok(Self { keys: held })
    }
}

impl Signer for SoftwareSigner {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        Ok(self
            .keys
            .iter()
            .map(|(id, key)| KeyInfo {
                id: id.clone(),
                public_key: key.public_key().clone(),
            })
            .collect())
    }

    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError> {
        let key = self
            .keys
            .get(id)
            .ok_or_else(|| SignerError::UnknownKey(id.clone()))?;
        key.try_sign(data)
            .map_err(|_| SignerError::Failed(id.clone()))
    }

    fn capabilities(&self) -> Capabilities {
        let mut algorithms: Vec<Algorithm> = Vec::new();
        for key in self.keys.values() {
            if !algorithms.contains(&key.algorithm()) {
                algorithms.push(key.algorithm());
            }
        }
        Capabilities {
            algorithms,
            exportable: true,
            needs_touch: false,
        }
    }
}
