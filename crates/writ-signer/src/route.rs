//! [`Routed`]: a [`Signer`] over several named backends, each key on exactly one of them
//! (`docs/architecture/signer.md`). A use's keys (the agent keys, the upstream credentials)
//! may live on a software backend and a device at once; each backend sits behind its own
//! queue, so a stuck device never holds up the other's keys.
//!
//! - a signature, or a removal, goes to the backend that lists the key; a key no backend
//!   lists is [`SignerError::UnknownKey`], one listed by two is refused
//!   ([`SignerError::DuplicateKey`]: fail closed, never one picked);
//! - a key is added to, or made on, the backend named ([`Routed::add_key_on`],
//!   [`Routed::create_key_on`]), refused when another backend holds its id already; through
//!   the trait, on the only backend that takes (or makes) keys, refused when there are
//!   several;
//! - its capabilities are the union of its backends' (the daemon checks each declared key
//!   against its own backend's pairs, never against this union).

use std::collections::BTreeMap;
use std::sync::Arc;

use writ_core::names::KeyId;
use writ_crypto::algorithm::{KeyAlgorithm, SignerHash};
use writ_crypto::keypair::{KeyPair, RawSignature};

use crate::{Capabilities, Created, KeyInfo, Signer, SignerError};

/// Backends by the name the policy gives them (`software`, `se-cryptokit`): each name once.
pub type Backends = BTreeMap<String, Arc<dyn Signer>>;

/// Several backends behind one [`Signer`]. See the module documentation.
pub struct Routed {
    backends: Backends,
}

impl std::fmt::Debug for Routed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.backends.keys().map(String::as_str).collect();
        f.debug_struct("Routed").field("backends", &names).finish()
    }
}

impl Routed {
    /// The backends; a key id two of them list is refused.
    pub fn new(backends: Backends) -> Result<Self, SignerError> {
        let routed = Self { backends };
        // Lists every key once, or refuses.
        routed.list_keys()?;
        Ok(routed)
    }

    /// The backend named `name`.
    pub fn on(&self, name: &str) -> Option<&Arc<dyn Signer>> {
        self.backends.get(name)
    }

    /// The backend that holds `id`: [`SignerError::UnknownKey`] when none does,
    /// [`SignerError::DuplicateKey`] when two do.
    fn holder(&self, id: &KeyId) -> Result<&dyn Signer, SignerError> {
        let mut found: Option<&dyn Signer> = None;
        for backend in self.backends.values() {
            if backend.list_keys()?.iter().any(|k| &k.id == id) {
                if found.is_some() {
                    return Err(SignerError::DuplicateKey(id.clone()));
                }
                found = Some(&**backend);
            }
        }
        found.ok_or_else(|| SignerError::UnknownKey(id.clone()))
    }

    /// Refuses `id` when a backend holds it already.
    fn free(&self, id: &KeyId) -> Result<(), SignerError> {
        match self.holder(id) {
            Err(SignerError::UnknownKey(_)) => Ok(()),
            Ok(_) => Err(SignerError::DuplicateKey(id.clone())),
            Err(e) => Err(e),
        }
    }

    /// The backend named `name`, or why there is none.
    fn named(&self, name: &str, id: &KeyId) -> Result<&dyn Signer, SignerError> {
        self.on(name)
            .map(|backend| &**backend)
            .ok_or_else(|| SignerError::Unsupported {
                id: id.clone(),
                what: format!("the backend {name}"),
            })
    }

    /// The only backend for which `can` holds, or why there is none (`none`) or no single
    /// one.
    fn only(
        &self,
        id: &KeyId,
        can: fn(&Capabilities) -> bool,
        none: fn(KeyId) -> SignerError,
    ) -> Result<&dyn Signer, SignerError> {
        let mut able = self
            .backends
            .values()
            .filter(|backend| can(&backend.capabilities()));
        match (able.next(), able.next()) {
            (Some(backend), None) => Ok(&**backend),
            (None, _) => Err(none(id.clone())),
            (Some(_), Some(_)) => Err(SignerError::Unsupported {
                id: id.clone(),
                what: "a key with no backend named, among several".to_owned(),
            }),
        }
    }

    /// Adds `key` under `id` to the backend named `name`.
    pub fn add_key_on(&self, name: &str, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        let backend = self.named(name, &id)?;
        self.free(&id)?;
        backend.add_key(id, key)
    }

    /// Makes a key of `algorithm` under `id` on the backend named `name`.
    pub fn create_key_on(
        &self,
        name: &str,
        id: KeyId,
        algorithm: KeyAlgorithm,
    ) -> Result<Created, SignerError> {
        let backend = self.named(name, &id)?;
        self.free(&id)?;
        backend.create_key(id, algorithm)
    }
}

impl Signer for Routed {
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError> {
        let mut all: Vec<KeyInfo> = Vec::new();
        for backend in self.backends.values() {
            for key in backend.list_keys()? {
                if all.iter().any(|k| k.id == key.id) {
                    return Err(SignerError::DuplicateKey(key.id));
                }
                all.push(key);
            }
        }
        Ok(all)
    }

    fn sign(&self, id: &KeyId, data: &[u8], hash: SignerHash) -> Result<RawSignature, SignerError> {
        self.holder(id)?.sign(id, data, hash)
    }

    fn capabilities(&self) -> Capabilities {
        let mut union = Capabilities {
            pairs: Vec::new(),
            exportable: false,
            takes_keys: false,
            makes_keys: false,
        };
        for backend in self.backends.values() {
            let c = backend.capabilities();
            for pair in c.pairs {
                if !union.pairs.contains(&pair) {
                    union.pairs.push(pair);
                }
            }
            union.exportable |= c.exportable;
            union.takes_keys |= c.takes_keys;
            union.makes_keys |= c.makes_keys;
        }
        union
    }

    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError> {
        let backend = self.only(&id, |c| c.takes_keys, SignerError::CannotTakeKeys)?;
        self.free(&id)?;
        backend.add_key(id, key)
    }

    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError> {
        let backend = self.only(&id, |c| c.makes_keys, SignerError::MakesNoKeys)?;
        self.free(&id)?;
        backend.create_key(id, algorithm)
    }

    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError> {
        self.holder(id)?.remove_key(id)
    }
}
