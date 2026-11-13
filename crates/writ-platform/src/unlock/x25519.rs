//! [`X25519Unwrap`]: an age X25519 identity held in memory, as a way into the keystore: the
//! keystore's own identity (once its data key is unwrapped), and from M7.6 the offline
//! recovery identity.

use super::{FileKey, KeystoreUnwrap, Stanza};
use crate::{PlatformError, Result};

/// An age X25519 identity as a [`KeystoreUnwrap`]. Its secret scalar is wiped on drop (age's
/// own type); its `Debug` shows its name only.
pub struct X25519Unwrap {
    name: String,
    identity: age::x25519::Identity,
}

impl X25519Unwrap {
    pub fn new(name: &str, identity: age::x25519::Identity) -> Self {
        Self {
            name: name.to_owned(),
            identity,
        }
    }

    /// The recipient files are encrypted to for this way (`age1…`).
    pub fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }
}

impl std::fmt::Debug for X25519Unwrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519Unwrap({})", self.name)
    }
}

impl KeystoreUnwrap for X25519Unwrap {
    fn name(&self) -> &str {
        &self.name
    }

    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<FileKey>> {
        // An X25519 stanza carries no tag of its recipient: one that isn't for this identity
        // fails to decrypt, and age reads that as "not mine" (`None`), never as an error.
        match age::Identity::unwrap_stanzas(&self.identity, stanzas) {
            None => Ok(None),
            Some(Ok(key)) => Ok(Some(key)),
            Some(Err(_)) => Err(PlatformError::Unlock("a damaged X25519 stanza".to_owned())),
        }
    }
}
