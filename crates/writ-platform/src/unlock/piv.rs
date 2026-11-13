//! [`PivUnwrap`] (M7.6): the `piv-p256` stanza (`writ_crypto::piv_p256`) unwrapped by a P-256
//! key-agreement key a device holds ([`KeyAgreement`]): the Secure Enclave through `writ-se`
//! (`writ_signer::helper::agreement`, wired by `writd`), later a YubiKey PIV slot or a TPM.
//! The stanza is read and checked here, before the device is handed its point; the device
//! does the ECDH alone; the file key opens only under the HKDF key, else it is refused.

use std::sync::Arc;

use writ_crypto::piv_p256::{Line, P256Recipient, SHARED_BYTES, UNCOMPRESSED_BYTES};
use zeroize::Zeroizing;

use super::{FileKey, KeystoreUnwrap, Stanza};
use crate::{PlatformError, Result};

/// A device holding a P-256 key-agreement key: the ECDH with a peer point (uncompressed, on
/// the curve: checked before it is asked), the shared point's x coordinate.
pub trait KeyAgreement: Send + Sync {
    /// Why not, never a secret: the device refuses, its key is gone, it didn't answer.
    fn agree(&self, peer: &[u8; UNCOMPRESSED_BYTES]) -> Result<Zeroizing<[u8; SHARED_BYTES]>>;
}

/// A hardware recipient as a way into the keystore: it opens the `piv-p256` stanzas wrapped to
/// its `recipient`, through `device`.
pub struct PivUnwrap {
    name: String,
    recipient: P256Recipient,
    device: Arc<dyn KeyAgreement>,
}

impl PivUnwrap {
    pub fn new(name: &str, recipient: P256Recipient, device: Arc<dyn KeyAgreement>) -> Self {
        Self {
            name: name.to_owned(),
            recipient,
            device,
        }
    }

    pub fn recipient(&self) -> &P256Recipient {
        &self.recipient
    }
}

impl std::fmt::Debug for PivUnwrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PivUnwrap({}, {})", self.name, self.recipient)
    }
}

impl KeystoreUnwrap for PivUnwrap {
    fn name(&self) -> &str {
        &self.name
    }

    /// A stanza of another kind, or of another recipient (its tag), is not this way's. A
    /// `piv-p256` stanza that isn't well made is refused before the device sees anything, and
    /// is the error when no stanza of this way's opens.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<FileKey>> {
        let mut malformed = None;
        for stanza in stanzas {
            let line = match Line::parse(stanza) {
                None => continue,
                Some(Ok(line)) => line,
                Some(Err(why)) => {
                    malformed.get_or_insert(why);
                    continue;
                }
            };
            if !line.is_for(&self.recipient) {
                continue;
            }
            let shared = self.device.agree(&line.peer_point())?;
            return line
                .unwrap(&self.recipient, shared.as_slice())
                .map(Some)
                .map_err(|why| PlatformError::Unlock(why.to_string()));
        }
        match malformed {
            Some(why) => Err(PlatformError::Unlock(why.to_string())),
            None => Ok(None),
        }
    }
}
