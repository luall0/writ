//! Recovers the keystore's data key at unseal time: the [`KeystoreUnlock`] interface and the
//! [`DataKey`] and [`Passphrase`] secrets.
//!
//! Portable implementation: [`passphrase::PassphraseUnlock`], the data key wrapped in a file
//! with age's scrypt passphrase recipient.

pub mod passphrase;

use std::io::Read;

use zeroize::Zeroizing;

use crate::Result;

/// The keystore's data key. Zeroized on drop, never printed.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A new random key from the OS random source (`/dev/urandom`). Fails, never panics, if
    /// the source can't be read.
    pub fn generate() -> Result<Self> {
        let mut key = Self(Zeroizing::new([0u8; 32]));
        let mut source = std::fs::File::open("/dev/urandom")?;
        source.read_exact(&mut key.0[..])?;
        Ok(key)
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// A keystore passphrase. Zeroized on drop, never printed.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// What an unseal brings to recover the data key. The approver signature that must come with
/// it is verified by the daemon before any [`KeystoreUnlock`] is asked.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct UnsealRequest {
    pub passphrase: Option<Passphrase>,
}

impl UnsealRequest {
    pub fn with_passphrase(passphrase: Passphrase) -> Self {
        Self {
            passphrase: Some(passphrase),
        }
    }
}

/// Recovers the keystore's data key at unseal time.
pub trait KeystoreUnlock: Send + Sync {
    fn unlock(&self, request: &UnsealRequest) -> Result<DataKey>;
}
