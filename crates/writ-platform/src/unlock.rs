//! Recovers the keystore's data key at unseal time: the [`KeystoreUnlock`] interface and the
//! [`DataKey`] and [`Passphrase`] secrets.
//!
//! Portable implementation: [`passphrase::PassphraseUnlock`], the data key wrapped in a file
//! with age's scrypt passphrase recipient.

pub mod passphrase;

use std::io::Read;

use zeroize::Zeroizing;

use crate::{PlatformError, Result};

/// The keystore's data key. Zeroized on drop, never printed.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The keystore's age X25519 identity: these 32 bytes are its secret scalar. Every secret
    /// of the sealed keystore is its own age file encrypted to this identity's recipient
    /// ([`Self::recipient`]); the passphrase wraps only these bytes.
    pub fn identity(&self) -> Result<age::x25519::Identity> {
        use bech32::ToBase32;
        // age's own text encoding of an identity (bech32), parsed back: age builds
        // one from that text only. The text, and the 5-bit groups it is made from, are wiped
        // once used (the review after M5.5); bech32's checksum work and age's parse keep
        // copies of their own (the threat model's row on libraries' buffers).
        let mut groups = self.0.as_slice().to_base32();
        let mut text = Zeroizing::new(String::with_capacity(96));
        let encoded = bech32::encode_to_fmt(
            &mut *text,
            "age-secret-key-",
            &groups,
            bech32::Variant::Bech32,
        );
        for group in &mut groups {
            *group = bech32::u5::default();
        }
        std::hint::black_box(&groups);
        drop(groups);
        match encoded {
            Ok(Ok(())) => {}
            _ => {
                return Err(PlatformError::Unlock(
                    "cannot encode the keystore identity".to_owned(),
                ));
            }
        }
        text.parse::<age::x25519::Identity>()
            .map_err(|_| PlatformError::Unlock("cannot read the keystore identity".to_owned()))
    }

    /// The public recipient of [`Self::identity`] (`age1…`): what a secret is encrypted to.
    pub fn recipient(&self) -> Result<age::x25519::Recipient> {
        Ok(self.identity()?.to_public())
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
