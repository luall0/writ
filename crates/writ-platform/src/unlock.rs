//! Unwraps the keystore's secret files: the [`KeystoreUnwrap`] interface (one way to unwrap
//! an age file's file key), [`open`] (the one place an age file of the keystore is opened
//! through such ways), [`data_key`], and the [`DataKey`] and [`Passphrase`] secrets.
//!
//! Portable implementations: [`passphrase::PassphraseUnwrap`] (age's scrypt stanza: the
//! keystore's identity wrapped with the passphrase) and [`x25519::X25519Unwrap`] (an age X25519
//! identity: the keystore's own, and from M7.6 the offline recovery identity). Hardware ways
//! (the Secure Enclave, later a YubiKey, a TPM, a KMS) are more implementations.

pub mod passphrase;
pub mod x25519;

use std::io::Read;
use std::sync::Mutex;

pub use age_core::format::{FileKey, Stanza};
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

    /// The way this identity opens the keystore's files (named `keystore`).
    pub fn way(&self) -> Result<x25519::X25519Unwrap> {
        Ok(x25519::X25519Unwrap::new("keystore", self.identity()?))
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
/// it is verified by the daemon before any way is asked.
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

/// One way to unwrap the file key of an age file of the keystore, from the stanzas of its
/// header: a passphrase, an identity held in memory, or a key held by hardware that alone can
/// unwrap it. Each secret file is encrypted to some ways' recipients, and opened by whichever
/// way has a stanza there ([`open`]).
pub trait KeystoreUnwrap: Send + Sync {
    /// What this way is, in errors and the log (`passphrase`, `keystore`, `recovery`, a
    /// hardware key's name). Never a secret.
    fn name(&self) -> &str;

    /// The file key from `stanzas`: `Ok(None)` when no stanza is this way's (the file is
    /// encrypted to others), an error when one is and unwrapping it fails (a wrong
    /// passphrase, a device that refuses, a damaged stanza). An error never holds a secret.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<FileKey>>;
}

/// Why an age file of the keystore didn't open. Its text never holds a secret; the caller
/// names the file.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("larger than a sealed secret ({0} bytes)")]
    TooLarge(u64),
    #[error("not an age file")]
    NotAge,
    #[error("it is encrypted to a passphrase")]
    Passphrase,
    /// No way given has a stanza in the file.
    #[error("no identity of this keystore opens it")]
    NoWay,
    /// A way had a stanza and failed: its name and why.
    #[error("{way}: {reason}")]
    Way { way: String, reason: PlatformError },
    /// A way unwrapped a file key and the file didn't decrypt with it (a changed header or
    /// payload).
    #[error("cannot decrypt it")]
    Damaged,
    #[error("its work factor is too high for this machine")]
    ExcessiveWork,
}

/// Whether [`open`] may open a file encrypted to a passphrase (only the keystore's identity
/// file is ever one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseFile {
    Allowed,
    Refused,
}

/// The plaintext of the age file `sealed` (at most `max` bytes, in memory wiped on drop),
/// opened by the first of `ways` that unwraps its file key. A way that fails doesn't stop the
/// next one from trying; if none opens it, the first failure is the error (else
/// [`OpenError::NoWay`]).
pub fn open(
    sealed: &[u8],
    ways: &[&dyn KeystoreUnwrap],
    passphrase: PassphraseFile,
    max: u64,
) -> std::result::Result<Zeroizing<Vec<u8>>, OpenError> {
    if u64::try_from(sealed.len()).unwrap_or(u64::MAX) > max {
        return Err(OpenError::TooLarge(max));
    }
    let decryptor = age::Decryptor::new_buffered(sealed).map_err(|_| OpenError::NotAge)?;
    if decryptor.is_scrypt() && passphrase == PassphraseFile::Refused {
        return Err(OpenError::Passphrase);
    }
    let failure = Mutex::new(None);
    let adapters: Vec<Adapter<'_>> = ways
        .iter()
        .map(|way| Adapter {
            way: *way,
            failure: &failure,
        })
        .collect();
    let opened = decryptor.decrypt(adapters.iter().map(|a| a as &dyn age::Identity));
    let mut reader = match opened {
        Ok(reader) => reader,
        Err(e) => {
            // poisoned: the failure kept is still the one to report; take it all the same.
            let failed = failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return Err(match (failed, e) {
                (Some((way, reason)), _) => OpenError::Way { way, reason },
                (None, age::DecryptError::NoMatchingKeys) => OpenError::NoWay,
                (None, age::DecryptError::ExcessiveWork { .. }) => OpenError::ExcessiveWork,
                (None, _) => OpenError::Damaged,
            });
        }
    };
    // Room for the largest secret up front: reading never moves the plaintext to a larger
    // buffer, which would leave an unwiped copy behind.
    let capacity = usize::try_from(max).unwrap_or(usize::MAX);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
    (&mut reader)
        .take(max)
        .read_to_end(&mut plaintext)
        .map_err(|_| OpenError::Damaged)?;
    Ok(plaintext)
}

/// The largest file read as the keystore's wrapped identity: a 32-byte key in an age file is a
/// few hundred bytes, anything far bigger isn't one.
pub const MAX_WRAPPED_LEN: u64 = 64 * 1024;

/// The keystore's data key, from the file at `path` that wraps it (`identity.age`), opened by
/// one of `ways` (the passphrase, on a passphrase keystore). The file must be private to the
/// daemon.
pub fn data_key(path: &std::path::Path, ways: &[&dyn KeystoreUnwrap]) -> Result<DataKey> {
    // Encrypted, but a copy allows an offline attack on a passphrase: a secret file.
    let wrapped =
        crate::fs::read_secret(path, "the wrapped key", MAX_WRAPPED_LEN).map_err(|e| match e {
            PlatformError::Config(message) => PlatformError::Unlock(message),
            other => other,
        })?;
    let corrupted =
        || PlatformError::Unlock(format!("{} is not a valid wrapped key", path.display()));
    let plaintext =
        open(&wrapped, ways, PassphraseFile::Allowed, MAX_WRAPPED_LEN).map_err(|e| match e {
            OpenError::Way { reason, .. } => reason,
            OpenError::NoWay => {
                PlatformError::Unlock(format!("{}: nothing given unwraps it", path.display()))
            }
            OpenError::ExcessiveWork => PlatformError::Unlock(
                "the wrapped key's work factor is too high for this machine".to_owned(),
            ),
            OpenError::TooLarge(_)
            | OpenError::NotAge
            | OpenError::Passphrase
            | OpenError::Damaged => corrupted(),
        })?;
    if plaintext.len() != 32 {
        return Err(PlatformError::Unlock(format!(
            "{} does not hold a 32-byte key",
            path.display()
        )));
    }
    let mut key = DataKey(Zeroizing::new([0u8; 32]));
    key.0
        .copy_from_slice(plaintext.get(..32).ok_or_else(corrupted)?);
    Ok(key)
}

/// A way as age sees it: a failure is kept for [`open`]'s error, and the next way tried.
struct Adapter<'a> {
    way: &'a dyn KeystoreUnwrap,
    failure: &'a Mutex<Option<(String, PlatformError)>>,
}

impl age::Identity for Adapter<'_> {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        self.unwrap_stanzas(std::slice::from_ref(stanza))
    }

    fn unwrap_stanzas(
        &self,
        stanzas: &[Stanza],
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        match self.way.unwrap(stanzas) {
            Ok(Some(key)) => Some(Ok(key)),
            Ok(None) => None,
            Err(reason) => {
                // poisoned: another way's thread panicked; the record is a plain Option, kept.
                let mut failure = self
                    .failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if failure.is_none() {
                    *failure = Some((self.way.name().to_owned(), reason));
                }
                None
            }
        }
    }
}
