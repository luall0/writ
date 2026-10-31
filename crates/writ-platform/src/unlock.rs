//! Recovers the keystore's data key at unseal time: the [`KeystoreUnlock`] interface, the
//! [`DataKey`] and [`Passphrase`] secrets, and [`PassphraseUnlock`], the data key wrapped in a
//! file with age's scrypt passphrase recipient.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
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

/// The data key wrapped with age's scrypt passphrase recipient, in a file only the daemon can
/// read. Unlocking needs the passphrase in the [`UnsealRequest`].
#[derive(Debug, Clone)]
pub struct PassphraseUnlock {
    wrapped_path: PathBuf,
}

/// The largest file accepted as a wrapped key: a 32-byte key in an age file is a few hundred
/// bytes, anything far bigger isn't one.
const MAX_WRAPPED_LEN: u64 = 64 * 1024;

impl PassphraseUnlock {
    /// Uses the wrapped key already enrolled at `wrapped_path`.
    pub fn new(wrapped_path: impl Into<PathBuf>) -> Self {
        Self {
            wrapped_path: wrapped_path.into(),
        }
    }

    /// Wraps `key` with `passphrase` (age's default scrypt work factor, about a second on
    /// this machine) and writes it to `wrapped_path` with mode 0600. Refuses to overwrite an
    /// existing file.
    pub fn enroll(
        wrapped_path: impl Into<PathBuf>,
        passphrase: &Passphrase,
        key: &DataKey,
    ) -> Result<Self> {
        Self::enroll_inner(wrapped_path.into(), passphrase, key, None)
    }

    /// [`Self::enroll`] with the scrypt work factor `N = 2^log_n` (1 to 63). **For tests
    /// only**: a low work factor makes the passphrase cheap to brute-force.
    pub fn enroll_with_work_factor(
        wrapped_path: impl Into<PathBuf>,
        passphrase: &Passphrase,
        key: &DataKey,
        log_n: u8,
    ) -> Result<Self> {
        if !(1..64).contains(&log_n) {
            return Err(PlatformError::Config(format!(
                "the scrypt work factor must be between 1 and 63, not {log_n}"
            )));
        }
        Self::enroll_inner(wrapped_path.into(), passphrase, key, Some(log_n))
    }

    pub fn wrapped_path(&self) -> &Path {
        &self.wrapped_path
    }

    fn enroll_inner(
        wrapped_path: PathBuf,
        passphrase: &Passphrase,
        key: &DataKey,
        log_n: Option<u8>,
    ) -> Result<Self> {
        let mut recipient = age::scrypt::Recipient::new(secret(passphrase));
        if let Some(log_n) = log_n {
            recipient.set_work_factor(log_n);
        }
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|_| PlatformError::Unlock("cannot wrap the data key".to_owned()))?;
        let mut wrapped = Vec::new();
        let mut writer = encryptor.wrap_output(&mut wrapped)?;
        writer.write_all(key.as_bytes())?;
        writer.finish()?;

        let mut file = create_new_private(&wrapped_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                PlatformError::Config(format!(
                    "{} already exists; refusing to overwrite a wrapped key",
                    wrapped_path.display()
                ))
            } else {
                PlatformError::Io(e)
            }
        })?;
        if let Err(e) = file.write_all(&wrapped).and_then(|()| file.sync_all()) {
            drop(file);
            // Don't leave a partial file behind: it would block the next enrollment.
            let _ = std::fs::remove_file(&wrapped_path);
            return Err(PlatformError::Io(e));
        }
        Ok(Self { wrapped_path })
    }

    fn read_wrapped(&self) -> Result<Vec<u8>> {
        let unreadable = |e: std::io::Error| {
            PlatformError::Unlock(format!(
                "cannot read the wrapped key {}: {e}",
                self.wrapped_path.display()
            ))
        };
        let file = std::fs::File::open(&self.wrapped_path).map_err(unreadable)?;
        let mut wrapped = Vec::new();
        file.take(MAX_WRAPPED_LEN + 1)
            .read_to_end(&mut wrapped)
            .map_err(unreadable)?;
        if wrapped.len() as u64 > MAX_WRAPPED_LEN {
            return Err(PlatformError::Unlock(format!(
                "{} is too large to be a wrapped key",
                self.wrapped_path.display()
            )));
        }
        Ok(wrapped)
    }
}

impl KeystoreUnlock for PassphraseUnlock {
    fn unlock(&self, request: &UnsealRequest) -> Result<DataKey> {
        let Some(passphrase) = &request.passphrase else {
            return Err(PlatformError::Unlock("a passphrase is required".to_owned()));
        };
        let wrapped = self.read_wrapped()?;
        let corrupted = || {
            PlatformError::Unlock(format!(
                "{} is not a valid wrapped key",
                self.wrapped_path.display()
            ))
        };
        let decryptor = age::Decryptor::new_buffered(&wrapped[..]).map_err(|_| corrupted())?;
        if !decryptor.is_scrypt() {
            return Err(corrupted());
        }
        let identity = age::scrypt::Identity::new(secret(passphrase));
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| match e {
                age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                    PlatformError::Unlock("wrong passphrase".to_owned())
                }
                age::DecryptError::ExcessiveWork { .. } => PlatformError::Unlock(
                    "the wrapped key's work factor is too high for this machine".to_owned(),
                ),
                _ => corrupted(),
            })?;

        // Read into a fixed buffer, one byte more than a key, so no plaintext copy is left
        // in a growing Vec or a probe buffer.
        let mut plaintext = Zeroizing::new([0u8; 33]);
        let mut len = 0;
        while len < plaintext.len() {
            match reader.read(&mut plaintext[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(corrupted()),
            }
        }
        if len != 32 {
            return Err(PlatformError::Unlock(format!(
                "{} does not hold a 32-byte key",
                self.wrapped_path.display()
            )));
        }
        let mut key = DataKey(Zeroizing::new([0u8; 32]));
        key.0.copy_from_slice(&plaintext[..32]);
        Ok(key)
    }
}

/// The passphrase as age wants it. The copy is moved into a zeroizing secret box.
fn secret(passphrase: &Passphrase) -> SecretString {
    SecretString::from(passphrase.expose().to_owned())
}

#[cfg(unix)]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
