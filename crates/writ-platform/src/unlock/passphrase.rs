//! [`PassphraseUnwrap`]: the keystore's identity wrapped with age's scrypt passphrase
//! recipient, and [`enroll`], which writes that file.

use std::io::Write;
use std::path::PathBuf;

use age::secrecy::SecretString;

use super::{DataKey, FileKey, KeystoreUnwrap, Passphrase, Stanza};
use crate::{PlatformError, Result};

/// The passphrase as a way into the keystore: it opens only a file encrypted to it with age's
/// scrypt stanza (the keystore's `identity.age`). Its `Debug` shows nothing of it.
pub struct PassphraseUnwrap {
    identity: age::scrypt::Identity,
}

impl PassphraseUnwrap {
    pub fn new(passphrase: &Passphrase) -> Self {
        Self {
            identity: age::scrypt::Identity::new(secret(passphrase)),
        }
    }
}

impl std::fmt::Debug for PassphraseUnwrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PassphraseUnwrap(<redacted>)")
    }
}

impl KeystoreUnwrap for PassphraseUnwrap {
    fn name(&self) -> &str {
        "passphrase"
    }

    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<FileKey>> {
        match age::Identity::unwrap_stanzas(&self.identity, stanzas) {
            None => Ok(None),
            Some(Ok(key)) => Ok(Some(key)),
            Some(Err(age::DecryptError::ExcessiveWork { .. })) => Err(PlatformError::Unlock(
                "the wrapped key's work factor is too high for this machine".to_owned(),
            )),
            Some(Err(age::DecryptError::DecryptionFailed)) => {
                Err(PlatformError::Unlock("wrong passphrase".to_owned()))
            }
            Some(Err(_)) => Err(PlatformError::Unlock(
                "a damaged passphrase stanza".to_owned(),
            )),
        }
    }
}

/// Wraps `key` with `passphrase` (age's default scrypt work factor, about a second on this
/// machine) and writes it to `wrapped_path` with mode 0600. Refuses to overwrite an existing
/// file.
pub fn enroll(
    wrapped_path: impl Into<PathBuf>,
    passphrase: &Passphrase,
    key: &DataKey,
) -> Result<()> {
    enroll_inner(wrapped_path.into(), passphrase, key, None)
}

/// [`enroll`] with the scrypt work factor `N = 2^log_n` (1 to 63). Behind the `testing`
/// feature: a low work factor makes the passphrase cheap to brute-force, so no production
/// build can reach it.
#[cfg(feature = "testing")]
pub fn enroll_with_work_factor(
    wrapped_path: impl Into<PathBuf>,
    passphrase: &Passphrase,
    key: &DataKey,
    log_n: u8,
) -> Result<()> {
    if !(1..64).contains(&log_n) {
        return Err(PlatformError::Config(format!(
            "the scrypt work factor must be between 1 and 63, not {log_n}"
        )));
    }
    enroll_inner(wrapped_path.into(), passphrase, key, Some(log_n))
}

fn enroll_inner(
    wrapped_path: PathBuf,
    passphrase: &Passphrase,
    key: &DataKey,
    log_n: Option<u8>,
) -> Result<()> {
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

    let mut file = crate::fs::create_new_private_file(&wrapped_path).map_err(|e| {
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
    Ok(())
}

/// The passphrase as age wants it. The copy is moved into a zeroizing secret box.
fn secret(passphrase: &Passphrase) -> SecretString {
    SecretString::from(passphrase.expose().to_owned())
}
