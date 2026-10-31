//! The daemon's keys. Until the sealed keystore (M5), a dev keystore only: plain key files in
//! a private directory, generated on first start, refused by a release build.

use std::path::Path;

use anyhow::{Context, bail};
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{LineEnding, PrivateKey};
use writ_crypto::tls::TlsIdentity;

use crate::config::{Config, KeystoreConfig};

/// Creates a directory (and its parents) only the daemon can enter (0700).
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    writ_platform::fs::create_private_dir(path)
        .with_context(|| format!("cannot create {} as a private directory", path.display()))
}

/// The daemon's keys. M2: plain files in a dev keystore, generated on first start.
pub struct Keys {
    pub ca: PrivateKey,
    pub host: PrivateKey,
    /// Signs commits until the `Signer` interface (M3).
    pub agent: PrivateKey,
    /// The HTTPS approval API's self-signed certificate and key.
    pub tls: TlsIdentity,
}

/// The TLS certificate and key of the dev keystore, generated on first start.
fn dev_tls(dir: &Path) -> anyhow::Result<TlsIdentity> {
    let (cert_path, key_path) = (dir.join("tls-cert.pem"), dir.join("tls-key.pem"));
    // The key is written first: a cert without its key (or a key alone, after a crash
    // between the two writes) is a pair to make again.
    if !(cert_path.exists() && key_path.exists()) {
        for leftover in [&cert_path, &key_path] {
            match std::fs::remove_file(leftover) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("cannot remove {}", leftover.display()));
                }
                _ => {}
            }
        }
        let generated = writ_crypto::tls::generate_self_signed()?;
        write_private(&key_path, generated.key_pem.as_bytes())?;
        std::fs::write(&cert_path, &generated.cert_pem)
            .with_context(|| format!("cannot write {}", cert_path.display()))?;
    }
    let cert = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key = writ_platform::fs::read_secret(&key_path, "the TLS key", 1 << 16)?;
    let key = std::str::from_utf8(&key)
        .with_context(|| format!("{} is not a PEM key", key_path.display()))?;
    Ok(TlsIdentity::from_pem(&cert, key)?)
}

/// Creates a new file only the daemon can read (0600); fails if it exists.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = writ_platform::fs::create_new_private_file(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    std::io::Write::write_all(&mut file, bytes)
        .with_context(|| format!("cannot write {}", path.display()))
}

/// The dev keystore's key `name`, generated on first start.
fn dev_key(dir: &Path, name: &str) -> anyhow::Result<PrivateKey> {
    let path = dir.join(name);
    if path.exists() {
        // A private file of the daemon's user, read into memory wiped on drop.
        let pem = writ_platform::fs::read_secret(&path, "the key", 1 << 16)?;
        return Ok(PrivateKey::from_openssh(pem.as_slice())?);
    }
    let key = generate(KeyKind::Ed25519)?;
    write_private(&path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
    Ok(key)
}

/// The daemon's keys, from the configured keystore.
pub fn keys(config: &Config) -> anyhow::Result<Keys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => {
            // Both: an explicit build feature, and a debug build. A release build, or one
            // without the feature, refuses plaintext keys whatever its profile says.
            if !(cfg!(feature = "dev-keystore") && cfg!(debug_assertions)) {
                bail!(
                    "keystore.dev holds unencrypted keys for tests and development: only a \
                     debug build with the dev-keystore feature takes it (the sealed keystore \
                     comes in M5)"
                );
            }
            private_dir(dir)?;
            Ok(Keys {
                ca: dev_key(dir, "ca")?,
                host: dev_key(dir, "host")?,
                agent: dev_key(dir, "agent")?,
                tls: dev_tls(dir)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn a_tls_pair_cut_short_by_a_crash_is_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let first = dev_tls(dir.path()).unwrap().fingerprint().to_owned();
        assert_eq!(dev_tls(dir.path()).unwrap().fingerprint(), first, "kept");
        // The key written, the cert not: a crash between the two writes.
        std::fs::remove_file(dir.path().join("tls-cert.pem")).unwrap();
        let second = dev_tls(dir.path()).unwrap().fingerprint().to_owned();
        assert_ne!(second, first);
        // The cert alone.
        std::fs::remove_file(dir.path().join("tls-key.pem")).unwrap();
        assert_ne!(dev_tls(dir.path()).unwrap().fingerprint(), second);
        let mode = std::fs::metadata(dir.path().join("tls-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
