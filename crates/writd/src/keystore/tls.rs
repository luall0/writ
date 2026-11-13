//! The HTTPS approval API's key and certificate in the boot tier (`tls-01`, `tls-01.crt`): made
//! once (`writd init`, on the backend it is given; the development keystore, in software),
//! read at every start, and replaced while the daemon runs by an approver's signed
//! `writ-tls/1` (M7.5, `writ admin tls rotate`).
//!
//! A software key is an OpenSSH private key, as it always was. A device's (the Secure Enclave)
//! is a `writ-key/1` file naming its backend and holding the device's framed blob, with its
//! public half beside it (`tls-01.pub`).
//!
//! **A rotation never leaves a mismatched pair**: the new files are written beside the old as
//! `.new` (the public half, the key, then the certificate last), the new identity is built
//! from them, then each is renamed over the old, the certificate last. A start finding a
//! `.new` certificate finishes the renames (the rotation was decided); `.new` files without
//! one are a rotation cut short before it was, and are dropped.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use writ_core::names::KeyId;
use writ_crypto::algorithm::KeyAlgorithm;
use writ_crypto::keyfile::KeyMeta;
use writ_crypto::keypair::KeyPair;
use writ_crypto::ssh_key::PrivateKey;

use super::{Makers, Material, TLS_KEY, TlsKeyPair, write_private};
use crate::declared::Backend;

/// The largest TLS key file read (a device's blob in hex, and its header).
const MAX_KEY_FILE: u64 = 1 << 18;

/// Where the TLS key, its public half (a device's) and its certificate are.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub key: PathBuf,
    pub cert: PathBuf,
}

/// The `.new` file beside `path`.
fn next(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".new");
    PathBuf::from(name)
}

fn remove_if_there(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("cannot remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// A file written whole and synced, readable by others (a certificate, a public half).
fn write_public_file(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()))
}

impl TlsFiles {
    /// The device key's public half.
    pub fn public(&self) -> PathBuf {
        self.key.with_extension("pub")
    }

    /// Finishes a rotation cut short, or drops one never decided (see the module): whether one
    /// was finished (said in the audit log at start).
    pub fn finish(&self) -> anyhow::Result<bool> {
        let parts = [self.public(), self.key.clone(), self.cert.clone()];
        if next(&self.cert).exists() {
            for part in &parts {
                let pending = next(part);
                if pending.exists() {
                    std::fs::rename(&pending, part).with_context(|| {
                        format!("cannot finish the TLS rotation: {}", pending.display())
                    })?;
                }
            }
            tracing::warn!("a TLS key rotation cut short was finished at start");
            return Ok(true);
        }
        for part in &parts {
            remove_if_there(&next(part))?;
        }
        Ok(false)
    }

    /// The key and certificate in force, or the `.new` ones (`pending`).
    fn read_at(&self, pending: bool) -> anyhow::Result<TlsKeyPair> {
        let at = |path: PathBuf| if pending { next(&path) } else { path };
        let (key_path, cert_path, public_path) = (
            at(self.key.clone()),
            at(self.cert.clone()),
            at(self.public()),
        );
        let text = writ_platform::fs::read_secret(&key_path, "the TLS key", MAX_KEY_FILE)?;
        let key = if text.starts_with(b"writ-key/1\n") {
            let line =
                writ_platform::fs::read_authority(&public_path, "the TLS key's public half")?;
            let (public, _) = writ_crypto::keyfile::decode_public(line.as_bytes())
                .with_context(|| format!("{}: not a public half", public_path.display()))?;
            let (material, meta) = Material::decode(&text, public)
                .with_context(|| format!("{}: not a key", key_path.display()))?;
            if meta.backend.is_none() {
                bail!("{}: a software key with a header", key_path.display());
            }
            material
        } else {
            let key = PrivateKey::from_openssh(text.as_slice())
                .with_context(|| format!("{}: not an OpenSSH private key", key_path.display()))?;
            Material::Software(KeyPair::from_ssh(key)?)
        };
        if KeyAlgorithm::of_public(key.public_key().key_data()) != Some(KeyAlgorithm::P256) {
            bail!("{}: not a P-256 key", key_path.display());
        }
        let cert_pem = writ_platform::fs::read_authority(&cert_path, "the TLS certificate")?;
        Ok(TlsKeyPair { key, cert_pem })
    }

    /// The key and certificate in force (a rotation cut short finished first).
    pub fn read(&self) -> anyhow::Result<TlsKeyPair> {
        self.finish()?;
        self.read_at(false)
    }

    /// The backend the key in force is on.
    pub fn backend(&self) -> anyhow::Result<Backend> {
        let text = writ_platform::fs::read_secret(&self.key, "the TLS key", MAX_KEY_FILE)?;
        if !text.starts_with(b"writ-key/1\n") {
            return Ok(Backend::Software);
        }
        let line = writ_platform::fs::read_authority(&self.public(), "the TLS key's public half")?;
        let (_, meta) = writ_crypto::keyfile::decode_public(line.as_bytes())?;
        Backend::of_meta(&meta).context("the TLS key is on a backend writd lacks")
    }

    /// Writes a new key on `backend` and its self-signed certificate to `key`, `public` and
    /// `cert` (each refused if it exists): the certificate signed through the key, as every
    /// handshake is later.
    fn write(
        backend: Backend,
        makers: &Makers,
        key: &Path,
        public: &Path,
        cert: &Path,
    ) -> anyhow::Result<()> {
        let id: KeyId = TLS_KEY.parse()?;
        let signer: Arc<dyn writ_signer::Signer> = match backend {
            Backend::Software => {
                let pair = KeyPair::generate(KeyAlgorithm::P256)?;
                write_private(key, pair.to_pem()?.as_bytes())?;
                Arc::new(writ_signer::software::SoftwareSigner::new([(
                    id.clone(),
                    pair,
                )])?)
            }
            device => {
                let signer = makers.device(device)?;
                let created = signer
                    .create_key(id.clone(), KeyAlgorithm::P256)
                    .with_context(|| {
                        format!("the {} backend did not make the TLS key", device.name())
                    })?;
                let meta = KeyMeta::SSH.on(device
                    .key_backend()?
                    .context("a device backend has a name")?);
                write_public_file(
                    public,
                    &writ_crypto::keyfile::encode_public(&created.info.public_key, meta)?,
                )?;
                write_private(
                    key,
                    writ_crypto::keyfile::encode_device(created.stored.as_bytes(), meta)?
                        .as_bytes(),
                )?;
                signer
            }
        };
        let tls = writ_signer::tls::TlsSigner::new(signer, id)?;
        let cert_pem = writ_crypto::tls::remote::self_signed(&tls)?;
        write_public_file(cert, &cert_pem)
    }

    /// Makes the first key, on `backend`, and its certificate (`writd init`, the development
    /// keystore's first start). Refuses files there already.
    pub fn make(&self, backend: Backend, makers: &Makers) -> anyhow::Result<()> {
        Self::write(backend, makers, &self.key, &self.public(), &self.cert)
    }

    /// A rotation (see the module): the new key on `backend` and its certificate written as
    /// `.new`, built into what `build` makes of them (the identity to put in force: a failure
    /// drops them and keeps the old), then renamed over the old ones. A software key leaves no
    /// public half behind.
    pub fn rotate<T>(
        &self,
        backend: Backend,
        makers: &Makers,
        build: impl FnOnce(TlsKeyPair) -> anyhow::Result<T>,
        commit: impl FnOnce(&T) -> anyhow::Result<()>,
    ) -> anyhow::Result<T> {
        self.finish()?;
        let built = Self::write(
            backend,
            makers,
            &next(&self.key),
            &next(&self.public()),
            &next(&self.cert),
        )
        .and_then(|()| self.read_at(true))
        .and_then(build)
        // Its audit line, before anything is in force (the review after M7.6, S-2): a stop
        // after this finishes the rotation at the next start, said then too.
        .and_then(|built| commit(&built).map(|()| built));
        let built = match built {
            Ok(built) => built,
            Err(e) => {
                for part in [self.public(), self.key.clone(), self.cert.clone()] {
                    let _ = remove_if_there(&next(&part));
                }
                return Err(e);
            }
        };
        self.finish()?;
        // After the renames: a stop in between leaves a software key and a stale public
        // half, which a software key's read never looks at.
        if backend == Backend::Software {
            remove_if_there(&self.public())?;
        }
        Ok(built)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(dir: &Path) -> TlsFiles {
        TlsFiles {
            key: dir.join("tls-01"),
            cert: dir.join("tls-01.crt"),
        }
    }

    fn fingerprint(files: &TlsFiles) -> String {
        writ_crypto::tls::fingerprint_pem(&files.read().unwrap().cert_pem).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_rotation_puts_a_new_pair_in_force_and_a_failed_build_keeps_the_old() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        files.make(Backend::Software, &Makers::default()).unwrap();
        let first = fingerprint(&files);
        // Made once: never over another.
        let again = files
            .make(Backend::Software, &Makers::default())
            .unwrap_err();
        assert!(
            format!("{again:#}").starts_with("cannot create"),
            "{again:#}"
        );
        // A build that fails (the identity can't be made): the new files dropped, the old kept.
        let failed = files
            .rotate(
                Backend::Software,
                &Makers::default(),
                |_| -> anyhow::Result<()> { bail!("the identity can't be made") },
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(failed.to_string(), "the identity can't be made");
        assert_eq!(fingerprint(&files), first);
        assert_eq!(names(dir.path()), ["tls-01", "tls-01.crt"]);
        // Built, but its audit line refused (the review after M7.6, S-2): nothing in force
        // changes, the new files dropped.
        let unlogged = files
            .rotate(
                Backend::Software,
                &Makers::default(),
                |_| Ok(()),
                |_| -> anyhow::Result<()> { bail!("the audit log can't take the line") },
            )
            .unwrap_err();
        assert_eq!(unlogged.to_string(), "the audit log can't take the line");
        assert_eq!(fingerprint(&files), first);
        assert_eq!(names(dir.path()), ["tls-01", "tls-01.crt"]);
        // A rotation: built from the new pair, then in force.
        let built = files
            .rotate(
                Backend::Software,
                &Makers::default(),
                |pair| Ok(writ_crypto::tls::fingerprint_pem(&pair.cert_pem)?),
                |_| Ok(()),
            )
            .unwrap();
        assert_ne!(built, first);
        assert_eq!(fingerprint(&files), built);
        assert_eq!(names(dir.path()), ["tls-01", "tls-01.crt"]);
        // A device backend this test has no helper for: refused, nothing changed.
        let refused = files
            .rotate(
                Backend::SeCryptokit,
                &Makers::default(),
                |_| Ok(()),
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(
            format!("{refused:#}"),
            "this daemon has no se-cryptokit backend to make keys"
        );
        assert_eq!(fingerprint(&files), built);
    }

    #[test]
    fn a_rotation_cut_short_is_finished_once_decided_and_dropped_before() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(dir.path());
        files.make(Backend::Software, &Makers::default()).unwrap();
        let old = fingerprint(&files);
        // A second pair, as a rotation writes it beside the first.
        let other = tempfile::tempdir().unwrap();
        let made = super::tests::files(other.path());
        made.make(Backend::Software, &Makers::default()).unwrap();
        let new = fingerprint(&made);
        let pending = |what: &Path, to: &Path| std::fs::copy(what, next(to)).unwrap();
        // Stopped before the certificate was written: not decided, the old pair stays.
        pending(&made.key, &files.key);
        assert_eq!(fingerprint(&files), old);
        assert_eq!(names(dir.path()), ["tls-01", "tls-01.crt"]);
        // Stopped after the certificate was written, before or between the renames: decided,
        // finished at the next read, whichever renames were done.
        pending(&made.key, &files.key);
        pending(&made.cert, &files.cert);
        assert_eq!(fingerprint(&files), new);
        assert_eq!(names(dir.path()), ["tls-01", "tls-01.crt"]);
        files
            .make(Backend::Software, &Makers::default())
            .unwrap_err();
        // The key renamed already, the certificate not yet.
        let third = tempfile::tempdir().unwrap();
        let made = super::tests::files(third.path());
        made.make(Backend::Software, &Makers::default()).unwrap();
        std::fs::copy(&made.key, &files.key).unwrap();
        pending(&made.cert, &files.cert);
        assert_eq!(fingerprint(&files), fingerprint(&made));
    }
}
