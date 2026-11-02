//! The daemon's keys and tokens, from the configured keystore: the sealed keystore
//! ([`sealed`]: one age file per secret, made by `writd init`, [`init`]) or the development
//! keystore ([`dev`]: plain files, refused by release builds).

mod dev;
mod init;
mod sealed;

pub use init::init;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::ssh_key::{PrivateKey, PublicKey};
use writ_mirror::credential::UpstreamToken;
use writ_mirror::upstream::Upstream;

use crate::config::{Config, KeystoreConfig};

/// Creates a directory (and its parents) only the daemon can enter (0700).
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    writ_platform::fs::create_private_dir(path)
        .with_context(|| format!("cannot create {} as a private directory", path.display()))
}

/// Creates a new file only the daemon can read (0600); fails if it exists.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = writ_platform::fs::create_new_private_file(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    std::io::Write::write_all(&mut file, bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()))
}

/// The daemon's keys, private halves: what `writd run` needs.
pub struct Keys {
    pub ca: PrivateKey,
    pub host: PrivateKey,
    /// The keys commits are signed with, by id (each template's `signing_key`), for the
    /// `Signer`.
    pub signing: Vec<(KeyId, PrivateKey)>,
    /// The keys the daemon reaches `ssh://` upstreams with, by id (their repos'
    /// `upstream_credential`), for the upstream `Signer`.
    pub upstream: Vec<(KeyId, PrivateKey)>,
    /// The HTTPS approval API's key and self-signed certificate.
    pub tls: TlsKeyPair,
}

/// The HTTPS approval API's key id in its `Signer`.
pub const TLS_KEY: &str = "tls-01";

/// The HTTPS approval API's key (ECDSA P-256, for its `Signer`) and its certificate.
pub struct TlsKeyPair {
    pub key: PrivateKey,
    pub cert_pem: String,
}

/// Makes the HTTPS approval API's key (written to `key_path`, 0600) and its self-signed
/// certificate, signed through a `Signer` holding the key, as every handshake is later
/// (written to `cert_path`, by `write_cert`). The key is moved into that signer, never copied.
fn make_tls(
    key_path: &Path,
    cert_path: &Path,
    write_cert: &dyn Fn(&Path, &str) -> anyhow::Result<()>,
) -> anyhow::Result<String> {
    use writ_crypto::keys::{KeyKind, generate};
    let key = generate(KeyKind::P256)?;
    write_private(
        key_path,
        key.to_openssh(writ_crypto::ssh_key::LineEnding::LF)?
            .as_bytes(),
    )?;
    let id: KeyId = TLS_KEY.parse()?;
    let signer: Arc<dyn writ_signer::Signer> = Arc::new(
        writ_signer::software::SoftwareSigner::new([(id.clone(), key)])?,
    );
    let tls = writ_signer::tls::TlsSigner::new(signer, id)?;
    let cert_pem = writ_crypto::tls::remote::self_signed(&tls)?;
    write_cert(cert_path, &cert_pem)?;
    Ok(cert_pem)
}

/// The daemon's keys, public halves: what the commands that print a key need. From the sealed
/// keystore they are read with no unseal.
pub struct PublicKeys {
    pub host: PublicKey,
    /// The HTTPS approval API certificate's fingerprint, as clients pin it.
    pub tls_fingerprint: String,
    pub signing: Vec<(KeyId, PublicKey)>,
    pub upstream: Vec<(KeyId, PublicKey)>,
}

impl PublicKeys {
    fn of(keys: &Keys) -> anyhow::Result<Self> {
        let public = |keys: &[(KeyId, PrivateKey)]| {
            keys.iter()
                .map(|(id, key)| (id.clone(), key.public_key().clone()))
                .collect()
        };
        Ok(Self {
            host: keys.host.public_key().clone(),
            tls_fingerprint: writ_crypto::tls::fingerprint_pem(&keys.tls.cert_pem)?,
            signing: public(&keys.signing),
            upstream: public(&keys.upstream),
        })
    }
}

/// The signing keys every template names, each once.
fn signing_ids(policy: &PolicyConfig) -> BTreeSet<&KeyId> {
    policy
        .templates()
        .values()
        .filter_map(|t| t.signing_key.as_ref())
        .collect()
}

/// The upstream credentials the registry names, split by what reaches each: the ids of
/// `ssh://` repos (keys) and of `https://` repos (tokens). One id for both is refused: a
/// credential is a key or a token. A URL that doesn't parse is left out (the mirrors refuse it
/// at startup, with the reason).
fn upstream_credentials(
    policy: &PolicyConfig,
) -> anyhow::Result<(BTreeSet<&KeyId>, BTreeSet<&KeyId>)> {
    let (mut keys, mut tokens) = (BTreeSet::new(), BTreeSet::new());
    for entry in policy.repos().values() {
        match Upstream::parse(&entry.upstream) {
            Ok(Upstream::Ssh(_)) => keys.insert(&entry.upstream_credential),
            Ok(Upstream::Https(_)) => tokens.insert(&entry.upstream_credential),
            Err(_) => false,
        };
    }
    if let Some(both) = keys.intersection(&tokens).next() {
        bail!(
            "upstream credential {both} is named by an ssh:// repo (a key) and an https:// repo \
             (a token): give each its own id"
        );
    }
    Ok((keys, tokens))
}

/// The daemon's keys, from the configured keystore.
pub fn keys(config: &Config, policy: &PolicyConfig) -> anyhow::Result<Keys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => dev::keys(dir, policy),
        KeystoreConfig::Sealed(_) => bail!(
            "keystore.sealed: this build does not unseal yet (the sealed start comes in M5); \
             the commands that print a key work"
        ),
    }
}

/// The public halves of the daemon's keys, from the configured keystore: no unseal needed.
pub fn public(config: &Config, policy: &PolicyConfig) -> anyhow::Result<PublicKeys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => PublicKeys::of(&dev::keys(dir, policy)?),
        KeystoreConfig::Sealed(sealed) => sealed::public(sealed, policy),
    }
}

/// The tokens the daemon reaches `https://` upstreams with, by id (their repos'
/// `upstream_credential`), from the configured keystore. Apart from [`keys`]: the commands
/// that print a key run before the operator wrote any token.
pub fn tokens(
    config: &Config,
    policy: &PolicyConfig,
) -> anyhow::Result<BTreeMap<KeyId, Arc<UpstreamToken>>> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => dev::tokens(dir, policy),
        KeystoreConfig::Sealed(_) => {
            bail!("keystore.sealed: this build does not unseal yet (the sealed start comes in M5)")
        }
    }
}
