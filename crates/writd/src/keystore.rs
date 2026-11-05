//! The daemon's keys and tokens, from the configured keystore: the sealed keystore
//! ([`sealed`]: one age file per secret, made by `writd init`, [`init`]) or the development
//! keystore ([`dev`]: plain files, refused by release builds).

mod dev;
mod init;
mod sealed;

pub use init::init;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use writ_core::authority::PreviousToken;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::keyfile::KeyMeta;
use writ_crypto::keypair::KeyPair;
use writ_crypto::ssh_key::{PrivateKey, PublicKey};
use writ_mirror::credential::UpstreamToken;
use writ_proto::KeyRole;
use zeroize::Zeroizing;

use crate::config::{Config, KeystoreConfig, SealedConfig};
use crate::declared::{Declarations, Declared};

/// Creates a directory (and its parents) only the daemon can enter (0700).
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    writ_platform::fs::create_private_dir(path)
        .with_context(|| format!("cannot create {} as a private directory", path.display()))
}

/// Creates a new file only the daemon can read (0600); fails if it exists. Whole or not at
/// all (the review after M5.5, L7: a write cut short left a truncated secret beside its
/// public half, which every later unseal failed on): written to a private temporary file,
/// synced, then linked into place (a link, unlike a rename, never replaces a file there) and
/// the directory synced; the temporary file is removed whatever happens.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no directory", path.display()))?;
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    let temporary = dir.join(format!(".{name}.new-{}", writ_crypto::keys::random_hex(8)?));
    let written = (|| {
        let mut file = writ_platform::fs::create_new_private_file(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        std::io::Write::write_all(&mut file, bytes)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        std::fs::hard_link(&temporary, path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("cannot sync {}", dir.display()))
    })();
    let _ = std::fs::remove_file(&temporary);
    written
}

/// A key the policy declares (a signing key or an `ssh` upstream credential), opened: its key
/// and what its file says it is (format, creation time), checked against its declaration.
pub struct StoredKey {
    pub id: KeyId,
    pub key: KeyPair,
    pub meta: KeyMeta,
}

/// The daemon's keys an unseal opens (private halves).
pub struct Keys {
    pub ca: PrivateKey,
    /// The keys commits are signed with: every signing key the policy declares, for the
    /// `Signer`.
    pub signing: Vec<StoredKey>,
    /// The keys the daemon reaches `ssh://` upstreams with: every `ssh` upstream credential
    /// the policy declares, for the upstream `Signer`.
    pub upstream: Vec<StoredKey>,
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
    /// Each declared signing key: its public half and what its file says it is.
    pub signing: Vec<(KeyId, PublicKey, KeyMeta)>,
    pub upstream: Vec<(KeyId, PublicKey)>,
}

impl PublicKeys {
    fn of(boot: &Boot, keys: &Keys) -> anyhow::Result<Self> {
        Ok(Self {
            host: boot.host.public_key().clone(),
            tls_fingerprint: writ_crypto::tls::fingerprint_pem(&boot.tls.cert_pem)?,
            signing: keys
                .signing
                .iter()
                .map(|k| (k.id.clone(), k.key.public_key(), k.meta))
                .collect(),
            upstream: keys
                .upstream
                .iter()
                .map(|k| (k.id.clone(), k.key.public_key()))
                .collect(),
        })
    }
}

/// The upstream tokens the policy declares (`kind: token`): added with `writ admin token`,
/// never made.
pub fn tokens_declared(policy: &PolicyConfig) -> BTreeSet<&KeyId> {
    policy
        .upstream_keys()
        .filter(|(_, key)| matches!(key, writ_core::config::UpstreamKey::Token { .. }))
        .map(|(id, _)| id)
        .collect()
}

/// The declared keys of `role`, each with its declaration.
pub fn of_role(
    declared: &Declarations,
    role: KeyRole,
) -> impl Iterator<Item = (&KeyId, &Declared)> {
    declared.iter().filter(move |(_, key)| key.role == role)
}

/// The public halves of the daemon's keys, from the configured keystore: no unseal needed.
/// Each declared key must be there, as declared.
pub fn public(config: &Config, declared: &Declarations) -> anyhow::Result<PublicKeys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => PublicKeys::of(&dev::boot(dir)?, &dev::keys(dir, declared)?),
        KeystoreConfig::Sealed(sealed) => sealed::public(sealed, declared),
    }
}

/// Where the certificate of the OpenPGP key `id` is kept, beside its key: public, rewritten
/// whenever the daemon certifies the key again (what `writd signing-keys` prints).
pub fn certificate_path(config: &Config, id: &KeyId) -> PathBuf {
    let dir = match &config.keystore {
        KeystoreConfig::Dev(dir) => dir.join("signing"),
        KeystoreConfig::Sealed(sealed) => sealed::Layout(sealed).signing_dir(),
    };
    dir.join(format!("{id}.asc"))
}

/// Writes the certificate of `id` (whole, then moved in place; readable by others).
pub fn write_certificate(config: &Config, id: &KeyId, text: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = certificate_path(config, id);
    let suffix = writ_crypto::keys::random_hex(8)?;
    let temporary = path.with_extension(format!("asc.new-{suffix}"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)
        .with_context(|| format!("cannot create {}", temporary.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    std::fs::rename(&temporary, &path).with_context(|| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot move the certificate to {}", path.display())
    })
}

/// The certificate of `id` the daemon last wrote, if any.
pub fn read_certificate(config: &Config, id: &KeyId) -> anyhow::Result<Option<String>> {
    let path = certificate_path(config, id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(writ_platform::fs::read_authority(
        &path,
        "the certificate",
    )?))
}

/// Makes every key `declared` names that the keystore lacks (`writd recover`, on the host:
/// a sealed key is encrypted to the keystore's public recipient, with no unseal), and checks
/// each one it holds against its declaration. The keys made, with their public halves.
pub fn make_missing(
    config: &Config,
    declared: &Declarations,
) -> anyhow::Result<Vec<(KeyId, KeyRole, PublicKey, KeyMeta)>> {
    let mut made = Vec::new();
    for (id, key) in declared {
        let (stored, new) = match &config.keystore {
            KeystoreConfig::Dev(dir) => dev::key_or_make(dir, id, key)?,
            KeystoreConfig::Sealed(sealed) => {
                let layout = sealed::Layout(sealed);
                if layout.key(key.role, id).exists() {
                    // Held: as declared, or the policy is refused (it would never start).
                    sealed::check_public(&layout, id, key)?;
                    continue;
                }
                let recipient = sealed::recipient(sealed)?;
                (sealed::make_key(&layout, &recipient, id, key)?, true)
            }
        };
        if new {
            made.push((id.clone(), key.role, stored.key.public_key(), stored.meta));
        }
    }
    Ok(made)
}

/// What the daemon starts with: the boot tier alone (sealed), or every key (the development
/// keystore, open at start).
pub enum Start {
    Sealed(Boot),
    Open(Boot, Box<Opened>),
}

/// What a sealed daemon reads at start: the keys it authenticates itself with, and the CA's
/// public key (to check certificates against, and the CA key the unseal brings).
pub struct Boot {
    pub host: PrivateKey,
    pub tls: TlsKeyPair,
    pub ca_public: PublicKey,
}

/// What an open keystore gives: every key, the `https://` upstreams' tokens, and the tokens
/// of the notifiers that keep theirs sealed (by id); and what stays open for the keys and
/// tokens added later ([`Live`]).
pub struct Opened {
    pub keys: Keys,
    pub live: Live,
    /// The key of the MAC over the authority files in force.
    pub authority: writ_crypto::authority::AuthorityKey,
    pub tokens: BTreeMap<KeyId, Arc<UpstreamToken>>,
    pub bot_tokens: BTreeMap<KeyId, writ_platform::notify::telegram::BotToken>,
}

/// The keystore as the running daemon keeps it once open: where the keys a signed policy
/// change names are made, and how a token an approver sends is opened and put in force. The
/// sealed keystore's identity stays here, wiped on drop (`SecretFiles`), so a secret added
/// later is opened through the same seam as at start.
pub enum Live {
    Dev(PathBuf),
    Sealed {
        sealed: SealedConfig,
        files: sealed::SecretFiles,
        recipient: age::x25519::Recipient,
    },
}

impl Live {
    /// The declared key `id`, from the keystore (checked against `declared`), or made there
    /// now as `declared` describes it; whether it was made is the second value.
    pub fn key_or_make(
        &self,
        id: &KeyId,
        declared: &Declared,
    ) -> anyhow::Result<(StoredKey, bool)> {
        match self {
            Self::Dev(dir) => dev::key_or_make(dir, id, declared),
            Self::Sealed {
                sealed,
                files,
                recipient,
            } => {
                let layout = sealed::Layout(sealed);
                if layout.key(declared.role, id).exists() {
                    return Ok((sealed::stored_key(files, &layout, id, declared)?, false));
                }
                Ok((sealed::make_key(&layout, recipient, id, declared)?, true))
            }
        }
    }

    /// The sealed keystore's parts, or why the development keystore takes no token this way.
    fn sealed(&self) -> anyhow::Result<(&SealedConfig, &sealed::SecretFiles)> {
        match self {
            Self::Sealed { sealed, files, .. } => Ok((sealed, files)),
            Self::Dev(dir) => bail!(
                "the development keystore takes no token from writ admin token: write it alone \
                 to {} (mode 0600) and restart the daemon",
                dir.join("tokens").join("<id>").display()
            ),
        }
    }

    /// The token file in force for `id`.
    pub fn token_in_force(&self, id: &KeyId) -> anyhow::Result<PreviousToken> {
        let (sealed, _) = self.sealed()?;
        sealed::token_in_force(sealed, id)
    }

    /// The plaintext of a token an approver sealed to the keystore's recipient (`file`, an age
    /// file), wiped on drop.
    pub fn open_token(&self, id: &KeyId, file: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let (_, files) = self.sealed()?;
        files.open(file, &format!("the token sent for {id}"))
    }

    /// Puts the age file `file` in force as the token of `id`.
    pub fn write_token(&self, id: &KeyId, file: &[u8]) -> anyhow::Result<()> {
        let (sealed, _) = self.sealed()?;
        sealed::write_token(sealed, id, file)
    }
}

/// The sealed keystore's public recipient, as `writ info` serves it; none with the development
/// keystore.
pub fn recipient(config: &Config) -> anyhow::Result<Option<String>> {
    match &config.keystore {
        KeystoreConfig::Sealed(sealed) => Ok(Some(sealed::recipient(sealed)?.to_string())),
        KeystoreConfig::Dev(_) => Ok(None),
    }
}

/// A notifier's token, from the plaintext of its sealed file.
pub fn bot_token(
    id: &KeyId,
    bytes: &[u8],
) -> anyhow::Result<writ_platform::notify::telegram::BotToken> {
    sealed::bot_token(id, bytes)
}

/// The ids of the notifier tokens kept sealed (`notifiers[].telegram.token.sealed`).
pub fn sealed_bot_ids(config: &Config) -> BTreeSet<KeyId> {
    config
        .notifiers
        .iter()
        .filter_map(|notifier| match notifier {
            crate::config::NotifierConfig::Telegram(telegram) => match &telegram.token {
                crate::config::TokenConfig::Sealed(id) => Some(id.clone()),
                crate::config::TokenConfig::Boot(_) => None,
            },
        })
        .collect()
}

/// The sealed keystore's authority key, opened with the identity a passphrase unwrapped.
pub fn sealed_authority_key(
    sealed: &crate::config::SealedConfig,
    identity: age::x25519::Identity,
) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    sealed::authority_key(sealed, &sealed::SecretFiles::new(vec![Box::new(identity)]))
}

/// The development keystore's authority key (made on its first start).
pub fn dev_authority_key(dir: &Path) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    dev::authority_key(dir)
}

/// What the daemon starts with, from the configured keystore. A sealed start reads the boot
/// tier, and checks every declared key's public half: a key missing or held as something
/// else than declared stops the start before anything is served.
pub fn start(
    config: &Config,
    declared: &Declarations,
    policy: &PolicyConfig,
) -> anyhow::Result<Start> {
    match &config.keystore {
        KeystoreConfig::Sealed(sealed) => {
            sealed::public(sealed, declared)?;
            Ok(Start::Sealed(sealed::boot(sealed)?))
        }
        KeystoreConfig::Dev(dir) => Ok(Start::Open(
            dev::boot(dir)?,
            Box::new(Opened {
                keys: dev::keys(dir, declared)?,
                live: Live::Dev(dir.clone()),
                authority: dev::authority_key(dir)?,
                tokens: dev::tokens(dir, policy)?,
                bot_tokens: dev::bot_tokens(dir, &sealed_bot_ids(config))?,
            }),
        )),
    }
}

/// Opens the sealed keystore with the identity a passphrase unwrapped: every key and token
/// the configuration names.
pub fn open(
    config: &Config,
    declared: &Declarations,
    policy: &PolicyConfig,
    identity: age::x25519::Identity,
) -> anyhow::Result<Opened> {
    let KeystoreConfig::Sealed(sealed) = &config.keystore else {
        bail!("only a sealed keystore is opened at unseal");
    };
    // The recipient file is what every key and token sealed from now on is encrypted to (and
    // what `writ info` gives approvers): it must be this identity's, or someone who could
    // write it would receive them (the review after M5.5, L6).
    let recipient = sealed::recipient(sealed)?;
    if recipient.to_string() != identity.to_public().to_string() {
        bail!(
            "{}: not this keystore's recipient (replaced?): refused, nothing would be sealed to \
             it",
            sealed::Layout(sealed).recipient().display()
        );
    }
    let files = sealed::SecretFiles::new(vec![Box::new(identity)]);
    Ok(Opened {
        keys: sealed::keys(sealed, declared, &files)?,
        authority: sealed::authority_key(sealed, &files)?,
        tokens: sealed::tokens(sealed, policy, &files)?,
        bot_tokens: sealed::bot_tokens(sealed, &sealed_bot_ids(config), &files)?,
        live: Live::Sealed {
            sealed: sealed.clone(),
            recipient,
            files,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The review after M5.5 (L7): a secret's file is there whole or not at all, never over
    /// another, and no temporary file is left either way.
    #[test]
    fn a_secret_file_is_written_whole_never_over_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-01.age");
        write_private(&path, b"the whole secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"the whole secret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(names(dir.path()), ["agent-01.age"]);
        // There already: refused, the first one untouched, nothing left behind.
        let error = format!("{:#}", write_private(&path, b"another").unwrap_err());
        assert!(error.starts_with("cannot create"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"the whole secret");
        assert_eq!(names(dir.path()), ["agent-01.age"]);
        // A directory that doesn't exist: refused, nothing made.
        let error = format!(
            "{:#}",
            write_private(&dir.path().join("absent/x.age"), b"x").unwrap_err()
        );
        assert!(error.starts_with("cannot create"), "{error}");
        assert_eq!(names(dir.path()), ["agent-01.age"]);
    }
}
