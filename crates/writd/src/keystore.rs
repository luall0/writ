//! The daemon's keys and tokens, from the configured keystore: the sealed keystore
//! ([`sealed`]: one age file per secret, made by `writd init`, [`init`]) or the development
//! keystore ([`dev`]: plain files, refused by release builds).

pub mod ca;
mod dev;
mod init;
pub mod recipients;
pub mod rotation;
mod sealed;
pub mod tls;

pub use init::init;
pub use sealed::CA_ID;

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
use writ_platform::unlock::x25519::X25519Unwrap;
use writ_proto::KeyRole;
use zeroize::Zeroizing;

use crate::config::{Config, KeystoreConfig, SealedConfig};
use crate::declared::{Backend, Declarations, Declared};

/// Creates a directory (and its parents) only the daemon can enter (0700).
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    writ_platform::fs::create_private_dir(path)
        .with_context(|| format!("cannot create {} as a private directory", path.display()))
}

/// How [`write_whole`] meets a file already at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whole {
    /// Refused: nothing is ever written over it (a secret is made once).
    New,
    /// Replaced, in one rename.
    Replace,
}

/// Writes `bytes` at `path` whole or not at all, the one way every file of the keystore is
/// written (the review after M7.6, S-11; the review after M5.5, L7: a write cut short left a
/// truncated secret beside its public half, which every later unseal failed on): a
/// temporary file beside it, created with `mode` (set exactly, whatever the umask), written
/// and synced, then linked into place (`New`: a link, unlike a rename, never replaces a file
/// there) or renamed over it (`Replace`), and the directory synced; the temporary file is
/// removed whatever happens.
pub fn write_whole(path: &Path, bytes: &[u8], mode: u32, how: Whole) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dir = path
        .parent()
        .with_context(|| format!("{} has no directory", path.display()))?;
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    let temporary = dir.join(format!(".{name}.new-{}", writ_crypto::keys::random_hex(8)?));
    let written = (|| {
        // `create_new`: never through a link, never over a file.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .and_then(|()| std::io::Write::write_all(&mut file, bytes))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        match how {
            Whole::New => std::fs::hard_link(&temporary, path)
                .with_context(|| format!("cannot create {}", path.display()))?,
            Whole::Replace => std::fs::rename(&temporary, path)
                .with_context(|| format!("cannot move the new file to {}", path.display()))?,
        }
        sync_dir(dir)
    })();
    let _ = std::fs::remove_file(&temporary);
    written
}

/// Syncs the directory `dir` (what a rename or a removal in it changed).
pub fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("cannot sync {}", dir.display()))
}

/// Creates a new file only the daemon can read (0600); fails if it exists ([`write_whole`]).
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_whole(path, bytes, 0o600, Whole::New)
}

/// A key the policy declares (a signing key or an `ssh` upstream credential), opened: its key
/// and what its file says it is (format, creation time, backend), checked against its
/// declaration.
pub struct StoredKey {
    pub id: KeyId,
    pub key: Material,
    pub meta: KeyMeta,
}

/// A declared key's material, opened: a key the daemon holds in software, or what a device
/// backend gave it to keep for a key the device holds (M7.5), with the key's public half.
pub enum Material {
    Software(KeyPair),
    Device {
        backend: Backend,
        stored: writ_signer::Stored,
        public: PublicKey,
    },
}

impl Material {
    pub fn public_key(&self) -> PublicKey {
        match self {
            Material::Software(key) => key.public_key(),
            Material::Device { public, .. } => public.clone(),
        }
    }

    /// The key file's private half (wiped on drop).
    pub fn encode(&self, meta: KeyMeta) -> anyhow::Result<Zeroizing<String>> {
        Ok(match self {
            Material::Software(key) => writ_crypto::keyfile::encode_secret(key, meta)?,
            Material::Device { stored, .. } => {
                writ_crypto::keyfile::encode_device(stored.as_bytes(), meta)?
            }
        })
    }

    /// The material a key file's private half holds, `public` its kept public half.
    pub fn decode(text: &[u8], public: PublicKey) -> anyhow::Result<(Self, KeyMeta)> {
        use writ_crypto::keyfile::Held;
        let (held, meta) = writ_crypto::keyfile::decode_held(text)?;
        let material = match held {
            Held::Software(key) => Material::Software(key),
            Held::Device(stored) => Material::Device {
                backend: Backend::of_meta(&meta)
                    .ok_or_else(|| anyhow::anyhow!("a key file naming a backend writd lacks"))?,
                stored: writ_signer::Stored::new(stored.to_vec()),
                public,
            },
        };
        Ok((material, meta))
    }
}

/// Where the keys a declaration puts on a device are made: by each device backend's signer
/// (`writd init`, `writd recover` and the development keystore: one of their own; the running
/// daemon: the use's signer, which then holds the key). Software keys are made here.
#[derive(Default)]
pub struct Makers {
    devices: BTreeMap<Backend, Device>,
}

/// How a device backend's signer is had: built on first use (a command that never makes a
/// device key never starts its helper), or the running daemon's.
pub type Build = Box<dyn Fn() -> anyhow::Result<Arc<dyn writ_signer::Signer>> + Send + Sync>;

struct Device {
    built: std::sync::OnceLock<Arc<dyn writ_signer::Signer>>,
    build: Option<Build>,
}

impl Makers {
    /// The running daemon's signers, by backend.
    pub fn running(devices: BTreeMap<Backend, Arc<dyn writ_signer::Signer>>) -> Self {
        let devices = devices
            .into_iter()
            .map(|(backend, signer)| {
                let built = std::sync::OnceLock::new();
                let _ = built.set(signer);
                (backend, Device { built, build: None })
            })
            .collect();
        Self { devices }
    }

    /// Signers of their own, each built on first use.
    pub fn lazy(builds: BTreeMap<Backend, Build>) -> Self {
        let devices = builds
            .into_iter()
            .map(|(backend, build)| {
                let device = Device {
                    built: std::sync::OnceLock::new(),
                    build: Some(build),
                };
                (backend, device)
            })
            .collect();
        Self { devices }
    }

    /// The signer of the device backend `backend`, or why there is none.
    pub fn device(&self, backend: Backend) -> anyhow::Result<Arc<dyn writ_signer::Signer>> {
        let device = self.devices.get(&backend).with_context(|| {
            format!("this daemon has no {} backend to make keys", backend.name())
        })?;
        if let Some(signer) = device.built.get() {
            return Ok(signer.clone());
        }
        let build = device
            .build
            .as_ref()
            .with_context(|| format!("the {} backend is not started", backend.name()))?;
        let signer = build()?;
        Ok(device.built.get_or_init(|| signer).clone())
    }

    /// A new key `id` as `declared` describes it: made in software, or by its device.
    pub fn make(&self, id: &KeyId, declared: &Declared) -> anyhow::Result<(Material, KeyMeta)> {
        if !declared.backend.is_device() {
            let (key, meta) = crate::declared::make(declared)?;
            return Ok((Material::Software(key), meta));
        }
        let meta = crate::declared::meta_now(declared)?;
        let created = self
            .device(declared.backend)?
            .create_key(id.clone(), declared.algorithm)
            .with_context(|| {
                format!(
                    "{}: the {} backend did not make it",
                    crate::declared::named(declared.role, id),
                    declared.backend.name()
                )
            })?;
        Ok((
            Material::Device {
                backend: declared.backend,
                stored: created.stored,
                public: created.info.public_key,
            },
            meta,
        ))
    }

    /// Signs `data` with the key `id` (`writd init` and `writd recover`: an OpenPGP key's
    /// certificate): in software, or through the device that made it.
    pub fn sign(
        &self,
        id: &KeyId,
        key: &Material,
        data: &[u8],
        hash: writ_crypto::algorithm::SignerHash,
    ) -> anyhow::Result<writ_crypto::keypair::RawSignature> {
        match key {
            Material::Software(key) => Ok(key.sign(data, hash)?),
            Material::Device { backend, .. } => Ok(self.device(*backend)?.sign(id, data, hash)?),
        }
    }
}

/// The daemon's keys an unseal opens (private halves).
pub struct Keys {
    /// The SSH CA's key (M7.6: in software, or on a device), signing through its own signer.
    pub ca: StoredKey,
    /// The keys commits are signed with: every signing key the policy declares, for the
    /// `Signer`.
    pub signing: Vec<StoredKey>,
    /// The keys the daemon reaches `ssh://` upstreams with: every `ssh` upstream credential
    /// the policy declares, for the upstream `Signer`.
    pub upstream: Vec<StoredKey>,
}

/// The HTTPS approval API's key id in its `Signer`.
pub const TLS_KEY: &str = "tls-01";

/// The HTTPS approval API's key (ECDSA P-256, for its `Signer`: in software, or a device's)
/// and its certificate.
pub struct TlsKeyPair {
    pub key: Material,
    pub cert_pem: String,
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
pub fn public(
    config: &Config,
    declared: &Declarations,
    makers: &Makers,
) -> anyhow::Result<PublicKeys> {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => {
            PublicKeys::of(&dev::boot(dir)?, &dev::keys(dir, declared, makers)?)
        }
        KeystoreConfig::Sealed(sealed) => sealed::public(sealed, declared),
    }
}

/// Where the HTTPS approval API's key and certificate are, in the configured keystore.
pub fn tls_files(config: &Config) -> tls::TlsFiles {
    match &config.keystore {
        KeystoreConfig::Dev(dir) => dev::tls_files(dir),
        KeystoreConfig::Sealed(sealed) => sealed::tls_files(sealed),
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
    write_whole(
        &certificate_path(config, id),
        text.as_bytes(),
        0o644,
        Whole::Replace,
    )
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
/// a sealed key is encrypted to the keystore's public recipient, checked first to be the
/// identity `key` opens), and checks each one it holds against its declaration. The keys
/// made, with their public halves. A sealed keystore needs its data key; the development
/// keystore has none.
pub fn make_missing(
    config: &Config,
    declared: &Declarations,
    makers: &Makers,
    key: Option<&writ_platform::DataKey>,
) -> anyhow::Result<Vec<(KeyId, KeyRole, PublicKey, KeyMeta)>> {
    let recipient = match (&config.keystore, key) {
        (KeystoreConfig::Sealed(sealed), Some(key)) => Some(checked_recipient(sealed, key)?),
        (KeystoreConfig::Sealed(_), None) => {
            bail!("a sealed keystore's keys are made with its data key")
        }
        (KeystoreConfig::Dev(_), _) => None,
    };
    let mut made = Vec::new();
    for (id, key) in declared {
        let (stored, new) = match &config.keystore {
            KeystoreConfig::Dev(dir) => dev::key_or_make(dir, id, key, makers)?,
            KeystoreConfig::Sealed(sealed) => {
                let layout = sealed::Layout(sealed);
                if layout.key(key.role, id).exists() {
                    // Held: as declared, or the policy is refused (it would never start).
                    sealed::check_public(&layout, id, key)?;
                    continue;
                }
                let recipient = recipient
                    .as_ref()
                    .context("the keystore's recipient was not checked")?;
                (sealed::make_key(&layout, recipient, id, key, makers)?, true)
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
    /// References to the tokens in force, each unwrapped only when an operation uses it.
    pub tokens: writ_mirror::credential::Tokens,
    pub bot_tokens: BTreeMap<KeyId, writ_platform::notify::telegram::BotToken>,
    /// What the unseal did to the keystore before it opened it (a rotation of the data key
    /// it owed, one cut short settled), one line each: for the audit log.
    pub settled: Vec<String>,
}

/// The keystore as the running daemon keeps it once open: where the keys a signed policy
/// change names are made, and how a token an approver sends is opened and put in force. The
/// sealed keystore's identity stays here, wiped on drop (`SecretFiles`), so a secret added
/// later is opened through the same seam as at start.
pub enum Live {
    Dev(PathBuf),
    Sealed {
        sealed: SealedConfig,
        /// The ways the keystore's files open by now: the identity on a passphrase keystore,
        /// the hardware recipients on a hardware one (the identity wiped after unseal), and
        /// what a key is sealed to. Replaced whole when the recipients change (a rotation of
        /// the data key among them); every write that seals to it holds it.
        state: std::sync::RwLock<SealedState>,
    },
}

/// What a sealed keystore holds open, by its recipients.
pub struct SealedState {
    pub files: Arc<sealed::SecretFiles>,
    /// A passphrase keystore's data key, kept to wrap its identity again when the recipients
    /// change; none on a hardware keystore (its devices unwrap it again then).
    key: Option<writ_platform::DataKey>,
    /// The recipients secrets are sealed to now: `age1se1…` and `age1…` texts.
    pub token_recipients: Vec<String>,
    /// The identity's recipient: what a key made from now on is sealed to (a rotation
    /// replaces it).
    recipient: age::x25519::Recipient,
    /// Why the data key's rotation is owed (a passphrase keystore, until its next unseal):
    /// none once it is done.
    owed: Vec<String>,
}

impl SealedState {
    /// What a key or the CA is sealed to now.
    pub fn recipient(&self) -> &age::x25519::Recipient {
        &self.recipient
    }
}

/// The ways a keystore with `hardware` opens its files after unseal, and what tokens are
/// sealed to: the hardware recipients the policy declares (and the recovery recipient), or
/// the identity.
fn sealed_state(
    policy: &PolicyConfig,
    key: &writ_platform::DataKey,
    hardware: Vec<recipients::Hardware>,
    owed: Vec<String>,
) -> anyhow::Result<SealedState> {
    let recipient = key.recipient()?;
    let declared: Vec<recipients::Hardware> = hardware
        .into_iter()
        .filter(|h| {
            matches!(
                policy.recipients().get(&h.name),
                Some(writ_core::config::Recipient::Hardware { .. })
            )
        })
        .collect();
    if declared.is_empty() {
        let way = key.way()?;
        let text = way.recipient().to_string();
        return Ok(SealedState {
            files: Arc::new(sealed::SecretFiles::new(vec![Box::new(way)])),
            key: Some(writ_platform::DataKey::from_bytes(*key.as_bytes())),
            token_recipients: vec![text],
            recipient,
            owed,
        });
    }
    let mut texts: Vec<String> = declared.iter().map(|h| h.recipient.to_string()).collect();
    if let Some(recovery) = recipients::recovery(policy)? {
        texts.push(recovery.to_string());
    }
    let ways: Vec<sealed::SecretIdentity> = declared
        .into_iter()
        .map(|h| Box::new(h.way) as sealed::SecretIdentity)
        .collect();
    Ok(SealedState {
        files: Arc::new(sealed::SecretFiles::new(ways)),
        key: None,
        token_recipients: texts,
        recipient,
        owed,
    })
}

/// The data key and the hardware recipients of a sealed keystore at unseal: the hardware ones
/// open `identity.age` when they wrap it, else the passphrase `request` brings. A rotation of
/// the data key cut short is settled first (S-8: [`rotation::settle`], from the keystore's
/// own record, no policy read), so the identity read is the one in force.
pub fn unseal_key(
    config: &Config,
    request: &writ_platform::UnsealRequest,
) -> anyhow::Result<(writ_platform::DataKey, Vec<recipients::Hardware>)> {
    let KeystoreConfig::Sealed(sealed) = &config.keystore else {
        bail!("only a sealed keystore is unsealed");
    };
    for line in rotation::settle(sealed)? {
        tracing::warn!("keystore: {line}");
    }
    let hardware = recipients::load(config, sealed)?;
    if hardware_wrapped(sealed)? {
        let ways: Vec<&dyn writ_platform::KeystoreUnwrap> = hardware
            .iter()
            .map(|h| &h.way as &dyn writ_platform::KeystoreUnwrap)
            .collect();
        let key = writ_platform::unlock::data_key(&recipients::Paths(sealed).identity(), &ways)?;
        return Ok((key, hardware));
    }
    Ok((crate::platform::data_key(sealed, request)?, hardware))
}

/// Whether the keystore's identity is wrapped to hardware (no passphrase), from its header.
pub fn hardware_wrapped(sealed: &SealedConfig) -> anyhow::Result<bool> {
    let path = recipients::Paths(sealed).identity();
    let bytes = writ_platform::fs::read_secret(&path, "the wrapped key", 64 * 1024)?;
    let decryptor = age::Decryptor::new_buffered(&bytes[..])
        .map_err(|_| anyhow::anyhow!("{} is not a valid wrapped key", path.display()))?;
    Ok(!decryptor.is_scrypt())
}

impl Live {
    /// The declared key `id`, from the keystore (checked against `declared`), or made there
    /// now as `declared` describes it; whether it was made is the second value.
    pub fn key_or_make(
        &self,
        id: &KeyId,
        declared: &Declared,
        makers: &Makers,
    ) -> anyhow::Result<(StoredKey, bool)> {
        match self {
            Self::Dev(dir) => dev::key_or_make(dir, id, declared, makers),
            Self::Sealed { sealed, state } => {
                let layout = sealed::Layout(sealed);
                // Held while the key is read or made: a rotation of the data key (which takes
                // it to write) never runs between the recipient read and the file written.
                let state = state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if layout.key(declared.role, id).exists() {
                    return Ok((
                        sealed::stored_key(&state.files, &layout, id, declared)?,
                        false,
                    ));
                }
                Ok((
                    sealed::make_key(&layout, &state.recipient, id, declared, makers)?,
                    true,
                ))
            }
        }
    }

    /// The declared key `id` the keystore holds, checked against `declared` by its public
    /// half (nothing secret opened: a hardware keystore's identity is gone after unseal), and
    /// what its file says it is (an OpenPGP key's creation time).
    pub fn check_held(
        &self,
        id: &KeyId,
        declared: &Declared,
        makers: &Makers,
    ) -> anyhow::Result<KeyMeta> {
        match self {
            Self::Dev(dir) => Ok(dev::key_or_make(dir, id, declared, makers)?.0.meta),
            Self::Sealed { sealed, .. } => {
                sealed::check_public(&sealed::Layout(sealed), id, declared)
            }
        }
    }

    /// Deletes the key `id` of `role` from the keystore: a key a policy change took out
    /// (its sealed file, its public half, an OpenPGP key's certificate). What isn't there is
    /// fine; what can't be removed is an error, naming the file.
    pub fn forget(&self, id: &KeyId, role: KeyRole) -> anyhow::Result<()> {
        let files = match self {
            Self::Dev(dir) => {
                let key = dev::key_path(dir, role, id);
                // A device key's public half beside it.
                let public = key.with_file_name(format!("{id}.pub"));
                vec![key, public]
            }
            Self::Sealed { sealed, .. } => {
                let layout = sealed::Layout(sealed);
                let mut files = vec![layout.key(role, id), layout.key_public(role, id)];
                if role == KeyRole::Signing {
                    files.push(layout.signing_dir().join(format!("{id}.asc")));
                }
                files
            }
        };
        if let Self::Dev(dir) = self
            && role == KeyRole::Signing
        {
            remove_if_there(&dir.join("signing").join(format!("{id}.asc")))?;
        }
        for file in files {
            remove_if_there(&file)?;
        }
        Ok(())
    }

    /// Deletes the token `id` from the keystore: one a policy change took out.
    pub fn forget_token(&self, id: &KeyId) -> anyhow::Result<()> {
        match self {
            Self::Dev(dir) => remove_if_there(&dir.join("tokens").join(id.as_str())),
            Self::Sealed { sealed, .. } => remove_if_there(&sealed::Layout(sealed).token(id)),
        }
    }

    /// The sealed keystore's parts, or why the development keystore takes no token this way.
    fn sealed(&self) -> anyhow::Result<(&SealedConfig, Arc<sealed::SecretFiles>)> {
        match self {
            // poisoned: the state is replaced whole, never left half made.
            Self::Sealed { sealed, state, .. } => Ok((
                sealed,
                state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .files
                    .clone(),
            )),
            Self::Dev(dir) => bail!(
                "the development keystore takes no token from writ admin token: write it alone \
                 to {} (mode 0600) and restart the daemon",
                dir.join("tokens").join("<id>").display()
            ),
        }
    }

    /// The reference to the token in force for `id` (an `https://` upstream's), once it is
    /// written: none in the development keystore, whose tokens are read at start.
    pub fn token_ref(
        &self,
        id: &KeyId,
    ) -> anyhow::Result<Option<writ_mirror::credential::TokenRef>> {
        let Self::Sealed { sealed, .. } = self else {
            return Ok(None);
        };
        let (_, files) = self.sealed()?;
        let source = Arc::new(sealed::SealedTokens::new(sealed.clone(), files));
        sealed::token_ref(sealed, id, &source)
    }

    /// The tokens in force, each a reference unwrapped through the ways open now: what the
    /// mirrors get again once the recipients changed (each token file rewrapped is another
    /// version).
    pub fn token_refs(
        &self,
        policy: &PolicyConfig,
    ) -> anyhow::Result<writ_mirror::credential::Tokens> {
        let Self::Sealed { sealed, .. } = self else {
            bail!("the development keystore's tokens are read at start");
        };
        let (_, files) = self.sealed()?;
        let source = Arc::new(sealed::SealedTokens::new(sealed.clone(), files));
        sealed::tokens(sealed, policy, &source)
    }

    /// The sealed keystore's recipient (what a key is sealed to now) and its configuration;
    /// none for the development keystore. A rotation of the data key replaces the recipient:
    /// a write that seals to it holds [`Live::sealing`] instead, across the write.
    pub fn sealed_parts(&self) -> Option<(&SealedConfig, age::x25519::Recipient)> {
        let (sealed, state) = self.sealing()?;
        Some((sealed, state.recipient().clone()))
    }

    /// The sealed keystore's configuration and its state, held (read) for as long as the
    /// guard lives: a rotation of the data key waits for it.
    pub fn sealing(&self) -> Option<(&SealedConfig, std::sync::RwLockReadGuard<'_, SealedState>)> {
        match self {
            Self::Sealed { sealed, state } => Some((
                sealed,
                state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )),
            Self::Dev(_) => None,
        }
    }

    /// Why the data key's rotation is owed (none: done, or nothing to rotate).
    pub fn rotation_owed(&self) -> Vec<String> {
        match self.sealing() {
            Some((_, state)) => state.owed.clone(),
            None => Vec::new(),
        }
    }

    /// What a token is sealed to now (`writ info`), none for the development keystore.
    pub fn token_recipients(&self) -> Vec<String> {
        match self {
            Self::Dev(_) => Vec::new(),
            Self::Sealed { state, .. } => state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .token_recipients
                .clone(),
        }
    }

    /// Brings the keystore in line with `policy`'s recipients, live (a policy change that
    /// changed them): every hardware recipient loaded, the data key from the passphrase kept
    /// or from the hardware, every file rewrapped as needed, the ways open swapped whole on
    /// success. A change that takes a way in out rotates the data key (S-8): at once on a
    /// hardware keystore (the new identity wrapped to the hardware recipients that remain);
    /// recorded as owed on a passphrase keystore, whose passphrase the daemon doesn't hold,
    /// and done at its next unseal. Answers what changed (for the log) and what to tell the
    /// approver.
    pub fn apply_recipients(
        &self,
        config: &Config,
        policy: &PolicyConfig,
    ) -> anyhow::Result<RecipientsApplied> {
        let Self::Sealed { sealed, state } = self else {
            if policy.recipients().is_empty() {
                return Ok(RecipientsApplied::default());
            }
            bail!("the development keystore takes no recipient");
        };
        let mut state = state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hardware = recipients::load(config, sealed)?;
        let key = match &state.key {
            Some(key) => writ_platform::DataKey::from_bytes(*key.as_bytes()),
            None => {
                let ways: Vec<&dyn writ_platform::KeystoreUnwrap> = hardware
                    .iter()
                    .map(|h| &h.way as &dyn writ_platform::KeystoreUnwrap)
                    .collect();
                writ_platform::unlock::data_key(&recipients::Paths(sealed).identity(), &ways)?
            }
        };
        let mut applied = RecipientsApplied::default();
        let removed = rotation::removed_ways(sealed, policy)?;
        let key = if removed.is_empty() && state.owed.is_empty() {
            key
        } else {
            // Recorded first: a rotation cut short, or one this keystore can't do now, is
            // done at the next unseal.
            let owed = rotation::record_owed(sealed, &removed)?;
            match policy.hardware_keystore() {
                true => {
                    let (new, lines) =
                        rotate_with(sealed, policy, &hardware, &key, rotation::Wrap::Hardware)?;
                    applied.changed.extend(lines);
                    applied.said.push(rotated_said(&owed));
                    new
                }
                false => {
                    applied.said.push(owed_said(&owed));
                    key
                }
            }
        };
        let hardware = recipients::load(config, sealed)?;
        applied
            .changed
            .extend(reconcile_with(sealed, policy, &hardware, &key)?);
        *state = sealed_state(policy, &key, hardware, rotation::recorded(sealed)?)?;
        Ok(applied)
    }

    /// The token file in force for `id`.
    pub fn token_in_force(&self, id: &KeyId) -> anyhow::Result<PreviousToken> {
        let (sealed, _) = self.sealed()?;
        sealed::token_in_force(sealed, id)
    }

    /// The age file `file` an approver sealed for `id`, held for its write: the keystore's
    /// state held (read) for as long as the stage lives, so a rotation of the data key waits
    /// (it would leave a token the new identity doesn't open), and the file opened with the
    /// ways in force (on a hardware keystore, a device: before the service's lock is taken).
    /// What is written is the token sealed again here to what tokens are sealed to now,
    /// never the file as sent: one sealed by a client that read the recipients before a
    /// rotation (a recipient taken out among them) is never stored readable by it (the review
    /// after M7.6, S-8). The plaintext comes with it, wiped on drop, for the caller to check
    /// it is a token.
    pub fn stage_token<'a>(
        &'a self,
        id: &KeyId,
        file: &[u8],
    ) -> anyhow::Result<(StagedToken<'a>, Zeroizing<Vec<u8>>)> {
        let Some((sealed, state)) = self.sealing() else {
            self.sealed()?;
            bail!("the development keystore takes no token from writ admin token");
        };
        let plaintext = state
            .files
            .open(file, &format!("the token sent for {id}"))?;
        let resealed = writ_crypto::sealed::seal_to(&state.token_recipients, &plaintext)
            .and_then(|text| writ_crypto::sealed::decode(&text))
            .map_err(|e| anyhow::anyhow!("the token sent for {id}: {e}"))?;
        Ok((
            StagedToken {
                sealed,
                _state: state,
                id: id.clone(),
                file: resealed,
            },
            plaintext,
        ))
    }
}

/// A token file about to be put in force ([`Live::stage_token`]), the keystore's state held:
/// the token sealed to the recipients in force.
pub struct StagedToken<'a> {
    sealed: &'a SealedConfig,
    _state: std::sync::RwLockReadGuard<'a, SealedState>,
    id: KeyId,
    file: Vec<u8>,
}

impl StagedToken<'_> {
    /// The token file in force for the id now: what the change must replace.
    pub fn in_force(&self) -> anyhow::Result<PreviousToken> {
        sealed::token_in_force(self.sealed, &self.id)
    }

    /// The file that is written: what the change's line and answer name by its digest.
    pub fn bytes(&self) -> &[u8] {
        &self.file
    }

    /// Writes the file whole in place of the one in force.
    pub fn write(self) -> anyhow::Result<()> {
        sealed::write_token(self.sealed, &self.id, &self.file)
    }
}

/// What a change of the recipients did to the keystore.
#[derive(Debug, Default)]
pub struct RecipientsApplied {
    /// Each file rewritten, for the log.
    pub changed: Vec<String>,
    /// What the approver is told (the change's answer, the audit log): the data key
    /// rotated, or its rotation owed.
    pub said: Vec<String>,
}

/// What the approver is told of a rotation of the data key done for `why`.
pub fn rotated_said(why: &[String]) -> String {
    format!(
        "the keystore's data key rotated ({}): a new identity, every key, token, the \
         authority key and the recovery identity sealed to it; what was taken out opens no \
         copy of the keystore made from now on",
        why.join("; ")
    )
}

/// What the approver is told of a rotation of the data key owed for `why`.
pub fn owed_said(why: &[String]) -> String {
    format!(
        "the keystore's data key is to be rotated ({}): this passphrase keystore rotates it \
         at its next unseal, when the passphrase is given; until then, what was taken out \
         still opens the keystore with a copy of its files",
        why.join("; ")
    )
}

/// A rotation of the data key (S-8) from `key` to `policy`'s recipients, with every way the
/// files may still be wrapped to: the identity and each hardware recipient held.
fn rotate_with(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    hardware: &[recipients::Hardware],
    key: &writ_platform::DataKey,
    wrap: rotation::Wrap<'_>,
) -> anyhow::Result<(writ_platform::DataKey, Vec<String>)> {
    let identity = key.way()?;
    let mut ways: Vec<&dyn writ_platform::KeystoreUnwrap> = vec![&identity];
    ways.extend(
        hardware
            .iter()
            .map(|h| &h.way as &dyn writ_platform::KeystoreUnwrap),
    );
    rotation::Rotation {
        sealed,
        policy,
        held: hardware,
        old: key,
        ways: &ways,
        wrap,
    }
    .run()
}

/// [`recipients::reconcile`] with every way the files may still be wrapped to: the identity
/// and each hardware recipient held.
fn reconcile_with(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    hardware: &[recipients::Hardware],
    key: &writ_platform::DataKey,
) -> anyhow::Result<Vec<String>> {
    struct Shared<'a>(&'a writ_platform::unlock::piv::PivUnwrap);
    impl writ_platform::KeystoreUnwrap for Shared<'_> {
        fn name(&self) -> &str {
            writ_platform::KeystoreUnwrap::name(self.0)
        }
        fn unwrap(
            &self,
            stanzas: &[writ_platform::unlock::Stanza],
        ) -> writ_platform::Result<Option<writ_platform::unlock::FileKey>> {
            self.0.unwrap(stanzas)
        }
    }
    let ways: Vec<Box<dyn writ_platform::KeystoreUnwrap + '_>> =
        std::iter::once(Box::new(key.way()?) as Box<dyn writ_platform::KeystoreUnwrap>)
            .chain(
                hardware
                    .iter()
                    .map(|h| Box::new(Shared(&h.way)) as Box<dyn writ_platform::KeystoreUnwrap>),
            )
            .collect();
    let refs: Vec<&dyn writ_platform::KeystoreUnwrap> = ways.iter().map(AsRef::as_ref).collect();
    recipients::reconcile(sealed, policy, hardware, key, &refs)
}

/// Removes `path` if it is there (never following a link: the entry itself goes).
fn remove_if_there(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("cannot remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// The keys the keystore holds that `declared` doesn't name in their role (left by a change
/// that took them out, the daemon stopping before it deleted them): deleted, each said.
/// The CA, the authority key and the tokens are never touched.
pub fn sweep(live: &Live, declared: &Declarations) -> anyhow::Result<Vec<String>> {
    let mut swept = Vec::new();
    for role in [KeyRole::Signing, KeyRole::Upstream] {
        let held = match live {
            Live::Dev(dir) => dev::held(dir, role)?,
            Live::Sealed { sealed, .. } => sealed::held(&sealed::Layout(sealed), role)?,
        };
        for id in held {
            if declared.get(&id).is_some_and(|key| key.role == role) {
                continue;
            }
            live.forget(&id, role)?;
            swept.push(crate::declared::named(role, &id));
        }
    }
    Ok(swept)
}

/// The sealed keystore's public recipient, as `writ info` serves it; none with the development
/// keystore.
pub fn recipient(config: &Config) -> anyhow::Result<Option<String>> {
    match &config.keystore {
        KeystoreConfig::Sealed(sealed) => Ok(Some(sealed::recipient(sealed)?.to_string())),
        KeystoreConfig::Dev(_) => Ok(None),
    }
}

/// Settles the sealed keystore's keys directory before anything reads it: a rotation of the
/// data key cut short finished or undone ([`rotation::settle`], from its own record). Nothing
/// to do for the development keystore.
pub fn settle(config: &Config) -> anyhow::Result<()> {
    if let KeystoreConfig::Sealed(sealed) = &config.keystore {
        for line in rotation::settle(sealed)? {
            tracing::warn!("keystore: {line}");
        }
    }
    Ok(())
}

/// Why the sealed keystore owes a rotation of its data key, from its own record (`writ
/// info`, read with no unseal); none with the development keystore.
pub fn rotation_owed(config: &Config) -> anyhow::Result<Vec<String>> {
    match &config.keystore {
        KeystoreConfig::Sealed(sealed) => rotation::recorded(sealed),
        KeystoreConfig::Dev(_) => Ok(Vec::new()),
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
    identity: X25519Unwrap,
) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    sealed::authority_key(sealed, &sealed::SecretFiles::new(vec![Box::new(identity)]))
}

/// The development keystore's authority key (made on its first start).
pub fn dev_authority_key(dir: &Path) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    dev::authority_key(dir)
}

/// What the daemon starts with, from the configured keystore. A sealed start reads the boot
/// tier, and checks every declared key's public half: a key missing or held as something
/// else than declared stops the start before anything is served; nothing it does is read from
/// the policy but those checks (its MAC is checked at unseal, [`open`]). The development
/// keystore opens at start: `in_force` is checked against its authority key before its keys
/// are made from the policy.
pub fn start(
    config: &Config,
    declared: &Declarations,
    policy: &PolicyConfig,
    in_force: &writ_approval::InForce,
    makers: &Makers,
) -> anyhow::Result<Start> {
    match &config.keystore {
        KeystoreConfig::Sealed(sealed) => {
            // A rotation of the data key cut short (S-8): finished or undone before anything
            // is read from the keys directory (what `writ info` says opens it among them).
            for line in rotation::settle(sealed)? {
                tracing::warn!("keystore: {line}");
            }
            // A CA rotation cut short (M7.6): finished or dropped before the CA is read.
            ca::finish(sealed)?;
            sealed::public(sealed, declared)?;
            Ok(Start::Sealed(sealed::boot(sealed)?))
        }
        KeystoreConfig::Dev(dir) => {
            let authority = dev::authority_key(dir)?;
            in_force.check_mac(&authority)?;
            Ok(Start::Open(
                dev::boot(dir)?,
                Box::new(Opened {
                    keys: dev::keys(dir, declared, makers)?,
                    live: Live::Dev(dir.clone()),
                    authority,
                    tokens: dev::tokens(dir, policy)?,
                    bot_tokens: dev::bot_tokens(dir, &sealed_bot_ids(config))?,
                    settled: Vec::new(),
                }),
            ))
        }
    }
}

/// The sealed keystore's recipient file, checked to be the identity `key` opens: it is what
/// every key and token sealed from now on is encrypted to (and what `writ info` gives
/// approvers), so someone who could write it would receive them (the review after M5.5, L6).
/// Every path that seals to it reads it here (`open`, and `writd recover`'s [`make_missing`]:
/// the review after M7.6, S-7).
pub fn checked_recipient(
    sealed: &SealedConfig,
    key: &writ_platform::DataKey,
) -> anyhow::Result<age::x25519::Recipient> {
    let recipient = sealed::recipient(sealed)?;
    if recipient.to_string() != key.way()?.recipient().to_string() {
        bail!(
            "{}: not this keystore's recipient (replaced?): refused, nothing would be sealed to \
             it",
            sealed::Layout(sealed).recipient().display()
        );
    }
    Ok(recipient)
}

/// Opens the sealed keystore with the data key the passphrase or the hardware unwrapped:
/// every key and token the configuration names. `policy` and `declared` are the start's,
/// read from the state with no MAC checked (its key is sealed): `in_force` is checked
/// against the authority key as soon as it opens, before anything is read or written from
/// them (the review after M7.6, S-1: the reconcile below rewrites keystore files from the
/// policy's recipients, which an edit of the state at rest could have named).
///
/// A rotation of the data key the keystore owes (S-8: [`rotation::owed`], a recipient taken
/// out on a passphrase keystore, or a rotation that didn't finish) is done right after that
/// check, before anything else is read: with `passphrase` (the one that unwrapped the
/// identity) on a passphrase keystore, with the hardware recipients on a hardware one.
pub fn open(
    config: &Config,
    declared: &Declarations,
    policy: &PolicyConfig,
    in_force: &writ_approval::InForce,
    key: writ_platform::DataKey,
    hardware: Vec<recipients::Hardware>,
    passphrase: Option<&writ_platform::Passphrase>,
) -> anyhow::Result<Opened> {
    let KeystoreConfig::Sealed(sealed) = &config.keystore else {
        bail!("only a sealed keystore is opened at unseal");
    };
    checked_recipient(sealed, &key)?;
    let authority = sealed::authority_key(
        sealed,
        &sealed::SecretFiles::new(vec![Box::new(key.way()?)]),
    )?;
    in_force.check_mac(&authority)?;
    let mut settled = Vec::new();
    let owed = rotation::owed(sealed, policy)?;
    let (key, hardware) = if owed.is_empty() {
        (key, hardware)
    } else {
        let wrap = match (policy.hardware_keystore(), passphrase) {
            (true, _) => rotation::Wrap::Hardware,
            (false, Some(passphrase)) if !hardware_wrapped(sealed)? => {
                rotation::Wrap::Passphrase(passphrase)
            }
            (false, _) => bail!(
                "the keystore's data key is to be rotated ({}) back to a passphrase: that is \
                 writd recover, on the daemon's host",
                owed.join("; ")
            ),
        };
        rotation::record_owed(sealed, &owed)?;
        let (new, lines) = rotate_with(sealed, policy, &hardware, &key, wrap)?;
        for line in &lines {
            tracing::info!("keystore: {line}");
        }
        settled.push(format!("at unseal, {}", rotated_said(&owed)));
        (new, recipients::load(config, sealed)?)
    };
    // The recipient file is the identity's (the rotation's own, when one ran).
    checked_recipient(sealed, &key)?;
    let keys_files = sealed::SecretFiles::new(vec![Box::new(key.way()?)]);
    let keys = sealed::keys(sealed, declared, &keys_files)?;
    drop(keys_files);
    // A change of the recipients cut short is finished before anything is used (M7.6).
    for line in reconcile_with(sealed, policy, &hardware, &key)? {
        tracing::info!("keystore: {line}");
    }
    let state = sealed_state(policy, &key, hardware, rotation::recorded(sealed)?)?;
    drop(key);
    let source = Arc::new(sealed::SealedTokens::new(
        sealed.clone(),
        state.files.clone(),
    ));
    Ok(Opened {
        keys,
        authority,
        tokens: sealed::tokens(sealed, policy, &source)?,
        bot_tokens: sealed::bot_tokens(sealed, &sealed_bot_ids(config), &state.files)?,
        settled,
        live: Live::Sealed {
            sealed: sealed.clone(),
            state: std::sync::RwLock::new(state),
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

    /// The review after M7.6 (S-8's remainder): a token sealed by a client that read the
    /// recipients before a rotation (here: to the device and a recovery key since replaced)
    /// still opens with the device, but is stored sealed again to the recipients in force: the
    /// recovery key taken out opens nothing the daemon wrote, the new one and the device do.
    #[test]
    fn a_token_sealed_to_a_recipient_taken_out_is_stored_without_it() {
        use writ_platform::unlock::x25519::X25519Unwrap;
        let dir = tempfile::tempdir().unwrap();
        let sealed = SealedConfig {
            dir: dir.path().join("keys"),
            boot: dir.path().join("boot"),
        };
        std::fs::create_dir_all(&sealed.dir).unwrap();
        // The device (an X25519 key stands for it here: no hardware in a unit test), the
        // recovery key taken out, and the one in force.
        let device = age::x25519::Identity::generate();
        let (old_recovery, new_recovery) = (
            age::x25519::Identity::generate(),
            age::x25519::Identity::generate(),
        );
        let ways: Vec<sealed::SecretIdentity> =
            vec![Box::new(X25519Unwrap::new("se-01", device.clone()))];
        let live = Live::Sealed {
            sealed: sealed.clone(),
            state: std::sync::RwLock::new(SealedState {
                files: Arc::new(sealed::SecretFiles::new(ways)),
                key: None,
                token_recipients: vec![
                    device.to_public().to_string(),
                    new_recovery.to_public().to_string(),
                ],
                recipient: age::x25519::Identity::generate().to_public(),
                owed: Vec::new(),
            }),
        };
        let stale = writ_crypto::sealed::decode(
            &writ_crypto::sealed::seal_to(
                &[
                    device.to_public().to_string(),
                    old_recovery.to_public().to_string(),
                ],
                b"tok-0123456789",
            )
            .unwrap(),
        )
        .unwrap();
        let id: KeyId = "token-01".parse().unwrap();
        let (staged, plaintext) = live.stage_token(&id, &stale).unwrap();
        assert_eq!(plaintext.as_slice(), b"tok-0123456789");
        assert_ne!(
            staged.bytes(),
            stale.as_slice(),
            "sealed again, not as sent"
        );
        staged.write().unwrap();
        let stored = std::fs::read(sealed::Layout(&sealed).token(&id)).unwrap();
        let opens = |identity: &age::x25519::Identity| {
            let decryptor = age::Decryptor::new(stored.as_slice()).unwrap();
            let mut reader =
                match decryptor.decrypt(std::iter::once(identity as &dyn age::Identity)) {
                    Ok(reader) => reader,
                    Err(_) => return None,
                };
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut out).unwrap();
            Some(out)
        };
        assert_eq!(opens(&old_recovery), None, "the recovery key taken out");
        assert_eq!(
            opens(&new_recovery).as_deref(),
            Some(&b"tok-0123456789"[..])
        );
        assert_eq!(opens(&device).as_deref(), Some(&b"tok-0123456789"[..]));
    }
}
