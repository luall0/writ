//! The sealed keystore: every secret is its own age file, encrypted to the keystore's
//! recipient, whose identity is wrapped with the passphrase; the boot tier holds what a sealed
//! daemon authenticates itself with.
//!
//! ```text
//! keystore.sealed.dir (0700)
//!   identity.age            the keystore's identity, wrapped with the passphrase (age scrypt)
//!   recipient               its public recipient (age1…), for whoever encrypts a secret
//!   ca.age      ca.pub      the SSH CA key (age file), its public half (in clear)
//!   authority.age           the key of the MAC over the authority files in force
//!   signing/<id>.age .pub   the agent signing keys
//!   upstream/<id>.age .pub  the ssh:// upstreams' credentials
//!   tokens/<id>.age         the https:// upstreams' tokens, and the notifiers' kept sealed
//! keystore.sealed.boot (0700): read at a sealed start
//!   host                    the SSH host key (OpenSSH, 0600)
//!   tls-01 tls-01.crt       the HTTPS approval API's key (P-256, OpenSSH, 0600), its
//!                           certificate (signed through the `Signer`)
//! ```
//!
//! A secret is read only through [`SecretFiles`]: the one seam that knows which identities may
//! open a file. Hardware recipients (M7.6) are more identities there, with no format change.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::ssh_key::{PrivateKey, PublicKey};
use writ_mirror::credential::UpstreamToken;
use writ_platform::notify::telegram::BotToken;
use zeroize::Zeroizing;

use writ_proto::KeyRole;

use super::{
    Boot, Keys, PublicKeys, StoredKey, TlsKeyPair, of_role, tokens_declared, write_private,
};
use crate::config::SealedConfig;
use crate::declared::{Declarations, Declared};
use writ_crypto::keyfile::{self, KeyMeta};

/// The largest secret file read: a key or a token in an age file is a few hundred bytes.
const MAX_SECRET_FILE: u64 = 64 * 1024;

/// Where each file of the sealed keystore is. Key ids are plain names, never paths
/// (`KeyId`), so they join safely.
pub struct Layout<'a>(pub &'a SealedConfig);

impl Layout<'_> {
    pub fn recipient(&self) -> PathBuf {
        self.0.dir.join("recipient")
    }
    pub fn ca(&self) -> PathBuf {
        self.0.dir.join("ca.age")
    }
    pub fn authority(&self) -> PathBuf {
        self.0.dir.join("authority.age")
    }
    pub fn ca_public(&self) -> PathBuf {
        self.0.dir.join("ca.pub")
    }
    pub fn signing_dir(&self) -> PathBuf {
        self.0.dir.join("signing")
    }
    pub fn signing(&self, id: &KeyId) -> PathBuf {
        self.signing_dir().join(format!("{id}.age"))
    }
    pub fn signing_public(&self, id: &KeyId) -> PathBuf {
        self.signing_dir().join(format!("{id}.pub"))
    }
    pub fn upstream_dir(&self) -> PathBuf {
        self.0.dir.join("upstream")
    }
    pub fn upstream(&self, id: &KeyId) -> PathBuf {
        self.upstream_dir().join(format!("{id}.age"))
    }
    pub fn upstream_public(&self, id: &KeyId) -> PathBuf {
        self.upstream_dir().join(format!("{id}.pub"))
    }
    /// The directory of the keys of `role`.
    pub fn key_dir(&self, role: KeyRole) -> PathBuf {
        match role {
            KeyRole::Signing => self.signing_dir(),
            KeyRole::Upstream => self.upstream_dir(),
        }
    }
    /// The sealed key `id` of `role`.
    pub fn key(&self, role: KeyRole, id: &KeyId) -> PathBuf {
        match role {
            KeyRole::Signing => self.signing(id),
            KeyRole::Upstream => self.upstream(id),
        }
    }
    /// The public half of the key `id` of `role`.
    pub fn key_public(&self, role: KeyRole, id: &KeyId) -> PathBuf {
        match role {
            KeyRole::Signing => self.signing_public(id),
            KeyRole::Upstream => self.upstream_public(id),
        }
    }
    pub fn tokens_dir(&self) -> PathBuf {
        self.0.dir.join("tokens")
    }
    pub fn token(&self, id: &KeyId) -> PathBuf {
        self.tokens_dir().join(format!("{id}.age"))
    }
    pub fn host(&self) -> PathBuf {
        self.0.boot.join("host")
    }
    pub fn tls_key(&self) -> PathBuf {
        self.0.boot.join("tls-01")
    }
    pub fn tls_cert(&self) -> PathBuf {
        self.0.boot.join("tls-01.crt")
    }
}

/// An identity that may open a secret file: the keystore's own (unwrapped at unseal), or,
/// from M7.6, one held by hardware.
pub type SecretIdentity = Box<dyn age::Identity + Send + Sync>;

/// Opens the keystore's secret files: the one seam a secret is unwrapped through. A file is
/// opened by whichever of the identities its header names a stanza for.
pub struct SecretFiles {
    identities: Vec<SecretIdentity>,
}

impl SecretFiles {
    pub fn new(identities: Vec<SecretIdentity>) -> Self {
        Self { identities }
    }

    /// The plaintext of the secret file at `path` (`what` names it in errors), in memory
    /// wiped on drop. The file must be private to the daemon (0600, its owner, no link) and
    /// encrypted to a recipient, never to a passphrase.
    pub fn read(&self, path: &Path, what: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let sealed = writ_platform::fs::read_secret(path, what, MAX_SECRET_FILE)?;
        self.open(&sealed, &path.display().to_string())
    }

    /// The plaintext of the age file `sealed` (a secret not written yet: a token an approver
    /// sent; `name` names it in errors), as [`SecretFiles::read`] opens a file.
    pub fn open(&self, sealed: &[u8], name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if u64::try_from(sealed.len()).unwrap_or(u64::MAX) > MAX_SECRET_FILE {
            bail!("{name} is larger than a sealed secret ({MAX_SECRET_FILE} bytes)");
        }
        let not_one = || format!("{name} is not a sealed secret");
        let decryptor = age::Decryptor::new_buffered(sealed)
            .map_err(|_| anyhow::anyhow!("{}: not an age file", not_one()))?;
        if decryptor.is_scrypt() {
            bail!("{}: it is encrypted to a passphrase", not_one());
        }
        let mut reader = decryptor
            .decrypt(
                self.identities
                    .iter()
                    .map(|identity| identity.as_ref() as &dyn age::Identity),
            )
            .map_err(|e| match e {
                age::DecryptError::NoMatchingKeys => {
                    anyhow::anyhow!("{name}: no identity of this keystore opens it")
                }
                _ => anyhow::anyhow!("{name}: cannot decrypt it"),
            })?;
        // Room for the largest secret up front: reading never moves the plaintext to a
        // larger buffer, which would leave an unwiped copy behind.
        let capacity = usize::try_from(MAX_SECRET_FILE).unwrap_or(usize::MAX);
        let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
        (&mut reader)
            .take(MAX_SECRET_FILE)
            .read_to_end(&mut plaintext)
            .map_err(|_| anyhow::anyhow!("{name}: cannot decrypt it"))?;
        Ok(plaintext)
    }
}

/// Writes `plaintext` as a new secret file at `path`, encrypted to `recipients` (the
/// keystore's), private to the daemon (0600). Refuses an existing file.
pub fn seal(
    path: &Path,
    plaintext: &[u8],
    recipients: &[&dyn age::Recipient],
) -> anyhow::Result<()> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().copied())
        .map_err(|_| anyhow::anyhow!("{}: no recipient to encrypt to", path.display()))?;
    let mut sealed = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut sealed)
        .with_context(|| format!("cannot encrypt {}", path.display()))?;
    writer
        .write_all(plaintext)
        .and_then(|()| writer.finish().map(|_| ()))
        .with_context(|| format!("cannot encrypt {}", path.display()))?;
    write_private(path, &sealed)
}

/// Writes a public file (a public key, the recipient), new, readable by others: it holds
/// nothing secret.
pub fn write_public(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
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

/// The public key in the file at `path`, which `what` names. A missing one is a key the
/// keystore doesn't hold.
fn read_public(path: &Path, what: &str) -> anyhow::Result<PublicKey> {
    if !path.exists() {
        bail!(
            "{what} is not in the keystore ({} is missing): `writd init` makes the keys the \
             policy names",
            path.display()
        );
    }
    // Public, but whoever could replace it would choose the key an operator registers: an
    // authority file (the daemon's, nobody else can write it).
    let text = writ_platform::fs::read_authority(path, what)?;
    PublicKey::from_openssh(text.trim())
        .with_context(|| format!("{}: not a public key", path.display()))
}

/// The boot tier's host key: read at a sealed start, so a file, private to the daemon.
pub fn host_key(sealed: &SealedConfig) -> anyhow::Result<PrivateKey> {
    let path = Layout(sealed).host();
    let pem = writ_platform::fs::read_secret(&path, "the host key", MAX_SECRET_FILE)?;
    PrivateKey::from_openssh(pem.as_slice())
        .with_context(|| format!("{}: not an OpenSSH private key", path.display()))
}

/// The boot tier's TLS certificate (PEM): public, an authority file (whoever replaced it would
/// choose what clients pin).
fn tls_cert(sealed: &SealedConfig) -> anyhow::Result<String> {
    Ok(writ_platform::fs::read_authority(
        &Layout(sealed).tls_cert(),
        "the TLS certificate",
    )?)
}

/// The boot tier's TLS key and certificate.
pub fn tls(sealed: &SealedConfig) -> anyhow::Result<TlsKeyPair> {
    let path = Layout(sealed).tls_key();
    let text = writ_platform::fs::read_secret(&path, "the TLS key", MAX_SECRET_FILE)?;
    let key = PrivateKey::from_openssh(text.as_slice())
        .with_context(|| format!("{}: not an OpenSSH private key", path.display()))?;
    Ok(TlsKeyPair {
        key,
        cert_pem: tls_cert(sealed)?,
    })
}

/// What a sealed daemon reads at start: the boot tier, and the CA's public half.
pub fn boot(sealed: &SealedConfig) -> anyhow::Result<Boot> {
    Ok(Boot {
        host: host_key(sealed)?,
        tls: tls(sealed)?,
        ca_public: read_public(&Layout(sealed).ca_public(), "the CA key")?,
    })
}

/// The sealed secret `tokens/<id>.age`, opened by `files`; `what` names it. A missing one is
/// a token nobody added yet: `None`, said in the log.
fn sealed_token(
    files: &SecretFiles,
    sealed: &SealedConfig,
    id: &KeyId,
    what: &str,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let path = Layout(sealed).token(id);
    if !path.exists() {
        tracing::warn!(
            "{what} {id} is not in the keystore: an approver adds it with `writ admin token {id}`"
        );
        return Ok(None);
    }
    files.read(&path, what).map(Some)
}

/// The authority MAC's key, opened by `files`.
pub fn authority_key(
    sealed: &SealedConfig,
    files: &SecretFiles,
) -> anyhow::Result<writ_crypto::authority::AuthorityKey> {
    let bytes = files.read(&Layout(sealed).authority(), "the authority key")?;
    Ok(writ_crypto::authority::AuthorityKey::from_bytes(&bytes)?)
}

/// The tokens of `https://` repos, opened by `files`; one not added yet is left out (its
/// repos reach nothing upstream until it is).
pub fn tokens(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    files: &SecretFiles,
) -> anyhow::Result<std::collections::BTreeMap<KeyId, std::sync::Arc<UpstreamToken>>> {
    let ids = tokens_declared(policy);
    let mut tokens = std::collections::BTreeMap::new();
    for id in ids {
        if let Some(bytes) = sealed_token(files, sealed, id, "upstream token")? {
            let token = UpstreamToken::from_bytes(&bytes)
                .map_err(|why| anyhow::anyhow!("upstream token {id}: not a token: {why}"))?;
            tokens.insert(id.clone(), std::sync::Arc::new(token));
        }
    }
    Ok(tokens)
}

/// A notifier's token, from the plaintext of its sealed file.
pub fn bot_token(id: &KeyId, bytes: &[u8]) -> anyhow::Result<BotToken> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("notifier token {id}: not text"))?;
    Ok(BotToken::new(text.trim().to_owned())?)
}

/// The tokens of the notifiers that keep theirs sealed, opened by `files`; one not added yet
/// is left out (its notifier stays off until it is).
pub fn bot_tokens(
    sealed: &SealedConfig,
    ids: &std::collections::BTreeSet<KeyId>,
    files: &SecretFiles,
) -> anyhow::Result<std::collections::BTreeMap<KeyId, BotToken>> {
    let mut tokens = std::collections::BTreeMap::new();
    for id in ids {
        if let Some(bytes) = sealed_token(files, sealed, id, "notifier token")? {
            tokens.insert(id.clone(), bot_token(id, &bytes)?);
        }
    }
    Ok(tokens)
}

/// The keystore's recipient, from its file: public (`writ info` serves it), an authority file
/// all the same (whoever replaced it would receive the tokens added next).
pub fn recipient(sealed: &SealedConfig) -> anyhow::Result<age::x25519::Recipient> {
    let path = Layout(sealed).recipient();
    let text = writ_platform::fs::read_authority(&path, "the keystore's recipient")?;
    text.trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{}: not an age X25519 recipient", path.display()))
}

/// The digest of the token file in force for `id`, or none.
pub fn token_in_force(
    sealed: &SealedConfig,
    id: &KeyId,
) -> anyhow::Result<writ_core::authority::PreviousToken> {
    use writ_core::authority::{PreviousToken, TextDigest};
    let path = Layout(sealed).token(id);
    if !path.exists() {
        return Ok(PreviousToken::None);
    }
    let bytes = writ_platform::fs::read_secret(&path, "the token file", MAX_SECRET_FILE)?;
    Ok(PreviousToken::File(TextDigest::of_bytes(&bytes)))
}

/// Puts `bytes` (an age file) in force as `tokens/<id>.age`, replacing the one there: written
/// whole beside it (0600), then moved in place.
pub fn write_token(sealed: &SealedConfig, id: &KeyId, bytes: &[u8]) -> anyhow::Result<()> {
    let layout = Layout(sealed);
    super::private_dir(&layout.tokens_dir())?;
    let suffix = writ_crypto::keys::random_hex(8)?;
    let temporary = layout.tokens_dir().join(format!(".{id}.age.new-{suffix}"));
    write_private(&temporary, bytes)?;
    let path = layout.token(id);
    std::fs::rename(&temporary, &path).with_context(|| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot move the new token to {}", path.display())
    })
}

/// The public half of the declared key `id` and what its file says it is. A missing one is a
/// declared key the keystore doesn't hold.
fn stored_public(
    layout: &Layout<'_>,
    role: KeyRole,
    id: &KeyId,
) -> anyhow::Result<(PublicKey, KeyMeta)> {
    let path = layout.key_public(role, id);
    let name = crate::declared::named(role, id);
    if !path.exists() {
        bail!(
            "{name} is declared but not in the keystore ({} is missing): the change that \
             declares a key makes it (writd init for the first policy, writd recover, a signed \
             admin change)",
            path.display()
        );
    }
    let text = writ_platform::fs::read_authority(&path, &name)?;
    keyfile::decode_public(text.as_bytes())
        .with_context(|| format!("{}: not a key's public half", path.display()))
}

/// The ids of the keys of `role` the sealed keystore holds (`<id>.age` files).
pub fn held(layout: &Layout<'_>, role: KeyRole) -> anyhow::Result<Vec<KeyId>> {
    let dir = layout.key_dir(role);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot read {}", dir.display()))?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".age"))
            .and_then(|name| name.parse::<KeyId>().ok())
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Checks the public half of the held key `id` against its declaration.
pub fn check_public(layout: &Layout<'_>, id: &KeyId, declared: &Declared) -> anyhow::Result<()> {
    let (public, meta) = stored_public(layout, declared.role, id)?;
    crate::declared::check_key(id, declared, &public, &meta)
}

/// The public halves: the boot tier's keys, and the `.pub` files beside each sealed key, for
/// every key the policy declares (each checked against its declaration). Nothing sealed is
/// opened.
pub fn public(sealed: &SealedConfig, declared: &Declarations) -> anyhow::Result<PublicKeys> {
    let layout = Layout(sealed);
    let read = |role: KeyRole| -> anyhow::Result<Vec<(KeyId, PublicKey, KeyMeta)>> {
        of_role(declared, role)
            .map(|(id, key)| {
                let (public, meta) = stored_public(&layout, role, id)?;
                crate::declared::check_key(id, key, &public, &meta)?;
                Ok((id.clone(), public, meta))
            })
            .collect()
    };
    Ok(PublicKeys {
        host: host_key(sealed)?.public_key().clone(),
        tls_fingerprint: writ_crypto::tls::fingerprint_pem(&tls_cert(sealed)?)?,
        signing: read(KeyRole::Signing)?,
        upstream: read(KeyRole::Upstream)?
            .into_iter()
            .map(|(id, public, _)| (id, public))
            .collect(),
    })
}

/// The sealed key at `secret`, opened by `files`, and checked against its public half at
/// `public` (the one printed and registered): a mismatch means one was replaced. The CA key.
fn sealed_key(
    files: &SecretFiles,
    secret: &Path,
    public: &Path,
    what: &str,
) -> anyhow::Result<PrivateKey> {
    let text = files.read(secret, what)?;
    let key = PrivateKey::from_openssh(text.as_slice())
        .with_context(|| format!("{}: not an OpenSSH private key", secret.display()))?;
    if read_public(public, what)? != *key.public_key() {
        bail!(
            "{} does not match {}: one of them was replaced",
            public.display(),
            secret.display()
        );
    }
    Ok(key)
}

/// The declared key `id`, opened by `files`, checked against its public half (the one printed
/// and registered, and what its file says it is) and against its declaration.
pub fn stored_key(
    files: &SecretFiles,
    layout: &Layout<'_>,
    id: &KeyId,
    declared: &Declared,
) -> anyhow::Result<StoredKey> {
    let role = declared.role;
    let path = layout.key(role, id);
    let text = files.read(&path, &crate::declared::named(role, id))?;
    let (public, public_meta) = stored_public(layout, role, id)?;
    let (key, meta) = super::Material::decode(&text, public.clone())
        .with_context(|| format!("{}: not a key", path.display()))?;
    if public != key.public_key() || public_meta != meta {
        bail!(
            "{} does not match {}: one of them was replaced",
            layout.key_public(role, id).display(),
            path.display()
        );
    }
    crate::declared::check_key(id, declared, &public, &meta)?;
    Ok(StoredKey {
        id: id.clone(),
        key,
        meta,
    })
}

/// Makes the key `id` as `declared` describes it, sealed to `recipient`: its public half
/// written first (a make cut short leaves at most a public half, which the next one
/// replaces). Refuses a key the keystore holds already.
pub fn make_key(
    layout: &Layout<'_>,
    recipient: &dyn age::Recipient,
    id: &KeyId,
    declared: &Declared,
    makers: &super::Makers,
) -> anyhow::Result<StoredKey> {
    let role = declared.role;
    let (secret, public) = (layout.key(role, id), layout.key_public(role, id));
    if secret.exists() {
        bail!(
            "{} is in the keystore already ({}): a key is made once",
            crate::declared::named(role, id),
            secret.display()
        );
    }
    super::private_dir(&layout.key_dir(role))?;
    match std::fs::remove_file(&public) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("cannot replace {}", public.display()));
        }
        _ => {}
    }
    let (key, meta) = makers.make(id, declared)?;
    write_public(&public, &keyfile::encode_public(&key.public_key(), meta)?)?;
    seal(&secret, key.encode(meta)?.as_bytes(), &[recipient])?;
    Ok(StoredKey {
        id: id.clone(),
        key,
        meta,
    })
}

/// The daemon's keys, from the sealed keystore opened by `files`: the CA key, and every key
/// the policy declares, each checked against its declaration.
pub fn keys(
    sealed: &SealedConfig,
    declared: &Declarations,
    files: &SecretFiles,
) -> anyhow::Result<Keys> {
    let layout = Layout(sealed);
    let open = |role: KeyRole| -> anyhow::Result<Vec<StoredKey>> {
        of_role(declared, role)
            .map(|(id, key)| stored_key(files, &layout, id, key))
            .collect()
    };
    Ok(Keys {
        ca: sealed_key(files, &layout.ca(), &layout.ca_public(), "the CA key")?,
        signing: open(KeyRole::Signing)?,
        upstream: open(KeyRole::Upstream)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::os::unix::fs::PermissionsExt;

    use age::secrecy::ExposeSecret;
    use age_core::format::{FileKey, Stanza};
    use writ_platform::unlock::passphrase::PassphraseUnlock;
    use writ_platform::{DataKey, KeystoreUnlock, Passphrase, UnsealRequest};

    use super::super::init::{Made, make};
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    /// The keys the policy declares: one signing key, one upstream key (a token too, never
    /// made).
    fn declared() -> Declarations {
        crate::declared::declarations(&policy()).unwrap()
    }

    /// Two templates sign with one key; an ssh:// and an https:// repo.
    fn policy() -> PolicyConfig {
        PolicyConfig::from_yaml(&policy_text()).unwrap()
    }

    /// Wraps the identity with a cheap work factor: the tests open it many times.
    fn cheap(sealed: &SealedConfig, passphrase: &Passphrase, key: &DataKey) -> anyhow::Result<()> {
        PassphraseUnlock::enroll_with_work_factor(
            sealed.dir.join("identity.age"),
            passphrase,
            key,
            4,
        )?;
        Ok(())
    }

    fn setup() -> (tempfile::TempDir, SealedConfig, Made) {
        let root = tempfile::tempdir().unwrap();
        let sealed = SealedConfig {
            dir: root.path().join("keys"),
            boot: root.path().join("boot"),
        };
        let made = make(
            &sealed,
            &declared(),
            &policy(),
            &Passphrase::new(PASSPHRASE.to_owned()),
            &cheap,
            &crate::keystore::Makers::default(),
        )
        .unwrap();
        (root, sealed, made)
    }

    /// The keystore's files opened with the passphrase, as the sealed start does.
    fn opened(sealed: &SealedConfig, passphrase: &str) -> anyhow::Result<SecretFiles> {
        let key = PassphraseUnlock::new(sealed.dir.join("identity.age")).unlock(
            &UnsealRequest::with_passphrase(Passphrase::new(passphrase.to_owned())),
        )?;
        Ok(SecretFiles::new(vec![Box::new(key.identity()?)]))
    }

    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                found.extend(files(&path));
            } else {
                found.push(path);
            }
        }
        found.sort();
        found
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_keys_directory_alone_reveals_no_key() {
        let (_root, sealed, made) = setup();
        let names: BTreeSet<String> = files(&sealed.dir)
            .iter()
            .map(|p| p.strip_prefix(&sealed.dir).unwrap().display().to_string())
            .collect();
        let expected: BTreeSet<String> = [
            "identity.age",
            "recipient",
            "authority.age",
            "ca.age",
            "ca.pub",
            "signing/agent-01.age",
            "signing/agent-01.pub",
            "upstream/key-01.age",
            "upstream/key-01.pub",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(names, expected, "one age file per secret, no token made");
        for path in files(&sealed.dir) {
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("PRIVATE KEY"), "{}", path.display());
            let name = path.file_name().unwrap().to_str().unwrap();
            if name.ends_with(".age") {
                assert!(
                    text.starts_with("age-encryption.org/v1\n"),
                    "{}",
                    path.display()
                );
                assert_eq!(mode(&path), 0o600, "{}", path.display());
                let stanza = if name == "identity.age" {
                    "-> scrypt "
                } else {
                    "-> X25519 "
                };
                assert!(text.contains(stanza), "{}: {text}", path.display());
            } else {
                // Public halves and the recipient: nothing to hide, nobody else may write them.
                assert_eq!(mode(&path), 0o644, "{}", path.display());
            }
        }
        assert_eq!(
            std::fs::read_to_string(sealed.dir.join("recipient")).unwrap(),
            format!("{}\n", made.recipient)
        );
        // The boot tier holds the keys a sealed daemon authenticates itself with, and only them.
        let boot: Vec<String> = files(&sealed.boot)
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(boot, ["host", "tls-01", "tls-01.crt"]);
        for (path, bits) in [
            (sealed.dir.clone(), 0o700),
            (sealed.boot.clone(), 0o700),
            (sealed.dir.join("signing"), 0o700),
            (sealed.boot.join("host"), 0o600),
            (sealed.boot.join("tls-01"), 0o600),
            (sealed.boot.join("tls-01.crt"), 0o644),
        ] {
            assert_eq!(mode(&path), bits, "{}", path.display());
        }
    }

    #[test]
    fn the_passphrase_opens_every_key_the_policy_names_and_nothing_else_does() {
        let (_root, sealed, made) = setup();
        // The public halves need no passphrase, and are the keys made.
        let public = public(&sealed, &declared()).unwrap();
        assert_eq!(public.host, made.keys.host);
        assert_eq!(public.tls_fingerprint, made.keys.tls_fingerprint);
        assert_eq!(public.signing, made.keys.signing);
        assert_eq!(public.upstream, made.keys.upstream);

        let keys = keys(&sealed, &declared(), &opened(&sealed, PASSPHRASE).unwrap()).unwrap();
        let boot = boot(&sealed).unwrap();
        assert_eq!(*boot.host.public_key(), made.keys.host);
        assert_eq!(boot.ca_public, *keys.ca.public_key());
        assert_eq!(
            writ_crypto::tls::fingerprint_pem(&boot.tls.cert_pem).unwrap(),
            made.keys.tls_fingerprint
        );
        let signing: Vec<String> = keys.signing.iter().map(|k| k.id.to_string()).collect();
        assert_eq!(signing, ["agent-01"]);
        let upstream: Vec<String> = keys.upstream.iter().map(|k| k.id.to_string()).collect();
        assert_eq!(upstream, ["key-01"]);
        assert_eq!(keys.signing[0].key.public_key(), made.keys.signing[0].1);
        assert_eq!(keys.signing[0].meta, KeyMeta::SSH);

        let wrong = opened(&sealed, "correct horse battery stapler")
            .err()
            .unwrap();
        assert_eq!(
            wrong.to_string(),
            "cannot unlock the keystore: wrong passphrase"
        );
        // Another keystore's identity opens none of these files.
        let other = SecretFiles::new(vec![Box::new(
            DataKey::from_bytes([3; 32]).identity().unwrap(),
        )]);
        let error = keys_error(&sealed, &other);
        assert!(
            error.ends_with("ca.age: no identity of this keystore opens it"),
            "{error}"
        );
    }

    fn keys_error(sealed: &SealedConfig, files: &SecretFiles) -> String {
        match keys(sealed, &declared(), files) {
            Ok(_) => panic!("must not open"),
            Err(e) => format!("{e:#}"),
        }
    }

    /// A recipient of another kind (a stand-in for M7.6's hardware ones): its stanza wraps the
    /// file key with a fixed pad. For this test only.
    struct FakeRecipient;
    struct FakeIdentity;
    const PAD: [u8; 16] = [0x5a; 16];

    fn padded(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().zip(PAD).map(|(b, p)| b ^ p).collect()
    }

    impl age::Recipient for FakeRecipient {
        fn wrap_file_key(
            &self,
            file_key: &FileKey,
        ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
            let stanza = Stanza {
                tag: "writ-fake".to_owned(),
                args: vec![],
                body: padded(file_key.expose_secret()),
            };
            Ok((vec![stanza], HashSet::new()))
        }
    }

    impl age::Identity for FakeIdentity {
        fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
            if stanza.tag != "writ-fake" {
                return None;
            }
            let key: [u8; 16] = padded(&stanza.body).try_into().ok()?;
            Some(Ok(FileKey::new(Box::new(key))))
        }
    }

    #[test]
    fn a_second_recipient_for_one_secret_reads_it_back_through_the_same_code() {
        let (_root, sealed, _made) = setup();
        let layout = Layout(&sealed);
        let files = opened(&sealed, PASSPHRASE).unwrap();
        let id: KeyId = "agent-01".parse().unwrap();
        let plaintext = files.read(&layout.signing(&id), "signing key").unwrap();
        // The same secret, sealed again to the keystore's recipient and a second one.
        let recipient: age::x25519::Recipient = std::fs::read_to_string(layout.recipient())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::remove_file(layout.signing(&id)).unwrap();
        seal(
            &layout.signing(&id),
            &plaintext,
            &[&recipient, &FakeRecipient],
        )
        .unwrap();

        // The second identity alone opens it, through the keystore's own reading.
        let fake = SecretFiles::new(vec![Box::new(FakeIdentity)]);
        assert_eq!(
            *fake.read(&layout.signing(&id), "signing key").unwrap(),
            *plaintext
        );
        // So does the keystore's identity, and the keys still load and match their halves.
        assert!(keys(&sealed, &declared(), &files).is_ok());
        // The fake opens nothing else.
        let error = format!("{:#}", fake.read(&layout.ca(), "the CA key").unwrap_err());
        assert!(
            error.ends_with("no identity of this keystore opens it"),
            "{error}"
        );
    }

    #[test]
    fn a_replaced_or_foreign_file_is_refused_by_name() {
        let (_root, sealed, _made) = setup();
        let layout = Layout(&sealed);
        let files = opened(&sealed, PASSPHRASE).unwrap();
        // A public half replaced: the operator would register a key the daemon doesn't hold.
        let ca_public = std::fs::read_to_string(layout.ca_public()).unwrap();
        let id: KeyId = "agent-01".parse().unwrap();
        std::fs::remove_file(layout.signing_public(&id)).unwrap();
        write_public(&layout.signing_public(&id), &ca_public).unwrap();
        let error = keys_error(&sealed, &files);
        assert!(
            error.contains("signing/agent-01.pub does not match"),
            "{error}"
        );
        assert!(
            error.ends_with("signing/agent-01.age: one of them was replaced"),
            "{error}"
        );

        // A secret encrypted to a passphrase, or not an age file at all.
        std::fs::remove_file(layout.ca()).unwrap();
        PassphraseUnlock::enroll_with_work_factor(
            layout.ca(),
            &Passphrase::new(PASSPHRASE.to_owned()),
            &DataKey::from_bytes([1; 32]),
            4,
        )
        .unwrap();
        let error = format!("{:#}", files.read(&layout.ca(), "the CA key").unwrap_err());
        assert!(
            error.ends_with("is not a sealed secret: it is encrypted to a passphrase"),
            "{error}"
        );
        std::fs::remove_file(layout.ca()).unwrap();
        write_private(&layout.ca(), b"a key in clear, not an age file\n").unwrap();
        let error = format!("{:#}", files.read(&layout.ca(), "the CA key").unwrap_err());
        assert!(
            error.ends_with("is not a sealed secret: not an age file"),
            "{error}"
        );
        // Readable by others: refused before it is read.
        std::fs::set_permissions(layout.ca(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!("{:#}", files.read(&layout.ca(), "the CA key").unwrap_err());
        assert!(error.contains("make it 0600"), "{error}");
    }

    #[test]
    fn a_declared_key_the_keystore_lacks_or_holds_otherwise_is_said() {
        let (_root, sealed, _made) = setup();
        // Declared, a template using it or not: it must be there.
        let more = crate::declared::declarations(&naming_agent_02()).unwrap();
        let error = match public(&sealed, &more) {
            Ok(_) => panic!("agent-02 was never made"),
            Err(e) => e.to_string(),
        };
        assert!(
            error.starts_with("signing key agent-02 is declared but not in the keystore"),
            "{error}"
        );
        assert!(
            error.ends_with(
                "the change that declares a key makes it (writd init for the first policy, \
                 writd recover, a signed admin change)"
            ),
            "{error}"
        );
        // agent-01 declared P-256, key-01 RSA: the keystore holds Ed25519 keys.
        for (from, to, expected) in [
            (
                "agent-01: { use: signing, format: ssh, algorithm: ed25519 }",
                "agent-01: { use: signing, format: ssh, algorithm: p256 }",
                "signing key agent-01: declared p256 but the keystore holds a ed25519 key",
            ),
            (
                "key-01: { use: upstream, kind: ssh, algorithm: ed25519 }",
                "key-01: { use: upstream, kind: ssh, algorithm: rsa4096 }",
                "upstream credential key-01: declared rsa4096 but the keystore holds a ed25519 \
                 key",
            ),
        ] {
            let text = policy_text().replacen(from, to, 1);
            assert_ne!(text, policy_text());
            let other =
                crate::declared::declarations(&PolicyConfig::from_yaml(&text).unwrap()).unwrap();
            let error = match public(&sealed, &other) {
                Ok(_) => panic!("held as Ed25519"),
                Err(e) => e.to_string(),
            };
            assert!(error.starts_with(expected), "{error}");
        }
    }

    /// The policy with agent-02 declared, and template `a` signing with it.
    fn naming_agent_02() -> PolicyConfig {
        PolicyConfig::from_yaml(
            &policy_text()
                .replacen("signing_key: agent-01", "signing_key: agent-02", 1)
                .replacen(
                    "keys:\n",
                    "keys:\n  agent-02: { use: signing, format: ssh, algorithm: ed25519 }\n",
                    1,
                ),
        )
        .unwrap()
    }

    fn policy_text() -> String {
        r#"keys:
  agent-01: { use: signing, format: ssh, algorithm: ed25519 }
  key-01: { use: upstream, kind: ssh, algorithm: ed25519 }
  token-01: { use: upstream, kind: token, host: example.org }
upstream_hosts:
  example.org: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
repos:
  plain:
    upstream: ssh://git@example.org/u/plain.git
    upstream_credential: key-01
    templates: [a, b]
  web:
    upstream: https://example.org/u/web.git
    upstream_credential: token-01
    templates: []
templates:
  a:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ.invalid"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 5
    max_push_size: 1MB
  b:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ.invalid"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 5
    max_pushes: 5
    max_ops_per_minute: 5
    max_push_size: 1MB
"#
        .to_owned()
    }

    fn recipient_of(sealed: &SealedConfig) -> age::x25519::Recipient {
        recipient(sealed).unwrap()
    }

    #[test]
    fn a_key_named_later_is_made_once_sealed_and_a_leftover_half_replaced() {
        let (_root, sealed, _made) = setup();
        let layout = Layout(&sealed);
        let files = opened(&sealed, PASSPHRASE).unwrap();
        let id: KeyId = "agent-02".parse().unwrap();
        let both = crate::declared::declarations(&naming_agent_02()).unwrap();
        let decl = both.get(&id).unwrap();
        let (secret, public) = (layout.signing(&id), layout.signing_public(&id));
        let make = || {
            make_key(
                &layout,
                &recipient_of(&sealed),
                &id,
                decl,
                &crate::keystore::Makers::default(),
            )
        };
        let key = make().unwrap();
        // Sealed to the recipient, its half beside it, both as `writd init` writes them.
        let text = String::from_utf8(std::fs::read(&secret).unwrap()).unwrap_or_default();
        assert!(!text.contains("PRIVATE KEY"));
        assert_eq!((mode(&secret), mode(&public)), (0o600, 0o644));
        assert_eq!(
            std::fs::read_to_string(&public).unwrap().trim(),
            key.key.public_key().to_openssh().unwrap()
        );
        // Made again: refused, the key kept.
        let error = make().err().unwrap().to_string();
        assert!(
            error.starts_with("signing key agent-02 is in the keystore already"),
            "{error}"
        );
        let again = stored_key(&files, &layout, &id, decl).unwrap();
        assert_eq!(again.key.public_key(), key.key.public_key());
        // A make cut short after the half: the half is replaced by the new key's.
        std::fs::remove_file(&secret).unwrap();
        let fresh = make().unwrap();
        assert_ne!(fresh.key.public_key(), key.key.public_key());
        assert_eq!(
            std::fs::read_to_string(&public).unwrap().trim(),
            fresh.key.public_key().to_openssh().unwrap()
        );
        // And it opens as `writd init`'s keys do, once a template uses it.
        let keys = keys(&sealed, &both, &files).unwrap();
        assert!(
            keys.signing
                .iter()
                .any(|k| k.id == id && k.key.public_key() == fresh.key.public_key())
        );
    }

    #[test]
    fn every_algorithm_and_an_openpgp_key_round_trip_through_the_keystore() {
        use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat};
        let (_root, sealed, _made) = setup();
        let layout = Layout(&sealed);
        let files = opened(&sealed, PASSPHRASE).unwrap();
        for (i, algorithm) in KeyAlgorithm::ALL.into_iter().enumerate() {
            for format in SignatureFormat::ALL {
                let id: KeyId = format!("k-{i}-{format}").parse().unwrap();
                let decl = crate::declared::Declared {
                    role: KeyRole::Signing,
                    format,
                    algorithm,
                    hash: Hash::Sha256,
                    backend: crate::declared::Backend::Software,
                };
                let made = make_key(
                    &layout,
                    &recipient_of(&sealed),
                    &id,
                    &decl,
                    &crate::keystore::Makers::default(),
                )
                .unwrap();
                assert_eq!(made.meta.format, format);
                assert_eq!(
                    made.meta.created.is_some(),
                    format == SignatureFormat::Openpgp
                );
                let read = stored_key(&files, &layout, &id, &decl).unwrap();
                assert_eq!(read.key.public_key(), made.key.public_key());
                assert_eq!(read.meta, made.meta);
            }
        }
    }

    #[test]
    fn a_token_is_put_in_force_whole_named_by_its_digest_and_a_missing_one_left_out() {
        use writ_core::authority::{PreviousToken, TextDigest};
        let (_root, sealed, _made) = setup();
        let files = opened(&sealed, PASSPHRASE).unwrap();
        let id: KeyId = "token-01".parse().unwrap();
        // Not added yet: no file in force, and the open leaves it out (the unseal goes on).
        assert_eq!(token_in_force(&sealed, &id).unwrap(), PreviousToken::None);
        assert!(tokens(&sealed, &policy(), &files).unwrap().is_empty());
        // As `writ admin token` seals it, on the approver's machine.
        let token = "writ-test-token-0123456789abcdefghij";
        let text = writ_crypto::sealed::seal(&recipient_of(&sealed).to_string(), token.as_bytes())
            .unwrap();
        let file = writ_crypto::sealed::decode(&text).unwrap();
        assert_eq!(
            *files.open(&file, "the token sent").unwrap(),
            token.as_bytes()
        );
        write_token(&sealed, &id, &file).unwrap();
        let path = Layout(&sealed).token(&id);
        assert_eq!(std::fs::read(&path).unwrap(), file);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            token_in_force(&sealed, &id).unwrap(),
            PreviousToken::File(TextDigest::of_bytes(&file))
        );
        let opened = tokens(&sealed, &policy(), &files).unwrap();
        assert_eq!(
            opened.get(&id).map(|t| format!("{t:?}")).as_deref(),
            Some("UpstreamToken(<redacted>)"),
            "opened: the token itself goes only to git (its file was read back above)"
        );
        // Replaced whole, nothing left beside it.
        write_token(&sealed, &id, &file).unwrap();
        let left: Vec<String> = std::fs::read_dir(Layout(&sealed).tokens_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["token-01.age"]);
        // A ciphertext for another keystore, or none at all: refused by name.
        let other = writ_crypto::sealed::seal(
            &DataKey::from_bytes([3; 32])
                .identity()
                .unwrap()
                .to_public()
                .to_string(),
            token.as_bytes(),
        )
        .unwrap();
        let error = format!(
            "{:#}",
            files
                .open(
                    &writ_crypto::sealed::decode(&other).unwrap(),
                    "the token sent"
                )
                .unwrap_err()
        );
        assert_eq!(
            error,
            "the token sent: no identity of this keystore opens it"
        );
        let error = format!(
            "{:#}",
            files.open(b"in clear", "the token sent").unwrap_err()
        );
        assert_eq!(
            error,
            "the token sent is not a sealed secret: not an age file"
        );
    }

    #[test]
    fn a_keystore_is_made_once_and_a_failed_one_leaves_nothing() {
        let (_root, sealed, _made) = setup();
        let again = make(
            &sealed,
            &declared(),
            &policy(),
            &Passphrase::new(PASSPHRASE.to_owned()),
            &cheap,
            &crate::keystore::Makers::default(),
        );
        let error = again.err().unwrap().to_string();
        assert!(error.starts_with("keystore.sealed.dir "), "{error}");
        assert!(
            error.ends_with("is not empty: a keystore is made once, into empty directories"),
            "{error}"
        );

        // A failure part way (the passphrase can't be wrapped): both directories left empty,
        // so `writd init` can run again.
        let root = tempfile::tempdir().unwrap();
        let fresh = SealedConfig {
            dir: root.path().join("keys"),
            boot: root.path().join("boot"),
        };
        let failing = |_: &SealedConfig, _: &Passphrase, _: &DataKey| -> anyhow::Result<()> {
            anyhow::bail!("no room left")
        };
        let error = make(
            &fresh,
            &declared(),
            &policy(),
            &Passphrase::new(PASSPHRASE.to_owned()),
            &failing,
            &crate::keystore::Makers::default(),
        );
        assert_eq!(error.err().unwrap().to_string(), "no room left");
        assert!(files(&fresh.dir).is_empty() && files(&fresh.boot).is_empty());
        assert!(
            make(
                &fresh,
                &declared(),
                &policy(),
                &Passphrase::new(PASSPHRASE.to_owned()),
                &cheap,
                &crate::keystore::Makers::default(),
            )
            .is_ok()
        );
    }
}
