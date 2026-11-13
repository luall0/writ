//! The keystore's recipients (M7.6, `recipients` in the policy): the hardware keys the daemon
//! makes in its device, and the offline recovery key; how they are kept beside the sealed
//! keystore, and how its files are brought in line with them ([`reconcile`]).
//!
//! ```text
//! keystore.sealed.dir
//!   identity.age               the keystore's identity: the passphrase's (scrypt), or the
//!                              hardware recipients' (piv-p256), never both
//!   identity.recovery.age      the identity again, to the recovery recipient (X25519)
//!   identity.recovery.pub      the recovery recipient it is sealed to (the marker; M7.6 kept
//!                              it as recipients/recovery.pub, moved once: S-3)
//!   recovery-check.age .sha256 the recovery challenge: a random value to the recovery
//!                              recipient, and its SHA-256 (`writ recovery check`)
//!   recipients/<name>.blob     a hardware recipient's key, framed (0600; usable only by its
//!                              device)
//!   recipients/<name>.pub      its public recipient (age1se1…) and its backend
//! ```
//!
//! **Where each secret is wrapped:** the keys to the keystore's identity, always; the tokens to
//! the identity on a passphrase keystore, to the hardware recipients and the recovery
//! recipient on a hardware one (unwrapped by the device at each use). [`reconcile`] rewrites
//! every file that isn't so (each written new, then moved over the old one), then deletes the
//! files of recipients the policy no longer declares: run after every change of the
//! recipients, and at each unseal, so a change cut short is finished. A change that takes a
//! way in out (a recipient removed or replaced, the passphrase given up for hardware) rotates
//! the data key first ([`super::rotation`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::config::{PolicyConfig, Recipient};
use writ_core::names::KeyId;
use writ_crypto::piv_p256::P256Recipient;
use writ_platform::unlock::piv::PivUnwrap;
use writ_platform::{DataKey, KeystoreUnwrap};

use super::sealed::{Layout, seal_bytes};
use crate::config::{Config, SealedConfig};
use crate::declared::Backend;

/// The largest recipient file read: a recipient line and a backend line.
const MAX_PUBLIC: u64 = 4096;
/// The largest blob file read: a framed device blob is a few hundred bytes.
const MAX_BLOB: u64 = 64 * 1024;
/// The bech32 prefix a hardware recipient prints with.
const HRP: &str = "age1se";

/// Where the recipients' files are.
pub struct Paths<'a>(pub &'a SealedConfig);

impl Paths<'_> {
    pub fn dir(&self) -> PathBuf {
        self.0.dir.join("recipients")
    }
    pub fn blob(&self, name: &KeyId) -> PathBuf {
        self.dir().join(format!("{name}.blob"))
    }
    pub fn public(&self, name: &KeyId) -> PathBuf {
        self.dir().join(format!("{name}.pub"))
    }
    pub fn identity(&self) -> PathBuf {
        self.0.dir.join("identity.age")
    }
    pub fn recovery_identity(&self) -> PathBuf {
        self.0.dir.join("identity.recovery.age")
    }
    pub fn challenge(&self) -> PathBuf {
        self.0.dir.join("recovery-check.age")
    }
    pub fn challenge_digest(&self) -> PathBuf {
        self.0.dir.join("recovery-check.sha256")
    }
    /// The recovery recipient the recovery files are sealed to (the marker that it changed):
    /// beside them, out of the hardware recipients' names (the review after M7.6, S-3).
    pub fn marker(&self) -> PathBuf {
        self.0.dir.join("identity.recovery.pub")
    }
    /// Where M7.6 kept the marker, moved once by [`super::rotation::settle`].
    pub fn old_marker(&self) -> PathBuf {
        self.dir().join("recovery.pub")
    }
}

/// The recovery recipient the keystore's recovery files are sealed to (its marker), if any.
pub fn marker(sealed: &SealedConfig) -> anyhow::Result<Option<String>> {
    let path = Paths(sealed).marker();
    if !path.exists() {
        return Ok(None);
    }
    let public = read_public(&path)?;
    if public.backend.is_some() {
        bail!(
            "{}: names a backend: not the recovery marker",
            path.display()
        );
    }
    Ok(Some(public.recipient))
}

/// Moves M7.6's recovery marker (`recipients/recovery.pub`, a recipient line alone) to
/// [`Paths::marker`], once: a hardware recipient may then be named `recovery` (S-3). A
/// `recovery.pub` naming a backend is that hardware recipient's, and stays. Whether one moved.
pub fn move_old_marker(sealed: &SealedConfig) -> anyhow::Result<bool> {
    let paths = Paths(sealed);
    let old = paths.old_marker();
    if !old.exists() || read_public(&old)?.backend.is_some() {
        return Ok(false);
    }
    match paths.marker().exists() {
        // Both: the new one is in force (a move cut short after its rename can't be: one
        // rename), the old one stale.
        true => std::fs::remove_file(&old)
            .with_context(|| format!("cannot remove {}", old.display()))?,
        false => std::fs::rename(&old, paths.marker())
            .with_context(|| format!("cannot move {} to its place", old.display()))?,
    }
    super::sync_dir(&paths.dir())?;
    super::sync_dir(&sealed.dir)?;
    Ok(true)
}

/// The names of the hardware recipients the keystore holds files of (their `.pub`), with no
/// device asked: what a change may have taken out.
pub fn held_names(sealed: &SealedConfig) -> anyhow::Result<Vec<KeyId>> {
    let dir = Paths(sealed).dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(&dir).with_context(|| format!("cannot read {}", dir.display()))?
    {
        let entry = entry?;
        let file = entry.file_name().to_string_lossy().into_owned();
        if let Some(name) = file.strip_suffix(".pub") {
            let name: KeyId = name.parse().map_err(|_| {
                anyhow::anyhow!("{}: not a recipient's file", entry.path().display())
            })?;
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// The hardware recipients `policy` declares, by name.
pub fn declared_names(policy: &PolicyConfig) -> Vec<KeyId> {
    policy
        .recipients()
        .iter()
        .filter(|(_, r)| matches!(r, Recipient::Hardware { .. }))
        .map(|(name, _)| name.clone())
        .collect()
}

/// A hardware recipient as the daemon holds it: its name, its public recipient, the way its
/// device opens the keystore's files.
pub struct Hardware {
    pub name: KeyId,
    pub recipient: P256Recipient,
    pub way: PivUnwrap,
}

/// What a recipient's `.pub` says: its recipient line, then `backend: <name>` for a hardware
/// one.
struct Public {
    recipient: String,
    backend: Option<String>,
}

fn read_public(path: &Path) -> anyhow::Result<Public> {
    // Public, but whoever could replace it would choose what secrets are wrapped to: an
    // authority file (the daemon's, nobody else can write it), read bounded.
    let text = writ_platform::fs::read_authority(path, "a recipient file")?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_PUBLIC {
        bail!("{}: larger than a recipient file", path.display());
    }
    let mut lines = text.lines();
    let recipient = lines
        .next()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .with_context(|| format!("{}: no recipient", path.display()))?
        .to_owned();
    let backend = match lines.next() {
        None => None,
        Some(line) => Some(
            line.strip_prefix("backend: ")
                .with_context(|| {
                    format!("{}: its second line is not backend: <name>", path.display())
                })?
                .trim()
                .to_owned(),
        ),
    };
    if lines.next().is_some() {
        bail!("{}: more than a recipient and its backend", path.display());
    }
    Ok(Public { recipient, backend })
}

/// Replaces `path` with `bytes`, whole ([`super::write_whole`]).
fn replace(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    super::write_whole(path, bytes, mode, super::Whole::Replace)
}

/// The recovery recipient the policy declares, read by age (its checksum checked).
pub fn recovery(policy: &PolicyConfig) -> anyhow::Result<Option<age::x25519::Recipient>> {
    policy
        .recovery_recipient()
        .map(|(name, recipient)| {
            recipient
                .as_str()
                .parse::<age::x25519::Recipient>()
                .map_err(|_| {
                    anyhow::anyhow!(
                        "recipients.{name}.recipient: not an age X25519 recipient (its checksum)"
                    )
                })
        })
        .transpose()
}

/// The hardware recipients the policy declares, each with its backend (one this daemon has,
/// and a device).
pub(super) fn declared_hardware(policy: &PolicyConfig) -> anyhow::Result<Vec<(KeyId, Backend)>> {
    policy
        .recipients()
        .iter()
        .filter_map(|(name, r)| match r {
            Recipient::Hardware { backend } => Some((name, backend)),
            Recipient::Recovery { .. } => None,
        })
        .map(|(name, backend)| {
            let at = format!("recipients.{name}.backend");
            let backend = Backend::of(backend, &at)?;
            if !backend.is_device() {
                bail!(
                    "{at}: a recipient is a device's key, not {}",
                    backend.name()
                );
            }
            Ok((name.clone(), backend))
        })
        .collect()
}

/// Makes, in its device, every hardware recipient the policy declares that the keystore
/// doesn't hold yet: its framed blob (0600) and its `.pub`. Answers each one made with its
/// recipient (`age1se1…`), to print and log.
pub fn make_missing(
    config: &Config,
    sealed: &SealedConfig,
    policy: &PolicyConfig,
) -> anyhow::Result<Vec<(KeyId, String)>> {
    let paths = Paths(sealed);
    let mut made = Vec::new();
    for (name, backend) in declared_hardware(policy)? {
        if paths.public(&name).exists() {
            continue;
        }
        super::private_dir(&paths.dir())?;
        let agreement = crate::platform::create_agreement(config, backend)?;
        let recipient = P256Recipient::from_sec1(&agreement.point, HRP)
            .map_err(|e| anyhow::anyhow!("recipient {name}: {e}"))?;
        replace(&paths.blob(&name), agreement.stored.as_bytes(), 0o600)?;
        // The .pub last: a recipient is held once both are written.
        let text = format!("{recipient}\nbackend: {}\n", backend.name());
        replace(&paths.public(&name), text.as_bytes(), 0o644)?;
        made.push((name, recipient.to_string()));
    }
    Ok(made)
}

/// Every hardware recipient the keystore holds (the policy's, and any it no longer declares
/// whose files are still there: what a change cut short may still need to read), its blob
/// checked against its point by its device. One its device refuses fails the whole.
pub fn load(config: &Config, sealed: &SealedConfig) -> anyhow::Result<Vec<Hardware>> {
    let (held, refused) = load_each(config, sealed)?;
    if let Some((_, why)) = refused.into_iter().next() {
        return Err(why);
    }
    Ok(held)
}

/// The hardware recipients loaded, and those refused with why.
pub type Each = (Vec<Hardware>, Vec<(KeyId, anyhow::Error)>);

/// [`load`], each recipient on its own: those loaded, and those refused with why (`writd
/// recover` after a device was lost, whose policy no longer declares them).
pub fn load_each(config: &Config, sealed: &SealedConfig) -> anyhow::Result<Each> {
    let paths = Paths(sealed);
    let (mut held, mut refused) = (Vec::new(), Vec::new());
    for name in held_names(sealed)? {
        match load_one(config, &paths, &name) {
            Ok(hardware) => held.push(hardware),
            Err(why) => refused.push((name, why)),
        }
    }
    Ok((held, refused))
}

/// The hardware recipient `name`. Only hardware recipients' files are in `recipients/` (the
/// recovery marker moved out, S-3): one naming no backend is refused.
fn load_one(config: &Config, paths: &Paths<'_>, name: &KeyId) -> anyhow::Result<Hardware> {
    let public = read_public(&paths.public(name))?;
    let Some(backend) = public.backend else {
        bail!(
            "{}: names no backend: not a hardware recipient's file",
            paths.public(name).display()
        );
    };
    let backend = Backend::of(
        &backend
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("recipient {name}: backend {backend:?}"))?,
        &format!("recipient {name}"),
    )?;
    let recipient = P256Recipient::parse(&public.recipient, HRP)
        .map_err(|e| anyhow::anyhow!("recipient {name}: {e}"))?;
    let stored = writ_platform::fs::read_secret(&paths.blob(name), "a recipient's key", MAX_BLOB)?;
    let way = crate::platform::agreement_way(
        config,
        backend,
        name.as_str(),
        &writ_signer::Stored::new(stored.to_vec()),
        &recipient.uncompressed(),
    )?;
    if way.recipient() != &recipient {
        bail!("recipient {name}: its key is not the one its file names");
    }
    Ok(Hardware {
        name: name.clone(),
        recipient,
        way,
    })
}

/// Deletes the files of the hardware recipient `name` (`writd recover`: one its device no
/// longer opens, which the recovered policy doesn't declare).
pub fn forget(sealed: &SealedConfig, name: &KeyId) -> anyhow::Result<()> {
    let paths = Paths(sealed);
    // The .pub first: a recipient is held while its .pub is there.
    for path in [paths.public(name), paths.blob(name)] {
        super::remove_if_there(&path)?;
    }
    super::sync_dir(&paths.dir())
}

/// The age header's stanzas, `(tag, first argument)` each: what a file is wrapped to, read
/// without opening it (the daemon's own files, bounded by their reader).
fn stanzas(file: &[u8]) -> Vec<(String, Option<String>)> {
    let text = String::from_utf8_lossy(file);
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if line.starts_with("---") {
            break;
        }
        if let Some(stanza) = line.strip_prefix("-> ") {
            let mut words = stanza.split(' ');
            let tag = words.next().unwrap_or_default().to_owned();
            // age adds a random stanza of its own to every file (its tag ending in
            // `-grease`, for the format's extensibility): never a recipient.
            if tag.ends_with("-grease") {
                continue;
            }
            out.push((tag, words.next().map(str::to_owned)));
        }
    }
    out
}

/// Whether `file` is wrapped exactly to the hardware recipients `hardware` (their tags) and,
/// when `x25519` says so, one X25519 recipient.
fn wrapped_to(file: &[u8], hardware: &[&P256Recipient], x25519: usize) -> bool {
    let stanzas = stanzas(file);
    let mut tags: Vec<String> = stanzas
        .iter()
        .filter(|(tag, _)| tag == writ_crypto::piv_p256::STANZA_TAG)
        .filter_map(|(_, arg)| arg.clone())
        .collect();
    tags.sort();
    let mut wanted: Vec<String> = hardware.iter().map(|r| r.tag_text()).collect();
    wanted.sort();
    let others = stanzas
        .iter()
        .filter(|(tag, _)| tag != writ_crypto::piv_p256::STANZA_TAG)
        .count();
    let x25519_count = stanzas.iter().filter(|(tag, _)| tag == "X25519").count();
    tags == wanted && x25519_count == x25519 && others == x25519
}

/// Brings the keystore's files in line with the policy's recipients (see the module):
/// `hardware` the hardware recipients held ([`load`]: the policy's and any left over), `key`
/// the keystore's data key, `ways` those that open the tokens as they are (the identity and
/// every hardware recipient held). Answers what changed, one line each.
pub fn reconcile(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
    hardware: &[Hardware],
    key: &DataKey,
    ways: &[&dyn KeystoreUnwrap],
) -> anyhow::Result<Vec<String>> {
    let paths = Paths(sealed);
    let layout = Layout(sealed);
    let declared: Vec<&Hardware> = hardware
        .iter()
        .filter(|h| {
            matches!(
                policy.recipients().get(&h.name),
                Some(Recipient::Hardware { .. })
            )
        })
        .collect();
    for (name, _) in declared_hardware(policy)? {
        if !declared.iter().any(|h| h.name == name) {
            bail!("recipient {name}: declared, and its key isn't in the keystore");
        }
    }
    let recovery = recovery(policy)?;
    let recovery_text = recovery.as_ref().map(ToString::to_string);
    let identity_recipient = key.recipient()?;
    let hardware_keystore = !declared.is_empty();
    let mut changed = Vec::new();

    // 1. The tokens: to the hardware recipients and the recovery recipient, or to the
    //    identity. The recovery recipient's file is the marker: one that changed rewrites
    //    every token wrapped to it.
    let recovery_marker = paths.marker();
    let recovery_changed = recovery_text != marker(sealed)?;
    let points: Vec<&P256Recipient> = declared.iter().map(|h| &h.recipient).collect();
    if layout.tokens_dir().exists() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(layout.tokens_dir())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "age"))
            .filter(|p| {
                !p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        entries.sort();
        for path in entries {
            let file = writ_platform::fs::read_secret(&path, "the token file", MAX_BLOB)?;
            let right = match hardware_keystore {
                true => {
                    !recovery_changed && wrapped_to(&file, &points, usize::from(recovery.is_some()))
                }
                false => wrapped_to(&file, &[], 1) && opens_with_identity(&file, key),
            };
            if right {
                continue;
            }
            let plaintext = writ_platform::unlock::open(
                &file,
                ways,
                writ_platform::unlock::PassphraseFile::Refused,
                MAX_BLOB,
            )
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            let mut to: Vec<&dyn age::Recipient> = Vec::new();
            match hardware_keystore {
                true => {
                    to.extend(points.iter().map(|r| *r as &dyn age::Recipient));
                    if let Some(recovery) = &recovery {
                        to.push(recovery);
                    }
                }
                false => to.push(&identity_recipient),
            }
            replace(&path, &seal_bytes(&plaintext, &to)?, 0o600)?;
            changed.push(format!("token {} rewrapped", path.display()));
        }
    }

    // 2. The recovery identity, its challenge, then its marker.
    match &recovery {
        Some(recipient) if recovery_changed || !paths.recovery_identity().exists() => {
            // The marker last: the files are the recipient's once it names it.
            for (name, bytes, mode) in recovery_files(key, recipient)? {
                replace(&sealed.dir.join(name), &bytes, mode)?;
            }
            changed.push("the recovery identity wrapped to the recovery recipient".to_owned());
        }
        Some(_) => {}
        None => {
            for path in [
                paths.recovery_identity(),
                paths.challenge(),
                paths.challenge_digest(),
                recovery_marker.clone(),
            ] {
                if path.exists() {
                    std::fs::remove_file(&path)
                        .with_context(|| format!("cannot remove {}", path.display()))?;
                    changed.push(format!("{} removed", path.display()));
                }
            }
            super::sync_dir(&sealed.dir)?;
        }
    }

    // 3. The identity, last: to the hardware recipients (a passphrase keystore keeps its
    //    scrypt file).
    if hardware_keystore {
        // None yet: `writd init` making a hardware keystore.
        let right = match paths.identity().exists() {
            true => wrapped_to(
                &writ_platform::fs::read_secret(&paths.identity(), "the wrapped key", MAX_BLOB)?,
                &points,
                0,
            ),
            false => false,
        };
        if !right {
            let to: Vec<&dyn age::Recipient> =
                points.iter().map(|r| *r as &dyn age::Recipient).collect();
            replace(&paths.identity(), &seal_bytes(key.as_bytes(), &to)?, 0o600)?;
            changed.push("the identity wrapped to the hardware recipients".to_owned());
        }
    }

    // 4. The recipients the policy no longer declares: their files go.
    for held in hardware {
        if declared.iter().any(|h| h.name == held.name) {
            continue;
        }
        forget(sealed, &held.name)?;
        changed.push(format!("recipient {} removed", held.name));
    }
    Ok(changed)
}

/// The recovery files for `recipient`, each `(name in the keys directory, bytes, mode)`, in
/// the order they are written: the identity `key` sealed to it, a new challenge and its
/// digest, then the marker naming it.
pub(super) fn recovery_files(
    key: &DataKey,
    recipient: &age::x25519::Recipient,
) -> anyhow::Result<[(&'static str, Vec<u8>, u32); 4]> {
    let value = writ_crypto::keys::random_array::<32>()?;
    let digest = writ_core::authority::TextDigest::of_bytes(&value);
    Ok([
        (
            "identity.recovery.age",
            seal_bytes(key.as_bytes(), &[recipient])?,
            0o600,
        ),
        (
            "recovery-check.age",
            seal_bytes(&value, &[recipient])?,
            0o600,
        ),
        (
            "recovery-check.sha256",
            format!("sha256:{digest}\n").into_bytes(),
            0o644,
        ),
        (
            "identity.recovery.pub",
            format!("{recipient}\n").into_bytes(),
            0o644,
        ),
    ])
}

/// Whether `file` opens with the keystore's identity alone.
fn opens_with_identity(file: &[u8], key: &DataKey) -> bool {
    let Ok(way) = key.way() else {
        return false;
    };
    writ_platform::unlock::open(
        file,
        &[&way as &dyn KeystoreUnwrap],
        writ_platform::unlock::PassphraseFile::Refused,
        MAX_BLOB,
    )
    .is_ok()
}

/// The recovery recipient in force and its challenge (`writ recovery check`), or why there is
/// none.
pub fn recovery_shown(
    sealed: &SealedConfig,
    policy: &PolicyConfig,
) -> anyhow::Result<writ_proto::RecoveryShown> {
    let Some((name, recipient)) = policy.recovery_recipient() else {
        bail!("the policy in force declares no recovery recipient (writ admin recipient add)");
    };
    let paths = Paths(sealed);
    let challenge =
        writ_platform::fs::read_secret(&paths.challenge(), "the recovery challenge", MAX_BLOB)?;
    let digest = writ_platform::fs::read_authority(
        &paths.challenge_digest(),
        "the recovery challenge's digest",
    )?;
    Ok(writ_proto::RecoveryShown {
        name: name.to_string(),
        recipient: recipient.to_string(),
        challenge: writ_crypto::sealed::encode(&challenge),
        digest: digest.trim().to_owned(),
    })
}
