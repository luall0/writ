//! The device keys a command run by hand owes the daemon (`to-make.json` in the keys
//! directory): a key on a device is made only by `writd run`, never by `writd init` or `writd
//! recover`. The device binds a key to where it is made: one the Secure Enclave made for
//! `sudo -u _writd writd init`, from a logged-in session, opened under the LaunchDaemon but
//! never signed there (found on the first real install, 2026-11-14).
//!
//! The file (`writ-to-make/1`, strict JSON) names the CA's backend, the TLS key's, and each
//! declared key with its declaration as the command read it (and an OpenPGP key's user ids).
//! `writd run` makes each at its start, still sealed, before it reads a key or opens a
//! listener: sealing needs only the keystore's recipient, a public file. The declaration is the
//! file's, never the policy in force, which a sealed start reads but never acts on (the review
//! after M7.6, S-1); the unseal then checks every key against the policy whose MAC it checked.
//!
//! **Each one is made whole or made again**: its secret is written last (the CA's backend
//! marker after it, the TLS key's certificate last), so one whose last file is there was made
//! and is taken as made; one cut short has its files removed and is made again. The file is
//! rewritten whole after each, and removed once empty.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use writ_core::names::{KeyId, Uid};
use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat};
use writ_proto::KeyRole;

use super::Makers;
use super::sealed::Layout;
use crate::config::SealedConfig;
use crate::declared::{Backend, Declared};

/// The file's name in the keys directory.
pub const FILE: &str = "to-make.json";

/// Its kind, first in the file.
const KIND: &str = "writ-to-make/1";

/// The most keys one file owes.
pub const MAX_KEYS: usize = 1000;

/// What a command run by hand left the daemon to make.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owed {
    /// The CA's key, on this device.
    pub ca: Option<Backend>,
    /// The HTTPS approval API's key and certificate, on this device.
    pub tls: Option<Backend>,
    /// Each declared key on a device.
    pub keys: Vec<OwedKey>,
}

/// A declared key owed, as the command that left it read its declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedKey {
    pub id: KeyId,
    pub declared: Declared,
    /// An OpenPGP key's user ids: its certificate is made with it.
    pub uids: Vec<Uid>,
}

impl Owed {
    pub fn is_empty(&self) -> bool {
        self.ca.is_none() && self.tls.is_none() && self.keys.is_empty()
    }

    /// The keys of `role` owed.
    pub fn of_role(&self, role: KeyRole) -> impl Iterator<Item = &OwedKey> {
        self.keys.iter().filter(move |k| k.declared.role == role)
    }

    /// Whether `id` of `role` is owed.
    pub fn owes(&self, role: KeyRole, id: &KeyId) -> bool {
        self.of_role(role).any(|k| &k.id == id)
    }
}

/// The file as written.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileText {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<KeyText>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyText {
    id: String,
    role: String,
    format: String,
    algorithm: String,
    hash: String,
    backend: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    uids: Vec<String>,
}

fn role_name(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Signing => "signing",
        KeyRole::Upstream => "upstream",
    }
}

/// Where the file is.
pub fn path(sealed: &SealedConfig) -> PathBuf {
    sealed.dir.join(FILE)
}

/// A device backend this daemon has, named at `at`: never software (a software key is made
/// by the command itself).
fn device(name: &str, at: &str) -> anyhow::Result<Backend> {
    let backend = crate::platform::backend_named(name).ok_or_else(|| {
        anyhow::anyhow!(
            "{at}: this daemon has no backend {name:?} (it has: {})",
            crate::platform::backend_names()
        )
    })?;
    if !backend.is_device() {
        bail!("{at}: {name} is not a device: only a device's key is owed");
    }
    Ok(backend)
}

fn parsed<T: std::str::FromStr>(text: &str, at: &str) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    text.parse().map_err(|e| anyhow::anyhow!("{at}: {e}"))
}

/// Reads and checks `text` (see [`read`]).
fn decode(text: &str) -> anyhow::Result<Owed> {
    let file: FileText = serde_json::from_str(text).context("not a writ-to-make/1 file")?;
    if file.kind != KIND {
        bail!("kind {:?}: not {KIND}", file.kind);
    }
    if file.keys.len() > MAX_KEYS {
        bail!("{} keys: at most {MAX_KEYS}", file.keys.len());
    }
    let ca = file.ca.as_deref().map(|n| device(n, "ca")).transpose()?;
    let tls = file.tls.as_deref().map(|n| device(n, "tls")).transpose()?;
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(file.keys.len());
    for key in &file.keys {
        let id: KeyId = parsed(&key.id, "keys[].id")?;
        let at = format!("keys.{id}");
        if !seen.insert(id.clone()) {
            bail!("{at}: named twice");
        }
        let role = match key.role.as_str() {
            "signing" => KeyRole::Signing,
            "upstream" => KeyRole::Upstream,
            other => bail!("{at}.role: {other:?} is not signing or upstream"),
        };
        let format: SignatureFormat = parsed(&key.format, &format!("{at}.format"))?;
        let algorithm: KeyAlgorithm = parsed(&key.algorithm, &format!("{at}.algorithm"))?;
        let hash: Hash = parsed(&key.hash, &format!("{at}.hash"))?;
        let backend = device(&key.backend, &format!("{at}.backend"))?;
        if role == KeyRole::Upstream && format != SignatureFormat::Ssh {
            bail!("{at}.format: an upstream credential is an ssh key");
        }
        // The pair its backend signs, as a policy declaring it is checked.
        let checked = writ_crypto::algorithm::check(
            format,
            algorithm,
            Some(hash),
            backend.name(),
            &backend.pairs(),
        )
        .map_err(|why| anyhow::anyhow!("{at}: {why}"))?;
        if checked != hash {
            bail!(
                "{at}.hash: {} is not what {} signs with",
                hash.name(),
                algorithm.name()
            );
        }
        if !key.uids.is_empty() && format != SignatureFormat::Openpgp {
            bail!("{at}.uids: only an OpenPGP key has user ids");
        }
        if key.uids.len() > writ_core::config::MAX_UIDS {
            bail!(
                "{at}.uids: {} user ids, at most {}",
                key.uids.len(),
                writ_core::config::MAX_UIDS
            );
        }
        let uids = key
            .uids
            .iter()
            .map(|u| parsed::<Uid>(u, &format!("{at}.uids")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        keys.push(OwedKey {
            id,
            declared: Declared {
                role,
                format,
                algorithm,
                hash,
                backend,
            },
            uids,
        });
    }
    let owed = Owed { ca, tls, keys };
    if owed.is_empty() {
        bail!("it owes nothing (an empty file is removed, never kept)");
    }
    Ok(owed)
}

fn encode(owed: &Owed) -> anyhow::Result<String> {
    let file = FileText {
        kind: KIND.to_owned(),
        ca: owed.ca.map(|b| b.name().to_owned()),
        tls: owed.tls.map(|b| b.name().to_owned()),
        keys: owed
            .keys
            .iter()
            .map(|k| KeyText {
                id: k.id.to_string(),
                role: role_name(k.declared.role).to_owned(),
                format: k.declared.format.name().to_owned(),
                algorithm: k.declared.algorithm.name().to_owned(),
                hash: k.declared.hash.name().to_owned(),
                backend: k.declared.backend.name().to_owned(),
                uids: k.uids.iter().map(|u| u.as_str().to_owned()).collect(),
            })
            .collect(),
    };
    Ok(format!("{}\n", serde_json::to_string_pretty(&file)?))
}

/// What the keystore owes, or `None` when it owes nothing (no file). The file is an authority
/// file (owner, mode, no link, 1 MiB); anything in it that doesn't check is refused, naming
/// the file and the entry: the start stops.
pub fn read(sealed: &SealedConfig) -> anyhow::Result<Option<Owed>> {
    let path = path(sealed);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        Ok(_) => {}
    }
    let text = writ_platform::fs::read_authority(&path, "the device keys owed")?;
    decode(&text)
        .map(Some)
        .with_context(|| format!("{}", path.display()))
}

/// Writes what is owed, whole (removed when nothing is).
pub fn write(sealed: &SealedConfig, owed: &Owed) -> anyhow::Result<()> {
    let path = path(sealed);
    if owed.is_empty() {
        return remove_if_there(&path);
    }
    super::write_whole(
        &path,
        encode(owed)?.as_bytes(),
        0o644,
        super::Whole::Replace,
    )
}

/// Adds `more` to what the keystore owes (`writd recover`): a key owed already under its id
/// with the same declaration is kept once; with another, refused.
pub fn add(sealed: &SealedConfig, more: Owed) -> anyhow::Result<()> {
    let mut owed = read(sealed)?.unwrap_or_default();
    owed.ca = owed.ca.or(more.ca);
    owed.tls = owed.tls.or(more.tls);
    for key in more.keys {
        match owed.keys.iter().find(|k| k.id == key.id) {
            Some(there) if there == &key => {}
            Some(_) => bail!(
                "{}: {} is owed already, declared otherwise: start the daemon once (it makes \
                 it), then run this again",
                path(sealed).display(),
                key.id
            ),
            None => owed.keys.push(key),
        }
    }
    if owed.keys.len() > MAX_KEYS {
        bail!("{} keys owed: at most {MAX_KEYS}", owed.keys.len());
    }
    write(sealed, &owed)
}

fn remove_if_there(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("cannot remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// One key the start made: its audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Made {
    /// `ca`, `tls-01`, or the declared key's id.
    pub id: String,
    pub line: String,
}

/// Said of a key found made at start: a start cut short after making it, before its entry left
/// the file (its audit line may be missing: it is written now).
const FOUND: &str = "found made at the daemon's start (a start cut short after making it)";

/// Makes what the keystore owes (`writd run`, at start, sealed): each sealed to the
/// keystore's recipient, its public half written, then `said` given its line (the audit log:
/// a failure there keeps the entry, for the next start), then its entry taken out of the
/// file. One whose last file is there is taken as made, and said so.
pub fn finish(
    sealed: &SealedConfig,
    makers: &Makers,
    said: &mut dyn FnMut(&Made) -> anyhow::Result<()>,
) -> anyhow::Result<usize> {
    let Some(mut owed) = read(sealed)? else {
        return Ok(0);
    };
    let layout = Layout(sealed);
    let recipient = super::sealed::recipient(sealed)?;
    let mut count = 0usize;
    if let Some(backend) = owed.ca {
        let line = make_ca(sealed, &layout, &recipient, backend, makers)?
            .unwrap_or_else(|| format!("the CA's key on {}: {FOUND}", backend.name()));
        said(&Made {
            id: super::sealed::CA_ID.to_owned(),
            line,
        })?;
        owed.ca = None;
        write(sealed, &owed)?;
        count = count.saturating_add(1);
    }
    if let Some(backend) = owed.tls {
        let line = make_tls(sealed, backend, makers)?
            .unwrap_or_else(|| format!("the TLS key on {}: {FOUND}", backend.name()));
        said(&Made {
            id: super::TLS_KEY.to_owned(),
            line,
        })?;
        owed.tls = None;
        write(sealed, &owed)?;
        count = count.saturating_add(1);
    }
    while let Some(key) = owed.keys.first().cloned() {
        let line = make_key(&layout, &recipient, &key, makers)?.unwrap_or_else(|| {
            format!(
                "{} on {}: {FOUND}",
                crate::declared::named(key.declared.role, &key.id),
                key.declared.backend.name()
            )
        });
        said(&Made {
            id: key.id.to_string(),
            line,
        })?;
        owed.keys.remove(0);
        write(sealed, &owed)?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

/// The CA, unless made: its secret, its public half, then its backend marker last.
fn make_ca(
    sealed: &SealedConfig,
    layout: &Layout<'_>,
    recipient: &age::x25519::Recipient,
    backend: Backend,
    makers: &Makers,
) -> anyhow::Result<Option<String>> {
    let (secret, public, marker) = (
        layout.ca(),
        layout.ca_public(),
        super::ca::backend_path(sealed),
    );
    if secret.exists() && public.exists() && super::ca::backend(sealed)? == backend.name() {
        return Ok(None);
    }
    for path in [&secret, &public, &marker] {
        remove_if_there(path)?;
    }
    let declared = Declared {
        role: KeyRole::Signing,
        format: SignatureFormat::Ssh,
        algorithm: KeyAlgorithm::P256,
        hash: Hash::Sha256,
        backend,
    };
    let (material, meta) = makers.make(&super::sealed::CA_ID.parse()?, &declared)?;
    let to: [&dyn age::Recipient; 1] = [recipient];
    super::sealed::seal(&secret, material.encode(meta)?.as_bytes(), &to)?;
    let line = material.public_key().to_openssh()?;
    super::sealed::write_public(&public, &format!("{line}\n"))?;
    super::ca::set_backend(sealed, backend.name())?;
    Ok(Some(format!(
        "the CA's key made on {} at the daemon's start (owed by a command run by hand): \
         {line}",
        backend.name()
    )))
}

/// The TLS key and its certificate, unless made (the certificate is written last).
fn make_tls(
    sealed: &SealedConfig,
    backend: Backend,
    makers: &Makers,
) -> anyhow::Result<Option<String>> {
    let files = super::sealed::tls_files(sealed);
    if files.key.exists() && files.cert.exists() {
        return Ok(None);
    }
    for path in [files.public(), files.key.clone(), files.cert.clone()] {
        remove_if_there(&path)?;
    }
    files.make(backend, makers)?;
    let cert = writ_platform::fs::read_authority(&files.cert, "the TLS certificate")?;
    let fingerprint = writ_crypto::tls::fingerprint_pem(&cert)?;
    Ok(Some(format!(
        "the TLS key made on {} at the daemon's start (owed by a command run by hand): \
         certificate {fingerprint} (approvers pin it: writd tls-fingerprint prints it)",
        backend.name()
    )))
}

/// A declared key, unless made: its public half, its certificate (OpenPGP, with user ids),
/// then its secret last.
fn make_key(
    layout: &Layout<'_>,
    recipient: &age::x25519::Recipient,
    key: &OwedKey,
    makers: &Makers,
) -> anyhow::Result<Option<String>> {
    let role = key.declared.role;
    let (secret, public) = (layout.key(role, &key.id), layout.key_public(role, &key.id));
    let certificate = layout.signing_dir().join(format!("{}.asc", key.id));
    if secret.exists() {
        return Ok(None);
    }
    super::private_dir(&layout.key_dir(role))?;
    remove_if_there(&public)?;
    remove_if_there(&certificate)?;
    let (material, meta) = makers.make(&key.id, &key.declared)?;
    let stored = super::StoredKey {
        id: key.id.clone(),
        key: material,
        meta,
    };
    super::sealed::write_public(
        &public,
        &writ_crypto::keyfile::encode_public(&stored.key.public_key(), meta)?,
    )?;
    if let Some(text) = crate::declared::certificate(&stored, &key.declared, &key.uids, makers)? {
        super::sealed::write_public(&certificate, &text)?;
    }
    let to: [&dyn age::Recipient; 1] = [recipient];
    super::sealed::seal(&secret, stored.key.encode(meta)?.as_bytes(), &to)?;
    let described = crate::declared::describe(&key.id, &stored.key.public_key(), &meta)?;
    Ok(Some(format!(
        "{} made on {} at the daemon's start (owed by a command run by hand): {}",
        crate::declared::named(role, &key.id),
        key.declared.backend.name(),
        described
            .strip_prefix(&format!("{} ", key.id))
            .unwrap_or(&described)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device backend this build has (the Secure Enclave on the Mac), if any: the entries
    /// that name one are checked only where one exists.
    fn a_device() -> Option<Backend> {
        crate::platform::BACKENDS
            .iter()
            .copied()
            .find(|b| b.is_device())
    }

    fn refused(text: &str) -> String {
        format!("{:#}", decode(text).unwrap_err())
    }

    fn key(id: &str, backend: &str, extra: &str) -> String {
        format!(
            r#"{{"id":"{id}","role":"signing","format":"ssh","algorithm":"p256","hash":"sha256","backend":"{backend}"{extra}}}"#
        )
    }

    fn file(keys: &[String]) -> String {
        format!(r#"{{"kind":"writ-to-make/1","keys":[{}]}}"#, keys.join(","))
    }

    /// The file is the daemon's own, but whoever can write the keys directory writes it too:
    /// every entry that doesn't check stops the start, by name, never skipped (and never a
    /// software key made from it). Each bound on both sides.
    #[test]
    fn a_to_make_file_out_of_bounds_or_hostile_stops_the_start() {
        let have = crate::platform::backend_names();
        for (text, why) in [
            ("{", "not a writ-to-make/1 file"),
            (
                r#"{"kind":"writ-to-make/1","ca":"software","more":1}"#,
                "not a writ-to-make/1 file",
            ),
            (
                r#"{"kind":"writ-to-make/2","ca":"se-cryptokit"}"#,
                r#"kind "writ-to-make/2": not writ-to-make/1"#,
            ),
            (
                r#"{"kind":"writ-to-make/1"}"#,
                "it owes nothing (an empty file is removed, never kept)",
            ),
            (
                r#"{"kind":"writ-to-make/1","ca":"software"}"#,
                "ca: software is not a device: only a device's key is owed",
            ),
            (
                r#"{"kind":"writ-to-make/1","tls":"software"}"#,
                "tls: software is not a device: only a device's key is owed",
            ),
            (
                r#"{"kind":"writ-to-make/1","ca":"yubikey"}"#,
                &format!(r#"ca: this daemon has no backend "yubikey" (it has: {have})"#),
            ),
            (&file(&[key("../ca", "software", "")]), "keys[].id: "),
            (
                &file(&[key("k", "software", "")]),
                "keys.k.backend: software is not a device: only a device's key is owed",
            ),
            (
                &file(&[
                    key("k", "software", "").replace(r#""role":"signing""#, r#""role":"admin""#)
                ]),
                r#"keys.k.role: "admin" is not signing or upstream"#,
            ),
            (
                &file(&[key("k", "software", "").replace(r#""hash":"sha256""#, r#""hash":"md5""#)]),
                "keys.k.hash: ",
            ),
            (
                &file(&[key("k", "software", "").replace("p256", "dsa")]),
                "keys.k.algorithm: ",
            ),
        ] {
            let said = refused(text);
            assert!(said.starts_with(why), "{text}: {said}");
        }
        // At most MAX_KEYS: one past it refused before any entry is read.
        let past: Vec<String> = (0..=MAX_KEYS)
            .map(|n| key(&format!("k{n}"), "software", ""))
            .collect();
        assert_eq!(refused(&file(&past)), "1001 keys: at most 1000");

        let Some(device) = a_device() else {
            return;
        };
        let device = device.name();
        // The limits on both sides, on a device this build has.
        let most: Vec<String> = (0..MAX_KEYS)
            .map(|n| key(&format!("k{n}"), device, ""))
            .collect();
        assert_eq!(decode(&file(&most)).unwrap().keys.len(), MAX_KEYS);
        let uids = |n: usize| {
            let list: Vec<String> = (0..n)
                .map(|i| format!(r#""Agent {i} <a{i}@writ>""#))
                .collect();
            format!(r#","uids":[{}]"#, list.join(","))
        };
        let openpgp = |extra: &str| {
            key("k", device, extra).replace(r#""format":"ssh""#, r#""format":"openpgp""#)
        };
        assert_eq!(
            decode(&file(&[openpgp(&uids(writ_core::config::MAX_UIDS))]))
                .unwrap()
                .keys[0]
                .uids
                .len(),
            writ_core::config::MAX_UIDS
        );
        for (text, why) in [
            (
                file(&[openpgp(&uids(writ_core::config::MAX_UIDS + 1))]),
                "keys.k.uids: 17 user ids, at most 16".to_owned(),
            ),
            (
                file(&[key("k", device, &uids(1))]),
                "keys.k.uids: only an OpenPGP key has user ids".to_owned(),
            ),
            (
                file(&[key("k", device, ""), key("k", device, "")]),
                "keys.k: named twice".to_owned(),
            ),
            (
                file(&[key("k", device, "")
                    .replace(r#""role":"signing""#, r#""role":"upstream""#)
                    .replace(r#""format":"ssh""#, r#""format":"openpgp""#)]),
                "keys.k.format: an upstream credential is an ssh key".to_owned(),
            ),
            (
                // A pair its device doesn't sign: the Secure Enclave makes P-256 keys only.
                file(&[key("k", device, "")
                    .replace("p256", "ed25519")
                    .replace("sha256", "sha512")]),
                "keys.k: ".to_owned(),
            ),
        ] {
            let said = refused(&text);
            assert!(said.starts_with(&why), "{text}: {said}");
        }
    }

    /// Read from the keys directory: no file owes nothing; the file is an authority file (a
    /// link or a file others may write refused), and what it owes is written back whole,
    /// removed once empty; `writd recover` adds to it, refusing a key owed otherwise.
    #[test]
    fn what_is_owed_is_read_written_whole_and_added_to() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = SealedConfig {
            dir: dir.path().to_owned(),
            boot: dir.path().join("boot"),
        };
        assert_eq!(read(&sealed).unwrap(), None);
        // A link in its place, or a file others may write: refused.
        let at = path(&sealed).display().to_string();
        std::fs::write(dir.path().join("elsewhere"), r#"{"kind":"writ-to-make/1"}"#).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), path(&sealed)).unwrap();
        let said = format!("{:#}", read(&sealed).unwrap_err());
        assert!(
            said.contains(&format!("cannot read the device keys owed {at}: ")),
            "{said}"
        );
        std::fs::remove_file(path(&sealed)).unwrap();
        std::fs::write(
            path(&sealed),
            r#"{"kind":"writ-to-make/1","ca":"software"}"#,
        )
        .unwrap();
        std::fs::set_permissions(
            path(&sealed),
            std::os::unix::fs::PermissionsExt::from_mode(0o666),
        )
        .unwrap();
        let said = format!("{:#}", read(&sealed).unwrap_err());
        assert!(
            said.contains(&format!(
                "the device keys owed {at} can be written by group or others (mode 666)"
            )),
            "{said}"
        );
        std::fs::remove_file(path(&sealed)).unwrap();
        // Nothing owed: no file.
        write(&sealed, &Owed::default()).unwrap();
        assert!(!path(&sealed).exists());

        let Some(device) = a_device() else {
            return;
        };
        let declared = Declared {
            role: KeyRole::Signing,
            format: SignatureFormat::Ssh,
            algorithm: KeyAlgorithm::P256,
            hash: Hash::Sha256,
            backend: device,
        };
        let owed_key = |id: &str, declared: Declared| OwedKey {
            id: id.parse().unwrap(),
            declared,
            uids: Vec::new(),
        };
        let owed = Owed {
            ca: Some(device),
            tls: Some(device),
            keys: vec![owed_key("agent-01", declared)],
        };
        write(&sealed, &owed).unwrap();
        assert_eq!(read(&sealed).unwrap(), Some(owed.clone()));
        // Added to: a key owed already the same way is kept once; another one joins.
        add(
            &sealed,
            Owed {
                keys: vec![
                    owed_key("agent-01", declared),
                    owed_key("agent-02", declared),
                ],
                ..Owed::default()
            },
        )
        .unwrap();
        let now = read(&sealed).unwrap().unwrap();
        assert_eq!(now.keys.len(), 2);
        assert_eq!(now.ca, Some(device));
        // Declared otherwise: refused, nothing changed.
        let other = Declared {
            role: KeyRole::Upstream,
            ..declared
        };
        let said = format!(
            "{:#}",
            add(
                &sealed,
                Owed {
                    keys: vec![owed_key("agent-02", other)],
                    ..Owed::default()
                },
            )
            .unwrap_err()
        );
        assert!(said.ends_with("agent-02 is owed already, declared otherwise: start the daemon once (it makes it), then run this again"), "{said}");
        assert_eq!(read(&sealed).unwrap().unwrap(), now);
        // Emptied: removed.
        write(&sealed, &Owed::default()).unwrap();
        assert!(!path(&sealed).exists());
    }
}
