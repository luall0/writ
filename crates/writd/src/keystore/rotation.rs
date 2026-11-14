//! The keystore's data key rotated (the review after M7.6, S-8): a change that takes a way
//! into the keystore out (a recipient removed or replaced, the passphrase given up for
//! hardware) gives the keystore a new identity, and every file sealed to the old one is sealed
//! again to the new one, crash-safe.
//!
//! ```text
//! keystore.sealed.dir
//!   rotation/          a rotation under way (0700): every new file, whole and synced, at
//!                      its path in the keys directory
//!   rotation/commit    its record, written last: each file put in place with its digest,
//!                      each file removed
//!   rotation-owed      a rotation the keystore owes, one reason a line: written before a
//!                      rotation is tried, removed by the rotation (a passphrase keystore
//!                      keeps it until its next unseal brings the passphrase)
//! ```
//!
//! **What a rotation writes** ([`Rotation::run`]): the new identity wrapped to the ways that
//! remain (the hardware recipients the policy declares, or the passphrase) in `identity.age`;
//! `recipient`; the CA, the authority key, every signing and upstream key sealed to the new
//! identity; every token sealed to the hardware recipients and the recovery recipient, or to
//! the new identity; the recovery files for the recovery recipient in force (or removed with
//! it); the files of the hardware recipients taken out removed; `rotation-owed` removed.
//!
//! **The states, and what each start or unseal finds** ([`settle`], run at a sealed start, at
//! unseal and by `writd recover`, before anything reads the keystore; it reads no policy):
//!
//! - *Before*: no `rotation/`. Every file is the old identity's, which opens them.
//! - *Staged*: `rotation/` without `commit`. Nothing in force changed: the old identity opens
//!   everything. Settled by removing `rotation/` (undone); the rotation is still owed
//!   (`rotation-owed`, and the files against the policy say so) and runs again at that
//!   unseal.
//! - *Committed*: `commit` is there, some files moved or none. Settled by moving each staged
//!   file into place (one moved already is checked by its digest: the moves are idempotent),
//!   removing what the record says, then the record, then `rotation/`. The new identity then
//!   opens everything, the old one nothing.
//! - *Finished*: no `rotation/` again, every file the new identity's.
//!
//! A `rotation` that isn't a directory, or a record that isn't well formed (its header, an
//! entry out of the keystore's own files, a digest neither the staged file nor the file in
//! place has), is refused by name: the start, the unseal or the recovery stops there. Who can
//! write the keys directory is Q38's subject (M8): a record they plant moves only their own
//! files into place, which they could have written there directly.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::authority::TextDigest;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyId;
use writ_crypto::piv_p256::P256Recipient;
use writ_platform::{DataKey, KeystoreUnwrap, Passphrase};
use writ_proto::KeyRole;

use super::recipients::{self, Hardware, Paths};
use super::sealed::{Layout, SecretFiles, seal_bytes};
use super::{Whole, sync_dir, write_whole};
use crate::config::SealedConfig;

/// The staging directory's name in the keys directory.
pub const STAGING: &str = "rotation";
/// The record's name in the staging directory.
const RECORD: &str = "commit";
/// The record of a rotation owed, in the keys directory.
pub const OWED: &str = "rotation-owed";
const HEADER: &str = "writ-rotation/1";
const OWED_HEADER: &str = "writ-rotation-owed/1";
/// The largest file a rotation reads back (a key, a token, a wrapped identity).
const MAX_FILE: u64 = 64 * 1024;
/// The most reasons a `rotation-owed` holds, and the longest.
const MAX_REASONS: usize = 64;
const MAX_REASON: usize = 512;

/// A file a rotation writes or removes, by its path in the keys directory: only the
/// keystore's own files (never a path out of it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rel(String);

impl Rel {
    const TOP: [&'static str; 9] = [
        "identity.age",
        "identity.recovery.age",
        "identity.recovery.pub",
        "recovery-check.age",
        "recovery-check.sha256",
        "recipient",
        "authority.age",
        "ca.age",
        OWED,
    ];

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        if Self::TOP.contains(&text) {
            return Ok(Self(text.to_owned()));
        }
        let shaped = text.split_once('/').and_then(|(dir, file)| {
            let suffixes: &[&str] = match dir {
                "signing" | "upstream" | "tokens" => &[".age"],
                "recipients" => &[".pub", ".blob"],
                _ => &[],
            };
            suffixes
                .iter()
                .find_map(|s| file.strip_suffix(s))
                .filter(|id| id.parse::<KeyId>().is_ok())
        });
        match shaped {
            Some(_) => Ok(Self(text.to_owned())),
            None => bail!("{text:?} is not a file of the keystore"),
        }
    }

    fn of(dir: &str, id: &KeyId, suffix: &str) -> Self {
        Self(format!("{dir}/{id}{suffix}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the file is public (0644; read as an authority file), else a secret (0600).
    fn public(&self) -> bool {
        matches!(
            self.0.as_str(),
            "recipient" | "identity.recovery.pub" | "recovery-check.sha256" | OWED
        ) || self.0.ends_with(".pub")
    }

    fn mode(&self) -> u32 {
        match self.public() {
            true => 0o644,
            false => 0o600,
        }
    }

    fn under(&self, dir: &Path) -> PathBuf {
        dir.join(&self.0)
    }
}

/// What a rotation puts in place and removes: its record.
#[derive(Debug, Default, PartialEq, Eq)]
struct Record {
    puts: Vec<(Rel, String)>,
    removes: Vec<Rel>,
}

impl Record {
    fn text(&self) -> String {
        let mut text = format!("{HEADER}\n");
        for (rel, digest) in &self.puts {
            text.push_str(&format!("put {} sha256:{digest}\n", rel.as_str()));
        }
        for rel in &self.removes {
            text.push_str(&format!("remove {}\n", rel.as_str()));
        }
        text
    }

    /// The record in `text`, strictly: its header, then `put <file> sha256:<hex>` and
    /// `remove <file>` lines, each file once, at least one put.
    fn parse(text: &str) -> anyhow::Result<Self> {
        let Some(body) = text.strip_suffix('\n') else {
            bail!("not whole (no last newline)");
        };
        let mut lines = body.split('\n');
        if lines.next() != Some(HEADER) {
            bail!("not a {HEADER} record");
        }
        let mut record = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        for line in lines {
            let (rel, put) = match line.split(' ').collect::<Vec<_>>().as_slice() {
                ["put", rel, digest] => {
                    let digest = digest
                        .strip_prefix("sha256:")
                        .filter(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
                        .with_context(|| format!("{line:?}: not a sha256 digest"))?;
                    (Rel::parse(rel)?, Some(digest.to_ascii_lowercase()))
                }
                ["remove", rel] => (Rel::parse(rel)?, None),
                _ => bail!("{line:?}: not a put or a remove"),
            };
            if !seen.insert(rel.clone()) {
                bail!("{} named twice", rel.as_str());
            }
            match put {
                Some(digest) => record.puts.push((rel, digest)),
                None => record.removes.push(rel),
            }
        }
        if record.puts.is_empty() {
            bail!("puts nothing in place");
        }
        Ok(record)
    }
}

/// Exits the process at `point`, as a crash there would: only a debug build with the
/// development keystore's feature (never a shipped one) reads `WRIT_TEST_ROTATION_STOP`
/// (the crash tests of `crates/writ-integration/tests/key_rotation.rs`).
#[cfg(all(feature = "dev-keystore", debug_assertions))]
fn stop(point: &str) {
    if std::env::var("WRIT_TEST_ROTATION_STOP").is_ok_and(|at| at == point) {
        eprintln!("writd: stopped at {point} (WRIT_TEST_ROTATION_STOP)");
        std::process::exit(86);
    }
}

#[cfg(not(all(feature = "dev-keystore", debug_assertions)))]
fn stop(_: &str) {}

fn staging(sealed: &SealedConfig) -> PathBuf {
    sealed.dir.join(STAGING)
}

/// Brings the keys directory to a settled state before anything reads it (see the module):
/// M7.6's recovery marker moved out of the hardware recipients' names (S-3, once), a
/// rotation staged and not committed removed, a committed one finished. What it did, one
/// line each.
pub fn settle(sealed: &SealedConfig) -> anyhow::Result<Vec<String>> {
    let mut said = Vec::new();
    if recipients::move_old_marker(sealed)? {
        said.push(format!(
            "the recovery marker moved to {}",
            Paths(sealed).marker().display()
        ));
    }
    let dir = staging(sealed);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(said),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
        Ok(meta) if !meta.is_dir() => bail!(
            "{}: not the directory a rotation of the data key stages in (a link, a file?): \
             refused",
            dir.display()
        ),
        Ok(_) => {}
    }
    let record = dir.join(RECORD);
    match std::fs::symlink_metadata(&record) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("cannot remove {}", dir.display()))?;
            sync_dir(&sealed.dir)?;
            said.push(
                "a rotation of the data key cut short before its commit: undone (the old \
                 identity still opens the keystore)"
                    .to_owned(),
            );
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", record.display())),
        Ok(_) => {
            let text = writ_platform::fs::read_authority(&record, "a rotation's record")?;
            let parsed = Record::parse(&text).map_err(|e| {
                anyhow::anyhow!(
                    "{}: {e:#}: refused (not a record writd wrote)",
                    record.display()
                )
            })?;
            finish(sealed, &parsed)?;
            said.push(
                "a rotation of the data key cut short after its commit: finished (the new \
                 identity opens the keystore)"
                    .to_owned(),
            );
        }
    }
    Ok(said)
}

/// The digest of the keystore file `path` (`rel` says how it is read).
fn digest_of(rel: &Rel, path: &Path) -> anyhow::Result<String> {
    let bytes = match rel.public() {
        true => writ_platform::fs::read_authority(path, "a rotation's file")?.into_bytes(),
        false => writ_platform::fs::read_secret(path, "a rotation's file", MAX_FILE)?.to_vec(),
    };
    Ok(TextDigest::of_bytes(&bytes).as_str().to_owned())
}

/// Puts a committed record in force: each staged file moved into place (one moved already
/// checked by its digest), what it removes removed, then the record and the staging
/// directory. Idempotent: a finish cut short anywhere is run again whole.
fn finish(sealed: &SealedConfig, record: &Record) -> anyhow::Result<()> {
    let stage = staging(sealed);
    let mut dirs = std::collections::BTreeSet::new();
    let mut moved = 0usize;
    for (rel, digest) in &record.puts {
        let (staged, target) = (rel.under(&stage), rel.under(&sealed.dir));
        let parent = target
            .parent()
            .with_context(|| format!("{} has no directory", target.display()))?
            .to_owned();
        if std::fs::symlink_metadata(&staged).is_ok() {
            if digest_of(rel, &staged)? != *digest {
                bail!(
                    "{}: not the file its rotation's record names: refused",
                    staged.display()
                );
            }
            super::private_dir(&parent)?;
            std::fs::rename(&staged, &target)
                .with_context(|| format!("cannot move {} into place", staged.display()))?;
            if let Some(from) = staged.parent() {
                dirs.insert(from.to_owned());
            }
            moved = moved.saturating_add(1);
            if moved == 1 {
                sync_dir(&parent)?;
                stop("moved-one");
            }
        } else if !target.exists() || digest_of(rel, &target)? != *digest {
            bail!(
                "{}: neither staged nor in place as its rotation's record says: refused",
                target.display()
            );
        }
        dirs.insert(parent);
    }
    for dir in &dirs {
        sync_dir(dir)?;
    }
    stop("moved");
    for rel in &record.removes {
        let path = rel.under(&sealed.dir);
        super::remove_if_there(&path)?;
        if let Some(parent) = path.parent() {
            sync_dir(parent)?;
        }
    }
    let file = stage.join(RECORD);
    std::fs::remove_file(&file).with_context(|| format!("cannot remove {}", file.display()))?;
    sync_dir(&stage)?;
    std::fs::remove_dir_all(&stage)
        .with_context(|| format!("cannot remove {}", stage.display()))?;
    sync_dir(&sealed.dir)
}

/// The reasons a rotation is owed that `rotation-owed` records (none without the file),
/// read strictly: it is shown to approvers (`writ info`).
pub fn recorded(sealed: &SealedConfig) -> anyhow::Result<Vec<String>> {
    let path = sealed.dir.join(OWED);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = writ_platform::fs::read_authority(&path, "the rotation owed")?;
    let bad = |why: &str| anyhow::anyhow!("{}: {why}: refused", path.display());
    let body = text.strip_suffix('\n').ok_or_else(|| bad("not whole"))?;
    let mut lines = body.split('\n');
    if lines.next() != Some(OWED_HEADER) {
        return Err(bad("not a record writd wrote"));
    }
    let reasons: Vec<String> = lines.map(str::to_owned).collect();
    if reasons.is_empty() || reasons.len() > MAX_REASONS {
        return Err(bad("not one to a few reasons"));
    }
    if reasons
        .iter()
        .any(|r| r.is_empty() || r.len() > MAX_REASON || r.chars().any(char::is_control))
    {
        return Err(bad("a reason that isn't one line of text"));
    }
    Ok(reasons)
}

/// Records that the data key's rotation is owed for `reasons` (with those recorded already),
/// before a rotation is tried: one cut short, or one a passphrase keystore can't do yet,
/// is done at the next unseal.
pub fn record_owed(sealed: &SealedConfig, reasons: &[String]) -> anyhow::Result<Vec<String>> {
    let mut all = recorded(sealed)?;
    for reason in reasons {
        if !all.contains(reason) {
            all.push(reason.clone());
        }
    }
    all.truncate(MAX_REASONS);
    let mut text = format!("{OWED_HEADER}\n");
    for reason in &all {
        let line: String = reason.chars().filter(|c| !c.is_control()).collect();
        text.push_str(&line);
        text.push('\n');
    }
    write_whole(
        &sealed.dir.join(OWED),
        text.as_bytes(),
        0o644,
        Whole::Replace,
    )?;
    Ok(all)
}

/// The ways into the keystore its files hold now that `policy` takes out: a reason each to
/// rotate the data key; none when the policy only adds (the recovery recipient in force, by
/// its marker; the hardware recipients held, by their files; the passphrase, by
/// `identity.age`'s header).
pub fn removed_ways(sealed: &SealedConfig, policy: &PolicyConfig) -> anyhow::Result<Vec<String>> {
    let mut why = Vec::new();
    if let Some(marker) = recipients::marker(sealed)? {
        match recipients::recovery(policy)? {
            None => why.push(format!("the recovery recipient {marker} removed")),
            Some(now) if now.to_string() != marker => {
                why.push(format!("the recovery recipient {marker} replaced"));
            }
            Some(_) => {}
        }
    }
    let declared = recipients::declared_names(policy);
    for name in recipients::held_names(sealed)? {
        if !declared.contains(&name) {
            why.push(format!("hardware recipient {name} removed"));
        }
    }
    if policy.hardware_keystore()
        && Paths(sealed).identity().exists()
        && !super::hardware_wrapped(sealed)?
    {
        why.push("the passphrase given up for the hardware recipients".to_owned());
    }
    Ok(why)
}

/// Why the data key's rotation is owed: what `rotation-owed` records, and what the files
/// against `policy` show.
pub fn owed(sealed: &SealedConfig, policy: &PolicyConfig) -> anyhow::Result<Vec<String>> {
    let mut all = recorded(sealed)?;
    for reason in removed_ways(sealed, policy)? {
        if !all.contains(&reason) {
            all.push(reason);
        }
    }
    Ok(all)
}

/// What the new identity is wrapped to.
pub enum Wrap<'a> {
    /// A passphrase keystore: the passphrase (the one the unseal or the recovery brought, or
    /// a new one `writd recover` asked).
    Passphrase(&'a Passphrase),
    /// A hardware keystore: the hardware recipients the policy declares.
    Hardware,
}

/// A rotation of the data key, from the keystore as it is to `policy`'s recipients.
pub struct Rotation<'a> {
    pub sealed: &'a SealedConfig,
    pub policy: &'a PolicyConfig,
    /// The hardware recipients held, loaded (the policy's among them).
    pub held: &'a [Hardware],
    /// The identity in force.
    pub old: &'a DataKey,
    /// The ways that open the tokens as they are (the identity, the hardware recipients
    /// held, the recovery key when it opened the keystore).
    pub ways: &'a [&'a dyn KeystoreUnwrap],
    pub wrap: Wrap<'a>,
}

impl Rotation<'_> {
    /// Rotates: staged, committed, finished (see the module). The new identity, and what was
    /// done, one line each.
    pub fn run(&self) -> anyhow::Result<(DataKey, Vec<String>)> {
        let mut said = settle(self.sealed)?;
        let sealed = self.sealed;
        let layout = Layout(sealed);
        let points: Vec<&P256Recipient> = self
            .held
            .iter()
            .filter(|h| recipients::declared_names(self.policy).contains(&h.name))
            .map(|h| &h.recipient)
            .collect();
        for (name, _) in recipients::declared_hardware(self.policy)? {
            if !self.held.iter().any(|h| h.name == name) {
                bail!("recipient {name}: declared, and its key isn't in the keystore");
            }
        }
        let recovery = recipients::recovery(self.policy)?;
        let new = DataKey::generate()?;
        let new_recipient = new.recipient()?;
        let old = SecretFiles::new(vec![Box::new(self.old.way()?)]);
        let mut puts: Vec<(Rel, Vec<u8>)> = Vec::new();
        let mut removes: Vec<Rel> = Vec::new();

        // The keys, sealed to the identity: opened by the old one, sealed to the new one.
        let mut keys = vec![Rel::parse("authority.age")?];
        // A CA owed to the daemon's first start has no file yet (`to-make.json`): the daemon
        // seals it to the recipient in force when it makes it.
        let ca_owed = super::to_make::read(sealed)?.is_some_and(|o| o.ca.is_some());
        if !ca_owed {
            keys.push(Rel::parse("ca.age")?);
        }
        for role in [KeyRole::Signing, KeyRole::Upstream] {
            let dir = match role {
                KeyRole::Signing => "signing",
                KeyRole::Upstream => "upstream",
            };
            for id in super::sealed::held(&layout, role)? {
                keys.push(Rel::of(dir, &id, ".age"));
            }
        }
        for rel in keys {
            let plaintext = old.read(&rel.under(&sealed.dir), rel.as_str())?;
            puts.push((rel, seal_bytes(&plaintext, &[&new_recipient])?));
        }
        // The tokens: to the hardware recipients and the recovery recipient, or the identity.
        let mut to_tokens: Vec<&dyn age::Recipient> = Vec::new();
        match &self.wrap {
            Wrap::Hardware => {
                to_tokens.extend(points.iter().map(|r| *r as &dyn age::Recipient));
                if let Some(recovery) = &recovery {
                    to_tokens.push(recovery);
                }
            }
            Wrap::Passphrase(_) => to_tokens.push(&new_recipient),
        }
        for id in token_ids(&layout)? {
            let rel = Rel::of("tokens", &id, ".age");
            let path = rel.under(&sealed.dir);
            let file = writ_platform::fs::read_secret(&path, "the token file", MAX_FILE)?;
            let plaintext = writ_platform::unlock::open(
                &file,
                self.ways,
                writ_platform::unlock::PassphraseFile::Refused,
                MAX_FILE,
            )
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            puts.push((rel, seal_bytes(&plaintext, &to_tokens)?));
        }
        // The identity's files.
        puts.push((
            Rel::parse("recipient")?,
            format!("{new_recipient}\n").into_bytes(),
        ));
        let passphrase = match &self.wrap {
            Wrap::Hardware => {
                if points.is_empty() {
                    bail!("no hardware recipient to wrap the new identity to");
                }
                let to: Vec<&dyn age::Recipient> =
                    points.iter().map(|r| *r as &dyn age::Recipient).collect();
                puts.push((
                    Rel::parse("identity.age")?,
                    seal_bytes(new.as_bytes(), &to)?,
                ));
                None
            }
            Wrap::Passphrase(passphrase) => Some(*passphrase),
        };
        match &recovery {
            Some(recipient) => {
                for (name, bytes, _) in recipients::recovery_files(&new, recipient)? {
                    puts.push((Rel::parse(name)?, bytes));
                }
            }
            None => {
                for name in [
                    "identity.recovery.age",
                    "recovery-check.age",
                    "recovery-check.sha256",
                    "identity.recovery.pub",
                ] {
                    if sealed.dir.join(name).exists() {
                        removes.push(Rel::parse(name)?);
                    }
                }
            }
        }
        let declared = recipients::declared_names(self.policy);
        for name in recipients::held_names(sealed)? {
            if !declared.contains(&name) {
                for suffix in [".pub", ".blob"] {
                    removes.push(Rel::of("recipients", &name, suffix));
                }
                said.push(format!("recipient {name} removed"));
            }
        }
        if sealed.dir.join(OWED).exists() {
            removes.push(Rel::parse(OWED)?);
        }

        let record = stage(sealed, &puts, passphrase.map(|p| (p, &new)), removes)?;
        stop("staged");
        let dir = staging(sealed);
        write_whole(
            &dir.join(RECORD),
            record.text().as_bytes(),
            0o644,
            Whole::New,
        )?;
        stop("committed");
        finish(sealed, &record)?;
        said.push(format!(
            "the data key rotated: a new identity ({new_recipient}); {} files sealed to it again",
            record.puts.len()
        ));
        Ok((new, said))
    }
}

/// The ids of the tokens the keystore holds (`tokens/<id>.age`).
fn token_ids(layout: &Layout<'_>) -> anyhow::Result<Vec<KeyId>> {
    let dir = layout.tokens_dir();
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
    ids.sort();
    Ok(ids)
}

/// Writes every new file into the staging directory (each whole, synced, the directories
/// synced), the identity wrapped with `passphrase` when it is given: the record of what was
/// staged, with each file's digest.
fn stage(
    sealed: &SealedConfig,
    puts: &[(Rel, Vec<u8>)],
    passphrase: Option<(&Passphrase, &DataKey)>,
    removes: Vec<Rel>,
) -> anyhow::Result<Record> {
    let dir = staging(sealed);
    if std::fs::symlink_metadata(&dir).is_ok() {
        bail!("{}: a rotation is under way already", dir.display());
    }
    super::private_dir(&dir)?;
    sync_dir(&sealed.dir)?;
    let mut record = Record {
        puts: Vec::new(),
        removes,
    };
    for (rel, bytes) in puts {
        let path = rel.under(&dir);
        if let Some(parent) = path.parent()
            && parent != dir
        {
            super::private_dir(parent)?;
            sync_dir(&dir)?;
        }
        write_whole(&path, bytes, rel.mode(), Whole::New)?;
        record
            .puts
            .push((rel.clone(), TextDigest::of_bytes(bytes).as_str().to_owned()));
    }
    if let Some((passphrase, key)) = passphrase {
        let rel = Rel::parse("identity.age")?;
        let path = rel.under(&dir);
        crate::platform::enroll_at(&path, passphrase, key)?;
        sync_dir(&dir)?;
        let digest = digest_of(&rel, &path)?;
        record.puts.push((rel, digest));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_reads_back_and_anything_else_is_refused_by_why() {
        let record = Record {
            puts: vec![
                (Rel::parse("identity.age").unwrap(), "ab".repeat(32)),
                (Rel::parse("signing/agent-01.age").unwrap(), "0f".repeat(32)),
            ],
            removes: vec![Rel::parse("recipients/se-02.blob").unwrap()],
        };
        assert_eq!(Record::parse(&record.text()).unwrap(), record);
        let digest = "ab".repeat(32);
        for (text, why) in [
            (
                format!("{HEADER}\nput identity.age sha256:{digest}"),
                "not whole (no last newline)",
            ),
            (
                format!("writ-rotation/2\nput identity.age sha256:{digest}\n"),
                "not a writ-rotation/1 record",
            ),
            (
                format!("{HEADER}\nremove identity.age\n"),
                "puts nothing in place",
            ),
            (
                format!("{HEADER}\nput ../x sha256:{digest}\n"),
                "\"../x\" is not a file of the keystore",
            ),
            (
                format!("{HEADER}\nput signing/../ca.age sha256:{digest}\n"),
                "\"signing/../ca.age\" is not a file of the keystore",
            ),
            (
                format!("{HEADER}\nput /etc/passwd sha256:{digest}\n"),
                "\"/etc/passwd\" is not a file of the keystore",
            ),
            (
                format!("{HEADER}\nput tokens/x.pub sha256:{digest}\n"),
                "\"tokens/x.pub\" is not a file of the keystore",
            ),
            (
                format!("{HEADER}\nput ca.age sha256:{}\n", "ab".repeat(31)),
                "not a sha256 digest",
            ),
            (
                format!("{HEADER}\nput ca.age sha256:{}\n", "zz".repeat(32)),
                "not a sha256 digest",
            ),
            (
                format!("{HEADER}\nput ca.age sha256:{digest}\nremove ca.age\n"),
                "ca.age named twice",
            ),
            (format!("{HEADER}\nmove ca.age\n"), "not a put or a remove"),
            (
                format!("{HEADER}\nput ca.age  sha256:{digest}\n"),
                "not a put or a remove",
            ),
        ] {
            let error = format!("{:#}", Record::parse(&text).unwrap_err());
            assert!(error.ends_with(why), "{text:?}: {error}");
        }
    }

    #[test]
    fn only_the_keystore_s_own_files_are_a_rotation_s_and_each_has_its_mode() {
        for (text, mode) in [
            ("identity.age", 0o600),
            ("recipient", 0o644),
            ("identity.recovery.pub", 0o644),
            ("recovery-check.sha256", 0o644),
            ("tokens/token-01.age", 0o600),
            ("recipients/se-01.pub", 0o644),
            ("recipients/se-01.blob", 0o600),
            (OWED, 0o644),
        ] {
            assert_eq!(Rel::parse(text).unwrap().mode(), mode, "{text}");
        }
        for bad in [
            "",
            "boot/host",
            "signing/.x.age",
            "signing/a b.age",
            "recipients/x.age",
            "ca.pub",
            "rotation/commit",
            "tls-01",
            "signing/x/y.age",
        ] {
            assert_eq!(
                Rel::parse(bad).unwrap_err().to_string(),
                format!("{bad:?} is not a file of the keystore")
            );
        }
    }
}
