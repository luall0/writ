//! The files that grant authority (the policy, `approvers`, `readers`), as the daemon holds
//! them since M5: the versions in force are in the state's store, bound to the keystore by a
//! MAC over their head (`writ_crypto::authority`). `writd init` records their first versions
//! from the files `writd.yaml` names; after that, only a signed admin change or `writd
//! recover` changes them. The daemon writes the text in force back to those files, and sets a
//! file edited by hand aside, never applying it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_approval::InForce;
use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::config::PolicyConfig;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_core::units::Timestamp;
use writ_crypto::allowed_signers::{self, AllowedSigner};
use writ_crypto::authority::AuthorityKey;
use writ_crypto::readers::{self, Reader};
use writ_store::{AuthorityHead, AuthorityHow, AuthorityVersion, Store};

use crate::config::Config;

/// The three files as the daemon runs with them.
pub struct Loaded {
    pub policy: PolicyConfig,
    pub approvers: Vec<AllowedSigner>,
    pub readers: Vec<Reader>,
    pub in_force: InForce,
    pub texts: BTreeMap<AdminTarget, String>,
}

/// The path `writd.yaml` names for each file.
pub fn path(config: &Config, target: AdminTarget) -> &Path {
    match target {
        AdminTarget::Policy => &config.policy,
        AdminTarget::Approvers => &config.approvers,
        AdminTarget::Readers => &config.readers,
    }
}

/// The policy's text, read as the daemon reads it.
pub fn parse_policy(text: &str) -> anyhow::Result<PolicyConfig> {
    PolicyConfig::from_yaml(text).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The approvers: none at all is refused (nothing could ever be signed).
pub fn parse_approvers(text: &str) -> anyhow::Result<Vec<AllowedSigner>> {
    let approvers = allowed_signers::parse(text, APPROVAL_NAMESPACE)?;
    if approvers.is_empty() {
        bail!("no approver key for {APPROVAL_NAMESPACE}: nothing could ever be signed");
    }
    Ok(approvers)
}

/// The readers: none at all is refused (nobody could use the approval API).
pub fn parse_readers(text: &str) -> anyhow::Result<Vec<Reader>> {
    let readers = readers::parse(text)?;
    if readers.is_empty() {
        bail!(
            "no reader key: nobody could use the approval API (add the line `writ reader` prints)"
        );
    }
    Ok(readers)
}

/// A key is an approver or a reader, never both: the reader key is a client key `writ` holds
/// in a file, the approval key stays in its agent (hard rule 8), and one key for both roles
/// would let whatever opens the API also sign approvals.
pub fn one_key_one_purpose(approvers: &[AllowedSigner], readers: &[Reader]) -> anyhow::Result<()> {
    for reader in readers {
        if approvers
            .iter()
            .any(|a| a.key.key_data() == reader.key.key_data())
        {
            bail!(
                "reader {} is also an approver key: a key has one purpose (make the reader key \
                 with `writ reader`)",
                reader.name
            );
        }
    }
    Ok(())
}

/// Checks the three texts together, as a start does: each parses, and no key is both an
/// approver and a reader.
fn parsed(texts: BTreeMap<AdminTarget, String>, in_force: InForce) -> anyhow::Result<Loaded> {
    let text = |target| texts.get(&target).map(String::as_str).unwrap_or_default();
    let policy = parse_policy(text(AdminTarget::Policy)).context("the policy in force")?;
    let approvers =
        parse_approvers(text(AdminTarget::Approvers)).context("the approvers in force")?;
    let readers = parse_readers(text(AdminTarget::Readers)).context("the readers in force")?;
    one_key_one_purpose(&approvers, &readers)?;
    Ok(Loaded {
        policy,
        approvers,
        readers,
        in_force,
        texts,
    })
}

/// Checks the three texts as a start would (each parses, no key both an approver and a
/// reader), before anything is made from them.
pub fn check(texts: &BTreeMap<AdminTarget, String>) -> anyhow::Result<()> {
    let unsigned = InForce {
        versions: BTreeMap::new(),
        mac: String::new(),
    };
    parsed(texts.clone(), unsigned).map(|_| ())
}

/// The files `writd.yaml` names, read as authority files (owner, mode, no link).
pub fn read_files(config: &Config) -> anyhow::Result<BTreeMap<AdminTarget, String>> {
    AdminTarget::ALL
        .into_iter()
        .map(|target| {
            let path = path(config, target);
            let text = writ_platform::fs::read_authority(path, &format!("{target} file"))?;
            Ok((target, text))
        })
        .collect()
}

/// The versions in force, from the store; `None` before any was recorded.
pub fn load(store: &Store) -> anyhow::Result<Option<Loaded>> {
    let Some((head, files)) = store.authority_in_force()? else {
        return Ok(None);
    };
    let in_force = InForce {
        versions: files
            .iter()
            .map(|(target, file)| (*target, (file.version, file.digest.clone())))
            .collect(),
        mac: head.mac,
    };
    let texts = files.into_iter().map(|(t, f)| (t, f.text)).collect();
    parsed(texts, in_force).map(Some)
}

/// Records the first version of each file, as `writd init` (or the development keystore's
/// first start) reads them, under `key`'s MAC. The three are checked together first.
pub fn seed(
    store: &Store,
    key: &AuthorityKey,
    texts: BTreeMap<AdminTarget, String>,
    now: Timestamp,
) -> anyhow::Result<Loaded> {
    let versions: BTreeMap<AdminTarget, (u64, TextDigest)> = texts
        .iter()
        .map(|(target, text)| (*target, (1, TextDigest::of(text))))
        .collect();
    let unsigned = InForce {
        versions,
        mac: String::new(),
    };
    let in_force = InForce {
        mac: key.sign_head(&unsigned.entries())?,
        ..unsigned
    };
    let loaded = parsed(texts, in_force)?;
    let rows: Vec<AuthorityVersion> = loaded
        .texts
        .iter()
        .map(|(target, text)| AuthorityVersion {
            target: *target,
            version: 1,
            text: text.clone(),
            digest: TextDigest::of(text),
            how: AuthorityHow::Init,
            document: None,
            signature: None,
            approver: None,
            applied_at: now,
        })
        .collect();
    store.record_authority(&rows, &head(&loaded.in_force))?;
    Ok(loaded)
}

/// The store's head for `in_force`.
fn head(in_force: &InForce) -> AuthorityHead {
    AuthorityHead {
        versions: in_force
            .versions
            .iter()
            .map(|(target, (version, _))| (*target, *version))
            .collect(),
        mac: in_force.mac.clone(),
    }
}

/// Puts `text` in force for `target` on the host (`writd recover`), after checking it
/// against the other two files in force: a new version, its head under `key`'s MAC.
/// The versions in force must carry the key's MAC already: recovery opens the keystore, it
/// doesn't take versions nobody can vouch for.
pub fn recover(
    store: &Store,
    key: &AuthorityKey,
    target: AdminTarget,
    text: String,
    now: Timestamp,
) -> anyhow::Result<(u64, u64, TextDigest)> {
    let Some(loaded) = load(store)? else {
        bail!("no authority files in force: `writd init` records them");
    };
    if !key.verify_head(&loaded.in_force.entries(), &loaded.in_force.mac) {
        bail!(
            "the versions in force don't carry this keystore's MAC: they were altered, or the \
             state is another keystore's"
        );
    }
    let mut texts = loaded.texts.clone();
    texts.insert(target, text.clone());
    let (old, _) = loaded
        .in_force
        .versions
        .get(&target)
        .cloned()
        .context("no version in force")?;
    let version = old.checked_add(1).context("version overflow")?;
    let digest = TextDigest::of(&text);
    let mut in_force = loaded.in_force.clone();
    in_force.versions.insert(target, (version, digest.clone()));
    in_force.mac = key.sign_head(&in_force.entries())?;
    // The new set must pass a start's checks.
    parsed(texts, in_force.clone())?;
    store.record_authority(
        &[AuthorityVersion {
            target,
            version,
            text,
            digest: digest.clone(),
            how: AuthorityHow::Recover,
            document: None,
            signature: None,
            approver: None,
            applied_at: now,
        }],
        &head(&in_force),
    )?;
    Ok((old, version, digest))
}

/// What happened to a file at start: written back, or set aside (a hand edit).
#[derive(Debug, PartialEq, Eq)]
pub enum Synced {
    Same,
    Written,
    SetAside(PathBuf),
}

/// Makes the file at `path` hold `text` (the version in force): a file that differs is moved
/// aside to `<file>.unapplied-<now>` first (a hand edit, kept, never applied). The text is
/// written whole (a temporary file renamed), 0644.
pub fn sync_file(path: &Path, text: &str, now: Timestamp) -> anyhow::Result<Synced> {
    let set_aside = match std::fs::read(path) {
        Ok(bytes) if bytes == text.as_bytes() => return Ok(Synced::Same),
        Ok(_) => {
            let mut aside = path.as_os_str().to_owned();
            aside.push(format!(".unapplied-{}", now.unix()));
            let aside = PathBuf::from(aside);
            std::fs::rename(path, &aside)
                .with_context(|| format!("cannot set {} aside", path.display()))?;
            Some(aside)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    write_back(path, text)?;
    Ok(match set_aside {
        Some(aside) => Synced::SetAside(aside),
        None => Synced::Written,
    })
}

/// Writes `text` to `path` whole: a temporary file beside it, renamed over it.
pub fn write_back(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".writing");
    let temporary = PathBuf::from(temporary);
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("cannot replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_unix(1_800_000_000).unwrap()
    }

    #[test]
    fn a_hand_edited_file_is_set_aside_and_the_text_in_force_written_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvers");
        assert_eq!(
            sync_file(&path, "in force\n", now()).unwrap(),
            Synced::Written
        );
        assert_eq!(sync_file(&path, "in force\n", now()).unwrap(), Synced::Same);
        std::fs::write(&path, "edited by hand\n").unwrap();
        let aside = dir.path().join("approvers.unapplied-1800000000");
        assert_eq!(
            sync_file(&path, "in force\n", now()).unwrap(),
            Synced::SetAside(aside.clone())
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "in force\n");
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), "edited by hand\n");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
}
