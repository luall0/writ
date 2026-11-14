//! The SSH CA's files in the sealed keystore and their rotation (M7.6, `writ admin ca
//! rotate`):
//!
//! ```text
//! keystore.sealed.dir
//!   ca.age  ca.pub          the CA in force (its key sealed; its public half)
//!   ca.age.new ca.pub.new   a rotation under way: written whole, then moved over the two
//!   ca.backend              the backend the CA's key is on (none: software), readable
//!                           while sealed (auto-unseal's check)
//!   ca-retired.pub          the CAs rotations replaced: one line each, the time (seconds
//!                           since the epoch) until which it stays trusted, then its public
//!                           half; those past their time dropped at the next rotation
//! ```
//!
//! A rotation (the review after M7.6, D-4, S-2, D-3) stages the three new files whole
//! (`ca.age.new`, `ca.pub.new`, `ca.backend.new`: [`stage`]), has its audit line written,
//! moves `ca.age.new` in (the point of no return: [`commit`]), then the two others; the retired
//! record is written once the new CA is in force, from the leases active then ([`retire`]). A
//! start finishes one cut short after the first move, and drops one cut short before it
//! ([`finish`]): the CA in force is always a whole pair with its marker.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_crypto::keyfile::KeyMeta;
use writ_crypto::ssh_key::PublicKey;

use super::Material;
use super::sealed::{Layout, seal_bytes};
use crate::config::SealedConfig;

/// The largest retired record read.
const MAX_RETIRED: usize = 8 * 1024;

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn retired_path(sealed: &SealedConfig) -> PathBuf {
    sealed.dir.join("ca-retired.pub")
}

/// Writes `bytes` whole at `path` (`mode`), over a file there (a `.new` left by a rotation
/// cut short): the keystore's one way to write a file (the review after M7.6, S-11).
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    super::write_whole(path, bytes, mode, super::Whole::Replace)
}

/// What [`finish`] found at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    /// No rotation was under way.
    Nothing,
    /// One whose key was in force already: its public half and marker moved in.
    Completed,
    /// One cut short before its key was in force: dropped, the old CA kept.
    Dropped,
}

/// The `.new` files of a rotation under way.
fn staged(sealed: &SealedConfig) -> [PathBuf; 3] {
    let layout = Layout(sealed);
    [
        with_suffix(&layout.ca(), ".new"),
        with_suffix(&layout.ca_public(), ".new"),
        with_suffix(&backend_path(sealed), ".new"),
    ]
}

pub(crate) fn backend_path(sealed: &SealedConfig) -> PathBuf {
    sealed.dir.join("ca.backend")
}

/// Syncs the keystore's directory: a rename is durable, and in order, only once it is.
fn sync_dir(sealed: &SealedConfig) -> anyhow::Result<()> {
    super::sync_dir(&sealed.dir)
}

/// A rotation cut short: finished when its key was moved in already (the public half and the
/// marker follow it), dropped otherwise (the CA in force is still the old pair).
pub fn finish(sealed: &SealedConfig) -> anyhow::Result<Finished> {
    let layout = Layout(sealed);
    let [age_new, pub_new, backend_new] = staged(sealed);
    if age_new.exists() {
        for path in [&age_new, &pub_new, &backend_new] {
            let _ = std::fs::remove_file(path);
        }
        tracing::warn!("a CA rotation cut short before it took effect was dropped");
        return Ok(Finished::Dropped);
    }
    let mut finished = Finished::Nothing;
    for (fresh, path) in [
        (&pub_new, layout.ca_public()),
        (&backend_new, backend_path(sealed)),
    ] {
        if fresh.exists() {
            std::fs::rename(fresh, &path)
                .with_context(|| format!("cannot finish the CA rotation ({})", fresh.display()))?;
            // Each move durable before the next: never a marker in force before its half.
            sync_dir(sealed)?;
            finished = Finished::Completed;
        }
    }
    Ok(finished)
}

/// The most CAs kept as retired (a rotation drops the oldest past it; a record holding more
/// is refused).
pub const MAX_RETIRED_CAS: usize = 16;

/// The farthest a retired CA's deadline may be from now (a year): no lease is meant to last
/// that long, so a farther one is a record no rotation wrote (the record is bound to nothing
/// yet: Q38, M8), refused.
pub const RETIRED_HORIZON: u64 = 366 * 86_400;

/// The CAs rotations replaced, each with until when it is trusted, as of `now`: at most
/// [`MAX_RETIRED_CAS`], each deadline within [`RETIRED_HORIZON`] of `now`, or the record is
/// refused, naming the line.
pub fn retired(sealed: &SealedConfig, now: u64) -> anyhow::Result<Vec<(PublicKey, u64)>> {
    let path = retired_path(sealed);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = writ_platform::fs::read_authority(&path, "the retired CAs")?;
    parse_retired(&text, now).with_context(|| path.display().to_string())
}

/// [`retired`]'s record, read.
fn parse_retired(text: &str, now: u64) -> anyhow::Result<Vec<(PublicKey, u64)>> {
    if text.len() > MAX_RETIRED {
        bail!("larger than a retired CAs' record ({MAX_RETIRED} bytes)");
    }
    let horizon = now.saturating_add(RETIRED_HORIZON);
    let mut kept = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let n = n.saturating_add(1);
        if kept.len() >= MAX_RETIRED_CAS {
            bail!("line {n}: more than {MAX_RETIRED_CAS} retired CAs");
        }
        let (until, key) = line
            .split_once(' ')
            .with_context(|| format!("line {n}: not a time then a public key"))?;
        let until: u64 = until
            .parse()
            .with_context(|| format!("line {n}: not a time"))?;
        if until > horizon {
            bail!(
                "line {n}: a deadline more than {} days ahead: no rotation writes that (remove \
                 the line)",
                RETIRED_HORIZON / 86_400
            );
        }
        let key = PublicKey::from_openssh(key.trim())
            .with_context(|| format!("line {n}: not a public key"))?;
        kept.push((key, until));
    }
    Ok(kept)
}

/// Writes `material` (sealed to `recipient`), its public half and its backend's name beside
/// the CA in force, as `.new` files, whole: nothing in force changes.
pub fn stage(
    sealed: &SealedConfig,
    recipient: &age::x25519::Recipient,
    material: &Material,
    meta: KeyMeta,
    backend: &str,
) -> anyhow::Result<()> {
    let [age_new, pub_new, backend_new] = staged(sealed);
    let text = material.encode(meta)?;
    let sealed_key = seal_bytes(text.as_bytes(), &[recipient])?;
    // Each written whole and its directory synced (`write_whole`).
    let written = write_new(&age_new, &sealed_key, 0o600)
        .and_then(|()| {
            write_new(
                &pub_new,
                format!("{}\n", material.public_key().to_openssh()?).as_bytes(),
                0o644,
            )
        })
        .and_then(|()| write_new(&backend_new, format!("{backend}\n").as_bytes(), 0o644));
    if written.is_err() {
        unstage(sealed);
    }
    written
}

/// Removes a rotation's `.new` files (one not put in force).
pub fn unstage(sealed: &SealedConfig) {
    for path in staged(sealed) {
        let _ = std::fs::remove_file(path);
    }
}

/// Puts the staged CA in force: its key moved in (the point of no return: a start finishes the
/// rest), then its public half and its marker.
pub fn commit(sealed: &SealedConfig) -> Result<(), Committed> {
    let layout = Layout(sealed);
    let [age_new, _, _] = staged(sealed);
    std::fs::rename(&age_new, layout.ca())
        .map_err(|e| Committed::NotInForce(format!("cannot put the new CA key in force: {e}")))?;
    sync_dir(sealed)
        .and_then(|()| finish(sealed).map(|_| ()))
        .map_err(|e| Committed::Unfinished(format!("{e:#}")))
}

/// Why [`commit`] stopped: before the key was in force, or after.
#[derive(Debug)]
pub enum Committed {
    NotInForce(String),
    /// In force; what a start finishes is left (said, never "not rotated").
    Unfinished(String),
}

/// Records the CA `old` as retired until `until` (none: no lease it certified is active), with
/// the retired CAs still trusted at `now`. Answers those now trusted.
pub fn retire(
    sealed: &SealedConfig,
    old: &PublicKey,
    until: Option<u64>,
    now: u64,
) -> anyhow::Result<Vec<(PublicKey, u64)>> {
    let mut kept: Vec<(PublicKey, u64)> = retired(sealed, now)?
        .into_iter()
        .filter(|(_, until)| *until > now)
        .collect();
    if let Some(until) = until {
        kept.push((old.clone(), until.min(now.saturating_add(RETIRED_HORIZON))));
    }
    // The newest kept when there are too many (each one's leases end by its deadline anyway).
    kept.sort_by_key(|(_, until)| std::cmp::Reverse(*until));
    kept.truncate(MAX_RETIRED_CAS);
    let mut text = String::new();
    for (key, until) in &kept {
        text.push_str(&format!("{until} {}\n", key.to_openssh()?));
    }
    let path = retired_path(sealed);
    if kept.is_empty() {
        let _ = std::fs::remove_file(&path);
        sync_dir(sealed)?;
        return Ok(kept);
    }
    write_new(&path, text.as_bytes(), 0o644)?;
    Ok(kept)
}

/// The backend the CA's key is on, as its marker says (none: software). Readable sealed.
pub fn backend(sealed: &SealedConfig) -> anyhow::Result<String> {
    let path = backend_path(sealed);
    if !path.exists() {
        return Ok("software".to_owned());
    }
    let text = writ_platform::fs::read_authority(&path, "the CA's backend")?;
    let name = text.trim();
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    {
        bail!("{}: not a backend name", path.display());
    }
    Ok(name.to_owned())
}

/// Records the backend the CA's key is on (`writd init`; a rotation stages it with the key).
pub fn set_backend(sealed: &SealedConfig, name: &str) -> anyhow::Result<()> {
    write_new(&backend_path(sealed), format!("{name}\n").as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_line() -> String {
        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        key.public_key().to_openssh().unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The review after M7.6 (D-4): the CA's key, public half and backend marker are staged
    /// together, put in force together; a stop before the key moves in drops all three, one
    /// after it finishes all three (never a marker that isn't the key's).
    #[test]
    fn a_staged_rotation_goes_in_whole_with_its_marker_or_not_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = SealedConfig {
            dir: dir.path().to_owned(),
            boot: dir.path().join("boot"),
        };
        let recipient = age::x25519::Identity::generate().to_public();
        let material = Material::Software(
            writ_crypto::keypair::KeyPair::generate(writ_crypto::algorithm::KeyAlgorithm::Ed25519)
                .unwrap(),
        );
        let stage = || stage(&sealed, &recipient, &material, KeyMeta::SSH, "se-cryptokit").unwrap();
        // Staged, then dropped (its line refused): nothing left.
        stage();
        assert_eq!(
            names(dir.path()),
            ["ca.age.new", "ca.backend.new", "ca.pub.new"]
        );
        unstage(&sealed);
        assert!(names(dir.path()).is_empty());
        // Staged, stopped before the key moved in: the start drops it.
        stage();
        assert_eq!(finish(&sealed).unwrap(), Finished::Dropped);
        assert!(names(dir.path()).is_empty());
        // The key moved in, stopped before the rest: the start finishes it, marker included.
        stage();
        std::fs::rename(dir.path().join("ca.age.new"), dir.path().join("ca.age")).unwrap();
        assert_eq!(finish(&sealed).unwrap(), Finished::Completed);
        assert_eq!(names(dir.path()), ["ca.age", "ca.backend", "ca.pub"]);
        assert_eq!(backend(&sealed).unwrap(), "se-cryptokit");
        assert_eq!(finish(&sealed).unwrap(), Finished::Nothing);
        // Committed whole.
        stage();
        commit(&sealed).unwrap();
        assert_eq!(names(dir.path()), ["ca.age", "ca.backend", "ca.pub"]);
    }

    /// The review after M7.6 (T-4, S-9): the record is the daemon's, but bound to nothing yet
    /// (Q38): it holds at most 16 CAs, each trusted at most a year from now, or it is
    /// refused, naming the line; anything else in it too.
    #[test]
    fn a_retired_record_is_read_within_its_bounds_and_hostile_forms_are_refused() {
        let now = 1_800_000_000;
        let line = |until: u64| format!("{until} {}\n", key_line());
        let sixteen: String = (0..MAX_RETIRED_CAS).map(|_| line(now + 60)).collect();
        assert_eq!(parse_retired(&sixteen, now).unwrap().len(), MAX_RETIRED_CAS);
        let refused = |text: &str| format!("{:#}", parse_retired(text, now).unwrap_err());
        assert_eq!(
            refused(&format!("{sixteen}{}", line(now + 60))),
            "line 17: more than 16 retired CAs"
        );
        // The horizon on both sides.
        assert_eq!(
            parse_retired(&line(now + RETIRED_HORIZON), now)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            refused(&line(now + RETIRED_HORIZON + 1)),
            "line 1: a deadline more than 366 days ahead: no rotation writes that (remove the \
             line)"
        );
        assert_eq!(refused("123\n"), "line 1: not a time then a public key");
        assert!(refused(&format!("-1 {}", key_line())).starts_with("line 1: not a time"));
        assert!(refused(&format!("{} {}", u64::MAX, key_line())).starts_with("line 1: a deadline"));
        assert!(refused("60 ssh-ed25519 !!!\n").starts_with("line 1: not a public key"));
        assert!(refused(&"x".repeat(MAX_RETIRED + 1)).starts_with("larger than"));
    }
}
