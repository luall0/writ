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
//! A rotation writes the retired record, then the two new files, then moves `ca.age.new`,
//! then `ca.pub.new`. A start finishes one cut short after the first move, and drops one cut
//! short before it ([`finish`]): the CA in force is always a whole pair.

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

/// Writes `bytes` whole at `path` (a new file, `mode`).
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()))
}

/// A rotation cut short: finished when its key was moved in already (the public half follows
/// it), dropped otherwise (the CA in force is still the old pair).
pub fn finish(sealed: &SealedConfig) -> anyhow::Result<()> {
    let layout = Layout(sealed);
    let (age_new, pub_new) = (
        with_suffix(&layout.ca(), ".new"),
        with_suffix(&layout.ca_public(), ".new"),
    );
    match (age_new.exists(), pub_new.exists()) {
        (false, true) => std::fs::rename(&pub_new, layout.ca_public())
            .with_context(|| format!("cannot finish the CA rotation ({})", pub_new.display()))?,
        (true, _) => {
            for path in [&age_new, &pub_new] {
                let _ = std::fs::remove_file(path);
            }
            tracing::warn!("a CA rotation cut short before it took effect was dropped");
        }
        (false, false) => {}
    }
    Ok(())
}

/// The most CAs kept as retired (a rotation drops the oldest past it).
const MAX_RETIRED_CAS: usize = 16;

/// The CAs rotations replaced, each with until when it is trusted.
pub fn retired(sealed: &SealedConfig) -> anyhow::Result<Vec<(PublicKey, u64)>> {
    let path = retired_path(sealed);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = writ_platform::fs::read_authority(&path, "the retired CAs")?;
    if text.len() > MAX_RETIRED {
        bail!("{}: larger than a retired CAs' record", path.display());
    }
    text.lines()
        .map(|line| {
            let (until, key) = line
                .split_once(' ')
                .with_context(|| format!("{}: not a time then a public key", path.display()))?;
            let until: u64 = until
                .parse()
                .with_context(|| format!("{}: not a time", path.display()))?;
            let key = PublicKey::from_openssh(key.trim())
                .with_context(|| format!("{}: not a public key", path.display()))?;
            Ok((key, until))
        })
        .collect()
}

/// Puts `material` in force as the CA (sealed to `recipient`), the CA `old` added to the
/// retired ones until `until` (none: no lease it certified is active), those past `now`
/// dropped. Answers the retired CAs now trusted.
pub fn rotate(
    sealed: &SealedConfig,
    recipient: &age::x25519::Recipient,
    material: &Material,
    meta: KeyMeta,
    old: &PublicKey,
    until: Option<u64>,
    now: u64,
) -> anyhow::Result<Vec<(PublicKey, u64)>> {
    let layout = Layout(sealed);
    let mut kept: Vec<(PublicKey, u64)> = retired(sealed)?
        .into_iter()
        .filter(|(_, until)| *until > now)
        .collect();
    if let Some(until) = until {
        kept.push((old.clone(), until));
    }
    // The newest kept when there are too many (each one's leases end by its deadline anyway).
    kept.sort_by_key(|(_, until)| std::cmp::Reverse(*until));
    kept.truncate(MAX_RETIRED_CAS);
    let mut text = String::new();
    for (key, until) in &kept {
        text.push_str(&format!("{until} {}\n", key.to_openssh()?));
    }
    match kept.is_empty() {
        true => {
            let _ = std::fs::remove_file(retired_path(sealed));
        }
        false => {
            let path = retired_path(sealed);
            let fresh = with_suffix(&path, ".new");
            write_new(&fresh, text.as_bytes(), 0o644)?;
            std::fs::rename(&fresh, &path)
                .with_context(|| format!("cannot move {} in place", fresh.display()))?;
        }
    }
    let text = material.encode(meta)?;
    let sealed_key = seal_bytes(text.as_bytes(), &[recipient])?;
    let (age_new, pub_new) = (
        with_suffix(&layout.ca(), ".new"),
        with_suffix(&layout.ca_public(), ".new"),
    );
    write_new(&age_new, &sealed_key, 0o600)?;
    write_new(
        &pub_new,
        format!("{}\n", material.public_key().to_openssh()?).as_bytes(),
        0o644,
    )?;
    std::fs::rename(&age_new, layout.ca()).with_context(|| "cannot put the new CA key in force")?;
    std::fs::rename(&pub_new, layout.ca_public())
        .with_context(|| "cannot put the new CA's public half in force")?;
    Ok(kept)
}

/// The backend the CA's key is on, as its marker says (none: software). Readable sealed.
pub fn backend(sealed: &SealedConfig) -> anyhow::Result<String> {
    let path = sealed.dir.join("ca.backend");
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

/// Records the backend the CA's key is on.
pub fn set_backend(sealed: &SealedConfig, name: &str) -> anyhow::Result<()> {
    let path = sealed.dir.join("ca.backend");
    let fresh = with_suffix(&path, ".new");
    write_new(&fresh, format!("{name}\n").as_bytes(), 0o644)?;
    std::fs::rename(&fresh, &path)
        .with_context(|| format!("cannot move {} in place", fresh.display()))
}
