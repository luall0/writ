//! The session files on an agent host: `<home>/sessions/<lease>/` holds the session key
//! (`key`, `key.pub`), its certificate (`key-cert.pub`), the ticket as submitted
//! (`ticket.json`, and `<ticket>.json` for each one submitted from the session) and the lease
//! as signed (`lease.json`); `<home>/sessions/current` points at the active one.
//!
//! The directory is 0700 and the key 0600: nothing else on the host can read them.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::names::TicketId;
use writ_crypto::ssh_key::PrivateKey;

use crate::Paths;

/// `<home>/sessions/<lease>`. The lease id is a validated ticket id, so never a path.
pub fn session_dir(paths: &Paths, id: &TicketId) -> PathBuf {
    paths.home.join("sessions").join(id.as_str())
}

/// Creates a new file only the user can read (0600); fails if it exists.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Writes a file that holds no secret.
pub fn write_file(path: &Path, contents: impl AsRef<[u8]>) -> anyhow::Result<()> {
    fs::write(path, contents).with_context(|| format!("cannot write {}", path.display()))
}

/// Creates a directory (and its parents) only the user can enter: 0700 from creation (no
/// moment at the umask's mode), made 0700 again if it exists; a link in its place is refused.
pub fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("{} is not a directory (a link?)", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot make {} private", path.display()))?;
    Ok(())
}

/// Reads a private key file: refused if others can read it (mode & 0o077), checked on the
/// open file; the text is wiped from memory once parsed.
pub fn load_key(path: &Path) -> anyhow::Result<PrivateKey> {
    use std::io::Read as _;
    let mut file =
        fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mode = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} can be read by others (mode {:o}): it must be 0600",
            path.display(),
            mode & 0o777
        );
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    file.read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    PrivateKey::from_openssh(text.as_bytes())
        .with_context(|| format!("{} is not a key", path.display()))
}

/// Points `<home>/sessions/current` at a lease's session, replacing the link atomically.
pub fn point_current(paths: &Paths, id: &TicketId) -> anyhow::Result<()> {
    let sessions = paths.home.join("sessions");
    let temporary = sessions.join(format!(".current-{id}"));
    let _ = fs::remove_file(&temporary);
    std::os::unix::fs::symlink(id.as_str(), &temporary)
        .with_context(|| format!("cannot link {}", temporary.display()))?;
    fs::rename(&temporary, sessions.join("current"))
        .with_context(|| format!("cannot update {}", sessions.join("current").display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(home: &Path) -> Paths {
        Paths {
            home: home.to_owned(),
            known_hosts: home.join("known_hosts"),
            tls_pins: home.join("tls_pins"),
            reader: home.join("reader"),
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn session_files_are_private_and_never_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths(home.path());
        let id: TicketId = "wrt_01JD8X0000000000000000000A".parse().unwrap();
        let dir = session_dir(&paths, &id);
        assert_eq!(
            dir,
            home.path().join("sessions/wrt_01JD8X0000000000000000000A")
        );
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        write_private(&dir.join("key"), b"secret").unwrap();
        assert_eq!(mode(&dir.join("key")), 0o600);
        assert!(
            write_private(&dir.join("key"), b"other").is_err(),
            "never overwritten"
        );
        assert_eq!(fs::read(dir.join("key")).unwrap(), b"secret");
        assert!(load_key(&dir.join("key")).is_err(), "not a key");
    }

    #[test]
    fn a_link_or_a_key_others_can_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        create_private_dir(&real).unwrap();
        assert_eq!(mode(&real), 0o700);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = create_private_dir(&link).unwrap_err().to_string();
        assert!(error.contains("is not a directory (a link?)"), "{error}");

        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let path = real.join("key");
        write_private(
            &path,
            key.to_openssh(writ_crypto::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(load_key(&path).unwrap().public_key(), key.public_key());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = load_key(&path).unwrap_err().to_string();
        assert!(
            error.contains("can be read by others (mode 640)"),
            "{error}"
        );
    }

    #[test]
    fn current_points_at_the_latest_session() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths(home.path());
        let first: TicketId = "wrt_01JD8X0000000000000000000A".parse().unwrap();
        let second: TicketId = "wrt_01JD8X0000000000000000000B".parse().unwrap();
        for id in [&first, &second] {
            create_private_dir(&session_dir(&paths, id)).unwrap();
        }
        point_current(&paths, &first).unwrap();
        let current = home.path().join("sessions/current");
        assert_eq!(fs::read_link(&current).unwrap(), Path::new(first.as_str()));
        point_current(&paths, &second).unwrap();
        assert_eq!(fs::read_link(&current).unwrap(), Path::new(second.as_str()));
        let leftovers: Vec<_> = fs::read_dir(home.path().join("sessions"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
