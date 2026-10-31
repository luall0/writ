//! The session files on an agent host: `<home>/sessions/<lease>/` holds the session key
//! (`key`, `key.pub`), its certificate (`key-cert.pub`), the ticket as submitted
//! (`ticket.json`, and `<ticket>.json` for each one submitted from the session) and the lease
//! as signed (`lease.json`); `<home>/sessions/current` points at the active one.
//!
//! The directory is 0700 and the key 0600: nothing else on the host can read them.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
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

/// Creates a directory (and its parents) only the user can enter (0700).
pub fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot make {} private", path.display()))?;
    Ok(())
}

/// Reads a session's private key.
pub fn load_key(path: &Path) -> anyhow::Result<PrivateKey> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    PrivateKey::from_openssh(text).with_context(|| format!("{} is not a key", path.display()))
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
