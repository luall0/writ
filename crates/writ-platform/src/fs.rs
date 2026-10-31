//! Files only the daemon may read: private directories (0700), new private files (0600), and
//! the check that a secret file handed to the daemon is not readable by others.
//!
//! Unix permissions, on every platform the daemon runs on (macOS, Linux).

use std::fs::{File, Metadata, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::{PlatformError, Result};

/// Creates `path` (and its parents) if needed, and makes it 0700.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Creates a new file only the daemon can read (0600). Fails if it exists: nothing is ever
/// overwritten, and nothing is followed through a link.
pub fn create_new_private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Refuses a file readable or writable by group or others (mode & 0o077 != 0), with a
/// `Config` error naming it. Check the metadata of the open file, so the file checked is the
/// file read.
pub fn check_private(path: &Path, metadata: &Metadata) -> Result<()> {
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(PlatformError::Config(format!(
            "{} is accessible by group or others (mode {:o}); make it 0600",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn private_files_are_private_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        create_private_dir(&sub).unwrap();
        assert_eq!(mode(&sub), 0o700);
        // An existing directory is made private again.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&sub).unwrap();
        assert_eq!(mode(&sub), 0o700);

        let file = sub.join("key");
        create_new_private_file(&file).unwrap();
        assert_eq!(mode(&file), 0o600);
        assert!(create_new_private_file(&file).is_err(), "never overwritten");
        let link = sub.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(
            create_new_private_file(&link).is_err(),
            "never through a link"
        );
    }

    #[test]
    fn a_file_others_can_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "x").unwrap();
        for (bits, allowed) in [
            (0o600, true),
            (0o400, true),
            (0o640, false),
            (0o604, false),
            (0o602, false),
            (0o620, false),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(bits)).unwrap();
            let checked = check_private(&file, &std::fs::metadata(&file).unwrap());
            assert_eq!(checked.is_ok(), allowed, "mode {bits:o}");
        }
    }
}
