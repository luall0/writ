//! Files the daemon trusts: private directories (0700), new private files (0600), and the
//! two kinds of file it reads that others must not have touched:
//!
//! - **secrets** ([`read_secret`]): readable by the daemon's user only (a bot token, a wrapped
//!   key);
//! - **authority files** ([`read_authority`]): files that decide who may do what (`approvers`,
//!   `readers`, the policy, `writd.yaml`). Not secret, but whoever can write one can make
//!   themselves an approver at the next start, which would bypass signed admin changes.
//!
//! Every such file is opened without following a link and without blocking (a FIFO in its
//! place never hangs the daemon), and checked on the open file (the file checked is the file
//! read): a regular file, owned by the daemon's user, with the right mode.
//!
//! Unix permissions, on every platform the daemon runs on (macOS, Linux).

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

use crate::{PlatformError, Result};

/// The largest authority file the daemon reads (a policy is a few kilobytes).
pub const MAX_AUTHORITY_FILE: u64 = 1 << 20;

/// The daemon's effective user id.
fn my_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Creates `path` (and its parents) if needed, private (0700) from the start. An existing
/// directory is made 0700 again; one that is a link, or owned by another user, is refused.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a directory (a link?)",
            path.display()
        )));
    }
    if metadata.uid() != my_uid() {
        return Err(std::io::Error::other(format!(
            "{} is owned by uid {}, not this user",
            path.display(),
            metadata.uid()
        )));
    }
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

/// Opens `path` for reading without following a link or blocking, and checks it is a regular
/// file owned by the daemon's user. `what` names the file in errors.
fn open_owned(path: &Path, what: &str) -> Result<(File, Metadata)> {
    let unreadable = |e: std::io::Error| {
        PlatformError::Config(format!(
            "cannot read {what} {}: {}",
            path.display(),
            e.kind()
        ))
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(|e| unreadable(e.into()))?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(PlatformError::Config(format!(
            "{what} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.uid() != my_uid() {
        return Err(PlatformError::Config(format!(
            "{what} {} is owned by uid {}, not the daemon's user (uid {})",
            path.display(),
            metadata.uid(),
            my_uid()
        )));
    }
    Ok((file, metadata))
}

/// Reads at most `max` bytes; more is refused, not cut.
fn read_bounded(mut file: File, path: &Path, what: &str, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    // Capacity above the limit: the buffer never grows, so no copy is left behind.
    let capacity = usize::try_from(max).unwrap_or(usize::MAX).saturating_add(1);
    let mut contents = Zeroizing::new(Vec::with_capacity(capacity.min(1 << 20)));
    (&mut file)
        .take(max.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|e| {
            PlatformError::Config(format!(
                "cannot read {what} {}: {}",
                path.display(),
                e.kind()
            ))
        })?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max {
        return Err(PlatformError::Config(format!(
            "{what} {} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(contents)
}

/// Reads a secret file: a regular file of the daemon's user that nobody else can read or
/// write, at most `max` bytes, into memory that is wiped when dropped.
pub fn read_secret(path: &Path, what: &str, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let (file, metadata) = open_owned(path, what)?;
    check_private(path, &metadata)?;
    read_bounded(file, path, what, max)
}

/// Reads an authority file (who may do what): a regular file of the daemon's user that
/// nobody else can write, as UTF-8, at most [`MAX_AUTHORITY_FILE`] bytes.
pub fn read_authority(path: &Path, what: &str) -> Result<String> {
    let (file, metadata) = open_owned(path, what)?;
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(PlatformError::Config(format!(
            "{what} {} can be written by group or others (mode {:o}): whoever can write it \
             decides who may do what; make it 0644 or stricter",
            path.display(),
            mode & 0o777
        )));
    }
    let contents = read_bounded(file, path, what, MAX_AUTHORITY_FILE)?;
    String::from_utf8(contents.to_vec())
        .map_err(|_| PlatformError::Config(format!("{what} {} is not UTF-8", path.display())))
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

    fn set_mode(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }

    /// The message of a `Config` error; anything else fails the test.
    fn config_error<T: std::fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(PlatformError::Config(message)) => message,
            other => panic!("expected a Config error, got {other:?}"),
        }
    }

    #[test]
    fn private_files_are_private_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        create_private_dir(&sub).unwrap();
        assert_eq!(mode(&sub), 0o700);
        assert_eq!(
            mode(&dir.path().join("a")),
            0o700,
            "parents too, from the start"
        );
        // An existing directory is made private again.
        set_mode(&sub, 0o755);
        create_private_dir(&sub).unwrap();
        assert_eq!(mode(&sub), 0o700);
        // A link in its place is refused.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&sub, &link).unwrap();
        let error = create_private_dir(&link).unwrap_err().to_string();
        assert!(error.ends_with("is not a directory (a link?)"), "{error}");

        let file = sub.join("key");
        create_new_private_file(&file).unwrap();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(
            create_new_private_file(&file).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists,
            "never overwritten"
        );
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
            set_mode(&file, bits);
            let checked = check_private(&file, &std::fs::metadata(&file).unwrap());
            assert_eq!(checked.is_ok(), allowed, "mode {bits:o}");
            assert_eq!(
                read_secret(&file, "token", 16).is_ok(),
                allowed,
                "mode {bits:o}"
            );
        }
    }

    #[test]
    fn a_secret_is_read_whole_up_to_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "0123456789").unwrap();
        set_mode(&file, 0o600);
        assert_eq!(
            read_secret(&file, "token", 10).unwrap().as_slice(),
            b"0123456789"
        );
        let error = config_error(read_secret(&file, "token", 9));
        assert!(error.contains("larger than 9 bytes"), "{error}");
    }

    #[test]
    fn an_authority_file_others_can_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("approvers");
        std::fs::write(&file, "me ssh-ed25519 AAAA\n").unwrap();
        for (bits, allowed) in [
            (0o644, true),
            (0o600, true),
            (0o444, true),
            (0o664, false),
            (0o646, false),
            (0o666, false),
        ] {
            set_mode(&file, bits);
            let read = read_authority(&file, "approvers file");
            assert_eq!(read.is_ok(), allowed, "mode {bits:o}: {read:?}");
            if !allowed {
                assert!(
                    config_error(read).contains("can be written by group or others"),
                    "mode {bits:o}"
                );
            }
        }
    }

    #[test]
    fn a_file_of_another_user_is_refused() {
        // A regular file every Unix has, owned by root, mode 0644: refused for its owner
        // alone (meaningless when the tests run as root).
        if my_uid() == 0 {
            return;
        }
        let hosts = Path::new("/etc/hosts");
        let error = config_error(read_authority(hosts, "policy"));
        assert!(
            error.contains("is owned by uid 0, not the daemon's user"),
            "{error}"
        );
        let error = config_error(read_secret(hosts, "token", 1 << 20));
        assert!(error.contains("is owned by uid 0"), "{error}");
    }

    #[test]
    fn links_fifos_and_directories_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, "x").unwrap();
        set_mode(&real, 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = config_error(read_authority(&link, "policy"));
        assert!(error.starts_with("cannot read policy"), "{error}");
        assert!(config_error(read_secret(&link, "token", 16)).starts_with("cannot read token"));

        // A FIFO: refused at once, never waited on.
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        set_mode(&fifo, 0o600);
        let error = config_error(read_secret(&fifo, "token", 16));
        assert!(error.ends_with("is not a regular file"), "{error}");

        let error = config_error(read_authority(dir.path(), "policy"));
        assert!(error.ends_with("is not a regular file"), "{error}");
        assert!(
            config_error(read_authority(&dir.path().join("none"), "policy"))
                .starts_with("cannot read policy")
        );
    }
}
