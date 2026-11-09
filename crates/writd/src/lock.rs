//! The state's lock: `writd run` holds an exclusive lock on `<state>/writd.lock` for its whole
//! life, its pid written in it, and `writd recover` takes it before changing anything, so
//! neither runs while the other does (two writers of the state would only refuse each
//! other's versions). The kernel releases the lock when its process ends: a crashed daemon
//! leaves the file, never a lock that blocks.

use std::fs::{File, TryLockError};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// The lock file's name in the state directory.
pub const LOCK_FILE: &str = "writd.lock";

/// The most of the lock file read for its holder's pid.
const MAX_LOCK_TEXT: u64 = 32;

/// The state's lock, held until dropped.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
}

/// Who holds the state, for the refusal.
#[derive(Debug, Clone, Copy)]
pub enum Holder {
    /// `writd run`.
    Daemon,
    /// `writd recover`.
    Recovery,
}

/// Takes the state directory's lock without waiting, for `by`, writing this process's pid in
/// it; refuses while another process holds it, naming that process.
pub fn hold(state_dir: &Path, by: Holder) -> anyhow::Result<StateLock> {
    let path = state_dir.join(LOCK_FILE);
    let mut file = writ_platform::fs::open_private_file(&path, "the state's lock")?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => bail!("{}", refusal(&mut file, &path, by)),
        Err(TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("cannot lock {}", path.display()));
        }
    }
    file.set_len(0)
        .and_then(|()| file.rewind())
        .and_then(|()| writeln!(file, "{}", std::process::id()))
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(StateLock { _file: file })
}

/// Why `by` can't take the lock: the holder's pid as it wrote it (a number, or nothing said).
fn refusal(file: &mut File, path: &Path, by: Holder) -> String {
    let mut text = String::new();
    let holder = match file.take(MAX_LOCK_TEXT).read_to_string(&mut text) {
        Ok(_) => match text.trim().parse::<u32>() {
            Ok(pid) => format!("writd (pid {pid})"),
            Err(_) => "another writd".to_owned(),
        },
        Err(_) => "another writd".to_owned(),
    };
    let path: PathBuf = path.to_owned();
    match by {
        Holder::Daemon => format!(
            "{holder} holds {}: one writd at a time on a state directory (a daemon already \
             runs, or `writd recover` does)",
            path.display()
        ),
        Holder::Recovery => format!(
            "{holder} holds {}: stop the daemon first (`writd recover` changes the state only \
             while nothing else does)",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_lock_is_held_once_and_names_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let held = hold(dir.path(), Holder::Daemon).unwrap();
        let written = std::fs::read_to_string(dir.path().join(LOCK_FILE)).unwrap();
        assert_eq!(written, format!("{}\n", std::process::id()));

        // Another open file description: refused, as another process would be.
        for (by, says) in [
            (Holder::Recovery, "stop the daemon first"),
            (Holder::Daemon, "one writd at a time"),
        ] {
            let message = hold(dir.path(), by).unwrap_err().to_string();
            let expected = format!(
                "writd (pid {}) holds {}",
                std::process::id(),
                dir.path().join(LOCK_FILE).display()
            );
            assert!(message.starts_with(&expected), "{message}");
            assert!(message.contains(says), "{message}");
        }

        // Released: taken again, the pid rewritten whole.
        drop(held);
        std::fs::write(dir.path().join(LOCK_FILE), "123456789012345\n").unwrap();
        let _again = hold(dir.path(), Holder::Recovery).unwrap();
        let written = std::fs::read_to_string(dir.path().join(LOCK_FILE)).unwrap();
        assert_eq!(written, format!("{}\n", std::process::id()));
    }

    #[test]
    fn a_holder_that_wrote_no_pid_is_named_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let held = hold(dir.path(), Holder::Daemon).unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), "\u{1b}[31mnot a pid\n").unwrap();
        let message = hold(dir.path(), Holder::Recovery).unwrap_err().to_string();
        assert!(message.starts_with("another writd holds"), "{message}");
        assert!(!message.contains('\u{1b}'));
        drop(held);
    }

    #[test]
    fn a_link_in_the_lock_files_place_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();
        let message = format!("{:#}", hold(dir.path(), Holder::Daemon).unwrap_err());
        assert!(
            message.contains("cannot open the state's lock"),
            "{message}"
        );
    }
}
