//! Reading one process at a time: [`ReadProcess`], what the attestor and the watcher ask, and
//! [`Direct`], which reads `/proc` in this process. The daemon, running as `writd`, can't read
//! another user's executable or namespaces itself: it asks the capped helper instead
//! ([`crate::helper`]), which answers with a [`Direct`] of its own.

use std::path::PathBuf;

use crate::procfs::{self, Namespaces, ReadError};

/// One process, read while a pidfd showed it running: everything here is of that process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub ppid: u32,
    /// Its start time (clock ticks after boot): the pid's generation.
    pub start: u64,
    pub executable: PathBuf,
    /// The kernel shows its executable as deleted.
    pub deleted: bool,
    pub namespaces: Namespaces,
}

/// Reads one process, and the namespaces a process must share to be on the host.
pub trait ReadProcess: Send + Sync {
    /// Whichever process runs as `pid` now.
    fn read(&self, pid: u32) -> Result<Entry, ReadError>;
    /// The host's pid and mount namespaces, the ones a session's root must be in.
    fn host(&self) -> Result<Namespaces, ReadError>;
}

/// Reads `/proc` in this process: every process when it holds `CAP_SYS_PTRACE` (the helper),
/// only its own user's otherwise (a development daemon running as its user, the tests).
/// The host is pid 1's namespaces for the helper (the daemon's own mount namespace is
/// systemd's private one), this process's own otherwise.
#[derive(Debug, Clone, Copy)]
pub struct Direct {
    host: Host,
}

/// Whose namespaces are the host's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// Pid 1's: the helper's view, reading with `CAP_SYS_PTRACE`.
    Init,
    /// This process's own: a reader with no capability can't read pid 1's.
    Myself,
}

impl Direct {
    pub fn new(host: Host) -> Self {
        Self { host }
    }
}

impl ReadProcess for Direct {
    fn read(&self, pid: u32) -> Result<Entry, ReadError> {
        // Held first: until it shows the process ended, its pid is not another's.
        let pidfd = procfs::hold(pid)?;
        let stat = procfs::stat(pid)?;
        let (executable, deleted) = procfs::executable(pid)?;
        let namespaces = procfs::namespaces_of(&pid.to_string())
            .map_err(|e| procfs::read_error(pid, "its namespaces", &e))?;
        match procfs::running(&pidfd) {
            Ok(true) => Ok(Entry {
                pid,
                ppid: stat.ppid,
                start: stat.start,
                executable,
                deleted,
                namespaces,
            }),
            Ok(false) => Err(ReadError::Gone(format!(
                "pid {pid} ended while it was read"
            ))),
            Err(e) => Err(procfs::read_error(pid, "its pidfd", &e)),
        }
    }

    fn host(&self) -> Result<Namespaces, ReadError> {
        match self.host {
            Host::Init => self.read(1).map(|init| init.namespaces),
            Host::Myself => procfs::namespaces_of("self")
                .map_err(|e| ReadError::Unreadable(format!("this process's namespaces: {e}"))),
        }
    }
}
