//! Reading one process at a time: [`ReadProcess`], what the attestor and the watcher ask.
//! A process is read in two parts: what anyone may read (`stat`: parent, start time) and its
//! links ([`ReadLinks`]: executable and namespaces), which another user's process shows only to
//! `CAP_SYS_PTRACE`. [`read_with`] reads both inside one pidfd's life, so all of it is that
//! process's. [`Direct`] reads the links itself; the daemon, running as `writd`, asks the
//! capped helper for them instead ([`crate::helper`]), which answers with a [`Direct`] of its
//! own under a seccomp filter that lets it do nothing else.

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

/// What a process's links say: its executable and its namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Links {
    pub executable: PathBuf,
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

/// Reads one process's links (`readlink` only: what the capped helper may do), and the host's
/// namespaces.
pub trait ReadLinks: Send + Sync {
    /// Whichever process runs as `pid` now: its links.
    fn links(&self, pid: u32) -> Result<Links, ReadError>;
    /// The host's pid and mount namespaces.
    fn host_namespaces(&self) -> Result<Namespaces, ReadError>;
}

/// Reads `pid` whole: a pidfd held first (until it shows the process ended, its pid is not
/// another's), its `stat`, its links through `links`, then the pidfd checked: still running,
/// so everything read was that process's.
pub fn read_with(links: &dyn ReadLinks, pid: u32) -> Result<Entry, ReadError> {
    let pidfd = procfs::hold(pid)?;
    let stat = procfs::stat(pid)?;
    let read = links.links(pid)?;
    match procfs::running(&pidfd) {
        Ok(true) => Ok(Entry {
            pid,
            ppid: stat.ppid,
            start: stat.start,
            executable: read.executable,
            deleted: read.deleted,
            namespaces: read.namespaces,
        }),
        Ok(false) => Err(ReadError::Gone(format!(
            "pid {pid} ended while it was read"
        ))),
        Err(e) => Err(procfs::read_error(pid, "its pidfd", &e)),
    }
}

/// Reads `/proc` in this process: every process's links when it holds `CAP_SYS_PTRACE` (the
/// helper), only its own user's otherwise (a development daemon running as its user, the
/// tests). The host is pid 1's namespaces for the helper (the daemon's own mount namespace is
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

impl ReadLinks for Direct {
    fn links(&self, pid: u32) -> Result<Links, ReadError> {
        let (executable, deleted) = procfs::executable(pid)?;
        let namespaces = procfs::namespaces_of(&pid.to_string())
            .map_err(|e| procfs::read_error(pid, "its namespaces", &e))?;
        Ok(Links {
            executable,
            deleted,
            namespaces,
        })
    }

    fn host_namespaces(&self) -> Result<Namespaces, ReadError> {
        let whose = match self.host {
            Host::Init => "1",
            Host::Myself => "self",
        };
        procfs::namespaces_of(whose)
            .map_err(|e| ReadError::Unreadable(format!("the host's namespaces ({whose}): {e}")))
    }
}

impl ReadProcess for Direct {
    fn read(&self, pid: u32) -> Result<Entry, ReadError> {
        read_with(self, pid)
    }

    fn host(&self) -> Result<Namespaces, ReadError> {
        self.host_namespaces()
    }
}
