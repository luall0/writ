//! Process facts from the kernel: a Unix socket peer's audit token, and a process's parent,
//! unique id, pid generation (pidversion) and executable.
//!
//! `proc_uniqidentifierinfo` (`PROC_PIDUNIQIDENTIFIERINFO`) is not in the public SDK headers
//! but is a stable kernel ABI (XNU's `proc_info_private.h`); its layout was checked on macOS
//! 27 against the public facts it repeats (its pidversion is the audit token's, its parent's
//! unique id is the parent's own, its size is the 56 bytes the kernel writes), and the tests
//! check it again on every run.

use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

/// `audit_token_t` (`<mach/message.h>`): eight words, of which the effective user and group
/// (words 1 and 2), the pid (5) and its generation, the pidversion (7).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditToken {
    val: [u32; 8],
}

impl AuditToken {
    pub fn euid(&self) -> u32 {
        let [_, euid, ..] = self.val;
        euid
    }

    pub fn egid(&self) -> u32 {
        let [_, _, egid, ..] = self.val;
        egid
    }

    pub fn pid(&self) -> u32 {
        let [_, _, _, _, _, pid, _, _] = self.val;
        pid
    }

    pub fn pidversion(&self) -> u32 {
        let [.., pidversion] = self.val;
        pidversion
    }
}

/// The audit token of the process at the other end of a connected Unix socket, as the kernel
/// recorded it at connect (`LOCAL_PEERTOKEN`).
pub fn peer_token(fd: BorrowedFd<'_>) -> io::Result<AuditToken> {
    let size = std::mem::size_of::<AuditToken>();
    let mut len = libc::socklen_t::try_from(size).map_err(|_| io::Error::other("token size"))?;
    let mut token = AuditToken::default();
    // SAFETY: the buffer is a valid, writable `audit_token_t` of `len` bytes, which is what
    // `LOCAL_PEERTOKEN` writes; `len` is updated to what was written; the fd is borrowed, so
    // it stays open for the call.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            std::ptr::addr_of_mut!(token).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(size) {
        return Err(io::Error::other("LOCAL_PEERTOKEN gave a short token"));
    }
    Ok(token)
}

/// `PROC_PIDUNIQIDENTIFIERINFO` (`<sys/proc_info_private.h>`).
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

/// `struct proc_uniqidentifierinfo` (`<sys/proc_info_private.h>`).
#[repr(C)]
#[derive(Default)]
struct UniqIdentifierInfo {
    /// The main executable's UUID.
    uuid: [u8; 16],
    /// Never reused while the system runs.
    uniqueid: u64,
    /// The parent's `uniqueid` when this process was made (an orphan keeps it).
    puniqueid: u64,
    /// The pidversion: a new one at each `exec`.
    idversion: i32,
    /// The parent's pidversion when this process was made.
    orig_ppidversion: i32,
    reserve2: u64,
    reserve3: u64,
}

const _: () = assert!(std::mem::size_of::<UniqIdentifierInfo>() == 56);

/// What the kernel says about one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcInfo {
    pub ppid: u32,
    pub uid: u32,
    /// Never reused while the system runs.
    pub uniqueid: u64,
    /// The parent's `uniqueid` when it was made: a parent whose own differs is another
    /// process (the parent ended; the orphan's `ppid` is then launchd's).
    pub puniqueid: u64,
    /// The pidversion: a reused pid, or the same process after an `exec`, has another.
    pub generation: u32,
}

/// Fills `info` with `flavor` for `pid`: the kernel must write exactly its size.
///
/// # Safety
/// `T` must be the plain C struct `flavor` writes, for which all zero bits is valid.
unsafe fn pidinfo<T: Default>(pid: u32, flavor: libc::c_int) -> io::Result<T> {
    let pid = libc::c_int::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
    let size = libc::c_int::try_from(std::mem::size_of::<T>())
        .map_err(|_| io::Error::other("proc_pidinfo size"))?;
    let mut info = T::default();
    // SAFETY: the buffer is a valid, writable `T` of exactly `size` bytes, which is what
    // `flavor` writes (the caller's contract).
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            flavor,
            0,
            std::ptr::addr_of_mut!(info).cast::<libc::c_void>(),
            size,
        )
    };
    if written != size {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(0 | libc::ESRCH) | None => {
                io::Error::new(io::ErrorKind::NotFound, "no such process")
            }
            Some(_) => error,
        });
    }
    Ok(info)
}

/// Default for `proc_bsdshortinfo` (a C struct of integers and byte arrays).
#[derive(Clone, Copy)]
struct ShortInfo(libc::proc_bsdshortinfo);

impl Default for ShortInfo {
    fn default() -> Self {
        // SAFETY: `proc_bsdshortinfo` is a plain C struct of integers and byte arrays, for
        // which all zero bits is a valid value.
        Self(unsafe { std::mem::zeroed() })
    }
}

/// The parent, user, unique ids and generation of `pid`; `NotFound` once it has ended.
pub fn proc_info(pid: u32) -> io::Result<ProcInfo> {
    // SAFETY: `UniqIdentifierInfo` is `PROC_PIDUNIQIDENTIFIERINFO`'s struct (checked in the
    // tests), all integers.
    let unique: UniqIdentifierInfo = unsafe { pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO)? };
    // SAFETY: `ShortInfo` wraps exactly `proc_bsdshortinfo`, `PROC_PIDT_SHORTBSDINFO`'s
    // struct, all integers and byte arrays.
    let short: ShortInfo = unsafe { pidinfo(pid, libc::PROC_PIDT_SHORTBSDINFO)? };
    let generation =
        u32::try_from(unique.idversion).map_err(|_| io::Error::other("a negative pidversion"))?;
    Ok(ProcInfo {
        ppid: short.0.pbsi_ppid,
        uid: short.0.pbsi_uid,
        uniqueid: unique.uniqueid,
        puniqueid: unique.puniqueid,
        generation,
    })
}

/// The executable `pid` runs, as the kernel resolved it (`proc_pidpath`), never its name or
/// arguments.
pub fn proc_path(pid: u32) -> io::Result<PathBuf> {
    let pid = libc::c_int::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
    let mut buffer = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size = u32::try_from(buffer.len()).map_err(|_| io::Error::other("path buffer"))?;
    // SAFETY: the buffer is valid and writable for `size` bytes; `proc_pidpath` writes at
    // most that and returns how many it wrote.
    let written =
        unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast::<libc::c_void>(), size) };
    let written = usize::try_from(written).map_err(|_| io::Error::last_os_error())?;
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = buffer
        .get(..written)
        .ok_or_else(|| io::Error::other("proc_pidpath wrote past its buffer"))?;
    Ok(PathBuf::from(OsStr::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_private_layout_agrees_with_the_public_facts() {
        let me = proc_info(std::process::id()).unwrap();
        let parent = proc_info(me.ppid).unwrap();
        // This process's parent link holds, and the parent's own parent is further up.
        assert_eq!(me.puniqueid, parent.uniqueid);
        assert_ne!(me.uniqueid, parent.uniqueid);
        assert_eq!(
            me.ppid,
            rustix::process::getppid().unwrap().as_raw_nonzero().get() as u32
        );
        assert_eq!(me.uid, rustix::process::geteuid().as_raw());
        // The pidversion is the audit token's: through a socket pair, this process's own.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let token = peer_token(std::os::fd::AsFd::as_fd(&a)).unwrap();
        drop(b);
        assert_eq!(token.pid(), std::process::id());
        assert_eq!(token.pidversion(), me.generation);
        assert_eq!(token.euid(), me.uid);
        assert_eq!(token.egid(), rustix::process::getegid().as_raw());
        // launchd: the root of every chain.
        let launchd = proc_info(1).unwrap();
        assert_eq!(launchd.ppid, 0);
        assert_eq!(proc_path(1).unwrap(), PathBuf::from("/sbin/launchd"));
    }

    #[test]
    fn the_executable_is_the_kernel_s_path() {
        let me = proc_path(std::process::id()).unwrap();
        assert_eq!(
            me.canonicalize().unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }

    #[test]
    fn an_ended_process_is_not_found() {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        // Reaped: the pid names nothing (macOS hands pids out in order, never at once again).
        let error = proc_info(pid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        let error = proc_path(pid).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH), "{error}");
    }
}
