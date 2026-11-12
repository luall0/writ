//! What `/proc` and a pidfd say about one process, read without any capability: its `stat`
//! (world-readable), and through the ptrace read check (`CAP_SYS_PTRACE`, or the same
//! user), its executable and its namespaces. Every read is bounded.

use std::io::Read as _;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, pidfd_open};

/// The most bytes read from a `/proc` text file (`stat`, `fdinfo`, `mountinfo`'s lines are
/// read whole too): `stat` is a few hundred bytes, `comm` at most 16 of them.
const MAX_PROC_TEXT: u64 = 64 * 1024;

/// The longest executable path the kernel gives (`PATH_MAX`).
pub const MAX_EXECUTABLE_BYTES: usize = 4096;

/// What `/proc/<pid>/exe` adds to a path whose file was deleted.
const DELETED: &str = " (deleted)";

/// Why a process couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// It has ended (or ended while read): a parent gone ends a chain there.
    Gone(String),
    /// It runs, but `/proc` won't say (a permission, `hidepid`, a malformed file): refused.
    Unreadable(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone(why) | Self::Unreadable(why) => f.write_str(why),
        }
    }
}

/// The error of reading `what` of `pid`: gone when the kernel says it is, unreadable otherwise.
pub fn read_error(pid: u32, what: &str, e: &std::io::Error) -> ReadError {
    let why = format!("pid {pid}: {what}: {e}");
    match e.raw_os_error().map(Errno::from_raw_os_error) {
        Some(Errno::NOENT | Errno::SRCH) => ReadError::Gone(why),
        _ => ReadError::Unreadable(why),
    }
}

/// A process's pid and mount namespaces, as their inode numbers (`pid:[4026531836]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespaces {
    pub pid: u64,
    pub mnt: u64,
}

/// What `/proc/<pid>/stat` says that the chain uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// The parent (0 for pid 1 and the kernel's threads).
    pub ppid: u32,
    /// The start time, in clock ticks after boot: with the pid, it names one process.
    pub start: u64,
}

/// Reads at most [`MAX_PROC_TEXT`] bytes of a text file.
fn read_text(path: &Path) -> std::io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_PROC_TEXT)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// Parses a `stat` line: `pid (comm) state ppid … starttime …`. `comm` is the process's own
/// choice (it may hold spaces and parentheses), so the fields are read after the last `)`.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let (_, after) = text.rsplit_once(')')?;
    let mut fields = after.split_ascii_whitespace();
    // Field 3 is the state, 4 the parent, 22 the start time.
    let _state = fields.next()?;
    let ppid = fields.next()?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some(Stat { ppid, start })
}

/// `/proc/<pid>/stat`.
pub fn stat(pid: u32) -> Result<Stat, ReadError> {
    let text = read_text(&PathBuf::from(format!("/proc/{pid}/stat")))
        .map_err(|e| read_error(pid, "stat", &e))?;
    parse_stat(&text).ok_or_else(|| ReadError::Unreadable(format!("pid {pid}: stat: malformed")))
}

/// `/proc/<pid>/exe`, and whether its file was deleted (the kernel's ` (deleted)` taken off).
pub fn executable(pid: u32) -> Result<(PathBuf, bool), ReadError> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|e| read_error(pid, "its executable", &e))?;
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() > MAX_EXECUTABLE_BYTES {
        return Err(ReadError::Unreadable(format!(
            "pid {pid}: its executable's path is longer than {MAX_EXECUTABLE_BYTES} bytes"
        )));
    }
    Ok(match path.to_str().and_then(|p| p.strip_suffix(DELETED)) {
        Some(kept) => (PathBuf::from(kept), true),
        None => (path, false),
    })
}

/// Parses a namespace link (`pid:[4026531836]`) of the kind `kind`.
pub fn parse_namespace(kind: &str, link: &str) -> Option<u64> {
    link.strip_prefix(kind)?
        .strip_prefix(":[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn namespace(pid: &str, kind: &str) -> std::io::Result<u64> {
    let link = std::fs::read_link(format!("/proc/{pid}/ns/{kind}"))?;
    link.to_str()
        .and_then(|text| parse_namespace(kind, text))
        .ok_or_else(|| std::io::Error::other(format!("ns/{kind}: not a namespace link")))
}

/// `/proc/<pid>/ns/pid` and `ns/mnt` (`pid` may be `self`).
pub fn namespaces_of(pid: &str) -> std::io::Result<Namespaces> {
    Ok(Namespaces {
        pid: namespace(pid, "pid")?,
        mnt: namespace(pid, "mnt")?,
    })
}

/// A pidfd of whichever process runs as `pid` now.
pub fn hold(pid: u32) -> Result<OwnedFd, ReadError> {
    let raw = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| ReadError::Gone(format!("pid {pid}: no such pid")))?;
    pidfd_open(raw, PidfdFlags::empty())
        .map_err(|e| read_error(pid, "its pidfd", &std::io::Error::from(e)))
}

/// Whether the process a pidfd names still runs: a pidfd turns readable when it exits, and
/// until it is reaped its pid can't be reused, so what was read of the pid before a `true`
/// was that process.
pub fn running(pidfd: impl AsFd) -> std::io::Result<bool> {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut fds, Some(&zero))?;
    Ok(fds.first().is_some_and(|fd| fd.revents().is_empty()))
}

/// The pid a pidfd of this process names, from its `fdinfo` (`Pid:`; 0 or -1 when it isn't
/// in this namespace or has been reaped).
pub fn pidfd_pid(pidfd: impl AsFd) -> std::io::Result<Option<u32>> {
    use std::os::fd::AsRawFd as _;
    let text = read_text(&PathBuf::from(format!(
        "/proc/self/fdinfo/{}",
        pidfd.as_fd().as_raw_fd()
    )))?;
    let pid = text
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<i64>().ok())
        .ok_or_else(|| std::io::Error::other("a pidfd's fdinfo without its Pid line"))?;
    Ok(u32::try_from(pid).ok().filter(|pid| *pid > 0))
}

/// The `hidepid` option of the `/proc` this process sees, from a `mountinfo`: `None` when
/// other users' processes are visible (no option, `0`, `off`), else the option as written.
pub fn hidepid(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        // `<id> <parent> <dev> <root> <mount point> <options> [<tags>…] - <type> <source> <super options>`
        let (before, after) = line.split_once(" - ")?;
        let point = before.split(' ').nth(4)?;
        let mut rest = after.split(' ');
        let kind = rest.next()?;
        let options = rest.nth(1)?;
        if point != "/proc" || kind != "proc" {
            return None;
        }
        options
            .split(',')
            .find_map(|option| option.strip_prefix("hidepid="))
            .filter(|value| !matches!(*value, "0" | "off"))
            .map(|value| format!("hidepid={value}"))
    })
}

/// [`hidepid`] of this process's own `/proc`.
pub fn hidepid_here() -> std::io::Result<Option<String>> {
    Ok(hidepid(&read_text(Path::new("/proc/self/mountinfo"))?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn stat_is_read_after_the_process_s_own_name() {
        let line = |comm: &str| {
            format!(
                "4242 ({comm}) S 4100 4242 4100 34816 4242 4194304 120 0 0 0 1 0 0 0 20 0 1 0 \
                 987654 9076736 401 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
            )
        };
        let expected = Some(Stat {
            ppid: 4100,
            start: 987_654,
        });
        assert_eq!(parse_stat(&line("sleep")), expected);
        // A name that looks like fields, with spaces and parentheses.
        assert_eq!(parse_stat(&line("x) S 1 1 1 (y")), expected);
        assert_eq!(parse_stat(&line(") 7 8")), expected);
        for broken in [
            "",
            "4242 sleep S 4100",
            "4242 (sleep) S",
            "4242 (sleep) S 4100 1 2 3",
            "4242 (sleep) S -1 4242 4100 34816 4242 4194304 120 0 0 0 1 0 0 0 20 0 1 0 98",
            "4242 (sleep) S 4100 4242 4100 34816 4242 4194304 120 0 0 0 1 0 0 0 20 0 1 0 x",
        ] {
            assert_eq!(parse_stat(broken), None, "{broken:?}");
        }
    }

    #[test]
    fn a_namespace_link_is_its_kind_and_inode() {
        assert_eq!(
            parse_namespace("pid", "pid:[4026531836]"),
            Some(4_026_531_836)
        );
        assert_eq!(
            parse_namespace("mnt", "mnt:[4026532201]"),
            Some(4_026_532_201)
        );
        for broken in [
            "mnt:[4026531836]",
            "pid:4026531836",
            "pid:[x]",
            "pid:[1",
            "pid:[]",
        ] {
            assert_eq!(parse_namespace("pid", broken), None, "{broken:?}");
        }
    }

    #[test]
    fn hidepid_is_found_on_proc_only() {
        let proc = |options: &str| {
            format!(
                "22 1 0:5 / /sys rw,nosuid shared:7 - sysfs sysfs rw,hidepid=2\n\
                 25 1 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc {options}\n"
            )
        };
        assert_eq!(hidepid(&proc("rw")), None);
        assert_eq!(hidepid(&proc("rw,hidepid=0")), None);
        assert_eq!(hidepid(&proc("rw,hidepid=off")), None);
        assert_eq!(hidepid(&proc("rw,hidepid=2")), Some("hidepid=2".to_owned()));
        assert_eq!(
            hidepid(&proc("rw,hidepid=invisible,gid=10")),
            Some("hidepid=invisible".to_owned())
        );
        assert_eq!(
            hidepid(&proc("rw,hidepid=ptraceable")),
            Some("hidepid=ptraceable".to_owned())
        );
        assert_eq!(hidepid(""), None);
    }

    #[test]
    fn this_process_reads_as_itself() {
        let me = std::process::id();
        let stat = stat(me).unwrap();
        assert_eq!(
            stat.ppid,
            rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get().unsigned_abs())
        );
        let (exe, deleted) = executable(me).unwrap();
        assert!(!deleted);
        assert_eq!(exe, std::env::current_exe().unwrap());
        let fd = hold(me).unwrap();
        assert!(running(&fd).unwrap());
        assert_eq!(pidfd_pid(&fd).unwrap(), Some(me));
        assert_eq!(
            namespaces_of("self").unwrap(),
            namespaces_of(&me.to_string()).unwrap()
        );
    }

    #[test]
    fn a_process_that_ended_reads_as_gone() {
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();
        let fd = hold(pid).unwrap();
        assert!(running(&fd).unwrap() || child.try_wait().unwrap().is_some());
        child.wait().unwrap();
        // The pidfd still names that process, whoever has its pid now.
        assert!(!running(&fd).unwrap());
    }

    #[test]
    fn the_kernel_s_errors_say_gone_or_unreadable() {
        let error = |errno: Errno| std::io::Error::from_raw_os_error(errno.raw_os_error());
        assert!(matches!(
            read_error(7, "stat", &error(Errno::NOENT)),
            ReadError::Gone(_)
        ));
        assert!(matches!(
            read_error(7, "stat", &error(Errno::SRCH)),
            ReadError::Gone(_)
        ));
        for errno in [Errno::ACCESS, Errno::PERM, Errno::IO] {
            assert!(matches!(
                read_error(7, "its executable", &error(errno)),
                ReadError::Unreadable(why) if why.starts_with("pid 7: its executable: ")
            ));
        }
        assert!(matches!(
            read_error(7, "stat", &std::io::Error::other("cut")),
            ReadError::Unreadable(_)
        ));
    }
}
