//! The process reader's seccomp filter, with real processes: each test re-runs this test
//! binary as a child (`child_side`, with `WRIT_SECCOMP_CHILD` naming what it does) that
//! confines one thread of its own, since a filter can't be taken off. Confined, the reader
//! still answers; an `open` (so `/proc/<pid>/mem`), an `execve` or a signal kills the process
//! (`SIGSYS`).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, Stdio};

use writ_platform_linux::helper::{self, Helper};
use writ_platform_linux::read::{Direct, Host, ReadLinks, ReadProcess};

const CHILD: &str = "WRIT_SECCOMP_CHILD";

/// This binary again, running `child_side` alone with `CHILD` set to `mode`.
fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_side", "--nocapture", "--test-threads=1"])
        .env(CHILD, mode)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

/// The child's side: nothing unless a test below runs this binary as its child. Each mode
/// confines a thread of its own (the filter is per thread; the harness's own are left alone).
#[test]
fn child_side() {
    let Ok(mode) = std::env::var(CHILD) else {
        return;
    };
    let confined = std::thread::spawn(move || match mode.as_str() {
        "serve" => {
            use std::os::fd::AsFd as _;
            let stdin = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
            helper::serve_confined(UnixStream::from(stdin), &Direct::new(Host::Myself)).unwrap();
        }
        "readlink" => {
            helper::confine().unwrap();
            std::fs::read_link("/proc/self/exe").unwrap();
        }
        "open" => {
            helper::confine().unwrap();
            let _ = std::fs::read("/proc/self/stat");
        }
        "exec" => {
            helper::confine().unwrap();
            let _ = Command::new("/bin/true").status();
        }
        "signal" => {
            helper::confine().unwrap();
            let _ = rustix::process::kill_process(
                rustix::process::getpid(),
                rustix::process::Signal::CONT,
            );
        }
        other => panic!("no such mode {other}"),
    });
    confined.join().unwrap();
}

fn finish(mut child: Child) -> std::process::ExitStatus {
    child.wait().unwrap()
}

#[test]
fn a_confined_reader_still_reads_links_and_ends_cleanly() {
    let (mine, theirs) = UnixStream::pair().unwrap();
    let served = child("serve")
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .spawn()
        .unwrap();
    let reader = Helper::over(mine, helper::ANSWER_DEADLINE).unwrap();
    let direct = Direct::new(Host::Myself);
    let me = std::process::id();
    for _ in 0..3 {
        assert_eq!(reader.links(me).unwrap(), direct.links(me).unwrap());
        assert_eq!(reader.read(me).unwrap(), direct.read(me).unwrap());
    }
    assert_eq!(reader.host().unwrap(), direct.host().unwrap());
    drop(reader);
    let status = finish(served);
    assert!(status.success(), "{status:?}");
    // readlink alone, then the thread's end and the process's exit: allowed.
    let status = child("readlink").stdin(Stdio::null()).status().unwrap();
    assert!(status.success(), "{status:?}");
}

#[test]
fn anything_else_kills_the_confined_reader() {
    for mode in ["open", "exec", "signal"] {
        let status = child(mode).stdin(Stdio::null()).status().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc_sigsys()),
            "{mode}: {status:?} (killed by SIGSYS expected)"
        );
    }
}

/// `SIGSYS`'s number, from rustix.
fn libc_sigsys() -> i32 {
    rustix::process::Signal::SYS.as_raw()
}
