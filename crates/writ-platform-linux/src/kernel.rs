//! What local mode needs of the kernel and of `/proc`, checked when the daemon starts, by
//! trying the calls (never from a version string): a missing one is a startup error naming
//! what is needed, never a caller left unchecked or a lease left unwatched.

use std::os::fd::AsFd as _;

use crate::{procfs, sys};

/// Pidfds (`pidfd_open`, Linux 5.3): the session watcher's.
pub fn check_pidfds() -> Result<(), String> {
    procfs::hold(std::process::id())
        .map(drop)
        .map_err(|e| format!("pidfds are needed (Linux 5.3 or later): {e}"))
}

/// A Unix socket peer's pidfd (`SO_PEERPIDFD`, Linux 6.5), pidfds, and a `/proc` showing
/// other users' processes (no `hidepid`): the process chain attestor's.
pub fn check_process_chain() -> Result<(), String> {
    check_pidfds()?;
    let (one, _other) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| format!("a socket pair to try SO_PEERPIDFD on: {e}"))?;
    sys::peer_pidfd(one.as_fd()).map(drop).map_err(|e| {
        format!("a Unix socket peer's pidfd is needed (SO_PEERPIDFD, Linux 6.5 or later): {e}")
    })?;
    match procfs::hidepid_here() {
        Ok(None) => Ok(()),
        Ok(Some(option)) => Err(format!(
            "/proc is mounted with {option}: the daemon can't see the processes of the users \
             it serves (mount it without hidepid)"
        )),
        Err(e) => Err(format!("/proc/self/mountinfo can't be read: {e}")),
    }
}
