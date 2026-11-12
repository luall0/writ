//! [`pidfd_peer`]: what the kernel says about a Unix socket's peer on Linux. Its user, group
//! and pid (`SO_PEERCRED`) and its pidfd (`SO_PEERPIDFD`, Linux 6.5), both taken at
//! `connect`; the generation is its start time, read while the pidfd shows it still running,
//! so a pid reused since the connect is never taken for the caller.

use std::os::fd::AsFd as _;

use tokio::net::UnixStream;
use writ_platform::PeerInfo;

use crate::procfs;
use crate::sys;

/// The peer of `stream`. A `writ_platform::transport::unix::PeerReader`.
pub fn pidfd_peer(stream: &UnixStream) -> std::io::Result<PeerInfo> {
    let cred = stream.peer_cred()?;
    let pid = cred
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| std::io::Error::other("the peer has no pid in this namespace"))?;
    let pidfd = sys::peer_pidfd(stream.as_fd())?;
    if procfs::pidfd_pid(&pidfd)? != Some(pid) {
        return Err(std::io::Error::other(format!(
            "the peer's pidfd doesn't name pid {pid}, its credentials' (it has ended?)"
        )));
    }
    let stat = procfs::stat(pid).map_err(|e| std::io::Error::other(e.to_string()))?;
    if !procfs::running(&pidfd)? {
        return Err(std::io::Error::other(format!(
            "the peer (pid {pid}) ended before it was read"
        )));
    }
    Ok(PeerInfo::Unix {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: Some(pid),
        generation: Some(stat.start),
    })
}
