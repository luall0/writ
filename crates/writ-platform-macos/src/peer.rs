//! [`audit_token_peer`]: what the kernel says about a Unix socket's peer on macOS, from its
//! audit token: its user and group, its pid and the pid's generation (pidversion), all as
//! recorded at connect, so a pid reused since can't be taken for the caller.

use std::os::fd::AsFd as _;

use tokio::net::UnixStream;
use writ_platform::PeerInfo;

use crate::sys;

/// The peer of `stream`, from its audit token (`LOCAL_PEERTOKEN`). A
/// `writ_platform::transport::unix::PeerReader`.
pub fn audit_token_peer(stream: &UnixStream) -> std::io::Result<PeerInfo> {
    let token = sys::process::peer_token(stream.as_fd())?;
    Ok(PeerInfo::Unix {
        uid: token.euid(),
        gid: token.egid(),
        pid: Some(token.pid()),
        generation: Some(u64::from(token.pidversion())),
    })
}
