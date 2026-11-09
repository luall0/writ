//! [`UnixTransport`]: a Unix socket, local mode's transport (portable Unix: macOS, Linux).
//!
//! Who may connect is decided by the socket's directory, made by the installer (on the Mac,
//! `_writd:_writ` `0750`): the daemon refuses a directory others could write (whoever can
//! write it can put their own socket in the daemon's place), makes the socket `0660`, and
//! replaces only a stale socket at its path, never anything else. What is known about the
//! peer is what the kernel says ([`PeerReader`]); turning it into facts is the attestor's job.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use super::{BoxFuture, Connection, PeerInfo, Transport};
use crate::{PlatformError, Result};

/// The longest socket path: `sockaddr_un` holds 104 bytes on macOS (108 on Linux), its
/// terminator included.
pub const MAX_SOCKET_PATH: usize = 103;

/// The socket's mode: its owner (the daemon) and its group (on the Mac, `_writ`).
pub const SOCKET_MODE: u32 = 0o660;

/// Reads what the kernel says about a connected peer. [`portable_peer`] gives its user,
/// group and pid; a platform with more gives its own (macOS: the peer's audit token, with
/// its pid's generation).
pub type PeerReader = fn(&UnixStream) -> std::io::Result<PeerInfo>;

/// The peer's user, group and pid, as the kernel gave them at connect (`getpeereid` and
/// `LOCAL_PEERPID` on macOS, `SO_PEERCRED` on Linux); no generation.
pub fn portable_peer(stream: &UnixStream) -> std::io::Result<PeerInfo> {
    let cred = stream.peer_cred()?;
    Ok(PeerInfo::Unix {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid().and_then(|pid| u32::try_from(pid).ok()),
        generation: None,
    })
}

/// A Unix socket listener.
pub struct UnixTransport {
    listener: UnixListener,
    path: PathBuf,
    /// The socket file made (device, inode): removed on drop if it is still that one.
    made: (u64, u64),
    peer: PeerReader,
}

impl std::fmt::Debug for UnixTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixTransport")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl UnixTransport {
    /// Listens on `path`: an absolute path of at most [`MAX_SOCKET_PATH`] bytes, in a
    /// directory owned by the daemon's user or root that neither group nor others can write.
    /// A socket already there (a daemon that stopped) is replaced; anything else is refused.
    /// The socket is made [`SOCKET_MODE`]. Needs a Tokio runtime.
    pub fn bind(path: &Path, peer: PeerReader) -> Result<Self> {
        let config =
            |why: String| PlatformError::Config(format!("unix socket {}: {why}", path.display()));
        if !path.is_absolute() {
            return Err(config("not an absolute path".to_owned()));
        }
        let length = path.as_os_str().len();
        if length > MAX_SOCKET_PATH {
            return Err(config(format!(
                "{length} bytes, more than a Unix socket allows ({MAX_SOCKET_PATH})"
            )));
        }
        let dir = path
            .parent()
            .ok_or_else(|| config("has no directory".to_owned()))?;
        check_dir(dir).map_err(config)?;
        match std::fs::symlink_metadata(path) {
            Ok(found) if found.file_type().is_socket() => std::fs::remove_file(path)
                .map_err(|e| config(format!("cannot remove the stale socket: {}", e.kind())))?,
            Ok(_) => {
                return Err(config(
                    "something that is not a socket is there; it is never replaced".to_owned(),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(config(format!("cannot look at it: {}", e.kind()))),
        }
        let listener = UnixListener::bind(path).map_err(|e| config(format!("cannot bind: {e}")))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|e| config(format!("cannot set its mode: {}", e.kind())))?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| config(format!("cannot look at it: {}", e.kind())))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            made: (metadata.dev(), metadata.ino()),
            peer,
        })
    }

    /// Where it listens.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A directory the socket may live in: a real directory (not a link), owned by the daemon's
/// user or root, that neither group nor others can write.
fn check_dir(dir: &Path) -> std::result::Result<(), String> {
    let metadata = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("its directory {}: {}", dir.display(), e.kind()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "its directory {} is not a directory (a link?)",
            dir.display()
        ));
    }
    let me = rustix::process::geteuid().as_raw();
    if metadata.uid() != me && metadata.uid() != 0 {
        return Err(format!(
            "its directory {} is owned by uid {}, neither the daemon's user (uid {me}) nor root",
            dir.display(),
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!(
            "its directory {} can be written by group or others (mode {:o}): whoever can \
             write it could put their own socket in the daemon's place; make it 0750 or \
             stricter",
            dir.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

impl Drop for UnixTransport {
    fn drop(&mut self) {
        // Only the socket this transport made: another daemon's, made since, stays.
        if let Ok(found) = std::fs::symlink_metadata(&self.path)
            && (found.dev(), found.ino()) == self.made
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Transport for UnixTransport {
    fn accept(&self) -> BoxFuture<'_, Result<Connection>> {
        Box::pin(async move {
            let listener = self.describe();
            loop {
                let (stream, _) =
                    super::retry::accept_retrying(&listener, || self.listener.accept()).await?;
                // A peer the kernel can't describe (gone already) is dropped, never served
                // without its facts.
                match (self.peer)(&stream) {
                    Ok(peer) => {
                        return Ok(Connection {
                            stream: Box::new(stream),
                            peer,
                        });
                    }
                    Err(e) => tracing::debug!(%listener, error = %e, "peer unreadable, dropped"),
                }
            }
        })
    }

    fn describe(&self) -> String {
        format!("unix {}", self.path.display())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A private directory for sockets (short: socket paths are bounded), and the error of a
    /// refused bind.
    fn dir() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("wu")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        dir
    }

    fn refused(path: &Path) -> String {
        match UnixTransport::bind(path, portable_peer) {
            Err(PlatformError::Config(message)) => message,
            Err(other) => panic!("expected a Config error, got {other:?}"),
            Ok(_) => panic!("{} was bound", path.display()),
        }
    }

    #[tokio::test]
    async fn the_socket_is_0660_and_goes_with_the_transport() {
        let dir = dir();
        let path = dir.path().join("a.sock");
        let transport = UnixTransport::bind(&path, portable_peer).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);
        assert_eq!(transport.describe(), format!("unix {}", path.display()));
        drop(transport);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_stale_socket_is_replaced_and_anything_else_refused() {
        let dir = dir();
        let path = dir.path().join("a.sock");
        // A daemon that ended without removing its socket.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let transport = UnixTransport::bind(&path, portable_peer).unwrap();
        drop(transport);

        std::fs::write(&path, "a file").unwrap();
        let message = refused(&path);
        assert!(
            message.ends_with("something that is not a socket is there; it is never replaced"),
            "{message}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a file");

        let link = dir.path().join("l.sock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let message = refused(&link);
        assert!(message.ends_with("it is never replaced"), "{message}");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[tokio::test]
    async fn a_socket_made_since_by_someone_else_is_left_on_drop() {
        let dir = dir();
        let path = dir.path().join("a.sock");
        let transport = UnixTransport::bind(&path, portable_peer).unwrap();
        std::fs::remove_file(&path).unwrap();
        let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(transport);
        assert!(path.exists());
        drop(other);
    }

    #[tokio::test]
    async fn a_path_or_directory_it_cannot_trust_is_refused() {
        let message = refused(Path::new("relative.sock"));
        assert!(message.ends_with("not an absolute path"), "{message}");

        let dir = dir();
        let long = dir.path().join("x".repeat(MAX_SOCKET_PATH));
        let message = refused(&long);
        assert!(
            message.contains("more than a Unix socket allows (103)"),
            "{message}"
        );
        // At the bound: taken.
        let base = dir.path().join("").as_os_str().len();
        let at = dir.path().join("y".repeat(MAX_SOCKET_PATH - base));
        assert_eq!(at.as_os_str().len(), MAX_SOCKET_PATH);
        drop(UnixTransport::bind(&at, portable_peer).unwrap());

        for (mode, shown) in [(0o770, "770"), (0o757, "757")] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let message = refused(&dir.path().join("a.sock"));
            assert!(
                message.contains(&format!("can be written by group or others (mode {shown})")),
                "{message}"
            );
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();

        let missing = dir.path().join("nowhere/a.sock");
        let message = refused(&missing);
        assert!(message.contains("its directory"), "{message}");

        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let message = refused(&link.join("a.sock"));
        assert!(
            message.contains("is not a directory (a link?)"),
            "{message}"
        );
    }
}
