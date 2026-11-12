//! The one call `rustix` has no wrapper for: `getsockopt(SO_PEERPIDFD)` (Linux 6.5), the
//! pidfd the kernel took of a Unix socket's peer when it connected.

use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// The pidfd of the process that connected `socket` (or made the pair), as the kernel took it
/// at `connect`: it names that process whatever happened to its pid since.
pub fn peer_pidfd(socket: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    let option = libc::c_int::try_from(linux_raw_sys::net::SO_PEERPIDFD)
        .map_err(|_| std::io::Error::other("SO_PEERPIDFD doesn't fit an int"))?;
    let mut fd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| std::io::Error::other("the size of an int doesn't fit a socklen_t"))?;
    // SAFETY: `socket` is a live descriptor for the duration of the call; `fd` and `len` are
    // valid for writes, and `len` holds the size of the buffer `fd` points to, which is what
    // SO_PEERPIDFD writes (one int).
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw mut fd).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if fd < 0 || usize::try_from(len).ok() != Some(std::mem::size_of::<libc::c_int>()) {
        return Err(std::io::Error::other(
            "SO_PEERPIDFD gave no descriptor (the peer has gone?)",
        ));
    }
    // SAFETY: the kernel just made `fd` for this process (a new descriptor, close-on-exec),
    // owned by no one else: it is closed exactly once, by the `OwnedFd`.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
