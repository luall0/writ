//! The system calls `rustix` has no wrapper for, the crate's only `unsafe` code: whether this
//! process is traced (`proc_pidinfo`), and `ptrace(PT_DENY_ATTACH)`.

use std::io;

/// `PROC_FLAG_TRACED` in `pbi_flags` (`<sys/proc_info.h>`): the process is being traced.
const PROC_FLAG_TRACED: u32 = 0x2;

/// Whether this process is being traced (a debugger attached, or started under one).
pub fn traced() -> io::Result<bool> {
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let size_c = libc::c_int::try_from(size).map_err(|_| io::Error::other("proc_bsdinfo size"))?;
    // SAFETY: `proc_bsdinfo` is a plain C struct of integers and byte arrays, for which all
    // zero bits is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: the buffer is a valid, writable `proc_bsdinfo` of exactly `size_c` bytes, which
    // is what `PROC_PIDTBSDINFO` writes; the pid is this process's.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::c_int::try_from(std::process::id()).map_err(|_| io::Error::other("pid"))?,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::addr_of_mut!(info).cast::<libc::c_void>(),
            size_c,
        )
    };
    if written != size_c {
        return Err(io::Error::last_os_error());
    }
    Ok(info.pbi_flags & PROC_FLAG_TRACED != 0)
}

/// `ptrace(PT_DENY_ATTACH)`: no debugger attaches to this process from now on. Kills a
/// process already traced: check [`traced`] first.
pub fn deny_attach() -> io::Result<()> {
    // SAFETY: `PT_DENY_ATTACH` reads neither the pid (0: this process) nor the address (null)
    // nor the data (0); it only sets a flag on the calling process.
    let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
