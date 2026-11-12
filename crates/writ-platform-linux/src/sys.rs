//! The calls `rustix` has no wrapper for: `getsockopt(SO_PEERPIDFD)` (Linux 6.5), the pidfd
//! the kernel took of a Unix socket's peer when it connected, and the process reader's seccomp
//! filter (`prctl(PR_SET_SECCOMP)`).

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

// ----- The process reader's seccomp filter -----

/// The architecture a filter checks (linux/audit.h: the ELF machine with `__AUDIT_ARCH_64BIT`
/// and `__AUDIT_ARCH_LE`): a call made through another ABI is refused, whatever its number.
#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xC000_00B7;

/// x32 system calls (the x86_64 kernel's other ABI) carry this bit in their number.
#[cfg(target_arch = "x86_64")]
const X32_BIT: u32 = 0x4000_0000;

/// What the process reader does once confined: its socket read and written (and its stderr),
/// `readlink`, its
/// memory managed (the allocator), a signal frame returned from, and its exit. No `open`
/// (so no `/proc/<pid>/mem`), no `ptrace`, `pidfd_getfd`, `process_vm_*`, `kill`, `execve`.
#[cfg(target_arch = "x86_64")]
const ALLOWED: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    // A socket's, through std: `send(MSG_NOSIGNAL)` and `recv`.
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_close,
    // On its own descriptors only (std checks one is open before it closes it).
    libc::SYS_fcntl,
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_futex,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_exit,
    libc::SYS_exit_group,
];
#[cfg(target_arch = "aarch64")]
const ALLOWED: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    // A socket's, through std: `send(MSG_NOSIGNAL)` and `recv`.
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_readlinkat,
    libc::SYS_close,
    // On its own descriptors only (std checks one is open before it closes it).
    libc::SYS_fcntl,
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_futex,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// One BPF instruction.
fn instruction(code: u32, k: u32, jt: u8, jf: u8) -> std::io::Result<libc::sock_filter> {
    Ok(libc::sock_filter {
        code: u16::try_from(code).map_err(|_| std::io::Error::other("a BPF code past 16 bits"))?,
        jt,
        jf,
        k,
    })
}

/// The filter: the architecture checked, then each allowed number; anything else kills the
/// whole process (`SECCOMP_RET_KILL_PROCESS`).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn program() -> std::io::Result<Vec<libc::sock_filter>> {
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let equal = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    let ret = libc::BPF_RET | libc::BPF_K;
    let kill = instruction(ret, libc::SECCOMP_RET_KILL_PROCESS, 0, 0)?;
    let allow = instruction(ret, libc::SECCOMP_RET_ALLOW, 0, 0)?;
    // `struct seccomp_data`: the number at offset 0, the architecture at 4.
    let mut filter = vec![
        instruction(load, 4, 0, 0)?,
        instruction(equal, ARCH, 1, 0)?,
        kill,
        instruction(load, 0, 0, 0)?,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        let at_least = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
        filter.push(instruction(at_least, X32_BIT, 0, 1)?);
        filter.push(kill);
    }
    for number in ALLOWED {
        let number = u32::try_from(*number)
            .map_err(|_| std::io::Error::other("a system call number past 32 bits"))?;
        filter.push(instruction(equal, number, 0, 1)?);
        filter.push(allow);
    }
    filter.push(kill);
    Ok(filter)
}

/// Confines the calling thread, and every thread and process it starts after, to [`ALLOWED`]
/// for good (the process reader is one thread). Sets `no_new_privs` first, which a filter
/// needs without `CAP_SYS_ADMIN`.
pub fn confine() -> std::io::Result<()> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(std::io::Error::other(
        "the process reader's seccomp filter knows x86_64 and aarch64 only",
    ));
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        rustix::thread::set_no_new_privs(true)?;
        let mut filter = program()?;
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len())
                .map_err(|_| std::io::Error::other("a filter of more than 65535 instructions"))?,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `prog` points to `filter`, `len` instructions long, both alive for the call
        // (the kernel copies the program before it returns); PR_SET_SECCOMP takes the mode and
        // a pointer to a `sock_fprog`, as passed.
        let status = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const prog,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
