//! The capability drop, in a test binary of its own (it changes the process): whatever this
//! process starts with (all of them as root in a container, none as a CI user), once dropped
//! it holds none, and can't take `CAP_SYS_PTRACE` back.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use writ_platform_linux::caps;

#[test]
fn a_dropped_capability_is_gone_for_good() {
    caps::drop_all().unwrap();
    assert!(!caps::holds_any().unwrap());
    assert!(!caps::passes_ptrace_on().unwrap());
    // Keeping one it no longer holds is refused by the kernel (EPERM).
    assert_eq!(
        caps::keep_ptrace_only().unwrap_err().raw_os_error(),
        Some(rustix::io::Errno::PERM.raw_os_error())
    );
    assert!(!caps::holds_any().unwrap());
    // Dropping again is harmless.
    caps::drop_all().unwrap();
}
