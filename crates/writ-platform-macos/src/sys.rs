//! The system calls `rustix` has no wrapper for, the crate's only `unsafe` code, each call
//! with its `SAFETY` comment:
//!
//! - [`debug`]: whether this process is traced (`proc_pidinfo`), `ptrace(PT_DENY_ATTACH)`;
//! - [`process`]: a socket peer's audit token (`LOCAL_PEERTOKEN`), a process's parent, unique
//!   id, pid generation and executable (`proc_pidinfo`, `proc_pidpath`);
//! - [`kqueue`]: a kqueue watching processes end (`EVFILT_PROC`, `NOTE_EXIT`);
//! - [`codesign`]: a running process's code signature (Security.framework).

pub mod codesign;
pub mod debug;
pub mod kqueue;
pub mod process;

pub use debug::{deny_attach, traced};
