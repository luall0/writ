//! Linux-only implementations of the platform interfaces (docs/architecture/platform.md).
//! On another OS this crate is empty: `writd/src/platform.rs` picks it on Linux only.
//!
//! | Trait | Implementation |
//! |---|---|
//! | `ProcessHardening` | [`hardening::Hardening`] |
//! | `CallerAttestor` | [`attest::ProcessChain`] |
//! | `SessionWatcher` | [`watch::PidfdWatcher`] |
//! | Unix socket peer (`PeerReader`) | [`peer::pidfd_peer`] |
//!
//! The attestor reads other users' processes through [`read::ReadProcess`]: the capped
//! helper ([`helper`], `writd proc-reader`, which alone keeps `CAP_SYS_PTRACE`: [`caps`]), or
//! `/proc` in this process ([`read::Direct`]). [`kernel`] checks at start what they need.
//! The calls `rustix` has no wrapper for (`SO_PEERPIDFD`, the process reader's seccomp
//! filter) are in `sys`, the crate's one `unsafe` module.

#![cfg(target_os = "linux")]

pub mod attest;
pub mod caps;
pub mod hardening;
pub mod helper;
pub mod kernel;
pub mod peer;
pub mod procfs;
pub mod read;
pub mod watch;
// The crate's only unsafe code: `getsockopt(SO_PEERPIDFD)` and `prctl(PR_SET_SECCOMP)`, each
// with its SAFETY.
#[allow(unsafe_code)]
mod sys;
