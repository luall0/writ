//! macOS-only implementations of the platform interfaces (docs/architecture/platform.md).
//! On another OS this crate is empty: `writd/src/platform.rs` picks it on macOS only.
//!
//! | Trait | Implementation |
//! |---|---|
//! | `ProcessHardening` | [`hardening::Hardening`] |
//! | `CallerAttestor` | [`attest::ProcessChain`] |
//! | `SessionWatcher` | [`watch::KqueueWatcher`] |
//! | Unix socket peer (`PeerReader`) | [`peer::audit_token_peer`] |
//!
//! The calls `rustix` has no wrapper for are in [`sys`], the crate's one `unsafe` module.

#![cfg(target_os = "macos")]

pub mod attest;
pub mod hardening;
pub mod peer;
pub mod watch;
// The crate's only unsafe code: the calls rustix doesn't wrap, each with its SAFETY.
#[allow(unsafe_code)]
mod sys;
