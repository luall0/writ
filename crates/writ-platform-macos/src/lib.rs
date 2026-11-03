//! macOS-only implementations of the platform interfaces (docs/architecture/platform.md).
//! On another OS this crate is empty: `writd/src/platform.rs` picks it on macOS only.
//!
//! | Trait | Implementation |
//! |---|---|
//! | `ProcessHardening` | [`hardening::Hardening`] |
//!
//! The calls `rustix` has no wrapper for are in [`sys`], the crate's one `unsafe` module.

#![cfg(target_os = "macos")]

pub mod hardening;
// The crate's only unsafe code: two system calls rustix doesn't wrap, each with its SAFETY.
#[allow(unsafe_code)]
mod sys;
