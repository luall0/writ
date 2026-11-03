//! Linux-only implementations of the platform interfaces (docs/architecture/platform.md).
//! On another OS this crate is empty: `writd/src/platform.rs` picks it on Linux only.
//!
//! | Trait | Implementation |
//! |---|---|
//! | `ProcessHardening` | [`hardening::Hardening`] |

#![cfg(target_os = "linux")]

pub mod hardening;
