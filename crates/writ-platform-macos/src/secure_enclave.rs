//! The Secure Enclave backend, `se-cryptokit` (docs/architecture/macos-secure-enclave.md): a
//! CryptoKit Secure Enclave key (P-256) per key, its blob sealed in the daemon's keystore,
//! used through `writ-se`, the Swift helper in `swift/writ-se.swift` (CryptoKit has no C or
//! Rust API, and crashes its process on a corrupted blob). `writd/src/platform.rs` makes the
//! `Signer` from `writ_signer::helper` with what is here.

use std::time::Duration;

/// The backend's name in the policy (`keys.<id>.backend`).
pub const BACKEND: &str = "se-cryptokit";

/// The helper's file name, beside `writd` by default (`signers.se_cryptokit.helper`).
pub const HELPER: &str = "writ-se";

/// How long one request to the helper may take: a signature takes 8-45 ms, the first ones
/// after a boot up to 420 ms (M0).
pub const DEADLINE: Duration = Duration::from_secs(5);

/// The helper this build compiled (`build.rs`), for the tests.
pub const BUILT_HELPER: &str = env!("WRIT_SE_HELPER");
