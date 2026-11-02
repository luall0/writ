//! The integration test harness: what every scenario in `tests/` needs to run the crates and
//! the binaries together, with the real local tools and nothing else.
//!
//! - [`tools`]: the `git` and OpenSSH versions the scenarios need, checked once.
//! - [`binaries`]: the workspace binaries (`writd`, `writ`, `writ-sign`), built by `make test`.
//! - [`agent`]: a throwaway `ssh-agent`, standing in for the approver's (Secretive).
//! - [`telegram`]: a fake Telegram Bot API that records what the daemon sends.
//! - [`process`]: waiting for a process, with a deadline.
//! - [`daemon`]: the real `writd` on a temporary configuration, and the `writ` CLI for it.
//! - [`gateway`]: the gateway in-process, driven by the real `git` and `ssh`.
//! - [`remote`]: a test remote (an SSH server serving git), standing in for GitHub or Forgejo.
//! - [`https_remote`]: the same repositories over HTTPS with a token (`git http-backend`).
//!
//! Scenarios never touch the user's `~/.ssh`, git configuration or ssh-agent: `HOME`,
//! `GIT_CONFIG_*` and `SSH_AUTH_SOCK` are always set to throwaway values.
//!
//! This crate only runs in tests, so it panics on any failure (with a message).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

pub mod agent;
pub mod binaries;
pub mod daemon;
pub mod gateway;
pub mod https_remote;
pub mod process;
pub mod remote;
pub mod telegram;
pub mod tools;

use std::path::Path;
use std::process::Output;

pub use writ_platform::testing::{WAIT_LIMIT, eventually};

/// Writes a file only its owner can read (0600), like a key or a token.
pub fn write_secret(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A command's stdout, as text.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A command's stderr, as text.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The audit log lines (JSONL) with this event and result.
pub fn audit_events(text: &str, event: &str, result: &str) -> Vec<serde_json::Value> {
    text.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|e| e["event"] == event && e["result"] == result)
        .collect()
}
