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
//! - [`proxy`]: a SOCKS5 or HTTP CONNECT proxy in front of them, which alone resolves their name.
//! - [`clone`]: an agent's clone of `demo`, and plain `git` and `writ` run in it.
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
pub mod clone;
pub mod daemon;
pub mod gateway;
pub mod https_remote;
pub mod process;
pub mod proxy;
pub mod remote;
pub mod telegram;
pub mod terminal;
pub mod tools;

use std::path::Path;
use std::process::Output;

pub use writ_platform::testing::{WAIT_LIMIT, eventually};

/// The host name a Unix socket endpoint is pinned under in `known_hosts` (`writ`'s own).
pub const LOCAL_HOST_ALIAS: &str = "writ-local";

/// Writes a file only its owner can read (0600), like a key or a token.
pub fn write_secret(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Every file under `dir` (followed down its directories, never through a link), by its path
/// relative to `dir`, with its bytes: what a test compares to say nothing in it changed.
pub fn files_under(dir: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn walk(
        root: &Path,
        dir: &Path,
        files: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if kind.is_dir() {
                files.insert(relative, b"(a directory)".to_vec());
                walk(root, &path, files);
            } else if kind.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                files.insert(relative, target.into_os_string().into_encoded_bytes());
            } else {
                files.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut files = std::collections::BTreeMap::new();
    walk(dir, dir, &mut files);
    files
}

/// The paths whose bytes differ between two [`files_under`], or that only one of them has.
pub fn changed_files(
    before: &std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    after: &std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
) -> Vec<std::path::PathBuf> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
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
