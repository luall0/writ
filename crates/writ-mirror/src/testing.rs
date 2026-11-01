//! Test support (feature `testing`): mirrors for tests that need a gateway but no upstream.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::known_hosts::PinnedHosts;
use crate::{MirrorConfig, Mirrors, Result};

/// A pin for a host nothing reaches: the pinned set can't be empty.
const UNREACHABLE_PIN: &str = "unreachable.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";

/// Mirrors of no repo at all, in `dir`: every repo is unknown to them.
pub async fn no_repos(dir: &Path) -> Result<Mirrors> {
    let signer = writ_signer::software::SoftwareSigner::new(Vec::new())
        .map_err(|e| crate::MirrorError::Config(e.to_string()))?;
    Mirrors::open(
        MirrorConfig {
            root: dir.join("repos"),
            run_dir: dir.join("mirror"),
            relay: PathBuf::from("/usr/bin/false"),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN)?,
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 1 << 20,
        },
        &BTreeMap::new(),
        Arc::new(signer),
    )
    .await
}
