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
            ca_certs: None,
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 1 << 20,
        },
        &BTreeMap::new(),
        Arc::new(signer),
        &BTreeMap::new(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relative_directories_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mirrors = no_repos(dir.path()).await;
        assert!(mirrors.is_ok(), "absolute: opened");
        let signer = writ_signer::software::SoftwareSigner::new(Vec::new()).unwrap();
        let mut config = MirrorConfig {
            root: PathBuf::from("repos"),
            run_dir: dir.path().join("mirror"),
            relay: PathBuf::from("/usr/bin/false"),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN).unwrap(),
            ca_certs: None,
            fresh_for: Duration::from_secs(1),
            timeout: Duration::from_secs(10),
            max_fetch_bytes: 1 << 20,
        };
        let signer: Arc<dyn writ_signer::Signer> = Arc::new(signer);
        let none = BTreeMap::new();
        let no_tokens = BTreeMap::new();
        let open = |config: MirrorConfig| Mirrors::open(config, &none, signer.clone(), &no_tokens);
        match open(config.clone()).await {
            Err(crate::MirrorError::Config(m)) => {
                assert!(m.contains("root repos must be an absolute path"), "{m}")
            }
            other => panic!("expected a configuration error, got {:?}", other.err()),
        }
        config.root = dir.path().join("repos");
        config.run_dir = PathBuf::from("mirror");
        match open(config).await {
            Err(crate::MirrorError::Config(m)) => {
                assert!(m.contains("run_dir mirror must be an absolute path"), "{m}")
            }
            other => panic!("expected a configuration error, got {:?}", other.err()),
        }
    }
}
