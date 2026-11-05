//! Test support (feature `testing`): mirrors for tests that need a gateway but no upstream.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::known_hosts::PinnedHosts;
use crate::{MirrorConfig, Mirrors, Result};

/// A pin for a host nothing reaches: the pinned set can't be empty.
const UNREACHABLE_PIN: &str = "unreachable.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";

/// The `git` the tests run, by absolute path: the first in the test's `PATH` (the daemon
/// never looks it up; its `mirrors.git` is configured).
pub fn git() -> PathBuf {
    let found = std::process::Command::new("/bin/sh")
        .args(["-c", "command -v git"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    PathBuf::from(if found.starts_with('/') {
        found
    } else {
        "/usr/bin/git".to_owned()
    })
}

/// Mirrors of no repo at all, in `dir`: every repo is unknown to them.
pub async fn no_repos(dir: &Path) -> Result<Mirrors> {
    let signer = writ_signer::software::SoftwareSigner::empty();
    Mirrors::open(
        MirrorConfig {
            root: dir.join("repos"),
            run_dir: dir.join("mirror"),
            relay: PathBuf::from("/usr/bin/false"),
            git: git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN)?,
            ca_certs: None,
            fresh_for: Duration::from_secs(3600),
            timeout: Duration::from_secs(60),
            max_fetch_bytes: 1 << 20,
            scan_timeout: crate::scan::DEFAULT_HANDSHAKE_DEADLINE,
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
        let signer = writ_signer::software::SoftwareSigner::empty();
        let mut config = MirrorConfig {
            root: PathBuf::from("repos"),
            run_dir: dir.path().join("mirror"),
            relay: PathBuf::from("/usr/bin/false"),
            git: git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN).unwrap(),
            ca_certs: None,
            fresh_for: Duration::from_secs(1),
            timeout: Duration::from_secs(10),
            max_fetch_bytes: 1 << 20,
            scan_timeout: crate::scan::DEFAULT_HANDSHAKE_DEADLINE,
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

    #[tokio::test]
    async fn the_programs_run_are_executable_files_named_by_absolute_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        let signer: Arc<dyn writ_signer::Signer> =
            Arc::new(writ_signer::software::SoftwareSigner::empty());
        let config = MirrorConfig {
            root: dir.path().join("repos"),
            run_dir: dir.path().join("mirror"),
            relay: PathBuf::from("/usr/bin/false"),
            git: git(),
            ssh: PathBuf::from("/usr/bin/ssh"),
            pinned: PinnedHosts::parse(UNREACHABLE_PIN).unwrap(),
            ca_certs: None,
            fresh_for: Duration::from_secs(1),
            timeout: Duration::from_secs(10),
            max_fetch_bytes: 1 << 20,
            scan_timeout: crate::scan::DEFAULT_HANDSHAKE_DEADLINE,
        };
        let (none, no_tokens) = (BTreeMap::new(), BTreeMap::new());
        let open = |config: MirrorConfig| Mirrors::open(config, &none, signer.clone(), &no_tokens);
        assert!(open(config.clone()).await.is_ok(), "as configured: opened");
        let missing = dir.path().join("missing");
        for (what, path, why) in [
            ("git", PathBuf::from("git"), "must be an absolute path"),
            ("git", missing.clone(), "not found"),
            ("git", plain.clone(), "not an executable file"),
            ("git", dir.path().to_owned(), "not an executable file"),
            ("ssh", missing.clone(), "not found"),
            ("the relay", plain.clone(), "not an executable file"),
        ] {
            let mut bad = config.clone();
            match what {
                "git" => bad.git = path.clone(),
                "ssh" => bad.ssh = path.clone(),
                _ => bad.relay = path.clone(),
            }
            match open(bad).await {
                Err(crate::MirrorError::Config(m)) => {
                    let expected = format!("{what} {}: {why}", path.display());
                    assert_eq!(m, expected);
                }
                other => panic!(
                    "{what} {}: expected a refusal, got {:?}",
                    path.display(),
                    other.err()
                ),
            }
        }
    }
}
