//! A throwaway `ssh-agent`: what the approver's agent (Secretive) is in production. Keys are
//! generated for the test; the user's own agent is never used.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use tempfile::TempDir;
use writ_crypto::ssh_key::{LineEnding, PrivateKey};

use crate::{eventually, write_secret};

/// A running `ssh-agent`, killed on drop.
pub struct TestAgent {
    child: Child,
    pub socket: PathBuf,
    dir: TempDir,
}

impl TestAgent {
    pub fn start() -> Self {
        crate::tools::require();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        // Built before waiting, so a timeout still stops the agent (on drop).
        let agent = Self { child, socket, dir };
        eventually("ssh-agent's socket", || agent.socket.exists());
        agent
    }

    /// Adds a key; its private file is deleted right after.
    pub fn add(&self, key: &PrivateKey) {
        let path = self.dir.path().join("key");
        write_secret(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes());
        let status = Command::new("ssh-add")
            .arg("-q")
            .arg(&path)
            .env("SSH_AUTH_SOCK", &self.socket)
            .status()
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(status.success(), "ssh-add failed");
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
