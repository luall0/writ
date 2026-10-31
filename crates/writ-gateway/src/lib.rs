//! The SSH gateway: the single entry point for agents. It authenticates daemon-issued
//! session certificates and serves git fetch/push and commit signing.
//!
//! M0 spike: the policy is a fixed list of protected refs and the signing key is held in
//! memory. Leases, the policy engine and the `Signer` interface replace both from M1–M3.

mod command;
mod handler;
pub mod hook;
mod process;

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use russh::server::Server as _;
use tokio::net::{TcpListener, UnixListener};
use writ_crypto::ssh_key::{Fingerprint, PrivateKey};

pub use command::Command;

/// Errors from the gateway.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What the gateway needs to run.
pub struct GatewayConfig {
    /// The gateway's SSH host key.
    pub host_key: PrivateKey,
    /// Certificate authorities whose user certificates are accepted.
    pub authorities: Vec<Fingerprint>,
    /// Directory holding one bare repository per registered repo (`<name>.git`).
    pub repos_root: PathBuf,
    /// Key used for the `writ-sign` command (M0: in memory; the `Signer` interface from M3).
    pub signing_key: PrivateKey,
    /// Program git's pre-receive hook runs, as `<program> hook pre-receive`.
    pub hook_program: PathBuf,
    /// Private directory for the gateway's own files (hooks, the hook socket).
    pub state_dir: PathBuf,
    /// Refs no push may update (`refs/heads/main`, or a prefix pattern `refs/tags/*`).
    pub protected_refs: Vec<String>,
}

/// A running gateway, shared by every connection.
#[derive(Clone)]
pub struct Gateway {
    shared: Arc<Shared>,
}

struct Shared {
    config: GatewayConfig,
    ssh: Arc<russh::server::Config>,
    revoked: RwLock<HashSet<u64>>,
    /// Pushes in progress, by the token handed to their pre-receive hook.
    pushes: Mutex<HashMap<String, hook::PushContext>>,
    hooks_dir: PathBuf,
    hook_socket: PathBuf,
}

impl Gateway {
    /// Prepares the state directory and starts the hook server.
    pub async fn start(config: GatewayConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.state_dir)?;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
        let hooks_dir = config.state_dir.join("hooks");
        write_hook_script(&hooks_dir, &config.hook_program)?;
        let hook_socket = config.state_dir.join("hook.sock");
        // sockaddr_un holds 104 bytes on macOS (108 on Linux), terminator included.
        let length = hook_socket.as_os_str().len();
        if length > 103 {
            return Err(Error::Config(format!(
                "hook socket path {} is {length} bytes, more than a Unix socket allows (103): \
                 use a shorter state directory",
                hook_socket.display()
            )));
        }
        if hook_socket.exists() {
            std::fs::remove_file(&hook_socket)?;
        }
        let hook_listener = UnixListener::bind(&hook_socket)?;

        let ssh = Arc::new(russh::server::Config {
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            keys: vec![config.host_key.clone()],
            auth_rejection_time: Duration::from_millis(300),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(3600)),
            ..Default::default()
        });
        let gateway = Self {
            shared: Arc::new(Shared {
                config,
                ssh,
                revoked: RwLock::new(HashSet::new()),
                pushes: Mutex::new(HashMap::new()),
                hooks_dir,
                hook_socket,
            }),
        };
        tokio::spawn(hook::serve(gateway.clone(), hook_listener));
        Ok(gateway)
    }

    /// Refuses certificates with this serial from now on.
    pub fn revoke(&self, serial: u64) {
        if let Ok(mut revoked) = self.shared.revoked.write() {
            revoked.insert(serial);
        }
    }

    /// Serves SSH connections from a TCP listener until it fails.
    pub async fn serve_tcp(&self, listener: TcpListener) -> Result<()> {
        let mut server = handler::Server(self.clone());
        server
            .run_on_socket(self.shared.ssh.clone(), &listener)
            .await?;
        Ok(())
    }

    /// Serves SSH connections from a Unix socket: same protocol, another transport.
    pub async fn serve_unix(&self, listener: UnixListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let handler = handler::Connection::new(self.clone());
            let ssh = self.shared.ssh.clone();
            tokio::spawn(async move {
                match russh::server::run_stream(ssh, stream, handler).await {
                    Ok(session) => {
                        if let Err(e) = session.await {
                            eprintln!("writ gateway: session ended with an error: {e}");
                        }
                    }
                    Err(e) => eprintln!("writ gateway: connection failed: {e}"),
                }
            });
        }
    }

    fn is_revoked(&self, serial: u64) -> bool {
        // A poisoned lock fails closed.
        self.shared
            .revoked
            .read()
            .map(|r| r.contains(&serial))
            .unwrap_or(true)
    }

    fn revoked_snapshot(&self) -> Option<HashSet<u64>> {
        self.shared.revoked.read().ok().map(|r| r.clone())
    }
}

fn write_hook_script(hooks_dir: &Path, program: &Path) -> Result<()> {
    let program = program
        .to_str()
        .filter(|p| !p.contains('\''))
        .ok_or_else(|| Error::Config(format!("unusable hook program path {program:?}")))?;
    std::fs::create_dir_all(hooks_dir)?;
    let script = hooks_dir.join("pre-receive");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nexec '{program}' hook pre-receive\n"),
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
