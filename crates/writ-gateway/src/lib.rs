//! The SSH gateway: the single entry point to the daemon. Every transport carries the same
//! SSH protocol; each listener has a [`Role`]:
//!
//! - [`Role::Agents`]: user `git` with a session certificate issued for an active lease (git
//!   fetch/push, `writ-sign git`); user `writ` with a plain key, the session key of a ticket
//!   being submitted (`writ request`, `writ wait`).
//! - [`Role::Approvals`]: the approval API (`writ info`, `ls`, `show`, `approve`, `refuse`,
//!   `revoke`). Any key gets in: an approval is an SSHSIG checked by the approval service,
//!   never the connection itself. The same API is also served over HTTPS
//!   ([`Gateway::serve_https`], [`https`]).
//!
//! The gateway only sees the platform traits ([`Transport`], [`CallerAttestor`]): connections
//! come from a transport, what is known about the caller from an attestor. Leases, tickets
//! and the deny list are the approval service's ([`writ_approval::Service`]); when a lease
//! ends, the gateway drops its open sessions.
//!
//! Until M3 and M4, signing uses a key held in memory and pushes are only checked against the
//! repo's protected refs (the M0 spike), for any active lease that allows the operation and
//! names the repo.
//!
//! Every request the gateway turns away on its own is logged through
//! [`Service::gateway_denied`]; the lease decisions are logged by the service itself.

mod api;
mod channel;
mod command;
mod exec;
mod handler;
mod hook;
mod https;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::Disconnect;
use tokio::net::UnixListener;
use tokio::sync::broadcast::error::RecvError;
use writ_approval::{EventKind, GatewayDenial, Service};
use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::policy::{CertIdentity, Denial, DenyCode};
use writ_core::ticket::Operation;
use writ_crypto::ssh_key::{Fingerprint, HashAlg, PrivateKey};
use writ_platform::{CallerAttestor, Connection, PeerInfo, Transport};

pub use exec::MAX_SIGN_INPUT;
pub use hook::run_pre_receive;

pub use writ_proto::{CLIENT_USER, LEASE_USER};

/// Errors from the gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Platform(#[from] writ_platform::PlatformError),
    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, GatewayError>;

/// What a listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Agents: git, signing, ticket submission.
    Agents,
    /// The approver: the approval API.
    Approvals,
}

/// What the gateway needs to run.
pub struct GatewayConfig {
    /// The gateway's SSH host key (clients pin it).
    pub host_key: PrivateKey,
    /// Directory holding one bare repository per repo (`<name>.git`).
    pub repos_root: PathBuf,
    /// Key used for the `writ-sign` command (in memory until the `Signer` interface, M3).
    pub signing_key: PrivateKey,
    /// Program git's pre-receive hook runs, as `<program> hook pre-receive`.
    pub hook_program: PathBuf,
    /// Private directory for the gateway's own files (hooks, the hook socket).
    pub state_dir: PathBuf,
}

/// A running gateway, shared by every connection.
#[derive(Clone)]
pub struct Gateway {
    shared: Arc<Shared>,
}

struct Shared {
    config: GatewayConfig,
    service: Arc<Service>,
    authorities: Vec<Fingerprint>,
    ssh: Arc<russh::server::Config>,
    /// Pushes in progress, by the token handed to their pre-receive hook.
    pushes: Mutex<HashMap<String, hook::PushContext>>,
    /// Open sessions of lease holders, by certificate serial, then connection number.
    sessions: Mutex<HashMap<u64, HashMap<u64, russh::server::Handle>>>,
    next_connection: AtomicU64,
    hooks_dir: PathBuf,
    hook_socket: PathBuf,
}

impl Gateway {
    /// Prepares the state directory, starts the hook server and the task that drops the
    /// sessions of leases that end.
    pub async fn start(config: GatewayConfig, service: Arc<Service>) -> Result<Self> {
        writ_platform::fs::create_private_dir(&config.state_dir)?;
        let hooks_dir = config.state_dir.join("hooks");
        write_hook_script(&hooks_dir, &config.hook_program)?;
        let hook_socket = config.state_dir.join("hook.sock");
        // sockaddr_un holds 104 bytes on macOS (108 on Linux), terminator included.
        let length = hook_socket.as_os_str().len();
        if length > 103 {
            return Err(GatewayError::Config(format!(
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
        let authorities = vec![service.ca_public_key().fingerprint(HashAlg::Sha256)];
        let revocations = service.subscribe_revocations();
        let gateway = Self {
            shared: Arc::new(Shared {
                config,
                service,
                authorities,
                ssh,
                pushes: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                next_connection: AtomicU64::new(1),
                hooks_dir,
                hook_socket,
            }),
        };
        tokio::spawn(hook::serve(gateway.clone(), hook_listener));
        tokio::spawn(drop_revoked_sessions(gateway.clone(), revocations));
        Ok(gateway)
    }

    /// The approval service the gateway asks.
    pub fn service(&self) -> &Arc<Service> {
        &self.shared.service
    }

    /// [`Service::authorize`], off the async threads (it reads the store and syncs the audit
    /// log).
    async fn authorize(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        operation: Option<Operation>,
    ) -> std::result::Result<Lease, Denial> {
        let (service, cert, caller) = (self.service().clone(), cert.clone(), caller.clone());
        tokio::task::spawn_blocking(move || service.authorize(&cert, &caller, operation))
            .await
            .unwrap_or_else(|_| {
                Err(Denial {
                    code: DenyCode::Invalid,
                    reason: "internal error in the daemon".to_owned(),
                    hint: None,
                })
            })
    }

    /// Logs a request the gateway turned away on its own ([`Service::gateway_denied`]), off
    /// the async threads.
    async fn log_denial(&self, denial: GatewayDenial, caller: CallerFacts) {
        let service = self.service().clone();
        let _ = tokio::task::spawn_blocking(move || service.gateway_denied(&denial, &caller)).await;
    }

    /// Serves SSH connections from a transport, with what `attestor` says about each caller,
    /// until the transport fails. A caller the attestor can't attest is turned away.
    pub async fn serve(
        &self,
        transport: Arc<dyn Transport>,
        attestor: Arc<dyn CallerAttestor>,
        role: Role,
    ) -> Result<()> {
        loop {
            let (connection, facts) = self.accept_attested(&*transport, &*attestor).await?;
            let handler = handler::Connection::new(self.clone(), role, facts);
            let ssh = self.shared.ssh.clone();
            tokio::spawn(async move {
                match russh::server::run_stream(ssh, connection.stream, handler).await {
                    Ok(session) => {
                        if let Err(e) = session.await
                            && !client_went_away(&e)
                        {
                            tracing::warn!(error = %e, "session ended with an error");
                        }
                    }
                    Err(e) if client_went_away(&e) => {}
                    Err(e) => tracing::warn!(error = %e, "connection failed"),
                }
            });
        }
    }

    /// The next connection whose caller the attestor can attest, with its facts. Others are
    /// logged and dropped.
    async fn accept_attested(
        &self,
        transport: &dyn Transport,
        attestor: &dyn CallerAttestor,
    ) -> Result<(Connection, CallerFacts)> {
        loop {
            let connection = transport.accept().await?;
            match attestor.attest(&connection.peer) {
                Ok(facts) => return Ok((connection, facts)),
                Err(e) => {
                    tracing::warn!(
                        listener = %transport.describe(),
                        error = %e,
                        "connection turned away"
                    );
                    self.turned_away(&connection.peer, &e).await;
                }
            }
        }
    }

    /// Logs a caller the attestor couldn't attest (event `connect`, denied).
    async fn turned_away(&self, peer: &PeerInfo, error: &writ_platform::PlatformError) {
        let caller = match peer {
            PeerInfo::Tcp { remote } => CallerFacts {
                source_addr: Some(remote.ip()),
                process_chain: None,
            },
            _ => CallerFacts::default(),
        };
        let denial = GatewayDenial::new(EventKind::Connect, format!("caller turned away: {error}"));
        self.log_denial(denial, caller).await;
    }

    fn connection_number(&self) -> u64 {
        self.shared.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    fn register_session(&self, serial: u64, connection: u64, handle: russh::server::Handle) {
        if let Ok(mut sessions) = self.shared.sessions.lock() {
            sessions
                .entry(serial)
                .or_default()
                .insert(connection, handle);
        }
        // Revoked between authentication and now: drop it like the others.
        if self.shared.service.is_revoked(serial) {
            self.drop_sessions(serial);
        }
    }

    fn unregister_session(&self, serial: u64, connection: u64) {
        if let Ok(mut sessions) = self.shared.sessions.lock()
            && let Some(by_connection) = sessions.get_mut(&serial)
        {
            by_connection.remove(&connection);
            if by_connection.is_empty() {
                sessions.remove(&serial);
            }
        }
    }

    /// Disconnects every open session of a certificate, and forgets its pushes in progress
    /// (their hook is then refused as an unknown push).
    fn drop_sessions(&self, serial: u64) {
        if let Ok(mut pushes) = self.shared.pushes.lock() {
            pushes.retain(|_, push| push.cert.serial != serial);
        }
        let handles: Vec<russh::server::Handle> = match self.shared.sessions.lock() {
            Ok(mut sessions) => sessions
                .remove(&serial)
                .map(|by_connection| by_connection.into_values().collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        for handle in handles {
            tokio::spawn(async move {
                let _ = handle
                    .disconnect(
                        Disconnect::ByApplication,
                        "writ: the lease ended".to_owned(),
                        "en".to_owned(),
                    )
                    .await;
            });
        }
    }

    /// Open sessions per certificate serial (for tests and logs).
    pub fn open_sessions(&self, serial: u64) -> usize {
        self.shared
            .sessions
            .lock()
            .map(|s| s.get(&serial).map_or(0, HashMap::len))
            .unwrap_or(0)
    }
}

/// Whether an error only says the client went away: it disconnected, or the connection was
/// closed, reset or cut mid-packet (a killed process, a lost network). That is how
/// connections end, not a fault of the daemon, so it isn't logged as an error.
fn client_went_away(error: &GatewayError) -> bool {
    use std::io::ErrorKind;
    let io = match error {
        GatewayError::Ssh(russh::Error::Disconnect) => return true,
        GatewayError::Ssh(russh::Error::IO(e)) | GatewayError::Io(e) => e,
        _ => return false,
    };
    matches!(
        io.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

/// Drops the open sessions of every lease that ends. If notices were missed, every session
/// whose certificate is on the deny list is dropped.
async fn drop_revoked_sessions(
    gateway: Gateway,
    mut revocations: tokio::sync::broadcast::Receiver<u64>,
) {
    loop {
        match revocations.recv().await {
            Ok(serial) => gateway.drop_sessions(serial),
            Err(RecvError::Lagged(_)) => {
                let serials: Vec<u64> = match gateway.shared.sessions.lock() {
                    Ok(sessions) => sessions.keys().copied().collect(),
                    Err(_) => Vec::new(),
                };
                for serial in serials {
                    if gateway.shared.service.is_revoked(serial) {
                        gateway.drop_sessions(serial);
                    }
                }
            }
            Err(RecvError::Closed) => return,
        }
    }
}

fn write_hook_script(hooks_dir: &Path, program: &Path) -> Result<()> {
    let program = program
        .to_str()
        .filter(|p| !p.contains('\''))
        .ok_or_else(|| GatewayError::Config(format!("unusable hook program path {program:?}")))?;
    std::fs::create_dir_all(hooks_dir)?;
    let script = hooks_dir.join("pre-receive");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nexec '{program}' hook pre-receive\n"),
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_going_away_is_not_an_error() {
        use std::io::{Error as Io, ErrorKind};
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
        ] {
            assert!(client_went_away(&GatewayError::Ssh(russh::Error::IO(
                Io::from(kind)
            ))));
            assert!(client_went_away(&GatewayError::Io(Io::from(kind))));
        }
        assert!(client_went_away(&GatewayError::Ssh(
            russh::Error::Disconnect
        )));
        assert!(!client_went_away(&GatewayError::Ssh(russh::Error::IO(
            Io::from(ErrorKind::PermissionDenied)
        ))));
        assert!(!client_went_away(&GatewayError::Config("bad".into())));
        assert!(!client_went_away(&GatewayError::Ssh(
            russh::Error::WrongServerSig
        )));
    }
}
