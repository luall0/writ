//! The SSH gateway: the single entry point to the daemon. Every transport carries the same
//! SSH protocol; each listener has a [`Role`]:
//!
//! - [`Role::Agents`]: user `git` with a session certificate issued for an active lease (git
//!   fetch/push, `writ-sign git`); user `writ` with a plain key, the session key of a ticket
//!   being submitted (`writ request`, `writ wait`).
//! - [`Role::Approvals`]: the approval API (`writ info`, `ls`, `show`, `approve`, `refuse`,
//!   `revoke`), for the keys in the `readers` file only (reads would otherwise show every
//!   ticket to anyone). An approval is still an SSHSIG checked by the approval service, never
//!   the connection itself. The same API is also served over HTTPS, where the reader key is
//!   the client certificate ([`Gateway::serve_https`], [`https`]).
//!
//! Every listener bounds what a peer can make it hold ([`limits`]) and accepts only the
//! [`Sources`] it is configured with.
//!
//! The gateway only sees the platform traits ([`Transport`], [`CallerAttestor`]): connections
//! come from a transport, what is known about the caller from an attestor. Leases, tickets
//! and the deny list are the approval service's ([`writ_approval::Service`]); when a lease
//! ends, the gateway drops its open sessions.
//!
//! Commits are signed by the approval service ([`Service::sign`]: the policy, the `Signer`,
//! the ledger); fetches are decided by it ([`Service::fetch`]: the policy, the rate) and served
//! from the repo's mirror once synced ([`writ_mirror::Mirrors`]). Until the rest of M4, pushes
//! are only checked against the repo's protected refs (the M0 spike), for any active lease
//! that allows the operation and names the repo.
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
mod limits;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::Disconnect;
use tokio::net::UnixListener;
use tokio::sync::broadcast::error::RecvError;
use writ_approval::{EventKind, GatewayDenial, Service};
use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::net::Sources;
use writ_core::policy::{CertIdentity, Denial};
use writ_core::ticket::Operation;
use writ_crypto::readers::Reader;
use writ_crypto::ssh_key::{Fingerprint, HashAlg, PrivateKey};
use writ_platform::{CallerAttestor, Connection, PeerInfo, Transport};

pub use hook::run_pre_receive;
pub use limits::{DEFAULT_SIGN_REQUESTS_PER_LEASE, MAX_SIGN_REQUESTS};

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
    /// The daemon's repositories: one mirror per registered repo, synced from upstream.
    pub mirrors: writ_mirror::Mirrors,
    /// Program git's pre-receive hook runs, as `<program> hook pre-receive`.
    pub hook_program: PathBuf,
    /// Private directory for the gateway's own files (hooks, the hook socket).
    pub state_dir: PathBuf,
    /// The keys that may use the approval API (`readers` file).
    pub readers: Vec<Reader>,
    /// Sign requests one lease may have held at once (1 to [`MAX_SIGN_REQUESTS`]).
    pub sign_requests_per_lease: usize,
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
    /// Denials before authentication, coalesced per source.
    throttle: limits::DenialThrottle,
    /// Sign requests held at once, all lease holders together.
    sign_slots: limits::SignSlots,
}

impl Gateway {
    /// Prepares the state directory, starts the hook server and the task that drops the
    /// sessions of leases that end.
    pub async fn start(config: GatewayConfig, service: Arc<Service>) -> Result<Self> {
        let sign_slots =
            limits::SignSlots::new(config.sign_requests_per_lease).map_err(GatewayError::Config)?;
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
            preferred: preferred_algorithms(),
            keys: vec![config.host_key.clone()],
            auth_rejection_time: Duration::from_millis(300),
            auth_rejection_time_initial: Some(Duration::ZERO),
            max_auth_attempts: 6,
            inactivity_timeout: Some(limits::INACTIVITY_TIMEOUT),
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
                throttle: limits::DenialThrottle::new(),
                sign_slots,
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
            .unwrap_or_else(|_| Err(Denial::internal()))
    }

    /// [`Service::fetch`], off the async threads.
    async fn fetch(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        repo: &writ_core::names::RepoName,
    ) -> std::result::Result<Lease, Denial> {
        let (service, cert, caller, repo) = (
            self.service().clone(),
            cert.clone(),
            caller.clone(),
            repo.clone(),
        );
        tokio::task::spawn_blocking(move || service.fetch(&cert, &caller, &repo))
            .await
            .unwrap_or_else(|_| Err(Denial::internal()))
    }

    /// Logs a request the gateway turned away on its own ([`Service::gateway_denied`]), off
    /// the async threads.
    async fn log_denial(&self, denial: GatewayDenial, caller: CallerFacts) {
        let service = self.service().clone();
        let _ = tokio::task::spawn_blocking(move || service.gateway_denied(&denial, &caller)).await;
    }

    /// Serves SSH connections from a transport, with what `attestor` says about each caller,
    /// until the transport fails. A caller the attestor can't attest, or from a source the
    /// listener doesn't accept, is turned away.
    pub async fn serve(
        &self,
        transport: Arc<dyn Transport>,
        attestor: Arc<dyn CallerAttestor>,
        role: Role,
        sources: Sources,
    ) -> Result<()> {
        let slots = limits::Slots::new();
        loop {
            let (connection, facts, slot) = self
                .accept_attested(&*transport, &*attestor, &sources, &slots)
                .await?;
            let authenticated = Arc::new(AtomicBool::new(false));
            let handler =
                handler::Connection::new(self.clone(), role, facts, authenticated.clone());
            let ssh = self.shared.ssh.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let started = tokio::time::timeout(
                    limits::AUTH_DEADLINE,
                    russh::server::run_stream(ssh, connection.stream, handler),
                )
                .await;
                let session = match started {
                    Err(_) => return,
                    Ok(Err(e)) if client_went_away(&e) => return,
                    // Any peer can cause these: diagnostics at debug level only, so a flood
                    // can't fill the daemon's log (the audit log holds the decisions).
                    Ok(Err(e)) => return tracing::debug!(error = %e, "connection failed"),
                    Ok(Ok(session)) => session,
                };
                // Not authenticated in time: disconnected.
                let handle = session.handle();
                let deadline = tokio::spawn(async move {
                    tokio::time::sleep(limits::AUTH_DEADLINE).await;
                    if !authenticated.load(Ordering::Acquire) {
                        let _ = handle
                            .disconnect(
                                Disconnect::ByApplication,
                                "writ: authentication took too long".to_owned(),
                                "en".to_owned(),
                            )
                            .await;
                    }
                });
                if let Err(e) = session.await
                    && !client_went_away(&e)
                {
                    tracing::debug!(error = %e, "session ended with an error");
                }
                deadline.abort();
            });
        }
    }

    /// The next connection whose caller the attestor can attest, from a source the listener
    /// accepts, with a free connection slot. Others are logged (coalesced) and dropped.
    async fn accept_attested(
        &self,
        transport: &dyn Transport,
        attestor: &dyn CallerAttestor,
        sources: &Sources,
        slots: &limits::Slots,
    ) -> Result<(Connection, CallerFacts, limits::Slot)> {
        loop {
            let connection = transport.accept().await?;
            let facts = match attestor.attest(&connection.peer) {
                Ok(facts) => facts,
                Err(e) => {
                    tracing::debug!(
                        listener = %transport.describe(),
                        error = %e,
                        "connection turned away"
                    );
                    let caller = peer_facts(&connection.peer);
                    self.turned_away(caller, "attest", format!("caller turned away: {e}"))
                        .await;
                    continue;
                }
            };
            if !sources.allows(facts.source_addr) {
                let reason = "caller turned away: its address is not allowed on this listener";
                self.turned_away(facts, "source", reason.to_owned()).await;
                continue;
            }
            match slots.take(facts.source_addr) {
                Ok(slot) => return Ok((connection, facts, slot)),
                Err(reason) => {
                    let reason = format!("caller turned away: {reason}");
                    self.turned_away(facts, "slots", reason).await;
                }
            }
        }
    }

    /// Logs a connection turned away before authentication (event `connect`, denied),
    /// coalesced per source and `kind`.
    async fn turned_away(&self, caller: CallerFacts, kind: &'static str, reason: String) {
        if let Some(suppressed) = self.shared.throttle.admit(caller.source_addr, kind) {
            let reason = limits::with_suppressed(reason, suppressed);
            let denial = GatewayDenial::new(EventKind::Connect, reason);
            self.log_denial(denial, caller).await;
        }
    }

    fn connection_number(&self) -> u64 {
        self.shared.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Tracks a lease holder's session so a revocation can drop it. Fails closed: a session
    /// that can't be tracked (a poisoned table) is refused, since nothing could drop it.
    fn register_session(
        &self,
        serial: u64,
        connection: u64,
        handle: russh::server::Handle,
    ) -> Result<()> {
        self.shared
            .sessions
            .lock()
            .map_err(|_| GatewayError::Config("the session table is poisoned".to_owned()))?
            .entry(serial)
            .or_default()
            .insert(connection, handle);
        // Revoked between authentication and now: drop it like the others.
        if self.shared.service.is_revoked(serial) {
            self.drop_sessions(serial);
        }
        Ok(())
    }

    fn unregister_session(&self, serial: u64, connection: u64) {
        let mut sessions = self
            .shared
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(by_connection) = sessions.get_mut(&serial) {
            by_connection.remove(&connection);
            if by_connection.is_empty() {
                sessions.remove(&serial);
            }
        }
    }

    /// Disconnects every open session of a certificate, and forgets its pushes in progress
    /// (their hook is then refused as an unknown push).
    ///
    /// A reduction of privilege: a poisoned table is still used (its handles are dropped),
    /// never skipped.
    fn drop_sessions(&self, serial: u64) {
        // No connection has this number: they count up from 1.
        self.drop_sessions_except(serial, u64::MAX);
    }

    /// [`Gateway::drop_sessions`], but the connection `keep`: it is answering the request
    /// that ended the lease, and a disconnect would overtake its answer. It ends when the
    /// client hangs up; every command it may still send is refused (deny list).
    pub(crate) fn drop_sessions_except(&self, serial: u64, keep: u64) {
        self.shared
            .pushes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, push| push.cert.serial != serial);
        let handles: Vec<russh::server::Handle> = {
            let mut sessions = self
                .shared
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let by_connection = sessions.entry(serial).or_default();
            let dropped: Vec<u64> = by_connection
                .keys()
                .copied()
                .filter(|&c| c != keep)
                .collect();
            let handles = dropped
                .iter()
                .filter_map(|c| by_connection.remove(c))
                .collect();
            if by_connection.is_empty() {
                sessions.remove(&serial);
            }
            handles
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

/// The SSH algorithms the gateway speaks, stated here rather than left to russh's defaults:
/// post-quantum hybrid or X25519 key exchange (with strict kex), AEAD ciphers only, Ed25519
/// and ECDSA P-256 keys (host, session, reader), no compression, no SHA-1 anywhere.
fn preferred_algorithms() -> russh::Preferred {
    use std::borrow::Cow;
    use writ_crypto::ssh_key::{Algorithm, EcdsaCurve};
    const KEX: &[russh::kex::Name] = &[
        russh::kex::MLKEM768X25519_SHA256,
        russh::kex::CURVE25519,
        russh::kex::EXTENSION_SUPPORT_AS_SERVER,
        russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ];
    const CIPHERS: &[russh::cipher::Name] =
        &[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM];
    const MACS: &[russh::mac::Name] = &[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM];
    const COMPRESSION: &[russh::compression::Name] = &[russh::compression::NONE];
    const KEYS: &[Algorithm] = &[
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    ];
    russh::Preferred {
        kex: Cow::Borrowed(KEX),
        key: Cow::Borrowed(KEYS),
        cipher: Cow::Borrowed(CIPHERS),
        mac: Cow::Borrowed(MACS),
        compression: Cow::Borrowed(COMPRESSION),
        ..russh::Preferred::DEFAULT
    }
}

/// What the transport alone says about a caller the attestor turned away.
fn peer_facts(peer: &PeerInfo) -> CallerFacts {
    match peer {
        PeerInfo::Tcp { remote } => CallerFacts {
            source_addr: Some(remote.ip()),
            process_chain: None,
        },
        _ => CallerFacts::default(),
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
                let serials: Vec<u64> = gateway
                    .shared
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .keys()
                    .copied()
                    .collect();
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
