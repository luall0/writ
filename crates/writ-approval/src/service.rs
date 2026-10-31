//! [`Service`]: see the crate documentation. Its methods are grouped by caller: [`agent`]
//! (submit, wait), [`approver`] (list, show, approve, refuse, revoke), [`gateway`]
//! (authorize, what the gateway denied) and [`sweep`] (time: expiry, exhaustion, ended
//! sessions).

mod agent;
mod approver;
mod gateway;
mod sweep;

pub use gateway::GatewayDenial;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, broadcast};
use writ_core::config::PolicyConfig;
use writ_core::lease::{State, TicketRecord};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_platform::{Clock, Notifier, SessionWatcher, WatchHandle};
use writ_proto::{Decisions, Info};
use writ_store::{AuditEvent, AuditLog, Outcome, Store};

use crate::ServiceError;
use writ_core::canonical::Canonical;

/// How far back a certificate's validity starts, for clocks a little behind the daemon's.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// The longest a waiting client sleeps before checking again.
const WAIT_RECHECK: Duration = Duration::from_secs(30);

/// The service's settings, from the daemon's configuration.
pub struct ServiceConfig {
    /// The repo registry and the templates.
    pub policy: PolicyConfig,
    /// The approver keys (`approvers` file).
    pub approvers: Vec<AllowedSigner>,
    /// Whether refusals and revocations need an approver signature.
    pub decisions: Decisions,
    /// How many tickets may wait at once.
    pub max_pending: usize,
}

/// The platform implementations the service uses.
pub struct ServicePlatform {
    pub notifier: Arc<dyn Notifier>,
    pub watcher: Arc<dyn SessionWatcher>,
    pub clock: Arc<dyn Clock>,
}

/// The approval service. Shared (`Arc`) by the gateway and the daemon's timers.
pub struct Service {
    config: ServiceConfig,
    approver_keys: Vec<PublicKey>,
    ca: CertificateAuthority,
    inner: Mutex<Inner>,
    /// Serials of every certificate whose lease ended: refused at connection.
    revoked: RwLock<HashSet<u64>>,
    /// Woken on every state change (waiting clients re-check).
    changed: Notify,
    /// Serials just revoked or expired: the gateway drops their open sessions.
    revocations: broadcast::Sender<u64>,
    notifier: Arc<dyn Notifier>,
    watcher: Arc<dyn SessionWatcher>,
    clock: Arc<dyn Clock>,
    me: Weak<Service>,
}

struct Inner {
    store: Store,
    audit: AuditLog,
    /// Session watches of leases bound to a process, dropped (cancelled) when they end.
    watches: HashMap<TicketId, WatchHandle>,
}

impl Inner {
    /// The ticket `id`; one that doesn't exist is a "does not exist" error.
    fn record(&self, id: &TicketId) -> Result<TicketRecord, ServiceError> {
        self.store
            .ticket(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))
    }
}

fn internal(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> ServiceError {
    ServiceError::internal(e)
}

fn not_found(id: &TicketId) -> ServiceError {
    ServiceError::NotFound(id.clone())
}

fn canonical_text(ticket: &Ticket) -> Result<String, ServiceError> {
    let bytes = ticket.canonical_bytes().map_err(internal)?;
    String::from_utf8(bytes).map_err(internal)
}

fn fingerprint(key: &PublicKey) -> Result<KeyFingerprint, ServiceError> {
    key.fingerprint(HashAlg::Sha256)
        .to_string()
        .parse()
        .map_err(internal)
}

impl Service {
    /// Starts the service on an open store and audit log. Every certificate of a lease that
    /// already ended goes on the deny list.
    pub fn new(
        config: ServiceConfig,
        ca: CertificateAuthority,
        store: Store,
        audit: AuditLog,
        platform: ServicePlatform,
    ) -> Result<Arc<Self>, ServiceError> {
        let mut revoked = HashSet::new();
        for state in [
            State::Revoked,
            State::Expired,
            State::Closed,
            State::Exhausted,
        ] {
            revoked.extend(
                store
                    .leases(state)
                    .map_err(internal)?
                    .into_iter()
                    .map(|l| l.cert_serial),
            );
        }
        let approver_keys = config.approvers.iter().map(|a| a.key.clone()).collect();
        let (revocations, _) = broadcast::channel(256);
        let service = Arc::new_cyclic(|me| Self {
            config,
            approver_keys,
            ca,
            inner: Mutex::new(Inner {
                store,
                audit,
                watches: HashMap::new(),
            }),
            revoked: RwLock::new(revoked),
            changed: Notify::new(),
            revocations,
            notifier: platform.notifier,
            watcher: platform.watcher,
            clock: platform.clock,
            me: me.clone(),
        });
        service.sweep();
        Ok(service)
    }

    /// The CA's public key, for the gateway's list of trusted authorities.
    pub fn ca_public_key(&self) -> &PublicKey {
        self.ca.public_key()
    }

    /// The repo registry and the templates.
    pub fn policy(&self) -> &PolicyConfig {
        &self.config.policy
    }

    /// Now, by the service's clock.
    pub(crate) fn now(&self) -> Result<Timestamp, ServiceError> {
        let seconds = i64::try_from(self.clock.now_ms() / 1000).map_err(internal)?;
        Timestamp::from_unix(seconds).map_err(internal)
    }

    /// Now in Unix seconds, for certificate validity checks.
    pub fn now_unix(&self) -> u64 {
        self.clock.now_ms() / 1000
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, ServiceError> {
        // A poisoned lock fails closed: nothing can be trusted about the state.
        self.inner
            .lock()
            .map_err(|_| internal("the service state lock is poisoned"))
    }

    /// What every request starts with: now, the state lock, and a sweep (so nothing past its
    /// time is acted on).
    fn begin(&self) -> Result<(Timestamp, MutexGuard<'_, Inner>), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        Ok((now, inner))
    }

    fn log(inner: &mut Inner, event: &AuditEvent) -> Result<(), ServiceError> {
        inner.audit.append(event).map_err(ServiceError::AuditLog)
    }

    /// Logs a denial, or a change the daemon makes on its own (an expiry). What it records
    /// happens whatever becomes of the log line: a denial is denied anyway.
    fn log_best_effort(inner: &mut Inner, event: &AuditEvent) {
        if let Err(e) = inner.audit.append(event) {
            tracing::error!(error = %e, "cannot write the audit log");
        }
    }

    /// Writes `event`, then makes the change it records: nothing changes without its log
    /// line. If the change then fails, a denial line with the reason follows.
    fn logged<T>(
        inner: &mut Inner,
        event: AuditEvent,
        change: impl FnOnce(&mut Inner) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        Self::log(inner, &event)?;
        change(inner).inspect_err(|e| {
            let mut failed = event;
            failed.result = Outcome::Denied;
            failed.reason = Some(format!("not applied: {e}"));
            Self::log_best_effort(inner, &failed);
        })
    }

    fn deny_serial(&self, serial: u64) {
        match self.revoked.write() {
            Ok(mut revoked) => {
                revoked.insert(serial);
            }
            Err(_) => tracing::error!(serial, "the deny list lock is poisoned"),
        }
        let _ = self.revocations.send(serial);
    }

    /// Whether a certificate serial is on the deny list. A poisoned lock says yes.
    pub fn is_revoked(&self, serial: u64) -> bool {
        self.revoked
            .read()
            .map(|r| r.contains(&serial))
            .unwrap_or(true)
    }

    /// Serials whose lease just ended (revoked, expired, exhausted): drop their sessions.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<u64> {
        self.revocations.subscribe()
    }

    /// How this daemon takes decisions.
    pub fn info(&self) -> Info {
        Info {
            decisions: self.config.decisions,
        }
    }
}
