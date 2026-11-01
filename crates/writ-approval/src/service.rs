//! [`Service`]: see the crate documentation. Its methods are grouped by caller: [`agent`]
//! (submit, wait), [`approver`] (list, show, approve, refuse, revoke), [`gateway`]
//! (authorize, what the gateway denied), [`sign`] (commit signatures) and [`sweep`] (time:
//! expiry, exhaustion, ended sessions).

mod agent;
mod approver;
mod gateway;
mod sign;
mod sweep;

pub use gateway::GatewayDenial;
pub use sign::{SignObject, SignedCommit, Signing};

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
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
use writ_platform::{Clock, Notification, Notifier, SessionWatcher, WatchHandle};
use writ_proto::{Decisions, Info};
use writ_signer::Signer;
use writ_store::{AuditEvent, AuditLog, Outcome, Store};

use crate::ServiceError;
use writ_core::canonical::Canonical;

/// How far back a certificate's validity starts, for clocks a little behind the daemon's.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// The longest a waiting client sleeps before checking again.
const WAIT_RECHECK: Duration = Duration::from_secs(30);

/// Tickets one session key may have waiting at once (a ticket, or an amendment of its lease,
/// and one more).
pub const MAX_PENDING_PER_SESSION: usize = 2;

/// Submissions one source address may make per minute, whatever becomes of them.
pub const MAX_SUBMISSIONS_PER_MINUTE: usize = 10;

/// Notifications waiting for the worker; past it they are counted and reported as one.
const MAX_QUEUED_NOTIFICATIONS: usize = 32;

/// Sources tracked for the submission rate; past it the table starts over.
const MAX_TRACKED_SOURCES: usize = 4096;

/// The most audit lines kept in memory while the log can't be written (a reduction of
/// privilege applied anyway, a denial). Past it, lines are counted as lost and reported.
const MAX_UNLOGGED: usize = 10_000;

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
    /// Holds the keys commits are signed with (each template's `signing_key`).
    pub signer: Arc<dyn Signer>,
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
    /// Notifications for the worker thread ([`notification_worker`]), delivered one at a
    /// time in the order they were queued. Bounded: past [`MAX_QUEUED_NOTIFICATIONS`] they
    /// are counted in `dropped`, and the worker reports the count.
    notifications: Mutex<std::sync::mpsc::SyncSender<Notification>>,
    dropped: Arc<AtomicU64>,
    watcher: Arc<dyn SessionWatcher>,
    clock: Arc<dyn Clock>,
    signer: Arc<dyn Signer>,
    me: Weak<Service>,
}

/// Delivers queued notifications one at a time, in order, until the service is dropped: one
/// thread however many tickets arrive, and a slow sink never holds a request. After each
/// one, the notifications dropped while the queue was full are reported as one.
fn notification_worker(
    notifier: Arc<dyn Notifier>,
    dropped: Arc<AtomicU64>,
) -> std::io::Result<std::sync::mpsc::SyncSender<Notification>> {
    let (outbox, inbox) = std::sync::mpsc::sync_channel::<Notification>(MAX_QUEUED_NOTIFICATIONS);
    std::thread::Builder::new()
        .name("writ-notify".to_owned())
        .spawn(move || {
            for notification in inbox {
                deliver(&*notifier, &notification);
                let missed = dropped.swap(0, Ordering::AcqRel);
                if missed > 0 {
                    deliver(
                        &*notifier,
                        &Notification {
                            title: format!("{missed} more notifications were dropped"),
                            message: "Too many at once. To see what waits: writ ls".to_owned(),
                            priority: writ_platform::Priority::Default,
                            tags: vec!["writ".to_owned()],
                        },
                    );
                }
            }
        })?;
    Ok(outbox)
}

fn deliver(notifier: &dyn Notifier, notification: &Notification) {
    if let Err(e) = notifier.notify(notification) {
        tracing::warn!(error = %e, "notification failed");
    }
}

/// Recent submissions from one source address.
#[derive(Default)]
struct SubmitWindow {
    times: VecDeque<Timestamp>,
    /// Submissions refused over the rate since the last one logged.
    refused: u64,
}

struct Inner {
    store: Store,
    audit: AuditLog,
    /// Session watches of leases bound to a process, dropped (cancelled) when they end.
    watches: HashMap<TicketId, WatchHandle>,
    /// Lines the log couldn't take when they happened, written first once it can.
    unlogged: VecDeque<AuditEvent>,
    /// Lines dropped because [`MAX_UNLOGGED`] was reached.
    lost: u64,
    /// Submissions per source address in the last minute.
    submissions: HashMap<Option<IpAddr>, SubmitWindow>,
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

/// Every template's signing key is one the signer holds: checked at startup, so a missing
/// key is a configuration error, not a denial found later on a commit.
fn signing_keys_exist(policy: &PolicyConfig, signer: &dyn Signer) -> Result<(), ServiceError> {
    let held: HashSet<_> = signer
        .list_keys()
        .map_err(internal)?
        .into_iter()
        .map(|key| key.id)
        .collect();
    for (name, template) in policy.templates() {
        if let Some(id) = template
            .signing_key
            .as_ref()
            .filter(|id| !held.contains(*id))
        {
            return Err(ServiceError::Config(format!(
                "template {name} signs with key {id}, which the signer doesn't hold"
            )));
        }
    }
    Ok(())
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
        signing_keys_exist(&config.policy, &*platform.signer)?;
        let dropped = Arc::new(AtomicU64::new(0));
        let outbox = notification_worker(platform.notifier, dropped.clone()).map_err(internal)?;
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
                unlogged: VecDeque::new(),
                lost: 0,
                submissions: HashMap::new(),
            }),
            revoked: RwLock::new(revoked),
            changed: Notify::new(),
            revocations,
            notifications: Mutex::new(outbox),
            dropped,
            watcher: platform.watcher,
            clock: platform.clock,
            signer: platform.signer,
            me: me.clone(),
        });
        service.sweep();
        service.rewatch_sessions()?;
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

    /// Writes the lines the log couldn't take earlier, oldest first; stops at the first
    /// failure.
    fn flush_unlogged(inner: &mut Inner) -> Result<(), ServiceError> {
        while let Some(event) = inner.unlogged.front() {
            inner.audit.append(event).map_err(ServiceError::AuditLog)?;
            inner.unlogged.pop_front();
        }
        if inner.lost > 0 {
            tracing::error!(
                lost = inner.lost,
                "audit lines were lost while the audit log couldn't be written"
            );
            inner.lost = 0;
        }
        Ok(())
    }

    /// Writes `event` (after any line still waiting): a grant or an allow is refused when
    /// this fails.
    fn log(inner: &mut Inner, event: &AuditEvent) -> Result<(), ServiceError> {
        Self::flush_unlogged(inner)?;
        inner.audit.append(event).map_err(ServiceError::AuditLog)
    }

    /// Logs a denial, or a reduction of privilege: what it records happens whatever becomes
    /// of the line (a denial is denied anyway, a revocation is never held back). A line the
    /// log can't take is kept and written first once it can.
    fn log_best_effort(inner: &mut Inner, event: &AuditEvent) {
        if let Err(e) = Self::log(inner, event) {
            // Once per outage (when the first line is kept), not once per line: denials can
            // be driven by peers, and the daemon's own log must stay bounded too.
            if inner.unlogged.is_empty() {
                tracing::error!(
                    error = %e.detail(),
                    "cannot write the audit log; lines are kept until it can"
                );
            }
            if inner.unlogged.len() < MAX_UNLOGGED {
                inner.unlogged.push_back(event.clone());
            } else {
                inner.lost += 1;
            }
        }
    }

    /// Writes `event`, then makes the change it records: nothing is granted or allowed
    /// without its log line. If the change then fails, a denial line with the reason follows.
    fn logged<T>(
        inner: &mut Inner,
        event: AuditEvent,
        change: impl FnOnce(&mut Inner) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        Self::log(inner, &event)?;
        Self::apply(inner, event, change)
    }

    /// A reduction of privilege (revocation, withdrawal, expiry, exhaustion, an ended
    /// session): its line is written first when the log can take it, but the change is made
    /// either way. A full disk must never keep a lease alive (docs/decisions.md).
    fn reduced<T>(
        inner: &mut Inner,
        event: AuditEvent,
        change: impl FnOnce(&mut Inner) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        Self::log_best_effort(inner, &event);
        Self::apply(inner, event, change)
    }

    /// Makes a logged change; a failure gets its denial line.
    fn apply<T>(
        inner: &mut Inner,
        event: AuditEvent,
        change: impl FnOnce(&mut Inner) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        change(inner).inspect_err(|e| {
            let mut failed = event;
            failed.result = Outcome::Denied;
            failed.reason = Some(format!("not applied: {e}"));
            Self::log_best_effort(inner, &failed);
        })
    }

    /// The ticket `id` for an approver request; an unknown id is logged as denied (event
    /// `kind`) before the "does not exist" answer.
    fn record_or_deny(
        inner: &mut Inner,
        id: &TicketId,
        denied: AuditEvent,
    ) -> Result<TicketRecord, ServiceError> {
        match inner.store.ticket(id).map_err(internal)? {
            Some(record) => Ok(record),
            None => {
                Self::log_best_effort(inner, &denied.ticket(id).reason("no such ticket"));
                Err(not_found(id))
            }
        }
    }

    /// Puts a certificate on the deny list, without announcing it: done first when a lease
    /// ends, before anything that can fail, so the certificate is refused whatever follows.
    fn bar_serial(&self, serial: u64) {
        match self.revoked.write() {
            Ok(mut revoked) => {
                revoked.insert(serial);
            }
            // Reads of a poisoned deny list say "revoked" ([`Service::is_revoked`]).
            Err(_) => tracing::error!(serial, "the deny list lock is poisoned"),
        }
    }

    /// Puts a certificate on the deny list and announces it (the gateway drops its open
    /// sessions). Called once the lease's state change was attempted, whatever its outcome.
    fn deny_serial(&self, serial: u64) {
        self.bar_serial(serial);
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

    /// The public key (OpenSSH text) commits are signed with under `ticket`, if it signs.
    fn signing_public_key(&self, ticket: &Ticket) -> Result<Option<String>, ServiceError> {
        let Some(id) = &ticket.scope.signing_key else {
            return Ok(None);
        };
        let key = writ_signer::public_key(&*self.signer, id).map_err(internal)?;
        key.to_openssh().map(Some).map_err(internal)
    }

    /// How this daemon takes decisions.
    pub fn info(&self) -> Info {
        Info {
            decisions: self.config.decisions,
        }
    }
}
