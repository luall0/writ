//! [`Service`]: see the crate documentation. Its methods are grouped by caller: [`agent`]
//! (submit, wait), [`approver`] (list, show, approve, refuse, revoke), [`prove`] (a signing
//! key's proof for a remote, an approver's request too), [`gateway`] (authorize, what the
//! gateway denied), [`sign`] (commit signatures), [`notes`] (the notes a push leaves to
//! write, under `ticket_link: notes`) and [`sweep`] (time: expiry, exhaustion,
//! ended sessions).

mod admin;
mod agent;
mod approver;
mod ca;
mod coalesced;
mod gateway;
mod notes;
mod openpgp;
mod policy;
mod prove;
mod push;
mod report;
mod scan;
mod sign;
mod submissions;
mod sweep;
mod tls;
mod token;
mod unseal;

pub use admin::{AdminParsed, AlteredAtRest, CheckedAdmin, InForce};
pub use ca::CheckedCa;
pub use gateway::GatewayDenial;
pub use push::{InFlightPush, Pushing};
pub use scan::{CheckedScan, MAX_CHECKS_A_MINUTE, MAX_NONCES, MAX_SCANS_A_MINUTE, NONCE_SECONDS};
pub use sign::{SignObject, SignedCommit, Signing};
pub use submissions::{
    DEFAULT_SUBMISSIONS_IN_ALL, DEFAULT_SUBMISSIONS_PER_SOURCE, MAX_SUBMISSIONS_IN_ALL,
    MAX_SUBMISSIONS_PER_SOURCE, SubmissionLimits,
};
pub use tls::{CheckedTls, MAX_ROTATIONS_A_MINUTE};
pub use token::CheckedToken;
pub use unseal::UnsealedBy;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, broadcast};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::lease::{State, TicketRecord};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::policy::CertIdentity;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_platform::{Clock, Notification, Notifier, SessionWatcher, WatchHandle};
use writ_proto::{Decisions, Info, SealedBoot};
use writ_signer::Signer;
use writ_store::{AuditEvent, AuditLog, EventKind, Outcome, Store};

use crate::{RefusalCode, ServiceError};
use writ_core::canonical::Canonical;

/// How far back a certificate's validity starts, for clocks a little behind the daemon's.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// The longest a waiting client sleeps before checking again.
const WAIT_RECHECK: Duration = Duration::from_secs(30);

/// Tickets one session key may have waiting at once (a ticket, or an amendment of its lease,
/// and one more).
pub const MAX_PENDING_PER_SESSION: usize = 2;

/// Notifications waiting for the worker; past it they are counted and reported as one.
const MAX_QUEUED_NOTIFICATIONS: usize = 32;

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
    /// The shortest TTL a ticket may ask for (`writd.yaml`'s `min_ttl`).
    pub min_ttl: writ_core::units::Duration,
    /// The submission rates (per source, all sources together).
    pub submissions: SubmissionLimits,
    /// The most active leases one source may hold at once (`None`: no limit).
    pub max_active_per_source: Option<u32>,
    /// How long after its `expires_at` an expired or used-up lease can still be renewed.
    pub renew_grace: writ_core::units::Duration,
    /// The CA's public key (its private key comes at unseal, and must be this one's).
    pub ca_public: PublicKey,
    /// The fingerprint of the daemon's SSH host key: what an unseal signature names.
    pub daemon: KeyFingerprint,
    /// The version of each authority file the daemon started with, and their MAC (checked at
    /// unseal).
    pub in_force: InForce,
    /// The sealed keystore's public recipient, served by `writ info` (what `writ admin
    /// token` encrypts to); `None` with the development keystore.
    pub recipient: Option<String>,
    /// What opens the keystore while sealed (M7.6), served by `writ info`; `None` with the
    /// development keystore.
    pub unseal: Option<writ_proto::UnsealWay>,
    /// How each signing key of `policy` signs, as its declaration resolves on its backend
    /// (`keys.<id>`). A key without its entry signs nothing; a policy change brings its own
    /// ([`AdminParsed::Policy`]).
    pub signing_keys: KeyUses,
    /// The session launcher (`writd.yaml`'s `session_launcher`, the installed `writ`), by
    /// the path the kernel names it with: a session binding's root must be its child. `None`
    /// where there is no process chain (the network attestor): nothing can be bound.
    pub session_launcher: Option<std::path::PathBuf>,
}

/// How each signing key signs, by id.
pub type KeyUses = BTreeMap<writ_core::names::KeyId, KeyUse>;

/// How an agent signing key signs: the format it is declared with, and the format's hash
/// (checked against its backend whenever a policy declaring it is read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUse {
    pub format: writ_crypto::algorithm::SignatureFormat,
    pub hash: writ_crypto::algorithm::Hash,
}

impl KeyUse {
    /// An SSH key with the SSHSIG hash `ssh-keygen` uses: the default of an SSH declaration
    /// that leaves `hash` out.
    pub const SSH: KeyUse = KeyUse {
        format: writ_crypto::algorithm::SignatureFormat::Ssh,
        hash: writ_crypto::sshsig::DEFAULT_HASH,
    };
}

/// The platform implementations the service uses.
pub struct ServicePlatform {
    pub notifier: Arc<dyn Notifier>,
    pub watcher: Arc<dyn SessionWatcher>,
    pub clock: Arc<dyn Clock>,
}

/// What an unseal brings: the keys that stay in the keystore while the daemon is sealed.
pub struct Opened {
    /// Issues session certificates.
    pub ca: CertificateAuthority,
    /// Holds the keys commits are signed with (each template's `signing_key`).
    pub signer: Arc<dyn Signer>,
    /// The authority MAC's key: checks the versions in force, signs each new head.
    pub authority: writ_crypto::authority::AuthorityKey,
    /// The creation time of each OpenPGP key the signer holds (from the keystore): part of
    /// its fingerprint, so of every signature and certificate.
    pub openpgp: BTreeMap<writ_core::names::KeyId, u32>,
}

/// The approval service. Shared (`Arc`) by the gateway and the daemon's timers.
///
/// It starts **sealed**: every request but `info` and an unseal fails with "daemon sealed"
/// until [`Service::unseal`] hands it the CA and the signer ([`unseal`]).
pub struct Service {
    config: ServiceConfig,
    /// The policy in force: replaced whole by an admin change, read as a snapshot.
    policy: RwLock<Arc<PolicyConfig>>,
    /// How its signing keys sign: replaced with it.
    key_uses: RwLock<Arc<KeyUses>>,
    /// The scan nonces handed out, the last scans and checks ([`scan`]).
    outbound: Mutex<scan::Outbound>,
    /// The approver keys in force: replaced whole by an admin change.
    approver_keys: RwLock<Arc<Vec<PublicKey>>>,
    /// The version of each authority file in force, and the head's MAC.
    in_force: RwLock<InForce>,
    /// Set once, at unseal; never taken back.
    opened: OnceLock<Opened>,
    /// The OpenPGP keys' creation times and certificates: set at unseal, replaced by a policy
    /// change.
    openpgp: RwLock<openpgp::OpenpgpKeys>,
    /// What an unseal signature must name while sealed: this daemon, this boot.
    boot: SealedBoot,
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
    /// `writ wait` calls in progress: each one ends with its answer, or with its client.
    waiting: std::sync::atomic::AtomicUsize,
    /// What a token is sealed to now (M7.6), set by the daemon at unseal and when the
    /// keystore's recipients change.
    token_recipients: Mutex<Vec<String>>,
    /// The keystore's recipient now, and why its data key's rotation is owed (the review
    /// after M7.6, S-8): set by the daemon at start, at unseal and when the recipients
    /// change (a rotation gives a new recipient).
    keystore_now: Mutex<(Option<String>, Vec<String>)>,
    /// Sessions that ended, their certificates refused, their revocations still to record
    /// (by the thread their notice started, or the next sweep): kept apart from the state
    /// lock, which a notice may come under ([`sweep`]).
    ended_sessions: Mutex<Vec<(TicketId, u64)>>,
    dropped: Arc<AtomicU64>,
    watcher: Arc<dyn SessionWatcher>,
    clock: Arc<dyn Clock>,
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

struct Inner {
    store: Store,
    audit: AuditLog,
    /// Session watches of leases bound to a process, dropped (cancelled) when they end.
    watches: HashMap<TicketId, WatchHandle>,
    /// Lines the log couldn't take when they happened, written first once it can.
    unlogged: VecDeque<AuditEvent>,
    /// Lines dropped because [`MAX_UNLOGGED`] was reached.
    lost: u64,
    /// The submission rates' windows.
    submissions: submissions::Submissions,
    /// Each lease's denial lines in the current window, and the denials counted past it.
    denials: coalesced::Coalesced,
    /// Each lease's allowed `connect` lines in the current window, and those counted past it.
    connections: coalesced::Coalesced,
    /// Signatures between their first and last phase ([`sign`]).
    signing: sign::InFlightCounts,
    /// Pushes decided and not yet ended ([`push`]): taken from the lease's count, on their way
    /// upstream (the review after M7.6, A-3).
    pushing: sign::InFlightCounts,
    /// Revocations the daemon decided (a violation, an ended session, a removed approver)
    /// that the store couldn't record, with their reason: their certificates are refused in
    /// memory meanwhile, and each sweep records them again until the store takes them.
    unrecorded: std::collections::BTreeMap<TicketId, String>,
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

/// An audit line about a request made with a certificate: its serial, the caller, and the
/// lease its key id names, when it names one (the request is decided either way).
fn cert_event(
    now: Timestamp,
    kind: EventKind,
    outcome: Outcome,
    cert: &CertIdentity,
    caller: &CallerFacts,
) -> AuditEvent {
    let event = AuditEvent::new(now, kind, outcome)
        .cert(cert.serial)
        .caller(caller);
    match cert.key_id.parse::<TicketId>() {
        Ok(id) => event.lease(&id),
        Err(_) => event,
    }
}

/// What the gateway's caller reads when [`Service::begin`] fails: "daemon sealed" as its own
/// code, anything else as `invalid`.
fn as_denial(error: ServiceError) -> writ_core::policy::Denial {
    use writ_core::policy::{Denial, DenyCode};
    match error.code() {
        Some(RefusalCode::Sealed) => Denial::sealed(),
        _ => Denial::new(DenyCode::Invalid, error.to_string()),
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
    /// Starts the service, sealed, on an open store and audit log. Every certificate of a
    /// lease that already ended goes on the deny list. `nonce` is this boot's (16 random
    /// bytes): what an unseal signature names.
    pub fn new(
        config: ServiceConfig,
        nonce: [u8; 16],
        store: Store,
        audit: AuditLog,
        platform: ServicePlatform,
    ) -> Result<Arc<Self>, ServiceError> {
        config.submissions.check().map_err(ServiceError::Config)?;
        let mut revoked = HashSet::new();
        for state in [
            State::Revoked,
            State::Expired,
            State::Closed,
            State::Exhausted,
            State::Renewed,
        ] {
            revoked.extend(
                store
                    .leases(state)
                    .map_err(internal)?
                    .into_iter()
                    .map(|l| l.cert_serial),
            );
        }
        let dropped = Arc::new(AtomicU64::new(0));
        let outbox = notification_worker(platform.notifier, dropped.clone()).map_err(internal)?;
        let submissions = submissions::Submissions::new(config.submissions);
        let approver_keys: Vec<PublicKey> =
            config.approvers.iter().map(|a| a.key.clone()).collect();
        let policy = RwLock::new(Arc::new(config.policy.clone()));
        let key_uses = RwLock::new(Arc::new(config.signing_keys.clone()));
        let in_force = RwLock::new(config.in_force.clone());
        let keystore_now = Mutex::new((config.recipient.clone(), Vec::new()));
        let (revocations, _) = broadcast::channel(256);
        let boot = SealedBoot {
            daemon: config.daemon.clone(),
            nonce: writ_core::signed::BootNonce::from_bytes(nonce),
        };
        let service = Arc::new_cyclic(|me| Self {
            config,
            policy,
            key_uses,
            outbound: Mutex::new(scan::Outbound::default()),
            approver_keys: RwLock::new(Arc::new(approver_keys)),
            in_force,
            opened: OnceLock::new(),
            openpgp: RwLock::new(openpgp::OpenpgpKeys::default()),
            boot,
            inner: Mutex::new(Inner {
                store,
                audit,
                watches: HashMap::new(),
                unlogged: VecDeque::new(),
                lost: 0,
                submissions,
                denials: coalesced::Coalesced::denials(),
                connections: coalesced::Coalesced::connections(),
                signing: sign::InFlightCounts::default(),
                pushing: sign::InFlightCounts::default(),
                unrecorded: std::collections::BTreeMap::new(),
            }),
            revoked: RwLock::new(revoked),
            changed: Notify::new(),
            revocations,
            notifications: Mutex::new(outbox),
            dropped,
            waiting: std::sync::atomic::AtomicUsize::new(0),
            token_recipients: Mutex::new(Vec::new()),
            keystore_now,
            ended_sessions: Mutex::new(Vec::new()),
            watcher: platform.watcher,
            clock: platform.clock,
            me: me.clone(),
        });
        service.sweep();
        service.rewatch_sessions()?;
        Ok(service)
    }

    /// The CA's public key, for the gateway's list of trusted authorities.
    pub fn ca_public_key(&self) -> &PublicKey {
        &self.config.ca_public
    }

    /// What the unseal brought, or "daemon sealed".
    fn opened(&self) -> Result<&Opened, ServiceError> {
        self.opened
            .get()
            .ok_or_else(|| ServiceError::refused(RefusalCode::Sealed, writ_core::policy::SEALED))
    }

    /// Whether the daemon is sealed.
    pub fn is_sealed(&self) -> bool {
        self.opened.get().is_none()
    }

    /// The repo registry and the templates in force: a snapshot (an admin change replaces it
    /// whole, never in part).
    pub fn policy(&self) -> Arc<PolicyConfig> {
        // poisoned: the last policy written stands (it was written whole).
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How the signing keys of the policy in force sign: a snapshot.
    pub fn key_uses(&self) -> Arc<KeyUses> {
        // poisoned: the last map written stands (it was written whole).
        self.key_uses
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The approver keys in force: a snapshot.
    pub(crate) fn approver_keys(&self) -> Arc<Vec<PublicKey>> {
        // poisoned: the last set written stands (it was written whole).
        self.approver_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
        self.opened()?;
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
    ///
    /// A lease's denials past its budget are counted instead ([`coalesced`]), and the counts
    /// of windows that are over written first.
    fn log_best_effort(inner: &mut Inner, event: &AuditEvent) {
        for counted in inner.denials.due(event.time) {
            Self::write_best_effort(inner, &counted);
        }
        if inner.denials.admit(event) {
            Self::write_best_effort(inner, event);
        }
    }

    /// Writes the counts of the denial and connection windows over at `now` (from the sweep:
    /// a lease that stopped sending requests still gets its count logged).
    fn log_counted_denials(inner: &mut Inner, now: Timestamp) {
        for counted in inner.denials.due(now) {
            Self::write_best_effort(inner, &counted);
        }
        for counted in inner.connections.due(now) {
            Self::write_best_effort(inner, &counted);
        }
    }

    /// Logs a lease holder's allowed connection, unless past its budget ([`coalesced`]): then
    /// it is counted, and the count written when the window is over. The counts of windows
    /// already over are written first.
    fn log_connection(inner: &mut Inner, event: &AuditEvent) -> Result<(), ServiceError> {
        for counted in inner.connections.due(event.time) {
            Self::write_best_effort(inner, &counted);
        }
        if inner.connections.admit(event) {
            Self::log(inner, event)?;
        }
        Ok(())
    }

    fn write_best_effort(inner: &mut Inner, event: &AuditEvent) {
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
        let Some(id) = &ticket.common.signing_key else {
            return Ok(None);
        };
        let key = writ_signer::public_key(&*self.opened()?.signer, id).map_err(internal)?;
        key.to_openssh().map(Some).map_err(internal)
    }

    /// The armored OpenPGP certificate commits are signed with under `ticket`, if its key signs
    /// in OpenPGP.
    fn signing_certificate(&self, ticket: &Ticket) -> Option<String> {
        ticket
            .common
            .signing_key
            .as_ref()
            .and_then(|id| self.openpgp_certificate(id))
    }

    /// Queues a notification for the worker: the request never waits on the sink. Best
    /// effort (it grants nothing): a poisoned queue sends none, a full one counts it.
    fn notify(&self, notification: Notification) {
        // poisoned: no notification (best effort: it grants nothing, the state is the store's).
        if let Ok(outbox) = self.notifications.lock()
            && outbox.try_send(notification).is_err()
        {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// This daemon: the fingerprint of its SSH host key, which every signed document bound to
    /// one daemon names (`writ-unseal/1`, `writ-admin/2`, `writ-token/3`).
    pub fn daemon(&self) -> &KeyFingerprint {
        &self.boot.daemon
    }

    /// How many `writ wait` calls are in progress (a wait dropped, its client gone, ends).
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }

    /// How this daemon takes decisions.
    pub fn info(&self) -> Info {
        // poisoned: the pair is replaced whole.
        let (recipient, rotation_owed) = self
            .keystore_now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Info {
            decisions: self.config.decisions,
            sealed: self.is_sealed().then(|| self.boot.clone()),
            recipient,
            rotation_owed,
            unseal: self.is_sealed().then_some(self.config.unseal).flatten(),
            token_recipients: match self.is_sealed() {
                true => Vec::new(),
                // poisoned: the list is replaced whole.
                false => self
                    .token_recipients
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            },
        }
    }

    /// What `writ info` says a token is sealed to (M7.6): the daemon's to set, at unseal and
    /// when the keystore's recipients change.
    pub fn set_token_recipients(&self, recipients: Vec<String>) {
        *self
            .token_recipients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = recipients;
    }

    /// What `writ info` says of the keystore (the review after M7.6, S-8): its recipient now
    /// (a rotation of the data key replaces it) and why a rotation is owed; the daemon's to
    /// set, at start, at unseal and when the recipients change.
    pub fn set_keystore(&self, recipient: Option<String>, rotation_owed: Vec<String>) {
        *self
            .keystore_now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (recipient, rotation_owed);
    }
}
