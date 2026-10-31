//! [`Service`]: see the crate documentation.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Notify, broadcast};
use writ_core::caller::{self, CallerFacts, ProcessRef};
use writ_core::config::{Operation, PolicyConfig};
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, APPROVAL_NAMESPACE, Approval, Lease, State, TicketRecord};
use writ_core::names::{KeyFingerprint, RepoName, TicketId};
use writ_core::policy::{self, CertIdentity, Denial, DenyCode};
use writ_core::signed::{MAX_FEEDBACK_CHARS, Refusal, Revocation};
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::{CertificateAuthority, CertificateRequest};
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_crypto::{keys, sshsig};
use writ_platform::{Notification, Notifier, Priority, SessionWatcher, WatchHandle};
use writ_proto::{
    Ack, ApiError, ApproveRequest, Decision, Decisions, Info, Listing, Previous, RefuseRequest,
    Relation, RevokeRequest, Shown, Submitted, Summary,
};
use writ_store::{AuditEvent, AuditLog, EventKind, Outcome, Store};

use crate::{Error, PRINCIPAL};

/// How far back a certificate's validity starts, for clocks a little behind the daemon's.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// The longest a waiting client sleeps before checking again.
const WAIT_RECHECK: Duration = Duration::from_secs(30);

/// Milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A clock moved by hand, for tests.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn at_unix(seconds: u64) -> Self {
        Self(AtomicU64::new(seconds.saturating_mul(1000)))
    }

    pub fn advance(&self, seconds: u64) {
        self.0
            .fetch_add(seconds.saturating_mul(1000), Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

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
pub struct Platform {
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

fn internal(e: impl std::fmt::Display) -> ApiError {
    eprintln!("writd: internal error: {e}");
    ApiError::new("internal error in the daemon (see its log)")
}

fn not_found(id: &TicketId) -> ApiError {
    ApiError::new(format!("ticket {id} does not exist"))
}

fn canonical_text(ticket: &Ticket) -> Result<String, ApiError> {
    let bytes = ticket.canonical_bytes().map_err(internal)?;
    String::from_utf8(bytes).map_err(internal)
}

fn fingerprint(key: &PublicKey) -> Result<KeyFingerprint, ApiError> {
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
        platform: Platform,
    ) -> Result<Arc<Self>, Error> {
        let mut revoked = HashSet::new();
        for state in [
            State::Revoked,
            State::Expired,
            State::Closed,
            State::Exhausted,
        ] {
            revoked.extend(store.leases(state)?.into_iter().map(|l| l.cert_serial));
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
    pub fn now(&self) -> Result<Timestamp, ApiError> {
        let seconds = i64::try_from(self.clock.now_ms() / 1000).map_err(internal)?;
        Timestamp::from_unix(seconds).map_err(internal)
    }

    /// Now in Unix seconds, for certificate validity checks.
    pub fn now_unix(&self) -> u64 {
        self.clock.now_ms() / 1000
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, ApiError> {
        // A poisoned lock fails closed: nothing can be trusted about the state.
        self.inner
            .lock()
            .map_err(|_| internal("the service state lock is poisoned"))
    }

    fn log(inner: &mut Inner, event: &AuditEvent) -> Result<(), ApiError> {
        inner.audit.append(event).map_err(|e| {
            eprintln!("writd: cannot write the audit log: {e}");
            ApiError::new("the audit log can't be written; nothing was done")
        })
    }

    /// Logs a denial, or a change the daemon makes on its own (an expiry). What it records
    /// happens whatever becomes of the log line: a denial is denied anyway.
    fn log_best_effort(inner: &mut Inner, event: &AuditEvent) {
        if let Err(e) = inner.audit.append(event) {
            eprintln!("writd: cannot write the audit log: {e}");
        }
    }

    /// Writes `event`, then makes the change it records: nothing changes without its log
    /// line. If the change then fails, a denial line with the reason follows.
    fn logged<T>(
        inner: &mut Inner,
        event: AuditEvent,
        change: impl FnOnce(&mut Inner) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        Self::log(inner, &event)?;
        change(inner).inspect_err(|e| {
            let mut failed = event;
            failed.result = Outcome::Denied;
            failed.reason = Some(format!("not applied: {}", e.message));
            Self::log_best_effort(inner, &failed);
        })
    }

    fn deny_serial(&self, serial: u64) {
        match self.revoked.write() {
            Ok(mut revoked) => {
                revoked.insert(serial);
            }
            Err(_) => eprintln!("writd: the deny list lock is poisoned"),
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

    // ----- time ---------------------------------------------------------------------------

    /// Expires pending tickets and leases past `expires_at`, and exhausted leases. Called by
    /// the daemon's timer and before every request.
    pub fn sweep(&self) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        match self.sweep_locked(&mut inner, now) {
            Ok(true) => self.changed.notify_waiters(),
            Ok(false) => {}
            Err(e) => eprintln!("writd: sweep failed: {e}"),
        }
    }

    fn sweep_locked(&self, inner: &mut Inner, now: Timestamp) -> Result<bool, ApiError> {
        let mut changed = false;
        for record in inner.store.tickets(State::Pending).map_err(internal)? {
            if let Some(next) = lease::pending_due(&record, now) {
                let id = &record.ticket.id;
                inner
                    .store
                    .transition(id, State::Pending, next, now)
                    .map_err(internal)?;
                let event = AuditEvent::new(now, EventKind::Expire, Outcome::Done)
                    .ticket(id)
                    .lease(record.ticket.lease_id())
                    .reason("not signed before expires_at");
                Self::log_best_effort(inner, &event);
                changed = true;
            }
        }
        for lease in inner.store.leases(State::Active).map_err(internal)? {
            let usage = inner.store.usage(&lease.id, now).map_err(internal)?;
            let Some(next) = lease::due_transition(&lease, &usage, now) else {
                continue;
            };
            inner
                .store
                .transition(&lease.id, State::Active, next, now)
                .map_err(internal)?;
            inner.watches.remove(&lease.id);
            self.deny_serial(lease.cert_serial);
            let kind = if next == State::Exhausted {
                EventKind::Exhaust
            } else {
                EventKind::Expire
            };
            let event = AuditEvent::new(now, kind, Outcome::Done)
                .lease(&lease.id)
                .cert(lease.cert_serial);
            Self::log_best_effort(inner, &event);
            changed = true;
        }
        Ok(changed)
    }

    // ----- the agent's side ---------------------------------------------------------------

    /// Submits a ticket file sent with `session_key` (the key the connection authenticated
    /// with: the submitter holds it). A ticket that fits no template is rejected with every
    /// reason, before it reaches the approver.
    pub fn submit(
        &self,
        session_key: &PublicKey,
        text: &[u8],
        caller: &CallerFacts,
    ) -> Result<Submitted, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let reject = |inner: &mut Inner, error: ApiError| {
            let reason = if error.reasons.is_empty() {
                error.message.clone()
            } else {
                error.reasons.join("; ")
            };
            let event = AuditEvent::new(now, EventKind::Submit, Outcome::Denied)
                .caller(caller)
                .reason(reason);
            Self::log_best_effort(inner, &event);
            Err(error)
        };

        let Ok(text) = std::str::from_utf8(text) else {
            return reject(&mut inner, ApiError::new("the ticket file is not UTF-8"));
        };
        let request = match TicketRequest::from_yaml(text) {
            Ok(request) => request,
            Err(e) => {
                return reject(
                    &mut inner,
                    ApiError::with_reasons("ticket rejected", vec![e.to_string()]),
                );
            }
        };
        let waiting = inner.store.count(State::Pending).map_err(internal)?;
        if waiting >= self.config.max_pending {
            return reject(
                &mut inner,
                ApiError::new(format!(
                    "{waiting} tickets are already waiting for the approver; try again later"
                )),
            );
        }
        let amends = match &request.ticket.amends {
            Some(id) => inner.store.lease(id).map_err(internal)?,
            None => None,
        };
        let revises = match &request.ticket.revises {
            Some(id) => inner.store.ticket(id).map_err(internal)?,
            None => None,
        };
        let random = keys::random_array::<10>().map_err(internal)?;
        let submission = Submission {
            id: TicketId::from_parts(self.clock.now_ms(), random),
            now,
            session_key: fingerprint(session_key)?,
            amends: amends.as_ref(),
            revises: revises.as_ref(),
        };
        let ticket = match fit::submit(&self.config.policy, &request, &submission) {
            Ok(ticket) => ticket,
            Err(rejection) => {
                return reject(
                    &mut inner,
                    ApiError::with_reasons("ticket rejected", rejection.reasons),
                );
            }
        };
        let pubkey = session_key.to_openssh().map_err(internal)?;
        let event = AuditEvent::new(now, EventKind::Submit, Outcome::Allowed)
            .ticket(&ticket.id)
            .lease(ticket.lease_id())
            .caller(caller);
        Self::logged(&mut inner, event, |inner| {
            inner
                .store
                .insert_pending(&ticket, &pubkey, now)
                .map_err(internal)
        })?;
        drop(inner);
        self.changed.notify_waiters();
        self.notify_waiting(&ticket);
        Ok(Submitted {
            id: ticket.id.clone(),
            canonical: canonical_text(&ticket)?,
        })
    }

    /// Tells the approver a ticket waits. Off the request's thread; a failure is only logged.
    fn notify_waiting(&self, ticket: &Ticket) {
        let kind = if ticket.ticket.amends.is_some() {
            "Amendment"
        } else {
            "Ticket"
        };
        let notification = Notification {
            title: format!("{kind} waiting: {}", ticket.ticket.title),
            message: format!(
                "{} (template {}, revision {}). To review it: writ sign {}",
                ticket.id, ticket.template, ticket.ticket.revision, ticket.id
            ),
            priority: Priority::Default,
            tags: vec!["writ".to_owned(), "ticket".to_owned()],
        };
        let notifier = Arc::clone(&self.notifier);
        std::thread::spawn(move || {
            if let Err(e) = notifier.notify(&notification) {
                eprintln!("writd: notification failed: {e}");
            }
        });
    }

    /// Waits until the ticket is decided. Only the session that submitted it (same key) can
    /// wait on it; to anyone else it doesn't exist.
    /// The store is read on a blocking thread, never on the runtime's.
    pub async fn wait(&self, id: &TicketId, session_key: &PublicKey) -> Result<Decision, ApiError> {
        let fingerprint = fingerprint(session_key)?;
        let service = self
            .me
            .upgrade()
            .ok_or_else(|| internal("the service is gone"))?;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (me, ticket, key) = (Arc::clone(&service), id.clone(), fingerprint.clone());
            let decided = tokio::task::spawn_blocking(move || me.decision(&ticket, &key))
                .await
                .map_err(internal)??;
            let deadline = match decided {
                Ok(decision) => return Ok(decision),
                Err(expires_at) => expires_at,
            };
            let left = self.now()?.seconds_until(deadline);
            let sleep =
                Duration::from_secs(u64::try_from(left.max(0)).unwrap_or(0) + 1).min(WAIT_RECHECK);
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep(sleep) => {
                    let me = Arc::clone(&service);
                    tokio::task::spawn_blocking(move || me.sweep()).await.map_err(internal)?;
                }
            }
        }
    }

    /// The decision, or the ticket's `expires_at` while it waits.
    fn decision(
        &self,
        id: &TicketId,
        session_key: &KeyFingerprint,
    ) -> Result<Result<Decision, Timestamp>, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let record = match inner.store.ticket(id).map_err(internal)? {
            Some(record) if &record.ticket.subject.session_key == session_key => record,
            _ => return Err(not_found(id)),
        };
        let lease_terms = |inner: &Inner, lease: &TicketId| -> Result<Lease, ApiError> {
            inner
                .store
                .lease(lease)
                .map_err(internal)?
                .ok_or_else(|| internal(format!("lease {lease} is missing")))
        };
        let decision = match record.state {
            State::Pending => return Ok(Err(record.ticket.limits.expires_at)),
            State::Active => {
                let lease = lease_terms(&inner, id)?;
                let certificate = inner
                    .store
                    .certificate(id)
                    .map_err(internal)?
                    .ok_or_else(|| internal(format!("lease {id} has no certificate")))?;
                Decision::Active {
                    lease: canonical_text(&lease.ticket)?,
                    certificate,
                }
            }
            State::Applied => {
                let lease = lease_terms(&inner, record.ticket.lease_id())?;
                Decision::Applied {
                    lease: canonical_text(&lease.ticket)?,
                }
            }
            State::Refused => Decision::Refused {
                feedback: record.feedback.unwrap_or_default(),
            },
            State::Expired => Decision::Expired,
            State::Revoked => Decision::Revoked,
            state @ (State::Closed | State::Exhausted) => Decision::Ended { state },
        };
        Ok(Ok(decision))
    }

    // ----- the approver's side ------------------------------------------------------------

    /// Pending tickets and active leases, or every ticket.
    pub fn list(&self, all: bool) -> Result<Listing, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let records = if all {
            inner.store.all_tickets().map_err(internal)?
        } else {
            let mut records = inner.store.tickets(State::Pending).map_err(internal)?;
            records.extend(inner.store.tickets(State::Active).map_err(internal)?);
            records.sort_by(|a, b| a.ticket.id.cmp(&b.ticket.id));
            records
        };
        Ok(Listing {
            tickets: records.iter().map(summary).collect(),
        })
    }

    /// A ticket's canonical bytes, and what it follows (for the diff).
    pub fn show(&self, id: &TicketId) -> Result<Shown, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let record = inner
            .store
            .ticket(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))?;
        let previous = if let Some(lease) = &record.ticket.ticket.amends {
            inner
                .store
                .lease(lease)
                .map_err(internal)?
                .map(|lease| -> Result<Previous, ApiError> {
                    Ok(Previous {
                        relation: Relation::Amends,
                        canonical: canonical_text(&lease.ticket)?,
                    })
                })
                .transpose()?
        } else {
            None
        };
        let previous = match (previous, &record.ticket.ticket.revises) {
            (Some(previous), _) => Some(previous),
            (None, Some(revised)) => inner
                .store
                .ticket(revised)
                .map_err(internal)?
                .map(|r| -> Result<Previous, ApiError> {
                    Ok(Previous {
                        relation: Relation::Revises,
                        canonical: canonical_text(&r.ticket)?,
                    })
                })
                .transpose()?,
            (None, None) => None,
        };
        Ok(Shown {
            state: record.state,
            canonical: canonical_text(&record.ticket)?,
            previous,
        })
    }

    /// Verifies an approver's SSHSIG over `signed` (namespace `writ-approval`); returns the
    /// approver's fingerprint.
    fn verify_approver(&self, signed: &[u8], signature: &str) -> Result<KeyFingerprint, String> {
        let key = sshsig::verify(&self.approver_keys, APPROVAL_NAMESPACE, signed, signature)
            .map_err(|e| match e {
                writ_crypto::Error::Namespace { found, .. } => {
                    format!("the signature is in namespace {found:?}, not {APPROVAL_NAMESPACE:?}")
                }
                writ_crypto::Error::UnknownSigner(fp) => {
                    format!("the signature is by {fp}, which is not in approvers")
                }
                writ_crypto::Error::BadSignature => {
                    "the signature does not match the signed bytes".to_owned()
                }
                e => format!("unreadable signature: {e}"),
            })?;
        fingerprint(key).map_err(|e| e.message)
    }

    /// Accepts an approval: an approver's SSHSIG over the canonical bytes of the submitted
    /// ticket or a narrowing of it. A ticket becomes an active lease with a certificate; an
    /// amendment becomes the terms of its lease. Anything wrong denies, and the ticket stays
    /// pending.
    pub fn approve(
        &self,
        id: &TicketId,
        request: &ApproveRequest,
        caller: &CallerFacts,
    ) -> Result<Ack, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let record = inner
            .store
            .ticket(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))?;
        // An amendment's approval is logged as `amend`, a new lease's as `grant`.
        let kind = if record.ticket.ticket.amends.is_some() {
            EventKind::Amend
        } else {
            EventKind::Grant
        };
        let deny = |inner: &mut Inner, reason: String, approver: Option<&KeyFingerprint>| {
            let mut event = AuditEvent::new(now, kind, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller)
                .reason(reason.clone());
            if let Some(approver) = approver {
                event = event.approver(approver);
            }
            Self::log_best_effort(inner, &event);
            Err(ApiError::new(format!("approval refused: {reason}")))
        };
        if record.state != State::Pending {
            let reason = format!("ticket {id} is {}, not pending", record.state);
            return deny(&mut inner, reason, None);
        }
        let signed = match Ticket::from_canonical(request.signed.as_bytes()) {
            Ok(signed) => signed,
            Err(e) => return deny(&mut inner, e.to_string(), None),
        };
        let approver = match self.verify_approver(request.signed.as_bytes(), &request.signature) {
            Ok(approver) => approver,
            Err(reason) => return deny(&mut inner, reason, None),
        };
        let approval = Approval {
            approver: approver.clone(),
            namespace: APPROVAL_NAMESPACE.to_owned(),
            sshsig: request.signature.clone(),
        };

        if let Some(lease_id) = record.ticket.ticket.amends.clone() {
            let Some(lease) = inner.store.lease(&lease_id).map_err(internal)? else {
                return deny(
                    &mut inner,
                    format!("lease {lease_id} is missing"),
                    Some(&approver),
                );
            };
            let (updated, applied) = match lease::apply_amendment(
                &self.config.policy,
                &lease,
                &record,
                signed,
                approval,
                now,
            ) {
                Ok(result) => result,
                Err(e) => return deny(&mut inner, e.to_string(), Some(&approver)),
            };
            let event = AuditEvent::new(now, EventKind::Amend, Outcome::Allowed)
                .lease(&lease_id)
                .ticket(id)
                .cert(updated.cert_serial)
                .approver(&approver)
                .caller(caller);
            Self::logged(&mut inner, event, |inner| {
                inner
                    .store
                    .apply_amendment(&updated, &applied, now)
                    .map_err(internal)
            })?;
            drop(inner);
            self.changed.notify_waiters();
            return Ok(Ack {
                id: id.clone(),
                state: State::Applied,
            });
        }

        let session_key = match self.session_key(&inner, &record) {
            Ok(key) => key,
            Err(reason) => return deny(&mut inner, reason, Some(&approver)),
        };
        let serial = keys::random_serial().map_err(internal)?;
        let lease =
            match lease::activate(&self.config.policy, &record, signed, approval, serial, now) {
                Ok(lease) => lease,
                Err(e) => return deny(&mut inner, e.to_string(), Some(&approver)),
            };
        let watch = match self.watch_session(&lease) {
            Ok(watch) => watch,
            Err(reason) => return deny(&mut inner, reason, Some(&approver)),
        };
        let valid_after = now.saturating_sub_seconds(CLOCK_SKEW_SECONDS).unix();
        let certificate = self
            .ca
            .issue(&CertificateRequest {
                subject: &session_key,
                serial,
                key_id: lease.id.as_str(),
                principals: &[PRINCIPAL],
                valid_after: u64::try_from(valid_after).unwrap_or(0),
                valid_before: u64::try_from(lease.ticket.limits.expires_at.unix()).unwrap_or(0),
            })
            .and_then(|cert| Ok(cert.to_openssh()?))
            .map_err(internal)?;
        let event = AuditEvent::new(now, EventKind::Grant, Outcome::Allowed)
            .lease(&lease.id)
            .cert(serial)
            .approver(&approver)
            .caller(caller);
        Self::logged(&mut inner, event, |inner| {
            inner
                .store
                .activate(&lease, &certificate, now)
                .map_err(internal)
        })?;
        if let Some(watch) = watch {
            inner.watches.insert(lease.id.clone(), watch);
        }
        drop(inner);
        self.changed.notify_waiters();
        Ok(Ack {
            id: id.clone(),
            state: State::Active,
        })
    }

    /// The session public key a ticket was submitted with, checked against its fingerprint.
    fn session_key(&self, inner: &Inner, record: &TicketRecord) -> Result<PublicKey, String> {
        let text = inner
            .store
            .session_pubkey(&record.ticket.id)
            .map_err(|e| e.to_string())?
            .ok_or("the ticket has no session key")?;
        let key = PublicKey::from_openssh(&text).map_err(|e| e.to_string())?;
        let matches = key.fingerprint(HashAlg::Sha256).to_string()
            == record.ticket.subject.session_key.as_str();
        if !matches {
            return Err("the stored session key doesn't match the ticket".to_owned());
        }
        Ok(key)
    }

    /// Starts watching the session process a lease is bound to (`subject.caller`), if any.
    /// A daemon that can't watch processes can't grant such a lease: it would outlive its
    /// session.
    fn watch_session(&self, lease: &Lease) -> Result<Option<WatchHandle>, String> {
        let Some(constraint) = &lease.ticket.subject.caller else {
            return Ok(None);
        };
        let target = &constraint.descends_from;
        let process = ProcessRef {
            pid: target.pid,
            generation: target.generation,
            executable: PathBuf::from(&target.executable),
            code_identity: target.code_identity.clone(),
        };
        let me = self.me.clone();
        let lease_id = lease.id.clone();
        let on_exit = Box::new(move || {
            // Possibly called right away, while the caller holds the state lock: revoke from
            // another thread.
            std::thread::spawn(move || {
                if let Some(service) = me.upgrade() {
                    service.session_ended(&lease_id);
                }
            });
        });
        self.watcher
            .watch(&process, on_exit)
            .map(Some)
            .map_err(|e| format!("the lease is bound to a session the daemon can't watch: {e}"))
    }

    /// The session process of a lease ended: the lease is revoked.
    fn session_ended(&self, lease_id: &TicketId) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        let Ok(Some(lease)) = inner.store.lease(lease_id) else {
            return;
        };
        if lease.state != State::Active {
            return;
        }
        if let Err(e) = inner
            .store
            .transition(lease_id, State::Active, State::Revoked, now)
        {
            eprintln!("writd: cannot revoke {lease_id} after its session ended: {e}");
            return;
        }
        inner.watches.remove(lease_id);
        self.deny_serial(lease.cert_serial);
        let event = AuditEvent::new(now, EventKind::Revoke, Outcome::Done)
            .lease(lease_id)
            .cert(lease.cert_serial)
            .reason("the session's process ended");
        Self::log_best_effort(&mut inner, &event);
        drop(inner);
        self.changed.notify_waiters();
    }

    /// With `decisions: signed`, an approver signature over `document` is required; with
    /// `open`, a signature is optional but checked when given.
    fn decision_signer(
        &self,
        document: &[u8],
        signature: Option<&str>,
    ) -> Result<Option<KeyFingerprint>, String> {
        match (self.config.decisions, signature) {
            (_, Some(signature)) => self.verify_approver(document, signature).map(Some),
            (Decisions::Signed, None) => {
                Err("this daemon requires an approver signature (decisions: signed)".to_owned())
            }
            (Decisions::Open, None) => Ok(None),
        }
    }

    /// Refuses a pending ticket with feedback for the agent.
    pub fn refuse(
        &self,
        id: &TicketId,
        request: &RefuseRequest,
        caller: &CallerFacts,
    ) -> Result<Ack, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let record = inner
            .store
            .ticket(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))?;
        let deny = |inner: &mut Inner, reason: String| {
            let event = AuditEvent::new(now, EventKind::Refuse, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller)
                .reason(reason.clone());
            Self::log_best_effort(inner, &event);
            Err(ApiError::new(format!("refusal not accepted: {reason}")))
        };
        let feedback = request.feedback.trim();
        if feedback.is_empty() {
            return deny(&mut inner, "the feedback is empty".to_owned());
        }
        if request.feedback.chars().count() > MAX_FEEDBACK_CHARS {
            return deny(
                &mut inner,
                format!("the feedback is longer than {MAX_FEEDBACK_CHARS} characters"),
            );
        }
        let document = Refusal::new(id.clone(), request.feedback.clone())
            .canonical_bytes()
            .map_err(internal)?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return deny(&mut inner, reason),
        };
        if record.state != State::Pending {
            return deny(
                &mut inner,
                format!("ticket {id} is {}, not pending", record.state),
            );
        }
        let mut event = AuditEvent::new(now, EventKind::Refuse, Outcome::Done)
            .ticket(id)
            .lease(record.ticket.lease_id())
            .caller(caller);
        if let Some(approver) = &approver {
            event = event.approver(approver);
        }
        Self::logged(&mut inner, event, |inner| {
            inner
                .store
                .refuse(id, &request.feedback, now)
                .map_err(internal)
        })?;
        drop(inner);
        self.changed.notify_waiters();
        Ok(Ack {
            id: id.clone(),
            state: State::Refused,
        })
    }

    /// Revokes an active lease (its certificate goes on the deny list and its open sessions
    /// are dropped), or withdraws a pending ticket.
    pub fn revoke(
        &self,
        id: &TicketId,
        request: &RevokeRequest,
        caller: &CallerFacts,
    ) -> Result<Ack, ApiError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        self.sweep_locked(&mut inner, now)?;
        let record = inner
            .store
            .ticket(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))?;
        let deny = |inner: &mut Inner, reason: String| {
            let event = AuditEvent::new(now, EventKind::Revoke, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller)
                .reason(reason.clone());
            Self::log_best_effort(inner, &event);
            Err(ApiError::new(format!("revocation not accepted: {reason}")))
        };
        let document = Revocation::new(id.clone())
            .canonical_bytes()
            .map_err(internal)?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return deny(&mut inner, reason),
        };
        let mut event = AuditEvent::new(now, EventKind::Revoke, Outcome::Done).caller(caller);
        if let Some(approver) = &approver {
            event = event.approver(approver);
        }
        match (record.state, inner.store.lease(id).map_err(internal)?) {
            (State::Active, Some(lease)) => {
                let event = event.lease(id).cert(lease.cert_serial);
                Self::logged(&mut inner, event, |inner| {
                    inner
                        .store
                        .transition(id, State::Active, State::Revoked, now)
                        .map_err(internal)
                })?;
                inner.watches.remove(id);
                self.deny_serial(lease.cert_serial);
            }
            (State::Pending, _) => {
                let event = event.ticket(id).lease(record.ticket.lease_id());
                Self::logged(&mut inner, event, |inner| {
                    inner
                        .store
                        .transition(id, State::Pending, State::Revoked, now)
                        .map_err(internal)
                })?;
            }
            (state, _) => {
                return deny(
                    &mut inner,
                    format!("ticket {id} is {state}: nothing to revoke"),
                );
            }
        }
        drop(inner);
        self.changed.notify_waiters();
        Ok(Ack {
            id: id.clone(),
            state: State::Revoked,
        })
    }

    // ----- the gateway's side -------------------------------------------------------------

    /// Finds the single active lease a session certificate stands for and checks the caller
    /// against its constraint. Run when a certificate is presented (`event: connect`) and
    /// again before each command (`event` of that command, with the operation it needs).
    pub fn authorize(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        operation: Option<Operation>,
    ) -> Result<Lease, Denial> {
        let fail = |code: DenyCode, reason: String| Denial {
            code,
            reason,
            hint: None,
        };
        let now = self.now().map_err(|e| fail(DenyCode::Invalid, e.message))?;
        let mut inner = self
            .lock()
            .map_err(|e| fail(DenyCode::Invalid, e.message))?;
        if let Err(e) = self.sweep_locked(&mut inner, now) {
            return Err(fail(DenyCode::Invalid, e.message));
        }
        let kind = match operation {
            None => EventKind::Connect,
            Some(Operation::CommitSign) => EventKind::Sign,
            Some(Operation::Push) => EventKind::Push,
            Some(Operation::Fetch) => EventKind::Fetch,
        };
        let decision =
            Self::lease_for(&mut inner, cert, caller, now).and_then(|lease| match operation {
                Some(op) if !lease.ticket.allows(op) => Err(Denial {
                    code: DenyCode::Operation,
                    reason: format!(
                        "outside ticket {}: operation {op} is not in the lease",
                        lease.id
                    ),
                    hint: Some(format!(
                        "If needed, submit an amendment (ticket.amends: {})",
                        lease.id
                    )),
                }),
                _ => Ok(lease),
            });
        let mut event = AuditEvent::new(
            now,
            kind,
            if decision.is_ok() {
                Outcome::Allowed
            } else {
                Outcome::Denied
            },
        )
        .cert(cert.serial)
        .caller(caller);
        if let Ok(id) = cert.key_id.parse::<TicketId>() {
            event = event.lease(&id);
        }
        match decision {
            Ok(lease) => {
                if let Err(e) = Self::log(&mut inner, &event) {
                    return Err(fail(DenyCode::Invalid, e.message));
                }
                Ok(lease)
            }
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.denial(&denial));
                Err(denial)
            }
        }
    }

    fn lease_for(
        inner: &mut Inner,
        cert: &CertIdentity,
        caller: &CallerFacts,
        now: Timestamp,
    ) -> Result<Lease, Denial> {
        let no_lease = || Denial {
            code: DenyCode::NoLease,
            reason: "no lease matches this certificate".to_owned(),
            hint: None,
        };
        let id: TicketId = cert.key_id.parse().map_err(|_| no_lease())?;
        let found = inner.store.lease(&id).map_err(|e| Denial {
            code: DenyCode::Invalid,
            reason: internal(e).message,
            hint: None,
        })?;
        let lease = policy::resolve_lease(found.iter(), cert)?.clone();
        if lease.state != State::Active {
            return Err(Denial {
                code: DenyCode::NotActive,
                reason: format!("lease {} is {}", lease.id, lease.state),
                hint: None,
            });
        }
        if now >= lease.ticket.limits.expires_at {
            return Err(Denial {
                code: DenyCode::Expired,
                reason: format!("lease {} has expired", lease.id),
                hint: None,
            });
        }
        caller::check(lease.ticket.subject.caller.as_ref(), caller).map_err(|e| Denial {
            code: DenyCode::Caller,
            reason: e.to_string(),
            hint: None,
        })?;
        Ok(lease)
    }

    /// Logs a request the gateway turned away on its own, without a lease decision: a
    /// certificate refused before any lease lookup (unknown CA, expired, revoked, wrong
    /// principal), a caller the attestor can't attest, a command it doesn't serve, an unknown
    /// repo, a ref update or a signature it refused.
    pub fn gateway_denied(&self, denial: &GatewayDenial, caller: &CallerFacts) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        let mut event = AuditEvent::new(now, denial.kind, Outcome::Denied)
            .caller(caller)
            .refs(denial.refs.iter().cloned())
            .reason(denial.reason.clone());
        if let Some(serial) = denial.serial {
            event = event.cert(serial);
        }
        if let Some(id) = denial
            .key_id
            .as_deref()
            .and_then(|k| k.parse::<TicketId>().ok())
        {
            event = event.lease(&id);
        }
        if let Some(repo) = &denial.repo {
            event = event.repo(repo);
        }
        Self::log_best_effort(&mut inner, &event);
    }
}

/// What the gateway denied on its own (see [`Service::gateway_denied`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDenial {
    pub kind: EventKind,
    /// The session certificate's serial, when one was presented.
    pub serial: Option<u64>,
    /// The certificate's key id (the lease id, if it is one).
    pub key_id: Option<String>,
    pub repo: Option<RepoName>,
    /// The ref updates refused.
    pub refs: Vec<String>,
    pub reason: String,
}

impl GatewayDenial {
    pub fn new(kind: EventKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            serial: None,
            key_id: None,
            repo: None,
            refs: Vec::new(),
            reason: reason.into(),
        }
    }

    /// The certificate the request came with.
    pub fn cert(mut self, cert: &CertIdentity) -> Self {
        self.serial = Some(cert.serial);
        self.key_id = Some(cert.key_id.clone());
        self
    }

    pub fn repo(mut self, repo: &RepoName) -> Self {
        self.repo = Some(repo.clone());
        self
    }

    pub fn refs(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.refs = refs.into_iter().collect();
        self
    }
}

fn summary(record: &TicketRecord) -> Summary {
    let ticket = &record.ticket;
    Summary {
        id: ticket.id.clone(),
        lease: ticket.lease_id().clone(),
        state: record.state,
        template: ticket.template.clone(),
        revision: ticket.ticket.revision,
        repos: ticket.scope.repos.iter().cloned().collect(),
        created_at: ticket.created_at,
        expires_at: ticket.limits.expires_at,
        title: ticket.ticket.title.clone(),
    }
}
