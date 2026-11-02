//! The gateway's side: the lease a session certificate stands for, and what the gateway
//! denied on its own.

use writ_core::caller::{self, CallerFacts};
use writ_core::lease::{Lease, State};
use writ_core::names::{RepoName, TicketId};
use writ_core::policy::{self, CertIdentity, Context, Denial, DenyCode, FetchRequest};
use writ_core::ticket::Operation;
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, Counter, EventKind, Outcome};

use super::{Inner, Service, cert_event, internal};

impl Service {
    /// Finds the single active lease a session certificate stands for and checks the caller
    /// against its constraint. Run when a certificate is presented (`event: connect`) and
    /// again before each command (`event` of that command, with the operation it needs).
    pub fn authorize(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        operation: Option<Operation>,
    ) -> Result<Lease, Denial> {
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let kind = match operation {
            None => EventKind::Connect,
            Some(Operation::CommitSign) => EventKind::Sign,
            Some(Operation::Push) => EventKind::Push,
            Some(Operation::Fetch) => EventKind::Fetch,
        };
        let decision = self
            .lease_for(&mut inner, cert, caller, now)
            .and_then(|lease| {
                if let Some(operation) = operation {
                    policy::check_operation(&lease, operation)?;
                }
                Ok(lease)
            });
        let outcome = if decision.is_ok() {
            Outcome::Allowed
        } else {
            Outcome::Denied
        };
        let event = cert_event(now, kind, outcome, cert, caller);
        match decision {
            Ok(lease) => {
                let logged = match operation {
                    // A connection: coalesced per lease past its budget.
                    None => Self::log_connection(&mut inner, &event),
                    Some(_) => Self::log(&mut inner, &event),
                };
                if let Err(e) = logged {
                    return Err(Denial::new(DenyCode::Invalid, e.to_string()));
                }
                Ok(lease)
            }
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.denial(&denial));
                Err(denial)
            }
        }
    }

    /// A fetch from `repo` under the lease the certificate stands for: the single active
    /// lease, the policy's `decide_fetch` (the lease allows `fetch` and names the repo, the
    /// rate), and one operation taken from the rate window, under one lock, so
    /// `max_ops_per_minute` bounds fetches like every other operation. One `fetch` line in
    /// the audit log, whatever the outcome; a violation under `on_violation: revoke_lease`
    /// revokes the lease.
    pub fn fetch(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        repo: &RepoName,
    ) -> Result<Lease, Denial> {
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let event = cert_event(now, EventKind::Fetch, Outcome::Allowed, cert, caller).repo(repo);
        let refuse = |inner: &mut Inner, denial: Denial| {
            Self::log_best_effort(inner, &event.clone().denial(&denial));
            denial
        };
        let lease = match self.lease_for(&mut inner, cert, caller, now) {
            Ok(lease) => lease,
            Err(denial) => return Err(refuse(&mut inner, denial)),
        };
        let event = event.lease(&lease.id);
        let refuse = |inner: &mut Inner, denial: Denial| {
            Self::log_best_effort(inner, &event.clone().denial(&denial));
            denial
        };
        let usage = match inner.store.usage(&lease.id, now) {
            Ok(usage) => usage,
            Err(e) => {
                let denial = Denial::new(DenyCode::Invalid, internal(e).to_string());
                return Err(refuse(&mut inner, denial));
            }
        };
        let ctx = Context {
            config: &self.config.policy,
            lease: &lease,
            usage: &usage,
            caller,
            now,
        };
        if let Err(denial) = policy::decide_fetch(&ctx, &FetchRequest { repo: repo.clone() }) {
            let denial = refuse(&mut inner, denial);
            self.after_violation(inner, &lease, &denial);
            return Err(denial);
        }
        // Under the same lock as the decision; the store still refuses a lease that isn't
        // active whatever happens.
        match inner
            .store
            .consume(&lease.id, Counter::Fetch, u32::MAX, now)
        {
            Ok(true) => {}
            Ok(false) => {
                let reason = format!("lease {} is not active", lease.id);
                return Err(refuse(&mut inner, Denial::new(DenyCode::NotActive, reason)));
            }
            Err(e) => {
                let denial = Denial::new(DenyCode::Invalid, internal(e).to_string());
                return Err(refuse(&mut inner, denial));
            }
        }
        if let Err(e) = Self::log(&mut inner, &event) {
            return Err(Denial::new(DenyCode::Invalid, e.to_string()));
        }
        Ok(lease)
    }

    pub(super) fn lease_for(
        &self,
        inner: &mut Inner,
        cert: &CertIdentity,
        caller: &CallerFacts,
        now: Timestamp,
    ) -> Result<Lease, Denial> {
        let no_lease = || Denial::new(DenyCode::NoLease, "no lease matches this certificate");
        let id: TicketId = cert.key_id.parse().map_err(|_| no_lease())?;
        let found = inner
            .store
            .lease(&id)
            .map_err(|e| Denial::new(DenyCode::Invalid, internal(e).to_string()))?;
        let lease = policy::resolve_lease(found.iter(), cert)?.clone();
        // The deny list first: a lease that ended is refused even if its state change hasn't
        // reached the store.
        if lease.state != State::Active || self.is_revoked(cert.serial) {
            let state = if lease.state == State::Active {
                State::Revoked
            } else {
                lease.state
            };
            return Err(Denial::new(
                DenyCode::NotActive,
                format!("lease {} is {state}", lease.id),
            ));
        }
        if lease.ticket.is_expired(now) {
            return Err(Denial::new(
                DenyCode::Expired,
                format!("lease {} has expired", lease.id),
            ));
        }
        caller::check(lease.ticket.subject.caller.as_ref(), caller)
            .map_err(|e| Denial::new(DenyCode::Caller, e.to_string()))?;
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

    /// The lease it is about, without a certificate (the notes of a push).
    pub fn lease(mut self, lease: &TicketId) -> Self {
        self.key_id = Some(lease.to_string());
        self
    }

    pub fn refs(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.refs = refs.into_iter().collect();
        self
    }
}
