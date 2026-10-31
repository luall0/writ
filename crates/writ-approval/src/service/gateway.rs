//! The gateway's side: the lease a session certificate stands for, and what the gateway
//! denied on its own.

use writ_core::caller::{self, CallerFacts};
use writ_core::lease::{Lease, State};
use writ_core::names::{RepoName, TicketId};
use writ_core::policy::{self, CertIdentity, Denial, DenyCode};
use writ_core::ticket::Operation;
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Inner, Service, internal};

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
        let fail = |code: DenyCode, reason: String| Denial {
            code,
            reason,
            hint: None,
        };
        let (now, mut inner) = self
            .begin()
            .map_err(|e| fail(DenyCode::Invalid, e.to_string()))?;
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
                    return Err(fail(DenyCode::Invalid, e.to_string()));
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
        &self,
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
            reason: internal(e).to_string(),
            hint: None,
        })?;
        let lease = policy::resolve_lease(found.iter(), cert)?.clone();
        // The deny list first: a lease that ended is refused even if its state change hasn't
        // reached the store.
        if lease.state != State::Active || self.is_revoked(cert.serial) {
            let state = if lease.state == State::Active {
                State::Revoked
            } else {
                lease.state
            };
            return Err(Denial {
                code: DenyCode::NotActive,
                reason: format!("lease {} is {state}", lease.id),
                hint: None,
            });
        }
        if lease.ticket.is_expired(now) {
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
