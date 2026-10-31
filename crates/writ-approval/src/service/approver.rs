//! The approver's side: listing and showing tickets, approving, refusing, revoking.

use std::path::PathBuf;

use writ_core::caller::{CallerFacts, ProcessRef};
use writ_core::lease::{self, APPROVAL_NAMESPACE, Approval, Lease, State, TicketRecord};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::signed::{MAX_FEEDBACK_CHARS, Refusal, Revocation};
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::ca::CertificateRequest;
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_crypto::{keys, sshsig};
use writ_platform::WatchHandle;
use writ_proto::{
    Ack, ApiError, ApproveRequest, Decisions, Listing, Previous, RefuseRequest, Relation,
    RevokeRequest, Shown, Summary,
};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{CLOCK_SKEW_SECONDS, Inner, Service, canonical_text, fingerprint, internal};
use crate::PRINCIPAL;
use writ_core::canonical::Canonical;

impl Service {
    /// Pending tickets and active leases, or every ticket.
    pub fn list(&self, all: bool) -> Result<Listing, ApiError> {
        let (_, inner) = self.begin()?;
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
        let (_, inner) = self.begin()?;
        let record = inner.record(id)?;
        let previous = if let Some(lease) = &record.ticket.text.amends {
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
        let previous = match (previous, &record.ticket.text.revises) {
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
        let (now, mut inner) = self.begin()?;
        let record = inner.record(id)?;
        // An amendment's approval is logged as `amend`, a new lease's as `grant`.
        let kind = if record.ticket.text.amends.is_some() {
            EventKind::Amend
        } else {
            EventKind::Grant
        };
        let denied = Denied::new(
            AuditEvent::new(now, kind, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller),
            "approval refused",
        );
        if record.state != State::Pending {
            let reason = format!("ticket {id} is {}, not pending", record.state);
            return denied.deny(&mut inner, reason);
        }
        let signed = match Ticket::from_canonical(request.signed.as_bytes()) {
            Ok(signed) => signed,
            Err(e) => return denied.deny(&mut inner, e.to_string()),
        };
        let approver = match self.verify_approver(request.signed.as_bytes(), &request.signature) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, reason),
        };
        let approving = Approving {
            record: &record,
            signed,
            approval: Approval {
                approver: approver.clone(),
                namespace: APPROVAL_NAMESPACE.to_owned(),
                sshsig: request.signature.clone(),
            },
            caller,
            now,
            denied: denied.approver(&approver),
        };
        let state = match &record.ticket.text.amends {
            Some(lease_id) => self.apply_amendment_approval(&mut inner, lease_id, approving)?,
            None => self.grant_lease(&mut inner, approving)?,
        };
        drop(inner);
        self.changed.notify_waiters();
        Ok(Ack {
            id: id.clone(),
            state,
        })
    }

    /// An approved amendment becomes the terms of its lease.
    fn apply_amendment_approval(
        &self,
        inner: &mut Inner,
        lease_id: &TicketId,
        approving: Approving<'_>,
    ) -> Result<State, ApiError> {
        let Approving {
            record,
            signed,
            approval,
            caller,
            now,
            denied,
        } = approving;
        let Some(lease) = inner.store.lease(lease_id).map_err(internal)? else {
            return denied.deny(inner, format!("lease {lease_id} is missing"));
        };
        let approver = approval.approver.clone();
        let (updated, applied) = match lease::apply_amendment(
            &self.config.policy,
            &lease,
            record,
            signed,
            approval,
            now,
        ) {
            Ok(result) => result,
            Err(e) => return denied.deny(inner, e.to_string()),
        };
        let event = AuditEvent::new(now, EventKind::Amend, Outcome::Allowed)
            .lease(lease_id)
            .ticket(&record.ticket.id)
            .cert(updated.cert_serial)
            .approver(&approver)
            .caller(caller);
        Self::logged(inner, event, |inner| {
            inner
                .store
                .apply_amendment(&updated, &applied, now)
                .map_err(internal)
        })?;
        Ok(State::Applied)
    }

    /// An approved ticket becomes an active lease, with a certificate for its session key.
    fn grant_lease(&self, inner: &mut Inner, approving: Approving<'_>) -> Result<State, ApiError> {
        let Approving {
            record,
            signed,
            approval,
            caller,
            now,
            denied,
        } = approving;
        let session_key = match self.session_key(inner, record) {
            Ok(key) => key,
            Err(reason) => return denied.deny(inner, reason),
        };
        let approver = approval.approver.clone();
        let serial = keys::random_serial().map_err(internal)?;
        let lease =
            match lease::activate(&self.config.policy, record, signed, approval, serial, now) {
                Ok(lease) => lease,
                Err(e) => return denied.deny(inner, e.to_string()),
            };
        let watch = match self.watch_session(&lease) {
            Ok(watch) => watch,
            Err(reason) => return denied.deny(inner, reason),
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
        Self::logged(inner, event, |inner| {
            inner
                .store
                .activate(&lease, &certificate, now)
                .map_err(internal)
        })?;
        if let Some(watch) = watch {
            inner.watches.insert(lease.id.clone(), watch);
        }
        Ok(State::Active)
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
        let (now, mut inner) = self.begin()?;
        let record = inner.record(id)?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Refuse, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller),
            "refusal not accepted",
        );
        let feedback = request.feedback.trim();
        if feedback.is_empty() {
            return denied.deny(&mut inner, "the feedback is empty");
        }
        if request.feedback.chars().count() > MAX_FEEDBACK_CHARS {
            return denied.deny(
                &mut inner,
                format!("the feedback is longer than {MAX_FEEDBACK_CHARS} characters"),
            );
        }
        let document = Refusal::new(id.clone(), request.feedback.clone())
            .canonical_bytes()
            .map_err(internal)?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, reason),
        };
        if record.state != State::Pending {
            return denied.deny(
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
        let (now, mut inner) = self.begin()?;
        let record = inner.record(id)?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Revoke, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller),
            "revocation not accepted",
        );
        let document = Revocation::new(id.clone())
            .canonical_bytes()
            .map_err(internal)?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, reason),
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
                return denied.deny(
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
}

/// What an approval carries into [`Service::grant_lease`] or
/// [`Service::apply_amendment_approval`].
struct Approving<'a> {
    record: &'a TicketRecord,
    /// The ticket as signed: the submitted one or a narrowing of it.
    signed: Ticket,
    approval: Approval,
    caller: &'a CallerFacts,
    now: Timestamp,
    denied: Denied,
}

/// A turned-down approver request: the audit line it writes (event, ticket, caller, approver)
/// and the prefix of the error the approver sees.
#[derive(Clone)]
struct Denied {
    event: AuditEvent,
    prefix: &'static str,
}

impl Denied {
    fn new(event: AuditEvent, prefix: &'static str) -> Self {
        Self { event, prefix }
    }

    fn approver(&self, approver: &KeyFingerprint) -> Self {
        Self {
            event: self.event.clone().approver(approver),
            prefix: self.prefix,
        }
    }

    /// Logs the denial with its reason and returns the error.
    fn deny<T>(&self, inner: &mut Inner, reason: impl Into<String>) -> Result<T, ApiError> {
        let reason = reason.into();
        Service::log_best_effort(inner, &self.event.clone().reason(reason.clone()));
        Err(ApiError::new(format!("{}: {reason}", self.prefix)))
    }
}

fn summary(record: &TicketRecord) -> Summary {
    let ticket = &record.ticket;
    Summary {
        id: ticket.id.clone(),
        lease: ticket.lease_id().clone(),
        state: record.state,
        template: ticket.template.clone(),
        revision: ticket.text.revision,
        repos: ticket.scope.repos.iter().cloned().collect(),
        created_at: ticket.created_at,
        expires_at: ticket.limits.expires_at,
        title: ticket.text.title.clone(),
    }
}
