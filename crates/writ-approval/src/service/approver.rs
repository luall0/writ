//! The approver's side: listing and showing tickets, approving, refusing, revoking.

use std::collections::BTreeSet;
use std::path::PathBuf;

use writ_core::caller::{CallerFacts, ProcessRef};
use writ_core::lease::{self, APPROVAL_NAMESPACE, Approval, Lease, Renewed, State, TicketRecord};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::signed::{Refusal, Revocation};
use writ_core::ticket::{Operation, Ticket};
use writ_core::units::Timestamp;
use writ_crypto::ca::CertificateRequest;
use writ_crypto::ssh_key::{HashAlg, PublicKey};
use writ_crypto::{keys, sshsig};
use writ_platform::WatchHandle;
use writ_proto::{
    Ack, ApproveRequest, Count, Decisions, Listing, OtherLease, Others, Previous, RefuseRequest,
    Relation, Renewal, RevokeRequest, Shown, Summary,
};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{CLOCK_SKEW_SECONDS, Inner, Service, canonical_text, fingerprint, internal};
use crate::PRINCIPAL;
use crate::{RefusalCode, ServiceError};
use writ_core::canonical::Canonical;

/// The most tickets `writ ls --all` returns: the most recent ones (the audit log holds the
/// whole history), so a listing never loads an unbounded table under the state lock.
pub const MAX_LISTED: usize = 200;

/// The most other active leases of a source `writ sign` lists (the rest are counted).
pub const MAX_OTHERS: usize = 10;

impl Service {
    /// Pending tickets and active leases, or the [`MAX_LISTED`] most recent tickets.
    pub fn list(&self, all: bool) -> Result<Listing, ServiceError> {
        let (_, inner) = self.begin()?;
        let records = if all {
            inner.store.recent_tickets(MAX_LISTED).map_err(internal)?
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

    /// A ticket's canonical bytes, what it follows (for the diff), the chain a renewal
    /// continues, and the other active leases from its source.
    pub fn show(&self, id: &TicketId) -> Result<Shown, ServiceError> {
        let (now, inner) = self.begin()?;
        let record = inner.record(id)?;
        let follows = match (&record.ticket.text.amends, &record.ticket.text.renews) {
            (Some(lease), _) => Some((lease, Relation::Amends)),
            (None, Some(lease)) => Some((lease, Relation::Renews)),
            (None, None) => None,
        };
        let previous = match follows {
            Some((lease, relation)) => inner
                .store
                .lease(lease)
                .map_err(internal)?
                .map(|lease| -> Result<Previous, ServiceError> {
                    Ok(Previous {
                        relation,
                        canonical: canonical_text(&lease.ticket)?,
                    })
                })
                .transpose()?,
            None => None,
        };
        let previous = match (previous, &record.ticket.text.revises) {
            (Some(previous), _) => Some(previous),
            (None, Some(revised)) => inner
                .store
                .ticket(revised)
                .map_err(internal)?
                .map(|r| -> Result<Previous, ServiceError> {
                    Ok(Previous {
                        relation: Relation::Revises,
                        canonical: canonical_text(&r.ticket)?,
                    })
                })
                .transpose()?,
            (None, None) => None,
        };
        let renewal = match &record.ticket.text.renews {
            Some(lease) => Self::renewal_view(&inner, lease, now)?,
            None => None,
        };
        Ok(Shown {
            state: record.state,
            canonical: canonical_text(&record.ticket)?,
            previous,
            renewal,
            others: Self::others(&inner, &record, now)?,
        })
    }

    /// The chain a renewal of `lease` continues: its original ticket, which renewal it is,
    /// the time used so far, and what the renewed lease used of its counts.
    fn renewal_view(
        inner: &Inner,
        lease: &TicketId,
        now: Timestamp,
    ) -> Result<Option<Renewal>, ServiceError> {
        let Some(renewed) = inner.store.lease(lease).map_err(internal)? else {
            return Ok(None);
        };
        let chain = inner.store.predecessors(lease).map_err(internal)?;
        let root = chain.last().unwrap_or(lease);
        let original = inner.record(root)?;
        let mut used_seconds = Self::used_seconds(inner, &renewed, now)?;
        for id in &chain {
            if let Some(earlier) = inner.store.lease(id).map_err(internal)? {
                used_seconds =
                    used_seconds.saturating_add(Self::used_seconds(inner, &earlier, now)?);
            }
        }
        let usage = inner.store.usage(lease, now).map_err(internal)?;
        Ok(Some(Renewal {
            original: canonical_text(&original.ticket)?,
            number: u32::try_from(chain.len())
                .map_err(internal)?
                .saturating_add(1),
            used_seconds,
            signatures: Count {
                used: usage.total().signatures,
                max: renewed.ticket.max_signatures(),
            },
            pushes: Count {
                used: usage.total().pushes,
                max: renewed.ticket.max_pushes(),
            },
            state: renewed.state,
        }))
    }

    /// The seconds a lease ran: from its submission to its end (now while it runs), never
    /// past its `expires_at`.
    pub(super) fn used_seconds(
        inner: &Inner,
        lease: &Lease,
        now: Timestamp,
    ) -> Result<u64, ServiceError> {
        let times = inner.store.times(&lease.id).map_err(internal)?;
        let end = if lease.state == State::Active {
            now
        } else {
            times.updated_at
        };
        let end = end.min(lease.ticket.limits.expires_at);
        Ok(u64::try_from(times.created_at.seconds_until(end).max(0)).unwrap_or(0))
    }

    /// The other active leases submitted from the ticket's source (not the lease it amends or
    /// renews): [`MAX_OTHERS`] of them, those that overlap the ticket first, and how many more.
    fn others(
        inner: &Inner,
        record: &TicketRecord,
        now: Timestamp,
    ) -> Result<Others, ServiceError> {
        let Some(source) = record.source else {
            return Ok(Others::default());
        };
        let ticket = &record.ticket;
        let skip = [Some(ticket.lease_id()), ticket.text.renews.as_ref()];
        let leases: Vec<Lease> = inner
            .store
            .active_from(source)
            .map_err(internal)?
            .into_iter()
            .filter(|lease| !skip.contains(&Some(&lease.id)) && lease.is_in_force(now))
            .collect();
        let more = u32::try_from(leases.len().saturating_sub(MAX_OTHERS)).map_err(internal)?;
        let mut listed: Vec<OtherLease> = leases
            .iter()
            .map(|lease| {
                let theirs = &lease.ticket.repos;
                // The same repository, with branches both may write.
                let overlap = theirs.iter().any(|(repo, other)| {
                    ticket.terms(repo).is_some_and(|mine| {
                        other
                            .branches
                            .iter()
                            .any(|b| mine.branches.iter().any(|m| m.intersects(b)))
                    })
                });
                let branches: BTreeSet<String> = theirs
                    .values()
                    .flat_map(|t| t.branches.iter().map(ToString::to_string))
                    .collect();
                let operations: BTreeSet<Operation> = theirs
                    .values()
                    .flat_map(|t| t.operations.iter().copied())
                    .collect();
                OtherLease {
                    id: lease.id.clone(),
                    repos: theirs.keys().cloned().collect(),
                    branches: branches.into_iter().collect(),
                    operations: operations.into_iter().collect(),
                    expires_at: lease.ticket.limits.expires_at,
                    overlap,
                }
            })
            .collect();
        // An overlap is never the one left out: those come first, then the others by id.
        listed.sort_by(|a, b| b.overlap.cmp(&a.overlap).then_with(|| a.id.cmp(&b.id)));
        listed.truncate(MAX_OTHERS);
        let shown = listed;
        Ok(Others { shown, more })
    }

    /// Verifies an approver's SSHSIG over `signed` (namespace `writ-approval`); returns the
    /// approver's fingerprint.
    pub(super) fn verify_approver(
        &self,
        signed: &[u8],
        signature: &str,
    ) -> Result<KeyFingerprint, String> {
        let approvers = self.approver_keys();
        let key = sshsig::verify(&approvers, APPROVAL_NAMESPACE, signed, signature).map_err(
            |e| match e {
                writ_crypto::CryptoError::Namespace { found, .. } => {
                    format!("the signature is in namespace {found:?}, not {APPROVAL_NAMESPACE:?}")
                }
                writ_crypto::CryptoError::UnknownSigner(fp) => {
                    format!("the signature is by {fp}, which is not in approvers")
                }
                writ_crypto::CryptoError::BadSignature => {
                    "the signature does not match the signed bytes".to_owned()
                }
                e => format!("unreadable signature: {e}"),
            },
        )?;
        fingerprint(key).map_err(|e| e.to_string())
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
    ) -> Result<Ack, ServiceError> {
        let (now, mut inner) = self.begin()?;
        let unknown = AuditEvent::new(now, EventKind::Grant, Outcome::Denied).caller(caller);
        let record = Self::record_or_deny(&mut inner, id, unknown)?;
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
            return denied.deny(&mut inner, RefusalCode::WrongState, reason);
        }
        let signed = match Ticket::from_canonical(request.signed.as_bytes()) {
            Ok(signed) => signed,
            Err(e) => return denied.deny(&mut inner, RefusalCode::Signature, e.to_string()),
        };
        let approver = match self.verify_approver(request.signed.as_bytes(), &request.signature) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, RefusalCode::Signature, reason),
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
        let state = match (&record.ticket.text.amends, &record.ticket.text.renews) {
            (Some(lease_id), _) => {
                self.apply_amendment_approval(&mut inner, lease_id, approving)?
            }
            (None, renews) => self.grant_lease(&mut inner, approving, renews.as_ref())?,
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
    ) -> Result<State, ServiceError> {
        let Approving {
            record,
            signed,
            approval,
            caller,
            now,
            denied,
        } = approving;
        let Some(lease) = inner.store.lease(lease_id).map_err(internal)? else {
            return denied.deny(
                inner,
                RefusalCode::WrongState,
                format!("lease {lease_id} is missing"),
            );
        };
        let approver = approval.approver.clone();
        let (updated, applied) =
            match lease::apply_amendment(&self.policy(), &lease, record, signed, approval, now) {
                Ok(result) => result,
                Err(e) => return denied.deny(inner, RefusalCode::Lifecycle, e.to_string()),
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

    /// An approved ticket becomes an active lease, with a certificate for its session key. A
    /// renewal (`renews`) also ends the lease it renews, in the same change.
    fn grant_lease(
        &self,
        inner: &mut Inner,
        approving: Approving<'_>,
        renews: Option<&TicketId>,
    ) -> Result<State, ServiceError> {
        let Approving {
            record,
            signed,
            approval,
            caller,
            now,
            denied,
        } = approving;
        let renewed = match renews {
            None => None,
            Some(id) => match inner.store.lease(id).map_err(internal) {
                Ok(Some(lease)) => {
                    let chain = inner.store.predecessors(id).map_err(internal);
                    let chain = denied.or_failed(inner, chain)?;
                    let renewals =
                        denied.or_failed(inner, u32::try_from(chain.len()).map_err(internal))?;
                    Some((lease, renewals))
                }
                Ok(None) => {
                    return denied.deny(
                        inner,
                        RefusalCode::WrongState,
                        format!("lease {id} is missing"),
                    );
                }
                Err(e) => return denied.failed(inner, e),
            },
        };
        let session_key = match self.session_key(inner, record) {
            Ok(key) => key,
            Err(reason) => return denied.deny(inner, RefusalCode::Session, reason),
        };
        // Checked again: a lease granted since the submission takes the slot it counted on.
        if let (Some(max), Some(source)) = (self.config.max_active_per_source, record.source) {
            let replaced = renewed
                .as_ref()
                .map(|(lease, _)| lease)
                .filter(|lease| {
                    lease.state == State::Active
                        && lease.ticket.subject.session_key == record.ticket.subject.session_key
                })
                .map(|lease| &lease.id);
            if let Err(e) = Self::active_slots(inner, source, max, replaced) {
                return denied.deny(inner, RefusalCode::TooManyActive, e.reason_text());
            }
        }
        let approver = approval.approver.clone();
        let serial = denied.or_failed(inner, keys::random_serial().map_err(internal))?;
        let policy = self.policy();
        let activated = match &renewed {
            None => lease::activate(&policy, record, signed, approval, serial, now),
            Some((old, renewals)) => lease::activate_renewal(
                &policy,
                record,
                signed,
                approval,
                serial,
                Renewed {
                    lease: old,
                    renewals: *renewals,
                    grace: self.config.renew_grace,
                },
                now,
            ),
        };
        let lease = match activated {
            Ok(lease) => lease,
            Err(e) => return denied.deny(inner, RefusalCode::Lifecycle, e.to_string()),
        };
        let watch = match self.watch_session(&lease) {
            Ok(watch) => watch,
            Err(reason) => return denied.deny(inner, RefusalCode::Session, reason),
        };
        // A time that doesn't fit fails the grant: no fallback (a 0 would mean "valid since
        // 1970").
        let valid_after = denied.or_failed(
            inner,
            u64::try_from(now.saturating_sub_seconds(CLOCK_SKEW_SECONDS).unix()).map_err(internal),
        )?;
        let valid_before = denied.or_failed(
            inner,
            u64::try_from(lease.ticket.limits.expires_at.unix()).map_err(internal),
        )?;
        let issued = self.opened().and_then(|opened| {
            opened
                .ca
                .issue(&CertificateRequest {
                    subject: &session_key,
                    serial,
                    key_id: lease.id.as_str(),
                    principals: &[PRINCIPAL],
                    valid_after,
                    valid_before,
                })
                .and_then(|cert| Ok(cert.to_openssh()?))
                .map_err(internal)
        });
        let certificate = denied.or_failed(inner, issued)?;
        let mut event = AuditEvent::new(now, EventKind::Grant, Outcome::Allowed)
            .lease(&lease.id)
            .cert(serial)
            .approver(&approver)
            .caller(caller);
        if let Some((old, _)) = &renewed {
            event = event.reason(format!("renews lease {}", old.id));
        }
        Self::logged(inner, event, |inner| match &renewed {
            None => inner
                .store
                .activate(&lease, &certificate, now)
                .map_err(internal),
            Some((old, _)) => inner
                .store
                .activate_renewal(&lease, &certificate, &old.id, old.state, now)
                .map_err(internal),
        })?;
        if let Some((old, _)) = &renewed {
            // The renewed lease ended with the change: its certificate is refused and its
            // sessions dropped (the renewal's certificate is a new one, for the same key).
            self.bar_serial(old.cert_serial);
            inner.watches.remove(&old.id);
            let ended = AuditEvent::new(now, EventKind::Renew, Outcome::Done)
                .lease(&old.id)
                .cert(old.cert_serial)
                .reason(format!("renewed by lease {}", lease.id));
            Self::log_best_effort(inner, &ended);
            self.deny_serial(old.cert_serial);
        }
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
    pub(super) fn watch_session(&self, lease: &Lease) -> Result<Option<WatchHandle>, String> {
        let Some(constraint) = &lease.ticket.subject.caller else {
            return Ok(None);
        };
        let target = &constraint.descends_from;
        let process = ProcessRef {
            pid: target.pid,
            generation: target.generation,
            executable: PathBuf::from(&target.executable),
            code_identity: target.code_identity.clone(),
            unbindable: None,
        };
        let me = self.me.clone();
        let (lease_id, serial) = (lease.id.clone(), lease.cert_serial);
        let on_exit = Box::new(move || {
            // Possibly called right away, while the caller holds the state lock: revoke from
            // another thread.
            std::thread::spawn(move || {
                if let Some(service) = me.upgrade() {
                    service.session_ended(&lease_id, serial);
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
    ) -> Result<Ack, ServiceError> {
        let (now, mut inner) = self.begin()?;
        let unknown = AuditEvent::new(now, EventKind::Refuse, Outcome::Denied).caller(caller);
        let record = Self::record_or_deny(&mut inner, id, unknown)?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Refuse, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller),
            "refusal not accepted",
        );
        if let Err(e) = lease::check_feedback(&request.feedback) {
            return denied.deny(&mut inner, RefusalCode::Feedback, e.to_string());
        }
        let document = denied.or_failed(
            &mut inner,
            Refusal::new(id.clone(), request.feedback.clone())
                .canonical_bytes()
                .map_err(internal),
        )?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, RefusalCode::Signature, reason),
        };
        if record.state != State::Pending {
            return denied.deny(
                &mut inner,
                RefusalCode::WrongState,
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
                .refuse(id, &request.feedback, approver.as_ref(), now)
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
    ) -> Result<Ack, ServiceError> {
        let (now, mut inner) = self.begin()?;
        let unknown = AuditEvent::new(now, EventKind::Revoke, Outcome::Denied).caller(caller);
        let record = Self::record_or_deny(&mut inner, id, unknown)?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Revoke, Outcome::Denied)
                .ticket(id)
                .lease(record.ticket.lease_id())
                .caller(caller),
            "revocation not accepted",
        );
        let document = denied.or_failed(
            &mut inner,
            Revocation::new(id.clone())
                .canonical_bytes()
                .map_err(internal),
        )?;
        let approver = match self.decision_signer(&document, request.signature.as_deref()) {
            Ok(approver) => approver,
            Err(reason) => return denied.deny(&mut inner, RefusalCode::Signature, reason),
        };
        let mut event = AuditEvent::new(now, EventKind::Revoke, Outcome::Done).caller(caller);
        if let Some(approver) = &approver {
            event = event.approver(approver);
        }
        match (record.state, inner.store.lease(id).map_err(internal)?) {
            // A reduction of privilege: applied even if the log can't take its line now
            // (kept and written once it can), and the certificate is refused first.
            (State::Active, Some(lease)) => {
                self.bar_serial(lease.cert_serial);
                inner.watches.remove(id);
                let event = event.lease(id).cert(lease.cert_serial);
                let done = Self::reduced(&mut inner, event, |inner| {
                    inner
                        .store
                        .transition(id, State::Active, State::Revoked, now)
                        .map_err(internal)
                });
                self.deny_serial(lease.cert_serial);
                done?;
            }
            (State::Pending, _) => {
                let event = event.ticket(id).lease(record.ticket.lease_id());
                Self::reduced(&mut inner, event, |inner| {
                    inner
                        .store
                        .transition(id, State::Pending, State::Revoked, now)
                        .map_err(internal)
                })?;
            }
            (state, _) => {
                return denied.deny(
                    &mut inner,
                    RefusalCode::WrongState,
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
pub(super) struct Denied {
    event: AuditEvent,
    prefix: &'static str,
}

impl Denied {
    pub(super) fn new(event: AuditEvent, prefix: &'static str) -> Self {
        Self { event, prefix }
    }

    /// The same denial, its audit line with more fields (a proof's key and namespace).
    pub(super) fn with(&self, edit: impl FnOnce(AuditEvent) -> AuditEvent) -> Self {
        Self {
            event: edit(self.event.clone()),
            prefix: self.prefix,
        }
    }

    pub(super) fn approver(&self, approver: &KeyFingerprint) -> Self {
        Self {
            event: self.event.clone().approver(approver),
            prefix: self.prefix,
        }
    }

    /// Logs the denial of a request the daemon couldn't complete (its cause goes to the
    /// daemon's log, never to the line or the caller) and returns the internal error: every
    /// turned-down request writes its line (hard rule 9), an internal fault too.
    pub(super) fn failed<T>(
        &self,
        inner: &mut Inner,
        error: ServiceError,
    ) -> Result<T, ServiceError> {
        tracing::error!(error = %error.detail(), "{}", self.prefix);
        Service::log_best_effort(
            inner,
            &self
                .event
                .clone()
                .reason("internal error (see the daemon's log)"),
        );
        Err(error)
    }

    /// `result`, or its error logged as [`Denied::failed`].
    pub(super) fn or_failed<T>(
        &self,
        inner: &mut Inner,
        result: Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        result.or_else(|error| self.failed(inner, error))
    }

    /// Logs the denial with its reason and returns the error, with its code.
    pub(super) fn deny<T>(
        &self,
        inner: &mut Inner,
        code: RefusalCode,
        reason: impl Into<String>,
    ) -> Result<T, ServiceError> {
        let reason = reason.into();
        Service::log_best_effort(inner, &self.event.clone().reason(reason.clone()));
        Err(ServiceError::refused(
            code,
            format!("{}: {reason}", self.prefix),
        ))
    }
}

fn summary(record: &TicketRecord) -> Summary {
    let ticket = &record.ticket;
    Summary {
        id: ticket.id.clone(),
        lease: ticket.lease_id().clone(),
        state: record.state,
        templates: ticket.templates().into_iter().cloned().collect(),
        revision: ticket.text.revision,
        repos: ticket.repos.keys().cloned().collect(),
        created_at: ticket.created_at,
        expires_at: ticket.limits.expires_at,
        title: ticket.text.title.clone(),
    }
}
