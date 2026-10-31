//! The agent's side: submitting a ticket, waiting for the decision.

use std::sync::Arc;
use std::time::Duration;

use writ_core::caller::CallerFacts;
use writ_core::fit::{self, Submission};
use writ_core::lease::{Lease, State};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;
use writ_crypto::keys;
use writ_crypto::ssh_key::{Algorithm, EcdsaCurve, PublicKey};
use writ_platform::{Notification, Priority};
use writ_proto::{Decision, Submitted};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{
    Inner, MAX_PENDING_PER_SESSION, MAX_SUBMISSIONS_PER_MINUTE, MAX_TRACKED_SOURCES, Service,
    WAIT_RECHECK, canonical_text, fingerprint, internal, not_found,
};
use crate::ServiceError;

impl Service {
    /// Submits a ticket file sent with `session_key` (the key the connection authenticated
    /// with: the submitter holds it). A ticket that fits no template is rejected with every
    /// reason, before it reaches the approver.
    pub fn submit(
        &self,
        session_key: &PublicKey,
        text: &[u8],
        caller: &CallerFacts,
    ) -> Result<Submitted, ServiceError> {
        let (now, mut inner) = self.begin()?;
        Self::within_rate(&mut inner, caller, now)?;
        let reject = |inner: &mut Inner, error: ServiceError| {
            let reason = error.reason_text();
            let event = AuditEvent::new(now, EventKind::Submit, Outcome::Denied)
                .caller(caller)
                .reason(reason);
            Self::log_best_effort(inner, &event);
            Err(error)
        };

        // Decided here, not by which algorithms the SSH library happens to verify: a session
        // key is made by `writ` (Ed25519) or a Secure Enclave (P-256).
        let algorithm = session_key.algorithm();
        if !matches!(
            algorithm,
            Algorithm::Ed25519
                | Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256
                }
        ) {
            return reject(
                &mut inner,
                ServiceError::refused(format!(
                    "the session key is {algorithm}: it must be ssh-ed25519 or ecdsa-sha2-nistp256"
                )),
            );
        }
        let Ok(text) = std::str::from_utf8(text) else {
            return reject(
                &mut inner,
                ServiceError::refused("the ticket file is not UTF-8"),
            );
        };
        let request = match TicketRequest::from_yaml(text) {
            Ok(request) => request,
            Err(e) => {
                return reject(
                    &mut inner,
                    ServiceError::rejected("ticket rejected", vec![e.to_string()]),
                );
            }
        };
        let waiting = inner.store.count(State::Pending).map_err(internal)?;
        if waiting >= self.config.max_pending {
            return reject(
                &mut inner,
                ServiceError::refused(format!(
                    "{waiting} tickets are already waiting for the approver; try again later"
                )),
            );
        }
        let session = fingerprint(session_key)?;
        let mine = inner
            .store
            .tickets(State::Pending)
            .map_err(internal)?
            .iter()
            .filter(|r| r.ticket.subject.session_key == session)
            .count();
        if mine >= MAX_PENDING_PER_SESSION {
            return reject(
                &mut inner,
                ServiceError::refused(format!(
                    "this session already has {mine} tickets waiting for the approver"
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
            session_key: session,
            amends: amends.as_ref(),
            revises: revises.as_ref(),
        };
        let ticket = match fit::submit(&self.config.policy, &request, &submission) {
            Ok(ticket) => ticket,
            Err(rejection) => {
                return reject(
                    &mut inner,
                    ServiceError::rejected("ticket rejected", rejection.reasons),
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

    /// Counts a submission from the caller's source address against
    /// [`MAX_SUBMISSIONS_PER_MINUTE`]. Over the rate, it is refused; only the first refusal
    /// of a burst is logged, and the count of the others with the next submission that
    /// passes, so a flood can't fill the audit log.
    fn within_rate(
        inner: &mut Inner,
        caller: &CallerFacts,
        now: Timestamp,
    ) -> Result<(), ServiceError> {
        let source = caller.source_addr;
        if inner.submissions.len() >= MAX_TRACKED_SOURCES
            && !inner.submissions.contains_key(&source)
        {
            inner.submissions.clear();
        }
        let window = inner.submissions.entry(source).or_default();
        while window
            .times
            .front()
            .is_some_and(|t| t.seconds_until(now) >= 60)
        {
            window.times.pop_front();
        }
        let event = |reason: String| {
            AuditEvent::new(now, EventKind::Submit, Outcome::Denied)
                .caller(caller)
                .reason(reason)
        };
        if window.times.len() >= MAX_SUBMISSIONS_PER_MINUTE {
            let first = window.refused == 0;
            window.refused += 1;
            let reason = format!(
                "more than {MAX_SUBMISSIONS_PER_MINUTE} submissions a minute from this address"
            );
            if first {
                Self::log_best_effort(inner, &event(reason.clone()));
            }
            return Err(ServiceError::refused(format!("{reason}; try again later")));
        }
        window.times.push_back(now);
        let refused = std::mem::take(&mut window.refused);
        if refused > 1 {
            let reason = format!(
                "{} more submissions from this address were refused over the rate",
                refused - 1
            );
            Self::log_best_effort(inner, &event(reason));
        }
        Ok(())
    }

    /// Tells the approver a ticket waits: queued for the notification worker, so the request
    /// never waits on the sink. A failure is only logged; a full queue counts it.
    fn notify_waiting(&self, ticket: &Ticket) {
        let kind = if ticket.text.amends.is_some() {
            "Amendment"
        } else {
            "Ticket"
        };
        let notification = Notification {
            title: format!("{kind} waiting: {}", ticket.text.title),
            message: format!(
                "{} (template {}, revision {}). To review it: writ sign {}",
                ticket.id, ticket.template, ticket.text.revision, ticket.id
            ),
            priority: Priority::Default,
            tags: vec!["writ".to_owned(), "ticket".to_owned()],
        };
        if let Ok(outbox) = self.notifications.lock()
            && outbox.try_send(notification).is_err()
        {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Waits until the ticket is decided. Only the session that submitted it (same key) can
    /// wait on it; to anyone else it doesn't exist.
    /// The store is read on a blocking thread, never on the runtime's.
    pub async fn wait(
        &self,
        id: &TicketId,
        session_key: &PublicKey,
    ) -> Result<Decision, ServiceError> {
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
    ) -> Result<Result<Decision, Timestamp>, ServiceError> {
        let (_, inner) = self.begin()?;
        let record = match inner.store.ticket(id).map_err(internal)? {
            Some(record) if &record.ticket.subject.session_key == session_key => record,
            _ => return Err(not_found(id)),
        };
        let lease_terms = |inner: &Inner, lease: &TicketId| -> Result<Lease, ServiceError> {
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
                signed_by: record.feedback_by,
            },
            State::Expired => Decision::Expired,
            State::Revoked => Decision::Revoked,
            state @ (State::Closed | State::Exhausted) => Decision::Ended { state },
        };
        Ok(Ok(decision))
    }
}
