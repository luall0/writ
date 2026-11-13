//! Time: pending tickets and leases past `expires_at`, exhausted leases, ended sessions.

use writ_core::lease::{self, State};
use writ_core::names::TicketId;
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Inner, Service, internal};

/// When the sessions of a lease the daemon revokes are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Announce {
    /// At once.
    Now,
    /// By the caller, which has the request that caused it to answer first (the agent reads
    /// why); the certificate is refused meanwhile.
    Later,
}
use crate::ServiceError;

impl Service {
    /// Expires pending tickets and leases past `expires_at`, and exhausted leases, then prunes
    /// the operations no rate window counts any more. Called by the daemon's timer; every
    /// request also sweeps first ([`Service::begin`]), without the pruning.
    pub fn sweep(&self) {
        // Ended sessions whose notice couldn't record them (before the lock: it takes it).
        self.record_ended_sessions();
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        // Lines kept while the log was down are retried even when no request comes.
        let _ = Self::flush_unlogged(&mut inner);
        match self.sweep_locked(&mut inner, now) {
            Ok(true) => self.changed.notify_waiters(),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e.detail(), "sweep failed"),
        }
        // The rate window's old operations: here, not on every request (a write each time).
        // A failure only leaves rows that no window counts.
        if let Err(e) = inner.store.prune_ops(now) {
            tracing::error!(error = %e, "cannot prune old operations");
        }
    }

    pub(super) fn sweep_locked(
        &self,
        inner: &mut Inner,
        now: Timestamp,
    ) -> Result<bool, ServiceError> {
        Self::log_counted_denials(inner, now);
        Self::log_counted_submissions(inner, now);
        let mut changed = self.record_unrecorded(inner, now)?;
        for record in inner.store.tickets(State::Pending).map_err(internal)? {
            if let Some(next) = lease::pending_due(&record, now) {
                let id = &record.ticket.id;
                let event = AuditEvent::new(now, EventKind::Expire, Outcome::Done)
                    .ticket(id)
                    .lease(record.ticket.lease_id())
                    .reason("not signed before expires_at");
                Self::reduced(inner, event, |inner| {
                    inner
                        .store
                        .transition(id, State::Pending, next, now)
                        .map_err(internal)
                })?;
                changed = true;
            }
        }
        for lease in inner.store.leases(State::Active).map_err(internal)? {
            let usage = inner.store.usage(&lease.id, now).map_err(internal)?;
            let Some(next) = lease::due_transition(&lease, &usage, now) else {
                continue;
            };
            // A signature or a push in flight took its slot already: the lease is used up once
            // it is settled, not before (its own last check, or the check before upstream,
            // would refuse it: the review after M7.6, A-3).
            if next == State::Exhausted
                && (inner.signing.any(&lease.id) || inner.pushing.any(&lease.id))
            {
                continue;
            }
            // The certificate is refused first: whatever happens to the store write, the
            // lease is over.
            self.bar_serial(lease.cert_serial);
            inner.watches.remove(&lease.id);
            let kind = if next == State::Exhausted {
                EventKind::Exhaust
            } else {
                EventKind::Expire
            };
            let event = AuditEvent::new(now, kind, Outcome::Done)
                .lease(&lease.id)
                .cert(lease.cert_serial);
            let done = Self::reduced(inner, event, |inner| {
                inner
                    .store
                    .transition(&lease.id, State::Active, next, now)
                    .map_err(internal)
            });
            self.deny_serial(lease.cert_serial);
            done?;
            changed = true;
        }
        Ok(changed)
    }

    /// The sessions kept as ended ([`Service::watch_session`]'s notices): a reduction of
    /// privilege, so a poisoned list is taken all the same.
    pub(super) fn ended_sessions(&self) -> std::sync::MutexGuard<'_, Vec<(TicketId, u64)>> {
        self.ended_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records the revocation of every session kept as ended (each certificate refused
    /// already). Never called under the state lock.
    pub(super) fn record_ended_sessions(&self) {
        let ended = std::mem::take(&mut *self.ended_sessions());
        for (lease, serial) in ended {
            self.session_ended(&lease, serial);
        }
    }

    /// The session process of a lease ended: the lease is revoked. Its certificate goes on the
    /// deny list first, before anything that could fail (the lock, the store, the log): the
    /// watch fires once, so a revocation lost here would be lost for good.
    pub(super) fn session_ended(&self, lease_id: &TicketId, serial: u64) {
        self.bar_serial(serial);
        let reason = "the session's process ended";
        if let Err(e) = self.revoke_by_daemon(lease_id, reason, Announce::Now) {
            tracing::error!(
                lease = %lease_id,
                error = %e.detail(),
                "cannot record the revocation of a lease whose session ended; its certificate is refused"
            );
        }
        self.deny_serial(serial);
        self.changed.notify_waiters();
    }

    /// Revokes an active lease on the daemon's own decision (`reason` in its audit line). Its
    /// certificate goes on the deny list first; its open sessions are dropped now, or by the
    /// caller once it has answered ([`Announce::Later`]).
    pub(super) fn revoke_by_daemon(
        &self,
        lease_id: &TicketId,
        reason: &str,
        announce: Announce,
    ) -> Result<(), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let lease = match inner.store.lease(lease_id).map_err(internal) {
            Ok(Some(lease)) => lease,
            Ok(None) => return Ok(()),
            Err(e) => {
                // Recorded by a later sweep; the caller barred the certificate already.
                inner.unrecorded.insert(lease_id.clone(), reason.to_owned());
                return Err(e);
            }
        };
        if lease.state != State::Active {
            return Ok(());
        }
        self.bar_serial(lease.cert_serial);
        inner.watches.remove(lease_id);
        let done = self.record_revocation(&mut inner, &lease, reason, now);
        drop(inner);
        match announce {
            Announce::Now => self.deny_serial(lease.cert_serial),
            Announce::Later => self.bar_serial(lease.cert_serial),
        }
        done
    }

    /// Records the daemon's revocation of the active `lease` (its certificate barred by the
    /// caller): the `revoke` line, then the store. One the store can't take is kept, and
    /// recorded again by the next sweeps.
    fn record_revocation(
        &self,
        inner: &mut Inner,
        lease: &lease::Lease,
        reason: &str,
        now: Timestamp,
    ) -> Result<(), ServiceError> {
        let event = AuditEvent::new(now, EventKind::Revoke, Outcome::Done)
            .lease(&lease.id)
            .cert(lease.cert_serial)
            .reason(reason);
        let done = Self::reduced(inner, event, |inner| {
            inner
                .store
                .transition(&lease.id, State::Active, State::Revoked, now)
                .map_err(internal)
        });
        match &done {
            Ok(()) => {
                inner.unrecorded.remove(&lease.id);
            }
            Err(_) => {
                inner.unrecorded.insert(lease.id.clone(), reason.to_owned());
            }
        }
        done
    }

    /// Records again the revocations the store couldn't take ([`Inner::unrecorded`]); their
    /// certificates stay refused meanwhile. Whether any was recorded.
    fn record_unrecorded(&self, inner: &mut Inner, now: Timestamp) -> Result<bool, ServiceError> {
        let mut changed = false;
        let mut pending = std::mem::take(&mut inner.unrecorded).into_iter();
        while let Some((id, reason)) = pending.next() {
            let lease = match inner.store.lease(&id) {
                Ok(Some(lease)) => lease,
                Ok(None) => continue,
                Err(e) => {
                    // This one and every one not reached yet stay for the next sweep.
                    inner.unrecorded.insert(id, reason);
                    inner.unrecorded.extend(pending);
                    return Err(internal(e));
                }
            };
            if lease.state != State::Active {
                continue;
            }
            self.bar_serial(lease.cert_serial);
            if self.record_revocation(inner, &lease, &reason, now).is_ok() {
                changed = true;
            }
        }
        Ok(changed)
    }

    /// At startup: watches again the session of every active lease bound to one (watches
    /// live in memory). A session the daemon can't watch any more revokes its lease, and a
    /// process that ended while the daemon was down revokes it right away (the watcher calls
    /// back at once).
    pub(super) fn rewatch_sessions(&self) -> Result<(), ServiceError> {
        let leases = self.lock()?.store.leases(State::Active).map_err(internal)?;
        for lease in leases.iter().filter(|l| l.ticket.subject.caller.is_some()) {
            match self.watch_session(lease) {
                Ok(Some(watch)) => {
                    self.lock()?.watches.insert(lease.id.clone(), watch);
                }
                Ok(None) => {}
                Err(reason) => {
                    let reason = format!("after a restart: {reason}");
                    self.revoke_by_daemon(&lease.id, &reason, Announce::Now)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use writ_core::caller::CallerFacts;
    use writ_core::canonical::Canonical;
    use writ_core::lease::State;
    use writ_core::ticket::Ticket;

    use crate::testing::TestServiceBuilder;

    const POLICY: &str = include_str!("../../../writ-core/tests/fixtures/policy.yaml");

    /// The review after M7.6 (L-6): an ended session's notice whose thread couldn't start was
    /// lost. Kept instead, its certificate refused at once: the next sweep records it.
    #[test]
    fn an_ended_session_kept_unrecorded_is_revoked_by_the_next_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let h = TestServiceBuilder::new(POLICY).build(dir.path());
        let key = writ_crypto::keys::generate(writ_crypto::keys::KeyKind::Ed25519).unwrap();
        let yaml = "repos:\n  omega-code:\n    template: feature-branch\n    operations: \
                    [fetch]\n    branches: [\"agent/x\"]\nticket:\n  title: T\n  task: T\n";
        let submitted = h
            .service
            .submit(key.public_key(), yaml.as_bytes(), &CallerFacts::default())
            .unwrap();
        let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
        h.service
            .approve(&ticket.id, &h.approval(&ticket), &CallerFacts::default())
            .unwrap();
        let serial = h
            .service
            .inner
            .lock()
            .unwrap()
            .store
            .lease(&ticket.id)
            .unwrap()
            .unwrap()
            .cert_serial;
        // What a notice does when no thread can start: the certificate refused, the end kept.
        h.service.bar_serial(serial);
        h.service.ended_sessions().push((ticket.id.clone(), serial));
        assert!(h.service.is_revoked(serial));
        assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Active);
        h.service.sweep();
        assert_eq!(h.service.show(&ticket.id).unwrap().state, State::Revoked);
        assert!(h.service.ended_sessions().is_empty());
        let revoked = h.events("revoke", "done");
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0]["reason"], "the session's process ended");
    }
}
