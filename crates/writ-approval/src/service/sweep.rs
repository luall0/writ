//! Time: pending tickets and leases past `expires_at`, exhausted leases, ended sessions.

use writ_core::lease::{self, State};
use writ_core::names::TicketId;
use writ_core::units::Timestamp;
use writ_proto::ApiError;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Inner, Service, internal};

impl Service {
    /// Expires pending tickets and leases past `expires_at`, and exhausted leases. Called by
    /// the daemon's timer; every request also sweeps first ([`Service::begin`]).
    pub fn sweep(&self) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        match self.sweep_locked(&mut inner, now) {
            Ok(true) => self.changed.notify_waiters(),
            Ok(false) => {}
            Err(e) => eprintln!("writd: sweep failed: {e}"),
        }
    }

    pub(super) fn sweep_locked(&self, inner: &mut Inner, now: Timestamp) -> Result<bool, ApiError> {
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

    /// The session process of a lease ended: the lease is revoked.
    pub(super) fn session_ended(&self, lease_id: &TicketId) {
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
}
