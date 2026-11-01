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
    /// Expires pending tickets and leases past `expires_at`, and exhausted leases. Called by
    /// the daemon's timer; every request also sweeps first ([`Service::begin`]).
    pub fn sweep(&self) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        // Lines kept while the log was down are retried even when no request comes.
        let _ = Self::flush_unlogged(&mut inner);
        match self.sweep_locked(&mut inner, now) {
            Ok(true) => self.changed.notify_waiters(),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e.detail(), "sweep failed"),
        }
    }

    pub(super) fn sweep_locked(
        &self,
        inner: &mut Inner,
        now: Timestamp,
    ) -> Result<bool, ServiceError> {
        let mut changed = false;
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
        let Some(lease) = inner.store.lease(lease_id).map_err(internal)? else {
            return Ok(());
        };
        if lease.state != State::Active {
            return Ok(());
        }
        self.bar_serial(lease.cert_serial);
        inner.watches.remove(lease_id);
        let event = AuditEvent::new(now, EventKind::Revoke, Outcome::Done)
            .lease(lease_id)
            .cert(lease.cert_serial)
            .reason(reason);
        let done = Self::reduced(&mut inner, event, |inner| {
            inner
                .store
                .transition(lease_id, State::Active, State::Revoked, now)
                .map_err(internal)
        });
        drop(inner);
        match announce {
            Announce::Now => self.deny_serial(lease.cert_serial),
            Announce::Later => self.bar_serial(lease.cert_serial),
        }
        done
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
