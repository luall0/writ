//! A ticket under `unsigned_fetch` templates (M7.9.7) becomes an active lease when it is
//! submitted, with no approver's signature: the signed policy that made those templates stands
//! for it. Fetch only, never amended or renewed (`writ_core::fit` and `lease` refuse both),
//! not counted against `max_active_per_source`, no notification.
//!
//! In phases, like a signed grant ([`Service::approve`]): decided under the lock, the
//! certificate signed without it (the CA may be a device), then decided again under the lock
//! against the policy in force before anything is recorded.

use writ_core::caller::CallerFacts;
use writ_core::lease::{self, Lease, TicketRecord};
use writ_core::net::Source;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;
use writ_crypto::ca::CertificateRequest;
use writ_crypto::keys;
use writ_crypto::ssh_key::PublicKey;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::approver::Denied;
use super::{CLOCK_SKEW_SECONDS, Inner, Service, internal};
use crate::PRINCIPAL;
use crate::{RefusalCode, ServiceError};

/// How many times an unsigned grant's certificate is signed again when the CA rotates
/// meanwhile (as a signed grant's).
const MAX_SIGNED_AGAIN: usize = 3;

/// What an unsigned grant decides under the lock: the lease and its certificate's validity.
struct Decided {
    lease: Lease,
    valid_after: u64,
    valid_before: u64,
}

impl Service {
    /// Grants `ticket`, just admitted under `unsigned_fetch` templates only, with no signature:
    /// the lease recorded active with its certificate for `session_key`, one `grant` line
    /// naming its templates where a signed one names the approver. Anything that no longer
    /// holds once the certificate is signed (the policy changed, the ticket expired) refuses
    /// it, the certificate discarded, the reason logged.
    pub(super) fn grant_unsigned(
        &self,
        ticket: Ticket,
        session_key: &PublicKey,
        source: Source,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let id = ticket.id.clone();
        let templates = super::agent::fitted(&ticket);
        let pubkey = session_key.to_openssh().map_err(internal)?;
        let serial = keys::random_serial().map_err(internal)?;
        let record = TicketRecord {
            source: Some(source),
            unsigned: true,
            ..TicketRecord::pending(ticket)
        };
        let (now, mut inner) = self.begin()?;
        let denied = Denied::new(
            AuditEvent::new(now, EventKind::Grant, Outcome::Denied)
                .ticket(&id)
                .lease(&id)
                .caller(caller),
            "grant refused",
        );
        let mut decided = self.decide_unsigned(&mut inner, &denied, &record, serial, now)?;
        drop(inner);
        for _ in 0..MAX_SIGNED_AGAIN {
            // The certificate, with no lock held.
            let opened = self.opened()?;
            let issued = opened.ca.issue(&CertificateRequest {
                subject: session_key,
                serial,
                key_id: decided.lease.id.as_str(),
                principals: &[PRINCIPAL],
                valid_after: decided.valid_after,
                valid_before: decided.valid_before,
            });
            let (now, mut inner) = self.begin()?;
            let (certificate, by) = match issued.and_then(|cert| {
                let by = cert.signature_key().clone();
                Ok((cert.to_openssh()?, by))
            }) {
                Ok(issued) => issued,
                Err(writ_crypto::CryptoError::CaUnusable(why)) => {
                    return denied.deny(
                        &mut inner,
                        RefusalCode::Ca,
                        format!("the daemon's CA key is unusable: {why}"),
                    );
                }
                Err(e) => return denied.failed(&mut inner, internal(e)),
            };
            // Decided again against what holds now: a policy changed while it was signed (the
            // template's unsigned_fetch turned off, the repo closed) discards it.
            let again = self.decide_unsigned(&mut inner, &denied, &record, serial, now)?;
            if by == *opened.ca.public_key().key_data()
                && again.valid_before == decided.valid_before
            {
                return self.record_unsigned(
                    &mut inner,
                    &denied,
                    again.lease,
                    &pubkey,
                    source,
                    &certificate,
                    &templates,
                    caller,
                    now,
                );
            }
            decided = again;
        }
        let (_, mut inner) = self.begin()?;
        denied.deny(
            &mut inner,
            RefusalCode::WrongState,
            format!(
                "the SSH CA changed {MAX_SIGNED_AGAIN} times while ticket {id}'s certificate was \
                 signed: submit it again"
            ),
        )
    }

    /// The unsigned lease `record` becomes under the policy in force at `now`, or the denial.
    fn decide_unsigned(
        &self,
        inner: &mut Inner,
        denied: &Denied,
        record: &TicketRecord,
        serial: u64,
        now: Timestamp,
    ) -> Result<Decided, ServiceError> {
        let lease = match lease::activate_unsigned(&self.policy(), record, serial, now) {
            Ok(lease) => lease,
            Err(e) => return denied.deny(inner, RefusalCode::Lifecycle, e.to_string()),
        };
        let valid_after = denied.or_failed(
            inner,
            u64::try_from(now.saturating_sub_seconds(CLOCK_SKEW_SECONDS).unix()).map_err(internal),
        )?;
        let valid_before = denied.or_failed(
            inner,
            u64::try_from(lease.ticket.limits.expires_at.unix()).map_err(internal),
        )?;
        Ok(Decided {
            lease,
            valid_after,
            valid_before,
        })
    }

    /// The last phase's record: the lease inserted active with its certificate, its `grant`
    /// line, its session watched.
    #[allow(clippy::too_many_arguments)] // the parts of one grant, taken apart once
    fn record_unsigned(
        &self,
        inner: &mut Inner,
        denied: &Denied,
        lease: Lease,
        pubkey: &str,
        source: Source,
        certificate: &str,
        templates: &str,
        caller: &CallerFacts,
        now: Timestamp,
    ) -> Result<(), ServiceError> {
        let watch = match self.watch_session(&lease) {
            Ok(watch) => watch,
            Err(reason) => return denied.deny(inner, RefusalCode::Session, reason),
        };
        let event = AuditEvent::new(now, EventKind::Grant, Outcome::Allowed)
            .ticket(&lease.id)
            .lease(&lease.id)
            .cert(lease.cert_serial)
            .caller(caller)
            .reason(format!(
                "granted with no signature (unsigned_fetch): {templates}"
            ));
        Self::logged(inner, event, |inner| {
            inner
                .store
                .insert_unsigned(&lease, pubkey, source, certificate, now)
                .map_err(internal)
        })?;
        if let Some(watch) = watch {
            inner.watches.insert(lease.id.clone(), watch);
        }
        Ok(())
    }
}
