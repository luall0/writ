//! The SSH CA rotated by an approver (M7.6, `writ admin ca rotate`): only on a signed
//! `writ-ca/1` naming this daemon, within the rotations' rate (shared with the TLS key's),
//! each logged (`admin`). That it names the CA in force, making the key and putting it in
//! force, is the daemon's ([`writ_gateway`]'s `AdminApplier`); deciding and logging is here.

use writ_core::caller::CallerFacts;
use writ_core::names::KeyFingerprint;
use writ_core::signed::CaRotation;
use writ_proto::CaRequest;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::Service;
use super::scan::within;
use super::tls::MAX_ROTATIONS_A_MINUTE;
use crate::{RefusalCode, ServiceError};

/// A rotation whose document and signature passed: only [`Service::check_ca`] makes one, and
/// it is never copied (what holds one moves it).
#[derive(Debug)]
pub struct CheckedCa {
    rotation: CaRotation,
    approver: KeyFingerprint,
}

impl CheckedCa {
    pub fn rotation(&self) -> &CaRotation {
        &self.rotation
    }

    /// The approver key that signed it.
    pub fn approver(&self) -> &KeyFingerprint {
        &self.approver
    }
}

fn refused(reason: impl Into<String>) -> ServiceError {
    ServiceError::refused(RefusalCode::Ca, reason)
}

impl Service {
    /// Checks a CA rotation's document and signature: a `writ-ca/1` decoded strictly, signed
    /// by an approver in force, naming this daemon, within the rate. A refusal is logged
    /// (`admin`, denied). Whether it names the CA in force is the daemon's to check, under the
    /// lock it rotates with.
    pub fn check_ca(
        &self,
        request: &CaRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedCa, ServiceError> {
        self.opened()?;
        let checked = self.ca_document(request);
        if let Err(e) = &checked {
            self.ca_denied(None, &e.to_string(), caller);
        }
        checked
    }

    fn ca_document(&self, request: &CaRequest) -> Result<CheckedCa, ServiceError> {
        let (rotation, approver) = self.approver_document(
            &request.document,
            &request.signature,
            |r: &CaRotation| &r.daemon,
            "rotation",
            RefusalCode::Ca,
        )?;
        let now = self.now()?;
        if !within(&mut self.outbound().rotations, now, MAX_ROTATIONS_A_MINUTE) {
            return Err(refused(format!(
                "more than {MAX_ROTATIONS_A_MINUTE} key rotations a minute: try again shortly"
            )));
        }
        Ok(CheckedCa { rotation, approver })
    }

    /// The line of a rotation about to be put in force (the review after M7.6, S-2): written
    /// before the new CA's key is moved in, and the rotation refused when the log can't take
    /// it (no line, no rotation), like an admin change's. From the CA it replaces to `new`, on
    /// its backend.
    pub fn ca_rotating(
        &self,
        checked: &CheckedCa,
        new: &KeyFingerprint,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Done)
            .caller(caller)
            .approver(&checked.approver)
            .reason(format!(
                "SSH CA rotated: {} replaced by {new}, its key on backend {}",
                checked.rotation.replaces, checked.rotation.backend
            ));
        Self::log(&mut inner, &event)
    }

    /// Logs a checked CA rotation refused after its check (denied, with the reason: a CA no
    /// longer in force, a backend the daemon lacks, the key not made). A rotation done has its
    /// line from [`Service::ca_rotating`], before it is in force.
    pub fn ca_refused(&self, checked: &CheckedCa, why: &str, caller: &CallerFacts) {
        self.ca_denied(Some(checked), why, caller);
    }

    fn ca_denied(&self, checked: Option<&CheckedCa>, why: &str, caller: &CallerFacts) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let reason = match checked {
            Some(checked) => format!(
                "SSH CA not rotated (CA {}, backend {}): {why}",
                checked.rotation.replaces, checked.rotation.backend
            ),
            None => format!("SSH CA not rotated: {why}"),
        };
        let mut event = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
            .caller(caller)
            .reason(reason);
        if let Some(checked) = checked {
            event = event.approver(&checked.approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }

    /// The CA in force's public key (M7.6: it changes with a rotation).
    pub fn ca_in_force(&self) -> Result<writ_crypto::ssh_key::PublicKey, ServiceError> {
        Ok(self.opened()?.ca.public_key())
    }

    /// Puts `key` in force for every certificate from now on: the rotation `checked` asked
    /// for, its line written ([`Service::ca_rotating`]). A certificate signed by the CA it
    /// replaces while an approval was in flight is signed again by this one before its lease
    /// is recorded ([`Service::approve`]'s last phase).
    pub fn replace_ca(
        &self,
        // The proof that an approver asked for it: nothing else of it is needed here.
        _asked: &CheckedCa,
        key: std::sync::Arc<dyn writ_crypto::ca::CaSigner>,
    ) -> Result<(), ServiceError> {
        self.opened()?.ca.replace(key);
        Ok(())
    }

    /// When the last active lease ends (seconds since the epoch), none without one: until
    /// when a CA a rotation replaced is still needed. Read under the state lock after the new
    /// CA is in force (the review after M7.6, D-3): a lease recorded after that was certified
    /// by the new one.
    pub fn last_active_expiry(&self) -> Result<Option<u64>, ServiceError> {
        let inner = self.lock()?;
        let leases = inner
            .store
            .leases(writ_core::lease::State::Active)
            .map_err(super::internal)?;
        Ok(leases
            .iter()
            .filter_map(|l| u64::try_from(l.ticket.limits.expires_at.unix()).ok())
            .max())
    }
}
