//! The HTTPS approval API's TLS key rotated by an approver (M7.5, `writ admin tls rotate`):
//! only on a signed `writ-tls/1` naming this daemon, a few a minute, each logged (`admin`).
//! That it names the certificate in force, and making the key, its certificate and putting
//! them in force, is the daemon's ([`writ_gateway`]'s `AdminApplier`); deciding and logging is
//! here.

use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::names::KeyFingerprint;
use writ_core::signed::{CertFingerprint, TlsRotation};
use writ_proto::TlsRequest;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::Service;
use super::scan::within;
use crate::{RefusalCode, ServiceError};

/// Rotations a minute, daemon-wide.
pub const MAX_ROTATIONS_A_MINUTE: usize = 5;

/// A rotation whose document and signature passed: only [`Service::check_tls`] makes one.
#[derive(Debug, Clone)]
pub struct CheckedTls {
    rotation: TlsRotation,
    approver: KeyFingerprint,
}

impl CheckedTls {
    pub fn rotation(&self) -> &TlsRotation {
        &self.rotation
    }

    /// The approver key that signed it.
    pub fn approver(&self) -> &KeyFingerprint {
        &self.approver
    }
}

fn refused(reason: impl Into<String>) -> ServiceError {
    ServiceError::refused(RefusalCode::Tls, reason)
}

impl Service {
    /// Checks a rotation's document and signature: a `writ-tls/1` decoded strictly, signed by
    /// an approver in force, naming this daemon, within the rotations' rate. A refusal is
    /// logged (`admin`, denied). Whether it names the certificate in force is checked by the
    /// daemon, which holds it, under the lock it rotates with.
    pub fn check_tls(
        &self,
        request: &TlsRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedTls, ServiceError> {
        self.opened()?;
        let checked = self.tls_document(request);
        if let Err(e) = &checked {
            self.tls_logged(None, Err(&e.to_string()), caller);
        }
        checked
    }

    fn tls_document(&self, request: &TlsRequest) -> Result<CheckedTls, ServiceError> {
        let rotation = TlsRotation::from_canonical(request.document.as_bytes())
            .map_err(|e| refused(format!("not a writ-tls/1 document: {e}")))?;
        let approver = self
            .verify_approver(request.document.as_bytes(), &request.signature)
            .map_err(|reason| ServiceError::refused(RefusalCode::Signature, reason))?;
        if rotation.daemon != self.boot.daemon {
            return Err(refused(format!(
                "the rotation names daemon {}, not this one ({})",
                rotation.daemon, self.boot.daemon
            )));
        }
        let now = self.now()?;
        if !within(&mut self.outbound().rotations, now, MAX_ROTATIONS_A_MINUTE) {
            return Err(refused(format!(
                "more than {MAX_ROTATIONS_A_MINUTE} TLS key rotations a minute: try again shortly"
            )));
        }
        Ok(CheckedTls { rotation, approver })
    }

    /// Tells the approvers a rotation is done, through the service's notification queue (the
    /// review after M7.6, D-9): never inline, never under the admin lock's wait on a sink.
    pub fn notify_rotation(&self, notification: writ_platform::Notification) {
        self.notify(notification);
    }

    /// The line of a rotation about to be put in force (the review after M7.6, S-2): written
    /// before the new key and certificate are moved in, and the rotation refused when the log
    /// can't take it (no line, no rotation).
    pub fn tls_rotating(
        &self,
        checked: &CheckedTls,
        new: &CertFingerprint,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Done)
            .caller(caller)
            .approver(&checked.approver)
            .reason(format!(
                "TLS key rotated: certificate {} replaced by {new}, its key on backend {}",
                checked.rotation.replaces, checked.rotation.backend
            ));
        Self::log(&mut inner, &event)
    }

    /// Logs a rotation refused (denied, with the reason: the document refused, a certificate
    /// no longer in force, the key not made), or one done whose line wasn't written first (a
    /// rotation finished at start).
    pub fn tls_logged(
        &self,
        checked: Option<&CheckedTls>,
        result: Result<&CertFingerprint, &str>,
        caller: &CallerFacts,
    ) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let (outcome, reason) = match (result, checked) {
            (Ok(new), Some(checked)) => (
                Outcome::Done,
                format!(
                    "TLS key rotated: certificate {} replaced by {new}, its key on backend {}",
                    checked.rotation.replaces, checked.rotation.backend
                ),
            ),
            (Ok(new), None) => (Outcome::Done, format!("TLS key rotated: certificate {new}")),
            (Err(why), Some(checked)) => (
                Outcome::Denied,
                format!(
                    "TLS key not rotated (certificate {}, backend {}): {why}",
                    checked.rotation.replaces, checked.rotation.backend
                ),
            ),
            (Err(why), None) => (Outcome::Denied, format!("TLS key not rotated: {why}")),
        };
        let mut event = AuditEvent::new(now, EventKind::Admin, outcome)
            .caller(caller)
            .reason(reason);
        if let Some(checked) = checked {
            event = event.approver(&checked.approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }
}
