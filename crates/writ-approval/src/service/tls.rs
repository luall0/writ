//! The HTTPS approval API's TLS key rotated by an approver (M7.5, `writ admin tls rotate`):
//! only on a signed `writ-tls/1` naming this daemon, a few a minute, each logged (`admin`).
//! That it names the certificate in force, and making the key, its certificate and putting
//! them in force, is the daemon's ([`writ_gateway`]'s `AdminApplier`); deciding and logging is
//! here.

use writ_core::caller::CallerFacts;
use writ_core::names::KeyFingerprint;
use writ_core::signed::{CertFingerprint, TlsRotation};
use writ_proto::TlsRequest;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::Service;
use super::scan::within;
use crate::{RefusalCode, ServiceError};

/// Rotations a minute, daemon-wide.
pub const MAX_ROTATIONS_A_MINUTE: usize = 5;

/// A rotation whose document and signature passed: only [`Service::check_tls`] makes one, and
/// it is never copied (what holds one moves it).
#[derive(Debug)]
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
            self.tls_denied(None, &e.to_string(), caller);
        }
        checked
    }

    fn tls_document(&self, request: &TlsRequest) -> Result<CheckedTls, ServiceError> {
        let (rotation, approver) = self.approver_document(
            &request.document,
            &request.signature,
            |r: &TlsRotation| &r.daemon,
            "rotation",
            RefusalCode::Tls,
        )?;
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

    /// Logs a checked rotation refused after its check (denied, with the reason: a
    /// certificate no longer in force, a backend the daemon lacks, the key not made). A
    /// rotation done has its line from [`Service::tls_rotating`], before it is in force.
    pub fn tls_refused(&self, checked: &CheckedTls, why: &str, caller: &CallerFacts) {
        self.tls_denied(Some(checked), why, caller);
    }

    fn tls_denied(&self, checked: Option<&CheckedTls>, why: &str, caller: &CallerFacts) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let reason = match checked {
            Some(checked) => format!(
                "TLS key not rotated (certificate {}, backend {}): {why}",
                checked.rotation.replaces, checked.rotation.backend
            ),
            None => format!("TLS key not rotated: {why}"),
        };
        let mut event = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
            .caller(caller)
            .reason(reason);
        if let Some(checked) = checked {
            event = event.approver(&checked.approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }
}
