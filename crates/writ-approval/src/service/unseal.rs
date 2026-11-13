//! Opening a sealed service: an approver's `writ-unseal/1` signature checked against this
//! daemon and this boot ([`Service::check_unseal`]), before anything costly is tried, then
//! the keys the keystore held ([`Service::unseal`]). Every attempt is one `unseal` line in
//! the audit log; the sealed start is one `seal` line.

use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::names::KeyFingerprint;
use writ_core::signed::Unseal;
use writ_platform::{Notification, Priority};
use writ_proto::UnsealRequest;
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Opened, Service, signing_keys_exist};
use crate::{RefusalCode, ServiceError};

impl Service {
    /// The sealed start, in the audit log (`seal`, done) and to the approver ("writd started,
    /// sealed"). Once, by the daemon, right after starting.
    pub fn announce_sealed(&self) {
        if let Ok(now) = self.now()
            && let Ok(mut inner) = self.lock()
        {
            let event = AuditEvent::new(now, EventKind::Seal, Outcome::Done)
                .reason("started sealed: waiting for `writ unseal`");
            Self::write_best_effort(&mut inner, &event);
        }
        self.notify(Notification {
            title: "writd started, sealed".to_owned(),
            message: format!(
                "Nothing is served until an approver unseals it: writ unseal (daemon {})",
                self.boot.daemon
            ),
            priority: Priority::High,
            tags: vec!["writ".to_owned(), "sealed".to_owned()],
        });
    }

    /// Checks an unseal's document and signature, before the passphrase is tried (scrypt
    /// costs a second: only an approver can make the daemon spend it). The daemon must be
    /// sealed, the document this daemon's and this boot's, the signature an approver's over
    /// exactly its canonical bytes. The approver, or the refusal (logged).
    pub fn check_unseal(
        &self,
        request: &UnsealRequest,
        caller: &CallerFacts,
    ) -> Result<KeyFingerprint, ServiceError> {
        let checked = self.unseal_document(request);
        if let Err((code, reason)) = &checked {
            self.unseal_failed(None, reason, caller);
            return Err(ServiceError::refused(*code, reason.clone()));
        }
        checked.map_err(|(code, reason)| ServiceError::refused(code, reason))
    }

    fn unseal_document(
        &self,
        request: &UnsealRequest,
    ) -> Result<KeyFingerprint, (RefusalCode, String)> {
        if !self.is_sealed() {
            return Err((
                RefusalCode::WrongState,
                "the daemon is not sealed".to_owned(),
            ));
        }
        let unseal = |reason: String| (RefusalCode::Unseal, reason);
        let document = Unseal::from_canonical(request.unseal.as_bytes())
            .map_err(|e| unseal(format!("not a writ-unseal/1 document: {e}")))?;
        if document.daemon != self.boot.daemon {
            return Err(unseal(format!(
                "the unseal names daemon {}, not this one ({})",
                document.daemon, self.boot.daemon
            )));
        }
        if document.nonce != self.boot.nonce {
            return Err(unseal(
                "the unseal is for another start of this daemon: a signature is good for one \
                 start only (run writ unseal again)"
                    .to_owned(),
            ));
        }
        self.verify_approver(request.unseal.as_bytes(), &request.signature)
            .map_err(|reason| (RefusalCode::Signature, reason))
    }

    /// Opens the service with the keys the keystore held, after `approver`'s unseal was
    /// checked and the keystore opened (`None`: the development keystore, open at start).
    /// The CA must be the one whose public key the daemon started with, and the signer must
    /// hold every template's signing key. The `unseal` line is written before anything is
    /// served: if the log can't take it, the daemon stays sealed. A refusal is not logged
    /// here: the caller logs it once ([`Service::unseal_failed`]), with any of its own.
    pub fn unseal(
        &self,
        opened: Opened,
        approver: Option<&KeyFingerprint>,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let by = match approver {
            Some(approver) => UnsealedBy::Approver(approver),
            None => UnsealedBy::DevKeystore,
        };
        self.unseal_by(opened, by, caller)
    }

    /// [`Service::unseal`], saying who opened it: an approver, the development keystore, or
    /// the daemon itself through its hardware (M7.6, `unseal: auto`): logged as automatic
    /// and notified.
    pub fn unseal_by(
        &self,
        opened: Opened,
        by: UnsealedBy<'_>,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let refuse = |reason: String| ServiceError::refused(RefusalCode::Unseal, reason);
        if !self.is_sealed() {
            return Err(ServiceError::refused(
                RefusalCode::WrongState,
                "the daemon is not sealed",
            ));
        }
        if opened.ca.public_key() != self.config.ca_public {
            return Err(refuse(
                "the keystore's CA key is not the one the daemon started with".to_owned(),
            ));
        }
        if let Err(e) = signing_keys_exist(&self.policy(), &*opened.signer) {
            return Err(refuse(e.to_string()));
        }
        // The OpenPGP keys' certificates, with the user ids in force.
        let certified = super::openpgp::certify(
            &self.policy(),
            &self.key_uses(),
            &*opened.signer,
            &opened.openpgp,
        )
        .map_err(|e| refuse(e.to_string()))?;
        let created = opened.openpgp.clone();
        // The authority files the daemon started with are the keystore's: their head carries
        // its MAC, and the store still holds exactly them.
        // The keystore checked it already, before writing anything from the policy (the
        // review after M7.6, S-1): checked again here, by the same function, whatever opened it.
        let in_force = self.in_force();
        if let Err(altered) = in_force.check_mac(&opened.authority) {
            return Err(refuse(altered.to_string()));
        }
        let held = self.lock()?.store.authority_in_force().map_err(|e| {
            refuse(format!(
                "the authority files in the store can't be read: {e}"
            ))
        })?;
        let same = held.is_some_and(|(head, files)| {
            head.mac == in_force.mac
                && in_force.versions.iter().all(|(target, (version, digest))| {
                    head.versions.get(target) == Some(version)
                        && files.get(target).is_some_and(|f| &f.digest == digest)
                })
        });
        if !same {
            return Err(refuse(
                "the authority files in the store changed since the daemon started: restart it"
                    .to_owned(),
            ));
        }
        let now = self.now()?;
        {
            let mut inner = self.lock()?;
            let mut event =
                AuditEvent::new(now, EventKind::Unseal, Outcome::Allowed).caller(caller);
            event = match by {
                UnsealedBy::Approver(approver) => event.approver(approver),
                UnsealedBy::DevKeystore => event.reason("the development keystore, open at start"),
                UnsealedBy::Automatic => event.reason(
                    "automatic: the daemon opened itself through its hardware (unseal: auto)",
                ),
            };
            Self::log(&mut inner, &event)?;
            if self.opened.set(opened).is_err() {
                return Err(ServiceError::refused(
                    RefusalCode::WrongState,
                    "the daemon is not sealed",
                ));
            }
            self.set_openpgp(super::openpgp::OpenpgpKeys { created, certified });
        }
        // The approvers in force now carry their MAC: the leases a removed approver signed,
        // which a change cut short left active, are revoked (the review after M7.6, A-4).
        self.revoke_orphaned();
        self.changed.notify_waiters();
        match by {
            UnsealedBy::Approver(_) => self.notify(Notification {
                title: "writd unsealed".to_owned(),
                message: format!("Daemon {} is open.", self.boot.daemon),
                priority: Priority::Default,
                tags: vec!["writ".to_owned(), "unsealed".to_owned()],
            }),
            UnsealedBy::Automatic => self.notify(Notification {
                title: "writd unsealed automatically".to_owned(),
                message: format!(
                    "Daemon {} started and opened itself through its hardware, with no one \
                     (unseal: auto).",
                    self.boot.daemon
                ),
                priority: Priority::High,
                tags: vec![
                    "writ".to_owned(),
                    "unsealed".to_owned(),
                    "automatic".to_owned(),
                ],
            }),
            UnsealedBy::DevKeystore => {}
        }
        Ok(())
    }

    /// An unseal that failed after its signature was checked (a wrong passphrase, a keystore
    /// that doesn't open), or before: one `unseal` line, denied, with the reason.
    pub fn unseal_failed(
        &self,
        approver: Option<&KeyFingerprint>,
        reason: &str,
        caller: &CallerFacts,
    ) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let mut event = AuditEvent::new(now, EventKind::Unseal, Outcome::Denied)
            .caller(caller)
            .reason(reason);
        if let Some(approver) = approver {
            event = event.approver(approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }
}

/// Who opened the service ([`Service::unseal_by`]).
#[derive(Debug, Clone, Copy)]
pub enum UnsealedBy<'a> {
    /// An approver's checked `writ unseal`.
    Approver(&'a KeyFingerprint),
    /// The development keystore, open at start.
    DevKeystore,
    /// The daemon itself, through its hardware (M7.6, `unseal: auto`).
    Automatic,
}
