//! Admin changes: an approver's signed `writ-admin/1` document replaces the policy,
//! `approvers` or `readers` in force. The service checks the document and its signature
//! ([`Service::check_admin`]), then, once the daemon parsed and checked the new text against
//! the rest of its configuration, records the new version under the keystore's MAC and puts
//! it in force ([`Service::commit_admin`]): the audit line first, the store next, the swap
//! last. Every attempt is one `admin` line.

use std::collections::BTreeMap;
use std::sync::Arc;

use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::config::PolicyConfig;
use writ_core::names::KeyFingerprint;
use writ_core::signed::Admin;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::authority::HeadEntry;
use writ_proto::{AdminApplied, AdminRequest, AdminShown, CreatedKey};
use writ_store::{AuditEvent, AuthorityHead, AuthorityHow, AuthorityVersion, EventKind, Outcome};

use super::{Service, internal, signing_keys_exist};
use crate::{RefusalCode, ServiceError};

/// The version of each authority file the daemon runs with, and the head's MAC as the store
/// held it: checked against the keystore's key at unseal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InForce {
    pub versions: BTreeMap<AdminTarget, (u64, TextDigest)>,
    pub mac: String,
}

impl InForce {
    /// The head's entries, in the order the MAC covers them.
    pub fn entries(&self) -> Vec<HeadEntry<'_>> {
        self.versions
            .iter()
            .map(|(target, (version, digest))| HeadEntry {
                target: target.as_str(),
                version: *version,
                digest: digest.as_str(),
            })
            .collect()
    }
}

/// An admin change whose document and signature passed: what the daemon checks the new text
/// of before [`Service::commit_admin`].
#[derive(Debug, Clone)]
pub struct CheckedAdmin {
    pub admin: Admin,
    /// The canonical document and the SSHSIG over it, kept with the version.
    pub document: String,
    pub signature: String,
    pub approver: KeyFingerprint,
}

/// The new text, as the daemon parsed and checked it: what the service puts in force itself
/// (the policy, the approvers); the readers are the gateway's.
pub enum AdminParsed {
    Policy(PolicyConfig),
    Approvers(Vec<AllowedSigner>),
    Readers,
}

impl AdminParsed {
    fn target(&self) -> AdminTarget {
        match self {
            Self::Policy(_) => AdminTarget::Policy,
            Self::Approvers(_) => AdminTarget::Approvers,
            Self::Readers => AdminTarget::Readers,
        }
    }
}

fn refused(reason: impl Into<String>) -> ServiceError {
    ServiceError::refused(RefusalCode::Admin, reason)
}

impl Service {
    /// The versions in force.
    pub fn in_force(&self) -> InForce {
        // poisoned: the last head written stands (it is written whole).
        self.in_force
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The version of `target` in force, its text and its digest.
    pub fn admin_show(&self, target: AdminTarget) -> Result<AdminShown, ServiceError> {
        let (_, inner) = self.begin()?;
        let (version, _) = self
            .in_force()
            .versions
            .get(&target)
            .cloned()
            .ok_or_else(|| internal(format!("no version of {target} in force")))?;
        let row = inner
            .store
            .authority_version(target, version)
            .map_err(internal)?
            .ok_or_else(|| internal(format!("{target} version {version} is missing")))?;
        Ok(AdminShown {
            target,
            version,
            digest: row.digest,
            text: row.text,
        })
    }

    /// Checks an admin change's document and signature: the daemon open, the document a
    /// `writ-admin/1` decoded strictly, signed by an approver in force, against the version in
    /// force. A refusal is logged.
    pub fn check_admin(
        &self,
        request: &AdminRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedAdmin, ServiceError> {
        self.opened()?;
        let checked = self.admin_document(request);
        if let Err(e) = &checked {
            self.admin_failed(None, None, &e.to_string(), caller);
        }
        checked
    }

    fn admin_document(&self, request: &AdminRequest) -> Result<CheckedAdmin, ServiceError> {
        let admin = Admin::from_canonical(request.document.as_bytes())
            .map_err(|e| refused(format!("not a writ-admin/1 document: {e}")))?;
        let approver = self
            .verify_approver(request.document.as_bytes(), &request.signature)
            .map_err(|reason| ServiceError::refused(RefusalCode::Signature, reason))?;
        self.current(admin.target, &admin.previous)?;
        Ok(CheckedAdmin {
            admin,
            document: request.document.clone(),
            signature: request.signature.clone(),
            approver,
        })
    }

    /// The version of `target` in force, if its digest is `previous`; a refusal naming it
    /// otherwise.
    fn current(&self, target: AdminTarget, previous: &TextDigest) -> Result<u64, ServiceError> {
        let in_force = self.in_force();
        let (version, digest) = in_force
            .versions
            .get(&target)
            .ok_or_else(|| internal(format!("no version of {target} in force")))?;
        if digest != previous {
            return Err(refused(format!(
                "the {target} in force is version {version}, not the one this change replaces: \
                 it changed since it was shown (writ admin show {target}, then apply again)"
            )));
        }
        Ok(*version)
    }

    /// Puts a checked change in force: the version it replaces is still the one in force, a
    /// new policy's signing keys are held by the signer; then the `admin` line (if the log
    /// can't take it, nothing changes), the new version and head under the keystore's MAC,
    /// and the swap. `parsed` is the daemon's reading of the new text; `created`, the keys it
    /// made for a new policy (named in the `admin` line and the reply).
    pub fn commit_admin(
        &self,
        checked: &CheckedAdmin,
        parsed: AdminParsed,
        created: Vec<CreatedKey>,
        caller: &CallerFacts,
    ) -> Result<AdminApplied, ServiceError> {
        let target = checked.admin.target;
        if parsed.target() != target {
            return Err(internal("an admin change parsed as another file"));
        }
        let opened = self.opened()?;
        if let AdminParsed::Policy(policy) = &parsed
            && let Err(e) = signing_keys_exist(policy, &*opened.signer)
        {
            let error = refused(e.to_string());
            self.admin_failed(
                Some(&checked.approver),
                Some(target),
                &error.to_string(),
                caller,
            );
            return Err(error);
        }
        let (now, mut inner) = self.begin()?;
        // Checked again under the lock: two changes of one file never both apply.
        let old = match self.current(target, &checked.admin.previous) {
            Ok(old) => old,
            Err(e) => {
                drop(inner);
                self.admin_failed(
                    Some(&checked.approver),
                    Some(target),
                    &e.to_string(),
                    caller,
                );
                return Err(e);
            }
        };
        let version = old
            .checked_add(1)
            .ok_or_else(|| internal("version overflow"))?;
        let digest = checked.admin.text.digest();
        let mut in_force = self.in_force();
        in_force.versions.insert(target, (version, digest.clone()));
        in_force.mac = opened
            .authority
            .sign_head(&in_force.entries())
            .map_err(internal)?;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Allowed)
            .approver(&checked.approver)
            .caller(caller)
            .reason(format!(
                "{target}: version {version} (sha256 {digest}) replaces version {old} (sha256 \
                 {}){}",
                checked.admin.previous,
                created
                    .iter()
                    .map(|key| format!(
                        "; created {} {}: {}",
                        key.role.as_str(),
                        key.id,
                        key.public_key
                    ))
                    .collect::<String>()
            ));
        Self::log(&mut inner, &event)?;
        let row = AuthorityVersion {
            target,
            version,
            text: checked.admin.text.as_str().to_owned(),
            digest: digest.clone(),
            how: AuthorityHow::Admin,
            document: Some(checked.document.clone()),
            signature: Some(checked.signature.clone()),
            approver: Some(checked.approver.clone()),
            applied_at: now,
        };
        let head = AuthorityHead {
            versions: in_force
                .versions
                .iter()
                .map(|(t, (v, _))| (*t, *v))
                .collect(),
            mac: in_force.mac.clone(),
        };
        if let Err(e) = inner.store.record_authority(&[row], &head) {
            let denial = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
                .approver(&checked.approver)
                .caller(caller)
                .reason(format!("{target}: version {version} could not be recorded"));
            Self::write_best_effort(&mut inner, &denial);
            return Err(internal(e));
        }
        *self
            .in_force
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = in_force;
        match parsed {
            AdminParsed::Policy(policy) => {
                *self
                    .policy
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
            }
            AdminParsed::Approvers(approvers) => {
                *self
                    .approver_keys
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Arc::new(approvers.into_iter().map(|a| a.key).collect());
            }
            AdminParsed::Readers => {}
        }
        drop(inner);
        self.changed.notify_waiters();
        Ok(AdminApplied {
            target,
            version,
            digest,
            signed_by: checked.approver.clone(),
            created,
        })
    }

    /// Something about the authority files worth a line of its own (a hand-edited file set
    /// aside at start): `admin`, done, best effort.
    pub fn admin_note(&self, reason: &str) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Done).reason(reason);
        Self::write_best_effort(&mut inner, &event);
    }

    /// An admin change refused after its signature was checked (a file that doesn't pass, a
    /// key the signer lacks), or before: one `admin` line, denied, with the reason.
    pub fn admin_failed(
        &self,
        approver: Option<&KeyFingerprint>,
        target: Option<AdminTarget>,
        reason: &str,
        caller: &CallerFacts,
    ) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let reason = match target {
            Some(target) => format!("{target}: {reason}"),
            None => reason.to_owned(),
        };
        let mut event = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
            .caller(caller)
            .reason(reason);
        if let Some(approver) = approver {
            event = event.approver(approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }
}
