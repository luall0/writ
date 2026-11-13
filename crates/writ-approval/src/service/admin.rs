//! Admin changes: an approver's signed `writ-admin/2` document replaces the policy,
//! `approvers` or `readers` in force. The service checks the document and its signature
//! ([`Service::check_admin`]), then, once the daemon parsed and checked the new text against
//! the rest of its configuration, records the new version under the keystore's MAC and puts
//! it in force ([`Service::commit_admin`]): the audit line first, the store next, the swap
//! last. Every attempt is one `admin` line.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::lease::Lease;
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::signed::Admin;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::authority::{AuthorityKey, HeadEntry};
use writ_proto::{AdminApplied, AdminRequest, AdminShown, CreatedKey, RemovedKey};
use writ_store::{AuditEvent, AuthorityHead, AuthorityHow, AuthorityVersion, EventKind, Outcome};

use super::{KeyUses, Service, internal, signing_keys_exist};
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

    /// Whether these versions carry `key`'s MAC: the one check of the authority files at
    /// rest, made by the keystore as soon as its authority key opens (before anything is
    /// written from the policy, the review after M7.6, S-1) and by the service when it
    /// opens.
    pub fn check_mac(&self, key: &AuthorityKey) -> Result<(), AlteredAtRest> {
        if key.verify_head(&self.entries(), &self.mac) {
            Ok(())
        } else {
            Err(AlteredAtRest)
        }
    }
}

/// The versions in force don't carry the keystore's MAC: altered at rest (or another
/// keystore's state). One reason, whichever check finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the policy, approvers and readers in force were altered at rest: their MAC is not this \
     keystore's (put them back with writd recover)"
)]
pub struct AlteredAtRest;

/// An admin change whose document and signature passed: what the daemon checks the new text
/// of before [`Service::commit_admin`]. Only [`Service::check_admin`] makes one (its fields
/// are private), so holding one proves the check ran; it is never copied (what holds one
/// moves it).
#[derive(Debug)]
pub struct CheckedAdmin {
    admin: Admin,
    /// The canonical document and the SSHSIG over it, kept with the version.
    document: String,
    signature: String,
    approver: KeyFingerprint,
}

impl CheckedAdmin {
    /// The change, as checked.
    pub fn admin(&self) -> &Admin {
        &self.admin
    }

    /// The approver key that signed it.
    pub fn approver(&self) -> &KeyFingerprint {
        &self.approver
    }
}

/// The new text, as the daemon parsed and checked it: what the service puts in force itself
/// (the policy with how its signing keys sign, the approvers); the readers are the gateway's.
pub enum AdminParsed {
    Policy(PolicyConfig, KeyUses),
    Approvers(Vec<AllowedSigner>),
    Readers,
}

impl AdminParsed {
    fn target(&self) -> AdminTarget {
        match self {
            Self::Policy(..) => AdminTarget::Policy,
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
            daemon: self.boot.daemon.clone(),
            target,
            version,
            digest: row.digest,
            text: row.text,
        })
    }

    /// Checks an admin change's document and signature: the daemon open, the document a
    /// `writ-admin/2` decoded strictly, signed by an approver in force, against the version in
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
        let (admin, approver) = self.approver_document(
            &request.document,
            &request.signature,
            |a: &Admin| &a.daemon,
            "change",
            RefusalCode::Admin,
        )?;
        self.current(&admin)?;
        Ok(CheckedAdmin {
            admin,
            document: request.document.clone(),
            signature: request.signature.clone(),
            approver,
        })
    }

    /// The version of the change's target in force, if the change replaces exactly that
    /// version (its number and its text's digest); a refusal naming what differs otherwise.
    /// Versions only grow, so a change applied once never applies again, even when the text
    /// comes back to what it was (the daemon it names is checked with its signature).
    fn current(&self, admin: &Admin) -> Result<u64, ServiceError> {
        let target = admin.target;
        let in_force = self.in_force();
        let (version, digest) = in_force
            .versions
            .get(&target)
            .ok_or_else(|| internal(format!("no version of {target} in force")))?;
        if admin.version != *version || &admin.previous != digest {
            return Err(refused(format!(
                "the {target} in force is version {version}, not the one this change replaces \
                 (version {}): it changed since it was shown, or the change was applied \
                 already (writ admin show {target}, then apply again)",
                admin.version
            )));
        }
        Ok(*version)
    }

    /// Puts a checked change in force: the version it replaces is still the one in force, a
    /// new policy's signing keys are held by the signer; then the `admin` line (if the log
    /// can't take it, nothing changes), the new version and head under the keystore's MAC,
    /// and the swap. `parsed` is the daemon's reading of the new text; `created`, the keys it
    /// made for a new policy (named in the `admin` line and the reply).
    // The change, what the daemon made and takes out for it, and who asked: each its own.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_admin(
        &self,
        checked: &CheckedAdmin,
        parsed: AdminParsed,
        created: Vec<CreatedKey>,
        removed: Vec<RemovedKey>,
        openpgp_created: std::collections::BTreeMap<writ_core::names::KeyId, u32>,
        caller: &CallerFacts,
    ) -> Result<AdminApplied, ServiceError> {
        let target = checked.admin.target;
        if parsed.target() != target {
            let error = internal("an admin change parsed as another file");
            self.admin_failed(
                Some(&checked.approver),
                Some(target),
                "internal error (see the daemon's log)",
                caller,
            );
            return Err(error);
        }
        let opened = self.opened()?;
        // The approvers the change keeps, if it changes them: a lease another key signed is
        // revoked once the change is in force.
        let kept = match &parsed {
            AdminParsed::Approvers(approvers) => Some(
                approvers
                    .iter()
                    .map(|a| super::fingerprint(&a.key))
                    .collect::<Result<BTreeSet<_>, _>>()?,
            ),
            AdminParsed::Policy(..) | AdminParsed::Readers => None,
        };
        if let AdminParsed::Policy(policy, _) = &parsed
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
        // A new policy's OpenPGP certificates, its user ids certified (refused if they can't
        // be): the keys the signer held, and those this change added.
        let openpgp = match &parsed {
            AdminParsed::Policy(policy, key_uses) => {
                let mut created = self.openpgp().created.clone();
                created.extend(openpgp_created);
                match super::openpgp::certify(policy, key_uses, &*opened.signer, &created) {
                    Ok(certified) => Some(super::openpgp::OpenpgpKeys { created, certified }),
                    Err(e) => {
                        let error = refused(e.to_string());
                        self.admin_failed(
                            Some(&checked.approver),
                            Some(target),
                            &error.to_string(),
                            caller,
                        );
                        return Err(error);
                    }
                }
            }
            _ => None,
        };
        let certified = openpgp.as_ref().map_or_else(String::new, |keys| {
            super::openpgp::changes(&self.openpgp().certified, &keys.certified)
        });
        let (now, mut inner) = self.begin()?;
        // Checked again under the lock: two changes of one file never both apply.
        let old = match self.current(&checked.admin) {
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
        // The leases a removed approver signed, listed under the lock (no approval lands
        // meanwhile: `approve` checks its approver under it), before anything is written: a
        // list the store can't give refuses the change, rather than leaving them running.
        let unapproved = match &kept {
            Some(kept) => match inner.store.leases(writ_core::lease::State::Active) {
                Ok(active) => active
                    .into_iter()
                    .filter(|lease| !kept.contains(&lease.approval.approver))
                    .collect(),
                Err(e) => {
                    tracing::error!(error = %e, "cannot list the leases the approvers signed");
                    let denial = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
                        .approver(&checked.approver)
                        .caller(caller)
                        .reason(format!("{target}: internal error (see the daemon's log)"));
                    Self::write_best_effort(&mut inner, &denial);
                    return Err(internal(e));
                }
            },
            None => Vec::new(),
        };
        let digest = checked.admin.text.digest();
        let mut in_force = self.in_force();
        let sealed = old
            .checked_add(1)
            .ok_or_else(|| internal("version overflow"))
            .and_then(|version| {
                in_force.versions.insert(target, (version, digest.clone()));
                let mac = opened
                    .authority
                    .sign_head(&in_force.entries())
                    .map_err(internal)?;
                Ok((version, mac))
            });
        let (version, mac) = match sealed {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::error!(error = %e.detail(), %target, "cannot seal the new version");
                let denial = AuditEvent::new(now, EventKind::Admin, Outcome::Denied)
                    .approver(&checked.approver)
                    .caller(caller)
                    .reason(format!("{target}: internal error (see the daemon's log)"));
                Self::write_best_effort(&mut inner, &denial);
                return Err(e);
            }
        };
        in_force.mac = mac;
        let event = AuditEvent::new(now, EventKind::Admin, Outcome::Allowed)
            .approver(&checked.approver)
            .caller(caller)
            .reason(format!(
                "{target}: version {version} (sha256 {digest}) replaces version {old} (sha256 \
                 {}){}{certified}",
                checked.admin.previous,
                created
                    .iter()
                    .map(|key| format!(
                        "; created {} {}: {}",
                        key.role.as_str(),
                        key.id,
                        key.public_key
                    ))
                    .chain(removed.iter().map(|key| {
                        match (&key.public_key, &key.fingerprint) {
                            (Some(public), Some(fingerprint)) => format!(
                                "; removed {} {} ({fingerprint}): {public}",
                                key.description, key.id
                            ),
                            _ => format!("; removed {} {}", key.description, key.id),
                        }
                    }))
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
            AdminParsed::Policy(policy, key_uses) => {
                *self
                    .policy
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
                *self
                    .key_uses
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(key_uses);
                if let Some(keys) = openpgp {
                    self.set_openpgp(keys);
                }
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
        // Their certificates refused before the lock goes (the review after M7.6, A-4): none
        // of them is usable while the revocations are recorded one by one.
        for lease in &unapproved {
            self.bar_serial(lease.cert_serial);
        }
        drop(inner);
        let revoked = self.revoke_unapproved(unapproved, version);
        self.changed.notify_waiters();
        Ok(AdminApplied {
            target,
            version,
            digest,
            signed_by: checked.approver.clone(),
            created,
            revoked,
            removed,
            // The daemon's to say, once the keystore follows the new recipients.
            keystore: Vec::new(),
        })
    }

    /// Revokes `leases`, the active ones signed by an approver key `version` removed (listed
    /// under the change's lock): removing a key takes back what it granted. Each lease is
    /// revoked as the daemon revokes on a violation (its certificate barred first, its audit
    /// line, its sessions dropped); the ids revoked are returned for the change's reply. A
    /// revocation that can't be recorded leaves the certificate refused in memory, and is
    /// logged.
    fn revoke_unapproved(&self, leases: Vec<Lease>, version: u64) -> Vec<TicketId> {
        let mut revoked = Vec::new();
        for lease in leases {
            let reason = format!(
                "its approver {} was removed from approvers (version {version})",
                lease.approval.approver
            );
            // Refused first, whatever the store does.
            self.bar_serial(lease.cert_serial);
            match self.revoke_by_daemon(&lease.id, &reason, super::sweep::Announce::Now) {
                Ok(()) => revoked.push(lease.id),
                Err(e) => tracing::error!(
                    lease = %lease.id,
                    error = %e.detail(),
                    "cannot record the revocation of a lease whose approver was removed; its \
                     certificate is refused"
                ),
            }
        }
        revoked
    }

    /// At unseal, once the approvers' MAC is checked (the review after M7.6, A-4): every active
    /// lease signed by a key no longer in `approvers` is revoked, so a change whose revocations
    /// a crash cut short takes them back at the next start. Best effort, each failure logged;
    /// its certificate is refused in memory whatever the store does.
    pub(super) fn revoke_orphaned(&self) {
        let approvers: Vec<KeyFingerprint> = self
            .approver_keys()
            .iter()
            .filter_map(|key| super::fingerprint(key).ok())
            .collect();
        let leases = match self.lock().and_then(|inner| {
            inner
                .store
                .leases(writ_core::lease::State::Active)
                .map_err(super::internal)
        }) {
            Ok(leases) => leases,
            Err(e) => {
                tracing::error!(error = %e.detail(), "cannot list the active leases to check their approvers");
                return;
            }
        };
        let orphaned: Vec<Lease> = leases
            .into_iter()
            .filter(|lease| !approvers.contains(&lease.approval.approver))
            .collect();
        if !orphaned.is_empty() {
            let version = self
                .in_force()
                .versions
                .get(&AdminTarget::Approvers)
                .map_or(0, |(version, _)| *version);
            self.revoke_unapproved(orphaned, version);
        }
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
