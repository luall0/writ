//! Commit signatures (`docs/flows.md` § 2): the lease a certificate stands for, the policy's
//! decision on the commit, the signature through the [`Signer`](writ_signer::Signer), then
//! the audit line, the signature counted and the commit in the ledger.
//!
//! All of it under the state lock, so a revocation, an expiry or a concurrent signature
//! can't come between the decision and what it allows. The signature is handed back only
//! once its line is written and the ledger holds the commit: a signature the daemon didn't
//! record never leaves it. The ledger holds the id of the commit git writes with the
//! signature in it (`writ_git::signed`), so only that commit passes a push later.

use std::sync::MutexGuard;

use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::names::{CommitId, RepoName, TicketId};
use writ_core::policy::{self, CertIdentity, Context, Denial, DenyCode, ObjectKind, SignRequest};
use writ_core::ticket::{OnViolation, Operation};
use writ_git::Commit;
use writ_store::{AuditEvent, Counter, EventKind, LedgerEntry, Outcome};

use super::sweep::Announce;
use super::{Inner, Service, internal};
use crate::{RefusalCode, ServiceError};

/// The SSHSIG namespace git signs commits in (the only one the gateway accepts).
const GIT_NAMESPACE: &str = "git";

/// A signing request, as the gateway parsed it.
#[derive(Debug, Clone)]
pub struct Signing {
    pub cert: CertIdentity,
    pub caller: CallerFacts,
    /// The repo the commit is for (`writ-sign git <repo>`).
    pub repo: RepoName,
    pub object: SignObject,
}

/// What git asked to sign.
#[derive(Debug, Clone)]
pub enum SignObject {
    /// A commit, with the paths it touches (`None`: they couldn't be computed).
    Commit {
        commit: Commit,
        touched_paths: Option<Vec<String>>,
    },
    /// Anything else, by its kind: the policy refuses it.
    Other(ObjectKind),
}

impl Signing {
    /// The facts the policy decides on, read from the object itself.
    fn request(&self) -> SignRequest {
        match &self.object {
            SignObject::Commit {
                commit,
                touched_paths,
            } => SignRequest {
                repo: self.repo.clone(),
                object: ObjectKind::Commit,
                object_format: Some(commit.algo().object_format()),
                committer_email: commit.committer_email().to_owned(),
                writ_trailers: commit.writ_trailers(),
                touched_paths: touched_paths.clone(),
            },
            SignObject::Other(kind) => SignRequest {
                repo: self.repo.clone(),
                object: *kind,
                object_format: None,
                committer_email: String::new(),
                writ_trailers: Vec::new(),
                touched_paths: None,
            },
        }
    }
}

/// A signed commit: the armored SSHSIG for git, and what the ledger recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    pub signature: String,
    /// The id of the commit git writes with the signature in it.
    pub commit: CommitId,
    /// For the activity report (files outside `expected_paths` with `paths_check: warn`).
    pub warnings: Vec<String>,
}

fn failed(code: DenyCode, reason: impl Into<String>) -> Denial {
    Denial {
        code,
        reason: reason.into(),
        hint: None,
    }
}

impl Service {
    /// Before the gateway reads a signing request (up to 16 MiB to decode, hash and walk):
    /// the certificate's single active lease, which allows `commit_sign` and names `repo`.
    /// Only a refusal is logged (a `sign` line, and the lease revoked for a violation under
    /// `on_violation: revoke_lease`); an allowed request gets its one line from
    /// [`Service::sign`], which checks everything again under the lock.
    pub fn may_sign(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        repo: &RepoName,
    ) -> Result<(), Denial> {
        let (now, mut inner) = self
            .begin()
            .map_err(|e| failed(DenyCode::Invalid, e.to_string()))?;
        let mut event = AuditEvent::new(now, EventKind::Sign, Outcome::Denied)
            .cert(cert.serial)
            .caller(caller)
            .repo(repo);
        if let Ok(id) = cert.key_id.parse::<TicketId>() {
            event = event.lease(&id);
        }
        let lease = match self.lease_for(&mut inner, cert, caller, now) {
            Ok(lease) => lease,
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.denial(&denial));
                return Err(denial);
            }
        };
        let checked = policy::check_operation(&lease, Operation::CommitSign)
            .and_then(|()| policy::check_repo(&lease, repo));
        match checked {
            Ok(()) => Ok(()),
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.denial(&denial));
                self.after_violation(inner, &lease, &denial);
                Err(denial)
            }
        }
    }

    /// Signs a commit under the lease the certificate stands for, if the policy allows it.
    /// Every outcome is one `sign` line in the audit log. A violation under a lease with
    /// `on_violation: revoke_lease` revokes it; the caller drops its sessions (it has the
    /// denial to send first: [`Service::is_revoked`] then says so).
    pub fn sign(&self, signing: &Signing) -> Result<SignedCommit, Denial> {
        let (now, mut inner) = self
            .begin()
            .map_err(|e| failed(DenyCode::Invalid, e.to_string()))?;
        let request = &signing.request();
        let mut event = AuditEvent::new(now, EventKind::Sign, Outcome::Allowed)
            .cert(signing.cert.serial)
            .caller(&signing.caller)
            .repo(&request.repo);
        if let Ok(id) = signing.cert.key_id.parse::<TicketId>() {
            event = event.lease(&id);
        }
        if !request.committer_email.is_empty() {
            event = event.committer(&request.committer_email);
        }
        let deny = |inner: &mut Inner, denial: Denial| {
            let mut line = event.clone().denial(&denial);
            line.result = Outcome::Denied;
            Self::log_best_effort(inner, &line);
            denial
        };

        let lease = match self.lease_for(&mut inner, &signing.cert, &signing.caller, now) {
            Ok(lease) => lease,
            Err(denial) => return Err(deny(&mut inner, denial)),
        };
        let usage = match inner.store.usage(&lease.id, now) {
            Ok(usage) => usage,
            Err(e) => {
                let reason = internal(e).to_string();
                return Err(deny(&mut inner, failed(DenyCode::Invalid, reason)));
            }
        };
        let ctx = Context {
            config: &self.config.policy,
            lease: &lease,
            usage: &usage,
            caller: &signing.caller,
            now,
        };
        let allowed = match policy::decide_sign(&ctx, request) {
            Ok(allowed) => allowed,
            Err(denial) => {
                let denial = deny(&mut inner, denial);
                self.after_violation(inner, &lease, &denial);
                return Err(denial);
            }
        };
        let (SignObject::Commit { commit, .. }, Some(key)) =
            (&signing.object, &lease.ticket.scope.signing_key)
        else {
            // The policy refuses both before this point (`ObjectType`, `Config`).
            tracing::error!("an allowed signature without a commit or a signing key");
            let denial = failed(DenyCode::Invalid, "internal error in the daemon");
            return Err(deny(&mut inner, denial));
        };
        let signature = match writ_signer::sshsig(&*self.signer, key, GIT_NAMESPACE, commit.bytes())
        {
            Ok(signature) => signature,
            Err(e) => {
                tracing::error!(error = %e, key = %key, "the signer failed");
                let denial = failed(
                    DenyCode::Invalid,
                    "the signer failed (see the daemon's log)",
                );
                return Err(deny(&mut inner, denial));
            }
        };
        let commit_id = match writ_git::signed::signed_id(commit, &signature)
            .and_then(|id| Ok(id.to_commit_id()?))
        {
            Ok(id) => id,
            Err(e) => {
                let denial = failed(DenyCode::Invalid, format!("cannot sign the commit: {e}"));
                return Err(deny(&mut inner, denial));
            }
        };
        let line = event
            .clone()
            .lease(&lease.id)
            .commit(&commit_id)
            .warnings(allowed.warnings.clone());
        let entry = LedgerEntry {
            commit: commit_id.clone(),
            lease: lease.id.clone(),
            repo: request.repo.clone(),
            key: key.clone(),
            signed_at: now,
        };
        let max = lease.ticket.limits.max_signatures;
        let recorded = Self::logged(&mut inner, line, |inner| {
            // Under the same lock as the decision: the counter can't have moved, but the
            // store refuses past the limit whatever happens.
            if !inner
                .store
                .consume(&lease.id, Counter::Signature, max, now)
                .map_err(internal)?
            {
                return Err(ServiceError::refused(
                    RefusalCode::WrongState,
                    format!("lease {}: all {max} signatures used", lease.id),
                ));
            }
            inner.store.ledger_append(&entry).map_err(internal)
        });
        match recorded {
            Ok(()) => Ok(SignedCommit {
                signature,
                commit: commit_id,
                warnings: allowed.warnings,
            }),
            Err(e) => {
                tracing::error!(error = %e.detail(), "a signature was not recorded");
                let code = match e.code() {
                    Some(RefusalCode::WrongState) => DenyCode::Limit,
                    _ => DenyCode::Invalid,
                };
                let denial = failed(code, e.to_string());
                // A failed change already has its line (`logged`); a log that couldn't take
                // the allowed line gets the denial kept for when it can.
                if matches!(e, ServiceError::AuditLog(_)) {
                    deny(&mut inner, denial.clone());
                }
                Err(denial)
            }
        }
    }

    /// A denial under a lease with `on_violation: revoke_lease`, if it is a violation:
    /// revokes the lease. Releases the state lock either way.
    fn after_violation(&self, inner: MutexGuard<'_, Inner>, lease: &Lease, denial: &Denial) {
        if denial.code.is_violation() && lease.ticket.on_violation == OnViolation::RevokeLease {
            // On the deny list before the lock is released: no other request of this lease
            // gets through meanwhile, and the certificate stays refused even if recording
            // the revocation fails.
            self.bar_serial(lease.cert_serial);
            drop(inner);
            self.revoke_for_violation(&lease.id, denial);
        }
    }

    /// `on_violation: revoke_lease`: the lease ends with the violation as its reason. Its
    /// certificate is refused at once; its sessions are dropped by the gateway, which has
    /// the denial to send first.
    fn revoke_for_violation(&self, lease: &TicketId, denial: &Denial) {
        let reason = format!("violation ({}): {}", denial.code, denial.reason);
        if let Err(e) = self.revoke_by_daemon(lease, &reason, Announce::Later) {
            tracing::error!(
                lease = %lease,
                error = %e.detail(),
                "cannot record the revocation of a lease after a violation; its certificate is refused"
            );
        }
        self.changed.notify_waiters();
    }
}
