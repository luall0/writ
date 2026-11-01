//! Commit signatures (`docs/flows.md` § 2): the lease a certificate stands for, the policy's
//! decision on the commit, the signature through the [`Signer`](writ_signer::Signer), then
//! the audit line, the signature counted and the commit in the ledger.
//!
//! All of it under the state lock, so a revocation, an expiry or a concurrent signature
//! can't come between the decision and what it allows. The signature is handed back only
//! once its line is written and the ledger holds the commit: a signature the daemon didn't
//! record never leaves it. The ledger holds the id of the commit git writes with the
//! signature in it (`writ_git::signed`), so only that commit passes a push later.

use writ_core::caller::CallerFacts;
use writ_core::names::{CommitId, TicketId};
use writ_core::policy::{self, CertIdentity, Context, Denial, DenyCode, SignRequest};
use writ_core::ticket::OnViolation;
use writ_git::Commit;
use writ_store::{AuditEvent, Counter, EventKind, LedgerEntry, Outcome};

use super::sweep::Announce;
use super::{Inner, Service, internal};
use crate::{RefusalCode, ServiceError};

/// A signing request, as the gateway parsed it.
#[derive(Debug, Clone)]
pub struct Signing {
    pub cert: CertIdentity,
    pub caller: CallerFacts,
    /// The SSHSIG namespace git asked for (`git`).
    pub namespace: String,
    /// The facts the policy decides on.
    pub request: SignRequest,
    /// The commit to sign; `None` when the object isn't a commit (the policy refuses it).
    pub commit: Option<Commit>,
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
    /// Signs a commit under the lease the certificate stands for, if the policy allows it.
    /// Every outcome is one `sign` line in the audit log. A violation under a lease with
    /// `on_violation: revoke_lease` revokes it; the caller drops its sessions (it has the
    /// denial to send first: [`Service::is_revoked`] then says so).
    pub fn sign(&self, signing: &Signing) -> Result<SignedCommit, Denial> {
        let (now, mut inner) = self
            .begin()
            .map_err(|e| failed(DenyCode::Invalid, e.to_string()))?;
        let request = &signing.request;
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
                if denial.code.is_violation()
                    && lease.ticket.on_violation == OnViolation::RevokeLease
                {
                    drop(inner);
                    self.revoke_for_violation(&lease.id, &denial);
                }
                return Err(denial);
            }
        };
        let (Some(commit), Some(key)) = (&signing.commit, &lease.ticket.scope.signing_key) else {
            let denial = failed(DenyCode::Invalid, "only commits are signed");
            return Err(deny(&mut inner, denial));
        };
        let signature =
            match writ_signer::sshsig(&*self.signer, key, &signing.namespace, commit.bytes()) {
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
            .and_then(|id| id.to_commit_id())
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
