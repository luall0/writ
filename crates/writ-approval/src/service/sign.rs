//! Commit signatures (`docs/flows.md` § 2), in three phases so the
//! [`Signer`](writ_signer::Signer) never runs under the state lock (a slow or hung device
//! would hold up every approval, wait and revocation):
//!
//! 1. under the lock: the lease a certificate stands for, the policy's decision on the
//!    commit, the count and the rate slot taken (never given back);
//! 2. without it: the signature, through the signer's queue and its deadline;
//! 3. under the lock again: the lease still the same, active, not expired and its
//!    certificate not on the deny list, then the audit line and the commit in the ledger.
//!
//! The signature is handed back only once its line is written and the ledger holds the
//! commit: a signature the daemon didn't record never leaves it, and one made while the lease
//! ended is discarded. The ledger holds the id of the commit git writes with the signature in
//! it (`writ_git::signed`), so only that commit passes a push later.

use std::collections::HashMap;
use std::sync::MutexGuard;

use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::names::{CommitId, KeyId, RepoName, TicketId};
use writ_core::policy::{self, CertIdentity, Context, Denial, DenyCode, ObjectKind, SignRequest};
use writ_core::ticket::{OnViolation, Operation};
use writ_core::units::Timestamp;
use writ_crypto::algorithm::SignatureFormat;
use writ_git::Commit;
use writ_signer::SignerError;
use writ_store::{AuditEvent, Counter, EventKind, LedgerEntry, Outcome};

use super::sweep::Announce;
use super::{Inner, Service, cert_event, internal};
use crate::ServiceError;

/// The SSHSIG namespace git signs commits in (the only one the gateway accepts).
const GIT_NAMESPACE: &str = "git";

/// A signing request, as the gateway parsed it.
#[derive(Debug, Clone)]
pub struct Signing {
    pub cert: CertIdentity,
    pub caller: CallerFacts,
    /// The repo the commit is for (`writ-sign git <repo>`).
    pub repo: RepoName,
    /// The signature format git asked for (`gpg.format`): it must be the lease's key's.
    pub format: SignatureFormat,
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
                author_email: commit.author_email().to_owned(),
                writ_trailers: commit.writ_trailers(),
                touched_paths: touched_paths.clone(),
            },
            SignObject::Other(kind) => SignRequest {
                repo: self.repo.clone(),
                object: *kind,
                object_format: None,
                committer_email: String::new(),
                author_email: String::new(),
                writ_trailers: Vec::new(),
                touched_paths: None,
            },
        }
    }
}

/// A signed commit: the armored signature for git (an SSHSIG, or an OpenPGP signature), and
/// what the ledger recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    pub signature: String,
    /// The id of the commit git writes with the signature in it.
    pub commit: CommitId,
    /// For the activity report (files outside `expected_paths` with `paths_check: warn`).
    pub warnings: Vec<String>,
}

/// The `sign` line of a request, before its outcome.
fn sign_event(signing: &Signing, request: &SignRequest, now: Timestamp) -> AuditEvent {
    let mut event = cert_event(
        now,
        EventKind::Sign,
        Outcome::Allowed,
        &signing.cert,
        &signing.caller,
    )
    .repo(&request.repo);
    if !request.committer_email.is_empty() {
        event = event.committer(&request.committer_email);
    }
    event
}

/// Logs `denial` as the request's `sign` line, and hands it back.
fn deny(inner: &mut Inner, event: &AuditEvent, denial: Denial) -> Denial {
    Service::log_best_effort(inner, &event.clone().denial(&denial));
    denial
}

/// What the agent reads when the signer didn't sign: the kind of failure, never its cause
/// (in the daemon's log).
fn signer_reason(e: &SignerError) -> String {
    match e {
        SignerError::Busy => "the signer is busy; retry shortly".to_owned(),
        SignerError::Timeout(_) => {
            "the signer did not sign in time (see the daemon's log)".to_owned()
        }
        _ => "the signer failed (see the daemon's log)".to_owned(),
    }
}

/// What [`Service::reserve`] took for a signature, for the next phases.
struct Reserved<'a> {
    lease: Lease,
    key: KeyId,
    /// How the key signs, as declared.
    key_use: crate::KeyUse,
    /// The time an OpenPGP signature says it was made (seconds since the epoch).
    time: u32,
    commit: &'a Commit,
    warnings: Vec<String>,
    in_flight: InFlight<'a>,
}

/// A signature of `lease` between its phases: while one is in flight, the sweep doesn't
/// mark the lease used up (the slot it took would make the signature's own check refuse
/// it). Released under the lock by [`Service::settle`], or when dropped if that never runs.
struct InFlight<'a> {
    service: &'a Service,
    lease: TicketId,
    settled: bool,
}

impl InFlight<'_> {
    fn settle(&mut self, inner: &mut Inner) {
        if !self.settled {
            inner.signing.end(&self.lease);
            self.settled = true;
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // Releasing lets the lease be marked used up: a reduction of privilege, so a
            // poisoned lock is recovered rather than skipped.
            let mut inner = self
                .service
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.settle(&mut inner);
        }
    }
}

/// The signatures in flight, per lease.
#[derive(Default)]
pub(super) struct InFlightSignatures(HashMap<TicketId, u32>);

impl InFlightSignatures {
    fn start(&mut self, lease: &TicketId) {
        let count = self.0.entry(lease.clone()).or_default();
        *count = count.saturating_add(1);
    }

    fn end(&mut self, lease: &TicketId) {
        if let Some(count) = self.0.get_mut(lease) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.0.remove(lease);
            }
        }
    }

    /// Whether a signature of `lease` is between its phases.
    pub(super) fn any(&self, lease: &TicketId) -> bool {
        self.0.contains_key(lease)
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
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let event = cert_event(now, EventKind::Sign, Outcome::Denied, cert, caller).repo(repo);
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
    ///
    /// Three phases, so the signer never runs under the state lock: [`Service::reserve`]
    /// (decide, take the slot), the signature, [`Service::settle`] (check again, record).
    pub fn sign(&self, signing: &Signing) -> Result<SignedCommit, Denial> {
        let request = signing.request();
        let reserved = self.reserve(signing, &request)?;
        let signer = &*self.opened().map_err(super::as_denial)?.signer;
        let signed = self.signature(
            signer,
            &reserved.key,
            reserved.key_use,
            GIT_NAMESPACE,
            reserved.commit.bytes(),
            reserved.time,
        );
        self.settle(signing, &request, reserved, signed)
    }

    /// The first phase, under the lock: the lease, the policy's decision, and the count and
    /// the rate slot taken. A denial is logged here (and a violation's certificate barred
    /// before the lock is released). The slot is never given back: a signature that fails or
    /// is discarded later still used it, so nothing can be retried past the limits.
    fn reserve<'a>(
        &'a self,
        signing: &'a Signing,
        request: &SignRequest,
    ) -> Result<Reserved<'a>, Denial> {
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let event = sign_event(signing, request, now);
        let lease = match self.lease_for(&mut inner, &signing.cert, &signing.caller, now) {
            Ok(lease) => lease,
            Err(denial) => return Err(deny(&mut inner, &event, denial)),
        };
        let usage = match inner.store.usage(&lease.id, now) {
            Ok(usage) => usage,
            Err(e) => {
                let reason = internal(e).to_string();
                return Err(deny(
                    &mut inner,
                    &event,
                    Denial::new(DenyCode::Invalid, reason),
                ));
            }
        };
        let policy = self.policy();
        let ctx = Context {
            config: &policy,
            lease: &lease,
            usage: &usage,
            caller: &signing.caller,
            now,
        };
        let allowed = match policy::decide_sign(&ctx, request) {
            Ok(allowed) => allowed,
            Err(denial) => {
                let denial = deny(&mut inner, &event, denial);
                self.after_violation(inner, &lease, &denial);
                return Err(denial);
            }
        };
        let (SignObject::Commit { commit, .. }, Some(key)) =
            (&signing.object, &lease.ticket.scope.signing_key)
        else {
            // The policy refuses both before this point (`ObjectType`, `Config`).
            tracing::error!("an allowed signature without a commit or a signing key");
            let denial = Denial::internal();
            return Err(deny(&mut inner, &event, denial));
        };
        // Declared: the daemon refuses to start otherwise (fail closed all the same, before a
        // slot is taken).
        let Some(key_use) = self.config.signing_keys.get(key).copied() else {
            tracing::error!(%key, "a signing key without a declaration");
            let denial = Denial::internal();
            return Err(deny(&mut inner, &event, denial));
        };
        // git asked for the format the lease's key signs in, or nothing is signed (and no
        // slot taken: a wiring mistake, never anything the ticket allowed).
        if signing.format != key_use.format {
            let reason = format!(
                "lease {}: its key {key} signs in {}, and git asked for {} (set gpg.format = {}, \
                 as `writ init` does)",
                lease.id, key_use.format, signing.format, key_use.format
            );
            let denial = Denial::new(DenyCode::SignatureFormat, reason);
            return Err(deny(&mut inner, &event, denial));
        }
        // An OpenPGP signature's time: a 32-bit count of seconds.
        let time = u32::try_from(now.unix()).unwrap_or(u32::MAX);
        let max = lease.ticket.limits.max_signatures;
        // Under the same lock as the decision: the counter can't have moved, but the store
        // refuses past the limit whatever happens.
        match inner.store.consume(&lease.id, Counter::Signature, max, now) {
            Ok(true) => {}
            Ok(false) => {
                let reason = format!("lease {}: all {max} signatures used", lease.id);
                return Err(deny(
                    &mut inner,
                    &event,
                    Denial::new(DenyCode::Limit, reason),
                ));
            }
            Err(e) => {
                let reason = internal(e).to_string();
                return Err(deny(
                    &mut inner,
                    &event,
                    Denial::new(DenyCode::Invalid, reason),
                ));
            }
        }
        inner.signing.start(&lease.id);
        Ok(Reserved {
            key: key.clone(),
            key_use,
            time,
            commit,
            warnings: allowed.warnings,
            in_flight: InFlight {
                service: self,
                lease: lease.id.clone(),
                settled: false,
            },
            lease,
        })
    }

    /// The last phase, under the lock again: the lease must still be the one the decision
    /// was made on, active, not past `expires_at` and its certificate not on the deny list;
    /// then the signed commit's id, the audit line and the ledger entry, and only then does
    /// the signature leave. Otherwise it is discarded and the denial logged. Then the lease
    /// is marked used up if it is, now that nothing of it is in flight.
    fn settle(
        &self,
        signing: &Signing,
        request: &SignRequest,
        mut reserved: Reserved<'_>,
        signed: Result<String, SignerError>,
    ) -> Result<SignedCommit, Denial> {
        let (now, mut inner) = match self.now().and_then(|now| Ok((now, self.lock()?))) {
            Ok(locked) => locked,
            // The slot stays used; the lease is released by `InFlight`'s drop. No line can
            // be written without the lock: the daemon's log says why.
            Err(e) => {
                tracing::error!(error = %e.detail(), "cannot settle a signature: it is discarded");
                return Err(Denial::new(DenyCode::Invalid, e.to_string()));
            }
        };
        reserved.in_flight.settle(&mut inner);
        let outcome = self.record(&mut inner, signing, request, &reserved, signed, now);
        match self.sweep_locked(&mut inner, now) {
            Ok(true) => self.changed.notify_waiters(),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e.detail(), "sweep failed"),
        }
        outcome
    }

    /// The checks of [`Service::settle`] and what it records, under the lock.
    fn record(
        &self,
        inner: &mut Inner,
        signing: &Signing,
        request: &SignRequest,
        reserved: &Reserved<'_>,
        signed: Result<String, SignerError>,
        now: Timestamp,
    ) -> Result<SignedCommit, Denial> {
        let event = &sign_event(signing, request, now).lease(&reserved.lease.id);
        let signature = match signed {
            Ok(signature) => signature,
            Err(e) => {
                tracing::error!(error = %e, key = %reserved.key, "the signer failed");
                return Err(deny(
                    inner,
                    event,
                    Denial::new(DenyCode::Invalid, signer_reason(&e)),
                ));
            }
        };
        // The lease may have ended or changed while the backend signed.
        let current = match self.lease_for(inner, &signing.cert, &signing.caller, now) {
            Ok(current) if current.ticket == reserved.lease.ticket => current,
            Ok(current) => {
                let reason = format!(
                    "lease {}: its terms changed while the commit was being signed; \
                     the signature was discarded",
                    current.id
                );
                return Err(deny(inner, event, Denial::new(DenyCode::NotActive, reason)));
            }
            Err(denial) => {
                let reason = format!(
                    "{} (while the commit was being signed); the signature was discarded",
                    denial.reason
                );
                return Err(deny(inner, event, Denial { reason, ..denial }));
            }
        };
        // The policy may have changed too (a signed change applies at once): the lease must
        // still fit the template in force, as the first phase checked.
        if let Err(why) = writ_core::fit::fits(&self.policy(), &current.ticket) {
            let reason = format!(
                "lease {} no longer fits template {}: {why} (changed while the commit was being \
                 signed); the signature was discarded",
                current.id, current.ticket.template
            );
            return Err(deny(inner, event, Denial::new(DenyCode::Config, reason)));
        }
        let commit_id = match writ_git::signed::signed_id(reserved.commit, &signature)
            .and_then(|id| Ok(id.to_commit_id()?))
        {
            Ok(id) => id,
            Err(e) => {
                let denial = Denial::new(DenyCode::Invalid, format!("cannot sign the commit: {e}"));
                return Err(deny(inner, event, denial));
            }
        };
        let line = event
            .clone()
            .commit(&commit_id)
            .warnings(reserved.warnings.clone());
        let entry = LedgerEntry {
            commit: commit_id.clone(),
            lease: current.id.clone(),
            repo: request.repo.clone(),
            key: reserved.key.clone(),
            signed_at: now,
            paths_digest: match &signing.object {
                SignObject::Commit {
                    touched_paths: Some(paths),
                    ..
                } => Some(writ_git::paths::digest(paths)),
                _ => None,
            },
        };
        let recorded = Self::logged(inner, line, |inner| {
            inner.store.ledger_append(&entry).map_err(internal)
        });
        match recorded {
            Ok(()) => Ok(SignedCommit {
                signature,
                commit: commit_id,
                warnings: reserved.warnings.clone(),
            }),
            Err(e) => {
                tracing::error!(error = %e.detail(), "a signature was not recorded");
                let denial = Denial::new(DenyCode::Invalid, e.to_string());
                // A failed change already has its line (`logged`); a log that couldn't take
                // the allowed line gets the denial kept for when it can.
                if matches!(e, ServiceError::AuditLog(_)) {
                    deny(inner, event, denial.clone());
                }
                Err(denial)
            }
        }
    }

    /// A denial under a lease with `on_violation: revoke_lease`, if it is a violation:
    /// revokes the lease. Releases the state lock either way.
    pub(super) fn after_violation(
        &self,
        inner: MutexGuard<'_, Inner>,
        lease: &Lease,
        denial: &Denial,
    ) {
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
