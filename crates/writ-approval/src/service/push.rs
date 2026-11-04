//! Pushes (`docs/flows.md` § 3), decided whole at git's pre-receive hook, once the pack is in
//! the quarantine: the gateway reads the facts from what git verified (the ref updates, the
//! new commits and the paths each touches, the pack's size), the service looks every commit
//! up in the ledger and decides with `decide_push`, and takes the push from the lease's
//! count and rate, all under one lock. Nothing reaches upstream or the mirror before this.

use std::collections::BTreeSet;

use writ_core::caller::CallerFacts;
use writ_core::config::PushMode;
use writ_core::lease::Lease;
use writ_core::names::{CommitId, RepoName, TicketId};
use writ_core::policy::{
    self, CertIdentity, Context, Denial, DenyCode, LedgerRef, PushRequest, PushedCommit, RefUpdate,
};
use writ_core::ticket::Operation;
use writ_store::{AuditEvent, Counter, EventKind, Outcome};

use super::{Inner, Service, cert_event, internal};
use crate::ServiceError;

/// A push, as the gateway read it from git's quarantine.
#[derive(Debug, Clone)]
pub struct Pushing {
    pub cert: CertIdentity,
    pub caller: CallerFacts,
    pub repo: RepoName,
    pub updates: Vec<RefUpdate>,
    /// Every commit the push brings that the mirror doesn't have, with the digest of the
    /// paths it touches computed again from the objects git verified (`None`: they couldn't
    /// be computed).
    pub commits: Vec<(CommitId, Option<String>)>,
    /// What the push holds in the quarantine, in bytes.
    pub pack_size: u64,
}

impl Pushing {
    fn event(&self, now: writ_core::units::Timestamp) -> AuditEvent {
        cert_event(
            now,
            EventKind::Push,
            Outcome::Allowed,
            &self.cert,
            &self.caller,
        )
        .repo(&self.repo)
        .refs(self.updates.iter().map(|u| u.name.clone()))
    }
}

impl Service {
    /// Before the gateway reads a push's objects (walking new commits and trees): the
    /// certificate's single active lease, which allows `push` and names `repo`. Only a refusal
    /// is logged (a violation revokes a lease with `on_violation: revoke_lease`); an allowed
    /// push gets its one line from [`Service::push`], which checks everything again.
    pub fn may_push(
        &self,
        cert: &CertIdentity,
        caller: &CallerFacts,
        repo: &RepoName,
    ) -> Result<Lease, Denial> {
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let event = cert_event(now, EventKind::Push, Outcome::Denied, cert, caller).repo(repo);
        let lease = match self.lease_for(&mut inner, cert, caller, now) {
            Ok(lease) => lease,
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.denial(&denial));
                return Err(denial);
            }
        };
        let checked = policy::check_operation(&lease, Operation::Push)
            .and_then(|()| policy::check_repo(&lease, repo));
        match checked {
            Ok(()) => Ok(lease),
            Err(denial) => {
                Self::log_best_effort(&mut inner, &event.lease(&lease.id).denial(&denial));
                self.after_violation(inner, &lease, &denial);
                Err(denial)
            }
        }
    }

    /// Decides a push under the lease the certificate stands for: each new commit looked up
    /// in the ledger, `decide_push`, then the push taken from the lease's count and rate, all
    /// under one lock. One `push` line, whatever the outcome; a violation under
    /// `on_violation: revoke_lease` revokes the lease (the caller drops its sessions).
    pub fn push(&self, pushing: &Pushing) -> Result<Lease, Denial> {
        let (now, mut inner) = self.begin().map_err(super::as_denial)?;
        let event = pushing.event(now);
        let refuse = |inner: &mut Inner, event: &AuditEvent, denial: Denial| {
            Self::log_best_effort(inner, &event.clone().denial(&denial));
            denial
        };
        let lease = match self.lease_for(&mut inner, &pushing.cert, &pushing.caller, now) {
            Ok(lease) => lease,
            Err(denial) => return Err(refuse(&mut inner, &event, denial)),
        };
        let event = event.lease(&lease.id);
        let request = match self.push_request(&mut inner, pushing, &lease.id) {
            Ok(request) => request,
            Err(denial) => return Err(refuse(&mut inner, &event, denial)),
        };
        let usage = match inner.store.usage(&lease.id, now) {
            Ok(usage) => usage,
            Err(e) => {
                let denial = Denial::new(DenyCode::Invalid, internal(e).to_string());
                return Err(refuse(&mut inner, &event, denial));
            }
        };
        let policy = self.policy();
        let ctx = Context {
            config: &policy,
            lease: &lease,
            usage: &usage,
            caller: &pushing.caller,
            now,
        };
        if let Err(denial) = policy::decide_push(&ctx, &request) {
            let denial = refuse(&mut inner, &event, denial);
            self.after_violation(inner, &lease, &denial);
            return Err(denial);
        }
        let max = lease.ticket.limits.max_pushes;
        // Under the same lock as the decision; the store still refuses past the limit.
        match inner.store.consume(&lease.id, Counter::Push, max, now) {
            Ok(true) => {}
            Ok(false) => {
                let reason = format!("lease {}: all {max} pushes used", lease.id);
                return Err(refuse(
                    &mut inner,
                    &event,
                    Denial::new(DenyCode::Limit, reason),
                ));
            }
            Err(e) => {
                let denial = Denial::new(DenyCode::Invalid, internal(e).to_string());
                return Err(refuse(&mut inner, &event, denial));
            }
        }
        if let Err(e) = Self::log(&mut inner, &event) {
            return Err(Denial::new(DenyCode::Invalid, e.to_string()));
        }
        Ok(lease)
    }

    /// The new commits of a push whose paths the gateway must compute again: those the
    /// ledger holds for this lease (or a lease it renews) and repo with the paths signing saw. The others need none,
    /// so a push of commits nobody signed costs no walk of their trees: `decide_push` refuses
    /// a commit with no entry here whatever its paths, and has nothing to compare for one
    /// signed with its paths unknown. A read under the state lock (no sweep, nothing logged);
    /// [`Service::push`] decides on everything again.
    pub fn paths_to_check(
        &self,
        lease: &TicketId,
        repo: &RepoName,
        commits: &[CommitId],
    ) -> Result<BTreeSet<CommitId>, ServiceError> {
        let inner = self.lock()?;
        let chain = inner.store.predecessors(lease).map_err(internal)?;
        let mut checked = BTreeSet::new();
        for commit in commits {
            let entries = inner.store.ledger_entries(commit).map_err(internal)?;
            if entries.iter().any(|e| {
                (&e.lease == lease || chain.contains(&e.lease))
                    && &e.repo == repo
                    && e.paths_digest.is_some()
            }) {
                checked.insert(commit.clone());
            }
        }
        Ok(checked)
    }

    /// The policy's view of a push: each new commit with every ledger entry for it, and the
    /// leases the pushing lease renews.
    fn push_request(
        &self,
        inner: &mut Inner,
        pushing: &Pushing,
        lease: &TicketId,
    ) -> Result<PushRequest, Denial> {
        let predecessors = inner
            .store
            .predecessors(lease)
            .map_err(|e| Denial::new(DenyCode::Invalid, internal(e).to_string()))?;
        let mut commits = Vec::with_capacity(pushing.commits.len());
        for (id, paths) in &pushing.commits {
            let entries = inner
                .store
                .ledger_entries(id)
                .map_err(|e| Denial::new(DenyCode::Invalid, internal(e).to_string()))?;
            commits.push(PushedCommit {
                id: id.clone(),
                signed_under: entries
                    .into_iter()
                    .map(|entry| LedgerRef {
                        lease: entry.lease,
                        repo: entry.repo,
                        paths: entry.paths_digest,
                    })
                    .collect(),
                paths: paths.clone(),
            });
        }
        Ok(PushRequest {
            repo: pushing.repo.clone(),
            mode: PushMode::Gateway,
            updates: pushing.updates.clone(),
            commits,
            pack_size: pushing.pack_size,
            predecessors,
        })
    }
}
