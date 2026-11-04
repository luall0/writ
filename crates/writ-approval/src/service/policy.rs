//! `writ policy <repo>`: what a ticket for one repo may ask, so an agent writes a ticket that
//! fits before it sends one. A read: it grants nothing, and the daemon checks every ticket
//! again. Only that repo is shown: never its upstream or credential, another repo, or what a
//! template allows elsewhere.

use writ_core::caller::CallerFacts;
use writ_core::config::{PolicyConfig, RepoEntry, Template};
use writ_core::names::{RepoName, TemplateName};
use writ_proto::{RepoPolicy, TemplateView};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::Service;
use crate::{RefusalCode, ServiceError};

impl Service {
    /// The policy in force for `repo`, for a caller on the agents' listener. It counts against
    /// the submission rates; a repo not in the registry is refused (and logged).
    pub fn repo_policy(
        &self,
        repo: &RepoName,
        caller: &CallerFacts,
    ) -> Result<RepoPolicy, ServiceError> {
        let (now, mut inner) = self.begin()?;
        Self::within_rate(&mut inner, caller, now)?;
        let policy = self.policy();
        let Some(view) = self.view(&policy, repo) else {
            let error = ServiceError::refused(
                RefusalCode::UnknownRepo,
                format!("repo {repo} is not in the registry"),
            );
            let event = AuditEvent::new(now, EventKind::Policy, Outcome::Denied)
                .caller(caller)
                .reason(error.reason_text());
            Self::log_best_effort(&mut inner, &event);
            return Err(error);
        };
        let event = AuditEvent::new(now, EventKind::Policy, Outcome::Allowed)
            .caller(caller)
            .repo(repo);
        Self::logged(&mut inner, event, |_| Ok(()))?;
        Ok(view)
    }

    /// What a ticket for `repo` may ask under `policy`, or none when the repo isn't there.
    fn view(&self, policy: &PolicyConfig, repo: &RepoName) -> Option<RepoPolicy> {
        let entry: &RepoEntry = policy.repo(repo)?;
        let templates = policy
            .templates()
            .iter()
            .filter(|(_, template)| template.repos.contains(repo))
            .map(|(name, template)| template_view(name, template))
            .collect();
        Some(RepoPolicy {
            repo: repo.clone(),
            protected_refs: entry
                .protected_refs
                .iter()
                .map(ToString::to_string)
                .collect(),
            ticket_link: entry.ticket_link,
            templates,
            min_ttl: self.config.min_ttl,
            renew_grace: self.config.renew_grace,
            max_active_per_source: self.config.max_active_per_source,
        })
    }
}

/// A template, without the repos it names (only the one asked about is shown); its signing
/// key by id only (one ticket's repositories must share one).
fn template_view(name: &TemplateName, template: &Template) -> TemplateView {
    TemplateView {
        name: name.clone(),
        operations: template.operations.iter().copied().collect(),
        branches: template.branches.iter().map(ToString::to_string).collect(),
        committer_emails: template.committer_emails.iter().cloned().collect(),
        committer_name: template.committer_name.clone(),
        force_push: template.force_push,
        max_ttl: template.max_ttl,
        max_signatures: template.max_signatures,
        max_pushes: template.max_pushes,
        max_ops_per_minute: template.max_ops_per_minute,
        max_push_size: template.max_push_size,
        paths_check: template.paths_check,
        require_expected_paths: template.require_expected_paths,
        max_renewals: template.max_renewals,
        signing_key: template.signing_key.clone(),
    }
}
