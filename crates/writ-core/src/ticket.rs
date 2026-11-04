//! Tickets: what the agent asks for ([`TicketRequest`]), and the complete ticket the daemon
//! builds from it ([`Ticket`]), whose canonical bytes an approval signs.
//!
//! # Canonical encoding
//!
//! A ticket is a [`Canonical`] document of kind `writ-ticket/3`: its fields in the order
//! declared below, sizes in bytes, durations as their text (`45m`) and timestamps as
//! `YYYY-MM-DDTHH:MM:SSZ`. Fixtures in `tests/fixtures/` pin the format.
//!
//! # The lease's terms, then each repository's (M6.1.5)
//!
//! A ticket says what is common to the lease ([`Common`]: the committer emails, and the
//! signing key and committer name its templates set; [`Limits`]: the end and the rate;
//! `on_violation`), then what each repository gets ([`RepoTerms`]: its template, operations,
//! branches, `force_push`, expected paths and counts). No term is overridden: each has one
//! place, so the approver reads it there. The layout before `writ-ticket/3` is refused
//! ([`old_layout`]), naming each key's new place.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::caller::CallerConstraint;
use crate::canonical::Canonical;
use crate::names::{CommitterName, Email, KeyFingerprint, KeyId, RepoName, TemplateName, TicketId};
use crate::pattern::{BranchPattern, PathPattern};
use crate::units::{ByteSize, Duration, Timestamp};
use crate::yaml::{FieldError, parse_yaml};

/// The format marker; only `"writ-ticket/3"` ([`Ticket::KIND`]) is accepted (`/3`: the
/// lease's terms, then each repository's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TicketKind {
    #[default]
    #[serde(rename = "writ-ticket/3")]
    V3,
}

/// A complete ticket: what an approval signs, and once signed, the lease's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub kind: TicketKind,
    pub id: TicketId,
    pub created_at: Timestamp,
    pub subject: Subject,
    /// The lease's terms, for every repository.
    pub common: Common,
    /// Each repository's terms, at least one ([`crate::fit::MAX_REPOS`] at most).
    pub repos: BTreeMap<RepoName, RepoTerms>,
    /// The agent's words and the links between tickets (`ticket` in the canonical bytes).
    #[serde(rename = "ticket")]
    pub text: TicketText,
    pub limits: Limits,
    pub on_violation: OnViolation,
}

/// Who may use the lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Fingerprint of the session key the certificate is issued for.
    pub session_key: KeyFingerprint,
    /// Where the agent says it runs. Shown to the approver, never enforced.
    pub origin_hint: Option<String>,
    /// A caller constraint checked against [`crate::caller::CallerFacts`].
    pub caller: Option<CallerConstraint>,
}

/// An operation a ticket can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Fetch,
    CommitSign,
    Push,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fetch => "fetch",
            Self::CommitSign => "commit_sign",
            Self::Push => "push",
        })
    }
}

impl std::str::FromStr for Operation {
    type Err = String;

    /// The names of [`Operation`]'s `Display` (and of the ticket's YAML).
    fn from_str(text: &str) -> Result<Self, String> {
        [Self::Fetch, Self::CommitSign, Self::Push]
            .into_iter()
            .find(|op| op.to_string() == text)
            .ok_or_else(|| format!("unknown operation {text:?} (fetch, commit_sign, push)"))
    }
}

/// The lease's terms, for every repository (`common` in the canonical bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Common {
    pub committer_emails: BTreeSet<Email>,
    /// The name every commit's author and committer must carry, from the templates'
    /// `committer_name` (one for the lease; `None`: not checked, and always `None` when no
    /// repository has `commit_sign`).
    pub committer_name: Option<CommitterName>,
    /// The signer key for commits, from the templates (one for the lease; `None` when no
    /// repository has `commit_sign`).
    pub signing_key: Option<KeyId>,
}

/// One repository's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoTerms {
    /// The template these terms fit (named by the ticket, or the only one that fits).
    pub template: TemplateName,
    pub operations: BTreeSet<Operation>,
    pub branches: BTreeSet<BranchPattern>,
    pub force_push: bool,
    /// The files the work should touch here: the path check's list, shown to the approver.
    pub expected_paths: BTreeSet<PathPattern>,
    pub limits: RepoLimits,
}

/// One repository's counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoLimits {
    pub max_signatures: u32,
    pub max_pushes: u32,
    pub max_push_size: ByteSize,
}

/// The agent's words, plus the links between tickets. The text is shown to the approver and
/// never read by the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketText {
    pub title: String,
    pub task: String,
    pub plan: Vec<String>,
    /// How long the agent thinks the work takes: shown to the approver and in the activity
    /// report, never read by the policy.
    pub estimate: Option<Estimate>,
    /// The lease this ticket amends, if any.
    pub amends: Option<TicketId>,
    /// The lease this ticket renews, if any: once signed, a lease of its own that ends the
    /// renewed one and may push the commits it signed.
    pub renews: Option<TicketId>,
    /// The refused ticket this one revises, if any.
    pub revises: Option<TicketId>,
    /// 1 for a first submission, then one more than the ticket it revises.
    pub revision: u32,
    /// The approver's feedback on the ticket it revises.
    pub previous_feedback: Option<String>,
}

/// The agent's estimate of the work, phase by phase: writing the change, the checks it runs
/// before committing, and waiting on remote CI after its pushes (with the fixes it brings).
/// Agent-written, display-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Estimate {
    #[serde(default)]
    pub coding: Option<Duration>,
    #[serde(default)]
    pub checks: Option<Duration>,
    #[serde(default)]
    pub ci: Option<Duration>,
}

impl Estimate {
    /// The phases' durations added up, none when no phase is given.
    pub fn total(&self) -> Option<Duration> {
        let phases = [self.coding, self.checks, self.ci];
        if phases.iter().all(Option::is_none) {
            return None;
        }
        Some(Duration::from_seconds(
            phases
                .iter()
                .flatten()
                .fold(0u64, |sum, phase| sum.saturating_add(phase.seconds())),
        ))
    }
}

/// The lease's limits: until when, and how fast (the counts are each repository's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub expires_at: Timestamp,
    pub max_ops_per_minute: u32,
}

/// What a violation (an out-of-scope request) does, besides being denied and notified.
/// Ordered from least to most strict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnViolation {
    #[default]
    DenyAndNotify,
    RevokeLease,
}

impl Canonical for Ticket {
    const KIND: &'static str = "writ-ticket/3";
}

impl Ticket {
    /// The lease this ticket belongs to once signed: the amended lease, or itself (a renewal is
    /// a lease of its own).
    pub fn lease_id(&self) -> &TicketId {
        self.text.amends.as_ref().unwrap_or(&self.id)
    }

    /// Whether `now` is at or past `expires_at`: from that second on, the ticket (or the lease
    /// it became) grants nothing.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.limits.expires_at
    }

    /// The terms of `repo`, if the lease names it.
    pub fn terms(&self, repo: &RepoName) -> Option<&RepoTerms> {
        self.repos.get(repo)
    }

    /// Whether the lease allows `operation` in `repo`.
    pub fn allows(&self, repo: &RepoName, operation: Operation) -> bool {
        self.terms(repo)
            .is_some_and(|terms| terms.operations.contains(&operation))
    }

    /// Whether the lease allows `operation` in any of its repositories.
    pub fn allows_anywhere(&self, operation: Operation) -> bool {
        self.repos
            .values()
            .any(|terms| terms.operations.contains(&operation))
    }

    /// Every repository's `max_signatures` added up (what the approver sees as the total).
    pub fn max_signatures(&self) -> u32 {
        self.repos
            .values()
            .fold(0u32, |sum, t| sum.saturating_add(t.limits.max_signatures))
    }

    /// Every repository's `max_pushes` added up.
    pub fn max_pushes(&self) -> u32 {
        self.repos
            .values()
            .fold(0u32, |sum, t| sum.saturating_add(t.limits.max_pushes))
    }

    /// The templates its repositories fit, each once.
    pub fn templates(&self) -> BTreeSet<&TemplateName> {
        self.repos.values().map(|terms| &terms.template).collect()
    }
}

/// A ticket as the agent writes it (YAML via `writ request`). The daemon completes it into a
/// [`Ticket`]: id, time, session key, each repository's template, the templates' defaults for
/// omitted limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketRequest {
    #[serde(default)]
    pub origin_hint: Option<String>,
    #[serde(default)]
    pub caller: Option<CallerConstraint>,
    /// The lease's terms (`common:` in the ticket file).
    #[serde(default)]
    pub common: RequestCommon,
    /// Each repository's terms (`repos:`), at least one.
    pub repos: BTreeMap<RepoName, RequestRepo>,
    pub ticket: RequestText,
    #[serde(default)]
    pub limits: RequestLimits,
    #[serde(default)]
    pub on_violation: OnViolation,
}

/// What the ticket asks for the whole lease (`common:`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCommon {
    /// Omitted: the emails every repository's template allows.
    #[serde(default)]
    pub committer_emails: Vec<Email>,
}

/// What the ticket asks for one repository (`repos.<name>:`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRepo {
    /// The template to fit; omitted, the only template that allows the repository and fits.
    #[serde(default)]
    pub template: Option<TemplateName>,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub branches: Vec<BranchPattern>,
    #[serde(default)]
    pub force_push: bool,
    #[serde(default)]
    pub expected_paths: Vec<PathPattern>,
    /// Omitted counts take the template's maximum.
    #[serde(default)]
    pub limits: RequestRepoLimits,
}

/// One repository's counts as asked (`repos.<name>.limits:`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRepoLimits {
    #[serde(default)]
    pub max_signatures: Option<u32>,
    #[serde(default)]
    pub max_pushes: Option<u32>,
    #[serde(default)]
    pub max_push_size: Option<ByteSize>,
}

/// The agent's words and the links to other tickets (`ticket:` in the ticket file). Shown to
/// the approver, never read by the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestText {
    pub title: String,
    pub task: String,
    #[serde(default)]
    pub plan: Vec<String>,
    #[serde(default)]
    pub estimate: Option<Estimate>,
    #[serde(default)]
    pub amends: Option<TicketId>,
    #[serde(default)]
    pub renews: Option<TicketId>,
    #[serde(default)]
    pub revises: Option<TicketId>,
}

/// The lease's limits as asked (`limits:`); omitted, the strictest of the templates'.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    #[serde(default)]
    pub ttl: Option<Duration>,
    #[serde(default)]
    pub max_ops_per_minute: Option<u32>,
}

/// The keys of the layout before `writ-ticket/3`, each with its new place: a ticket that
/// still has one is refused with these words (no conversion).
const MOVED: [(&str, &str); 10] = [
    ("template", "repos.<repo>.template"),
    ("scope.repos", "repos: one block per repository"),
    ("scope.operations", "repos.<repo>.operations"),
    ("scope.branches", "repos.<repo>.branches"),
    ("scope.force_push", "repos.<repo>.force_push"),
    ("scope.committer_emails", "common.committer_emails"),
    ("ticket.expected_paths", "repos.<repo>.expected_paths"),
    (
        "limits.max_signatures",
        "repos.<repo>.limits.max_signatures",
    ),
    ("limits.max_pushes", "repos.<repo>.limits.max_pushes"),
    ("limits.max_push_size", "repos.<repo>.limits.max_push_size"),
];

/// The top-level keys a ticket file may hold, to find an old one's keys without a schema.
#[derive(Debug, Default, Deserialize)]
struct Keys {
    #[serde(default)]
    template: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    scope: Option<BTreeMap<String, serde::de::IgnoredAny>>,
    #[serde(default)]
    ticket: Option<BTreeMap<String, serde::de::IgnoredAny>>,
    #[serde(default)]
    limits: Option<BTreeMap<String, serde::de::IgnoredAny>>,
}

/// The keys of `text` that belong to the layout before `writ-ticket/3`, each with its new
/// place (`scope.branches → repos.<repo>.branches`), in a fixed order; none for a ticket in
/// the current layout (or text that isn't a mapping).
pub fn old_layout(text: &str) -> Vec<String> {
    let Ok(keys) = parse_yaml::<Keys>(text) else {
        return Vec::new();
    };
    let mut found: Vec<&str> = Vec::new();
    if keys.template.is_some() {
        found.push("template");
    }
    for (section, map) in [
        ("scope", &keys.scope),
        ("ticket", &keys.ticket),
        ("limits", &keys.limits),
    ] {
        if let Some(map) = map {
            for key in map.keys() {
                found.push(match (section, key.as_str()) {
                    ("scope", "repos") => "scope.repos",
                    ("scope", "operations") => "scope.operations",
                    ("scope", "branches") => "scope.branches",
                    ("scope", "force_push") => "scope.force_push",
                    ("scope", "committer_emails") => "scope.committer_emails",
                    ("ticket", "expected_paths") => "ticket.expected_paths",
                    ("limits", "max_signatures") => "limits.max_signatures",
                    ("limits", "max_pushes") => "limits.max_pushes",
                    ("limits", "max_push_size") => "limits.max_push_size",
                    _ => continue,
                });
            }
        }
    }
    if keys.scope.is_some() && !found.iter().any(|k| k.starts_with("scope.")) {
        found.push("scope.repos");
    }
    MOVED
        .iter()
        .filter(|(old, _)| found.contains(old))
        .map(|(old, new)| format!("{old} is now {new}"))
        .collect()
}

impl TicketRequest {
    /// Parses a ticket file. Errors name the field; a ticket in the layout before
    /// `writ-ticket/3` is refused naming each old key's new place.
    pub fn from_yaml(text: &str) -> Result<Self, FieldError> {
        let moved = old_layout(text);
        if !moved.is_empty() {
            return Err(FieldError::at(
                ".",
                format!(
                    "this ticket uses the layout before writ-ticket/3 (the lease's terms, then \
                     each repository's): {}",
                    moved.join("; ")
                ),
            ));
        }
        parse_yaml(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_expires_at_its_expires_at_second() {
        use crate::canonical::Canonical;
        let ticket =
            Ticket::from_canonical(include_bytes!("../tests/fixtures/ticket-full.json")).unwrap();
        let end = ticket.limits.expires_at;
        assert!(
            !ticket.is_expired(end.saturating_sub_seconds(1)),
            "one second before"
        );
        assert!(ticket.is_expired(end), "at expires_at");
        assert!(
            ticket.is_expired(end.saturating_sub_seconds(-1)),
            "one second after"
        );
    }

    #[test]
    fn operation_names_are_the_same_everywhere() {
        for op in [Operation::Fetch, Operation::CommitSign, Operation::Push] {
            let serde = serde_json::to_string(&op).unwrap();
            assert_eq!(serde, format!("\"{op}\""), "Display matches serde");
            assert_eq!(
                op.to_string().parse::<Operation>(),
                Ok(op),
                "FromStr reads Display"
            );
        }
        for bad in ["", "Fetch", "commit-sign", "push ", "sign"] {
            let error = bad.parse::<Operation>().unwrap_err();
            assert!(error.starts_with("unknown operation"), "{bad:?}: {error}");
        }
    }
}
