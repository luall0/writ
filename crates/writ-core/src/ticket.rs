//! Tickets: what the agent asks for ([`TicketRequest`]), and the complete ticket the daemon
//! builds from it ([`Ticket`]), whose canonical bytes an approval signs.
//!
//! # Canonical encoding
//!
//! A ticket is a [`Canonical`] document of kind `writ-ticket/2`: its fields in the order
//! declared below, sizes in bytes, durations as their text (`45m`) and timestamps as
//! `YYYY-MM-DDTHH:MM:SSZ`. Fixtures in `tests/fixtures/` pin the format.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::caller::CallerConstraint;
use crate::canonical::Canonical;
use crate::names::{CommitterName, Email, KeyFingerprint, KeyId, RepoName, TemplateName, TicketId};
use crate::pattern::{BranchPattern, PathPattern};
use crate::units::{ByteSize, Duration, Timestamp};
use crate::yaml::{FieldError, parse_yaml};

/// The format marker; only `"writ-ticket/2"` ([`Ticket::KIND`]) is accepted (`/2` added
/// `scope.committer_name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TicketKind {
    #[default]
    #[serde(rename = "writ-ticket/2")]
    V2,
}

/// A complete ticket: what an approval signs, and once signed, the lease's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub kind: TicketKind,
    pub id: TicketId,
    pub created_at: Timestamp,
    pub template: TemplateName,
    pub subject: Subject,
    pub scope: Scope,
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

/// What the lease allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub repos: BTreeSet<RepoName>,
    pub operations: BTreeSet<Operation>,
    pub branches: BTreeSet<BranchPattern>,
    pub force_push: bool,
    pub committer_emails: BTreeSet<Email>,
    /// The name every commit's author and committer must carry, from the template's
    /// `committer_name` (`None`: not checked, and always `None` without `commit_sign`).
    pub committer_name: Option<CommitterName>,
    /// The signer key for commits, from the template (`None` without `commit_sign`).
    pub signing_key: Option<KeyId>,
}

/// The agent's words, plus the links between tickets. The text is shown to the approver and
/// never read by the policy, except `expected_paths` for the path check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketText {
    pub title: String,
    pub task: String,
    pub plan: Vec<String>,
    pub expected_paths: BTreeSet<PathPattern>,
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

/// How much, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub expires_at: Timestamp,
    pub max_signatures: u32,
    pub max_pushes: u32,
    pub max_ops_per_minute: u32,
    pub max_push_size: ByteSize,
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
    const KIND: &'static str = "writ-ticket/2";
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

    /// Whether the scope includes `operation`.
    pub fn allows(&self, operation: Operation) -> bool {
        self.scope.operations.contains(&operation)
    }
}

/// A ticket as the agent writes it (YAML via `writ request`). The daemon completes it into a
/// [`Ticket`]: id, time, session key, template defaults for omitted limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketRequest {
    /// The template to fit; omitted, the single template it fits is chosen.
    #[serde(default)]
    pub template: Option<TemplateName>,
    #[serde(default)]
    pub origin_hint: Option<String>,
    #[serde(default)]
    pub caller: Option<CallerConstraint>,
    pub scope: RequestScope,
    pub ticket: RequestText,
    #[serde(default)]
    pub limits: RequestLimits,
    #[serde(default)]
    pub on_violation: OnViolation,
}

/// What the agent asks the lease to allow (`scope:` in the ticket file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestScope {
    pub repos: Vec<RepoName>,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub branches: Vec<BranchPattern>,
    #[serde(default)]
    pub force_push: bool,
    /// Omitted: the template's committer emails.
    #[serde(default)]
    pub committer_emails: Vec<Email>,
}

/// The agent's words and the links to other tickets (`ticket:` in the ticket file). Shown to
/// the approver, never read by the policy (except `expected_paths`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestText {
    pub title: String,
    pub task: String,
    #[serde(default)]
    pub plan: Vec<String>,
    #[serde(default)]
    pub expected_paths: Vec<PathPattern>,
    #[serde(default)]
    pub estimate: Option<Estimate>,
    #[serde(default)]
    pub amends: Option<TicketId>,
    #[serde(default)]
    pub renews: Option<TicketId>,
    #[serde(default)]
    pub revises: Option<TicketId>,
}

/// Omitted limits take the template's maximum.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    #[serde(default)]
    pub ttl: Option<Duration>,
    #[serde(default)]
    pub max_signatures: Option<u32>,
    #[serde(default)]
    pub max_pushes: Option<u32>,
    #[serde(default)]
    pub max_ops_per_minute: Option<u32>,
    #[serde(default)]
    pub max_push_size: Option<ByteSize>,
}

impl TicketRequest {
    /// Parses a ticket file. Errors name the field.
    pub fn from_yaml(text: &str) -> Result<Self, FieldError> {
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
