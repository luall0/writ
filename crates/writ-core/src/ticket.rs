//! Tickets: what the agent asks for ([`TicketRequest`]), and the complete ticket the daemon
//! builds from it ([`Ticket`]), whose canonical bytes an approval signs.
//!
//! # Canonical encoding
//!
//! A ticket's canonical bytes are compact JSON (no whitespace) with the fields in the order
//! declared below, set-like lists sorted and deduplicated, absent values as `null`, sizes in
//! bytes and timestamps as `YYYY-MM-DDTHH:MM:SSZ`. The first field, `"kind":"writ-ticket/1"`,
//! names the format, so a ticket approval can't be mistaken for any other signed document.
//! [`Ticket::from_canonical`] only accepts bytes that re-encode to exactly themselves.
//! Fixtures in `tests/fixtures/` pin the format.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::caller::CallerConstraint;
use crate::config::{ConfigError, Operation, parse_yaml};
use crate::names::{Email, KeyFingerprint, KeyId, RepoName, TemplateName, TicketId};
use crate::pattern::{BranchPattern, PathPattern};
use crate::units::{ByteSize, Duration, Timestamp};

/// The format name at the start of every canonical ticket.
pub const TICKET_KIND: &str = "writ-ticket/1";

/// Errors from encoding or decoding canonical bytes.
#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    #[error("not a canonical ticket: {0}")]
    Decode(String),
    #[error("not a canonical ticket: the bytes are valid but not in canonical form")]
    NotCanonical,
    #[error("can't encode the ticket: {0}")]
    Encode(String),
}

/// The format marker; only `"writ-ticket/1"` is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TicketKind {
    #[default]
    #[serde(rename = "writ-ticket/1")]
    V1,
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
    pub ticket: TicketText,
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

/// What the lease allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub repos: BTreeSet<RepoName>,
    pub operations: BTreeSet<Operation>,
    pub branches: BTreeSet<BranchPattern>,
    pub force_push: bool,
    pub committer_emails: BTreeSet<Email>,
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
    /// The lease this ticket amends, if any.
    pub amends: Option<TicketId>,
    /// The refused ticket this one revises, if any.
    pub revises: Option<TicketId>,
    /// 1 for a first submission, then one more than the ticket it revises.
    pub revision: u32,
    /// The approver's feedback on the ticket it revises.
    pub previous_feedback: Option<String>,
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

impl Ticket {
    /// The canonical bytes: what `writ sign` signs and the daemon verifies.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TicketError> {
        serde_json::to_vec(self).map_err(|e| TicketError::Encode(e.to_string()))
    }

    /// Decodes canonical bytes, refusing anything that isn't exactly canonical (other key
    /// order, whitespace, unsorted or duplicate set entries, unknown fields, other kinds).
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, TicketError> {
        let ticket: Ticket =
            serde_json::from_slice(bytes).map_err(|e| TicketError::Decode(e.to_string()))?;
        if ticket.canonical_bytes()? != bytes {
            return Err(TicketError::NotCanonical);
        }
        Ok(ticket)
    }

    /// The lease this ticket belongs to once signed: the amended lease, or itself.
    pub fn lease_id(&self) -> &TicketId {
        self.ticket.amends.as_ref().unwrap_or(&self.id)
    }

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
    pub amends: Option<TicketId>,
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
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        parse_yaml(text)
    }
}
