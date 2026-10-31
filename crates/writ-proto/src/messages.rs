//! The replies and request bodies of each [`Command`](crate::Command).

use serde::{Deserialize, Serialize};
use writ_core::lease::State;
use writ_core::names::{RepoName, TemplateName, TicketId};
use writ_core::units::Timestamp;

/// Reply to [`Command::Request`]: the ticket is waiting for the approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitted {
    pub id: TicketId,
    /// The complete ticket the daemon built, as canonical bytes.
    pub canonical: String,
}

/// Reply to [`Command::Wait`]: how the ticket was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum Decision {
    /// Signed: the lease (canonical bytes of the terms in force, narrowed if I narrowed them)
    /// and the session certificate (OpenSSH text).
    Active { lease: String, certificate: String },
    /// A signed amendment, now the terms of its lease (the certificate doesn't change).
    Applied { lease: String },
    /// Refused, with the approver's feedback.
    Refused { feedback: String },
    /// Not signed before `expires_at`.
    Expired,
    /// Withdrawn, or the lease was revoked before the wait.
    Revoked,
    /// The lease ended another way (closed, exhausted) before the wait.
    Ended { state: State },
}

/// Reply to [`Command::Info`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub decisions: Decisions,
}

/// Whether refusals and revocations need an approver signature (`writd.yaml`: `decisions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decisions {
    /// An SSHSIG over a `writ-refusal/1` or `writ-revocation/1` document is required.
    #[default]
    Signed,
    /// Anyone who reaches the approval listener may refuse or revoke.
    Open,
}

/// Reply to [`Command::List`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub tickets: Vec<Summary>,
}

/// One line of `writ ls`. The title is agent-written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub id: TicketId,
    /// The lease it belongs to (itself, or the lease an amendment amends).
    pub lease: TicketId,
    pub state: State,
    pub template: TemplateName,
    pub revision: u32,
    pub repos: Vec<RepoName>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub title: String,
}

/// Reply to [`Command::Show`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shown {
    pub state: State,
    /// The ticket's canonical bytes (as submitted while pending, as signed once approved).
    pub canonical: String,
    /// What it follows: the refused ticket it revises, or the lease terms it amends.
    pub previous: Option<Previous>,
}

/// The ticket a revision or an amendment follows, for the diff `writ sign` shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    pub relation: Relation,
    pub canonical: String,
}

/// How a ticket follows the one shown with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// The refused ticket this one revises.
    Revises,
    /// The terms in force of the lease this one amends.
    Amends,
}

/// Body of [`Command::Approve`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    /// The canonical bytes signed: the submitted ticket, or a narrowing of it.
    pub signed: String,
    /// The armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Body of [`Command::Refuse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefuseRequest {
    pub feedback: String,
    /// With `decisions: signed`: an SSHSIG over the `writ-refusal/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Body of [`Command::Revoke`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// With `decisions: signed`: an SSHSIG over the `writ-revocation/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Reply to approve, refuse and revoke: where the ticket (or lease) now stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub id: TicketId,
    pub state: State,
}
