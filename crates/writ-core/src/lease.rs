//! The lifecycle of a ticket and of the lease it becomes.
//!
//! ```text
//! pending ──approve──▶ active ──▶ closed | exhausted | expired | revoked
//!    │ └─approve (amendment)──▶ applied      (the amended lease takes its scope)
//!    └──▶ refused | expired | revoked
//! ```
//!
//! Every other transition is refused ([`State::can_become`]). Approving needs a verified
//! approver signature over the signed ticket's canonical bytes: the caller of [`activate`]
//! and [`apply_amendment`] (the approval service) verifies it before calling them.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::PolicyConfig;
use crate::names::{KeyFingerprint, TicketId};
use crate::ticket::Operation;
use crate::ticket::Ticket;
use crate::units::Timestamp;
use crate::{fit, narrow};

/// The SSHSIG namespace of every approval.
pub const APPROVAL_NAMESPACE: &str = "writ-approval";

/// Where a ticket or lease is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Fits a template, waiting for the approver.
    Pending,
    /// Refused by the approver, with feedback.
    Refused,
    /// Signed: the lease is in force.
    Active,
    /// A signed amendment, now the scope of the lease it amends.
    Applied,
    /// Closed by the agent.
    Closed,
    /// Every operation it allows is used up (never with `fetch`, which has no count).
    Exhausted,
    /// `expires_at` passed.
    Expired,
    /// Revoked by the approver, a violation, the session ending, or withdrawn while pending.
    Revoked,
}

impl State {
    pub const ALL: [State; 8] = [
        State::Pending,
        State::Refused,
        State::Active,
        State::Applied,
        State::Closed,
        State::Exhausted,
        State::Expired,
        State::Revoked,
    ];

    /// The transitions of the lifecycle; nothing else is allowed.
    pub fn can_become(self, next: State) -> bool {
        use State::*;
        matches!(
            (self, next),
            (Pending, Active | Applied | Refused | Expired | Revoked)
                | (Active, Closed | Exhausted | Expired | Revoked)
        )
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, State::Pending | State::Active)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Refused => "refused",
            State::Active => "active",
            State::Applied => "applied",
            State::Closed => "closed",
            State::Exhausted => "exhausted",
            State::Expired => "expired",
            State::Revoked => "revoked",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for State {
    type Err = LifecycleError;

    fn from_str(text: &str) -> Result<Self, LifecycleError> {
        State::ALL
            .into_iter()
            .find(|s| s.as_str() == text)
            .ok_or_else(|| LifecycleError::UnknownState(text.to_owned()))
    }
}

/// Lifecycle errors: a transition that isn't allowed, or an approval that can't apply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    #[error("a ticket can't go from {from} to {to}")]
    Transition { from: State, to: State },
    #[error("unknown state {0:?}")]
    UnknownState(String),
    #[error(transparent)]
    Narrowing(#[from] narrow::NarrowingError),
    #[error("the signed ticket doesn't fit its template: {}", .0.join("; "))]
    Fit(Vec<String>),
    #[error("the approval's namespace is {0:?}, not {APPROVAL_NAMESPACE:?}")]
    Namespace(String),
    #[error("the ticket expired before it was signed")]
    ExpiredBeforeApproval,
    #[error("{0}")]
    Amendment(String),
}

/// Checks a transition.
pub fn transition(from: State, to: State) -> Result<State, LifecycleError> {
    if from.can_become(to) {
        Ok(to)
    } else {
        Err(LifecycleError::Transition { from, to })
    }
}

/// A verified approver signature over a ticket's canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Fingerprint of the approver key that signed.
    pub approver: KeyFingerprint,
    /// Always [`APPROVAL_NAMESPACE`].
    pub namespace: String,
    /// The armored SSHSIG, kept so the lease can be re-verified. Never written to the audit log.
    pub sshsig: String,
}

/// A submitted ticket and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRecord {
    /// As submitted, or as signed once approved.
    pub ticket: Ticket,
    pub state: State,
    /// The approver's feedback, once refused.
    pub feedback: Option<String>,
    /// Once approved.
    pub approval: Option<Approval>,
}

impl TicketRecord {
    /// A freshly submitted ticket.
    pub fn pending(ticket: Ticket) -> Self {
        Self {
            ticket,
            state: State::Pending,
            feedback: None,
            approval: None,
        }
    }
}

/// A lease: a signed ticket in force (or ended). Its id is the first ticket's id, kept when
/// amendments replace its terms; certificates carry it as key id, commits as `Writ:` trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub id: TicketId,
    /// The terms in force: the first signed ticket, or the last applied amendment.
    pub ticket: Ticket,
    pub approval: Approval,
    pub state: State,
    /// Serial of the session certificate issued for it.
    pub cert_serial: u64,
}

/// What a lease has used so far, gathered by the daemon from the store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub signatures: u32,
    pub pushes: u32,
    /// Allowed operations in the last [`crate::policy::RATE_WINDOW_SECONDS`].
    pub ops_last_minute: u32,
}

/// Refuses a pending ticket with the approver's feedback.
pub fn refuse(record: &TicketRecord, feedback: String) -> Result<TicketRecord, LifecycleError> {
    transition(record.state, State::Refused)?;
    Ok(TicketRecord {
        state: State::Refused,
        feedback: Some(feedback),
        ..record.clone()
    })
}

/// Turns a pending ticket into an active lease once its approval is verified. `signed` is the
/// ticket the approver signed: the submitted one, or a narrowing of it.
pub fn activate(
    config: &PolicyConfig,
    record: &TicketRecord,
    signed: Ticket,
    approval: Approval,
    cert_serial: u64,
    now: Timestamp,
) -> Result<Lease, LifecycleError> {
    transition(record.state, State::Active)?;
    if record.ticket.text.amends.is_some() {
        return Err(LifecycleError::Amendment(
            "an amendment is applied to its lease, not activated".to_owned(),
        ));
    }
    check_approval(config, &record.ticket, &signed, &approval, now)?;
    Ok(Lease {
        id: signed.id.clone(),
        ticket: signed,
        approval,
        state: State::Active,
        cert_serial,
    })
}

/// Applies a signed amendment: the lease keeps its id, certificate and usage, and takes the
/// amendment's terms. Returns the updated lease and the amendment record (now `applied`).
pub fn apply_amendment(
    config: &PolicyConfig,
    lease: &Lease,
    amendment: &TicketRecord,
    signed: Ticket,
    approval: Approval,
    now: Timestamp,
) -> Result<(Lease, TicketRecord), LifecycleError> {
    transition(amendment.state, State::Applied)?;
    if amendment.ticket.text.amends.as_ref() != Some(&lease.id) {
        return Err(LifecycleError::Amendment(format!(
            "ticket {} does not amend lease {}",
            amendment.ticket.id, lease.id
        )));
    }
    if lease.state != State::Active || now >= lease.ticket.limits.expires_at {
        return Err(LifecycleError::Amendment(format!(
            "lease {} is no longer active",
            lease.id
        )));
    }
    if signed.subject.session_key != lease.ticket.subject.session_key {
        return Err(LifecycleError::Amendment(
            "an amendment must keep the lease's session key".to_owned(),
        ));
    }
    check_approval(config, &amendment.ticket, &signed, &approval, now)?;
    let applied = TicketRecord {
        ticket: signed.clone(),
        state: State::Applied,
        feedback: None,
        approval: Some(approval.clone()),
    };
    let updated = Lease {
        ticket: signed,
        approval,
        ..lease.clone()
    };
    Ok((updated, applied))
}

fn check_approval(
    config: &PolicyConfig,
    submitted: &Ticket,
    signed: &Ticket,
    approval: &Approval,
    now: Timestamp,
) -> Result<(), LifecycleError> {
    if approval.namespace != APPROVAL_NAMESPACE {
        return Err(LifecycleError::Namespace(approval.namespace.clone()));
    }
    narrow::check(submitted, signed)?;
    fit::fits(config, signed).map_err(LifecycleError::Fit)?;
    if now >= signed.limits.expires_at {
        return Err(LifecycleError::ExpiredBeforeApproval);
    }
    Ok(())
}

/// Whether every operation the lease allows is used up: signatures (with `commit_sign`) and
/// pushes (with `push`). `fetch` has no count, so a lease that allows it is never exhausted:
/// it ends by expiry, closing or revocation. (This keeps exhaustion monotone: dropping an
/// operation while narrowing never revives a used-up lease.)
pub fn is_exhausted(ticket: &Ticket, usage: &Usage) -> bool {
    let signs = ticket.allows(Operation::CommitSign);
    let pushes = ticket.allows(Operation::Push);
    !ticket.allows(Operation::Fetch)
        && (signs || pushes)
        && (!signs || usage.signatures >= ticket.limits.max_signatures)
        && (!pushes || usage.pushes >= ticket.limits.max_pushes)
}

/// The state an active lease should move to now, if any (`expired` first, then `exhausted`).
pub fn due_transition(lease: &Lease, usage: &Usage, now: Timestamp) -> Option<State> {
    if lease.state != State::Active {
        return None;
    }
    if now >= lease.ticket.limits.expires_at {
        Some(State::Expired)
    } else if is_exhausted(&lease.ticket, usage) {
        Some(State::Exhausted)
    } else {
        None
    }
}

/// A pending ticket whose `expires_at` passed can no longer be signed.
pub fn pending_due(record: &TicketRecord, now: Timestamp) -> Option<State> {
    (record.state == State::Pending && now >= record.ticket.limits.expires_at)
        .then_some(State::Expired)
}
