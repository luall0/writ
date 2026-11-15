//! The lifecycle of a ticket and of the lease it becomes.
//!
//! ```text
//! pending ──approve──▶ active ──▶ closed | exhausted | expired | revoked | renewed
//!    │ └─approve (amendment)──▶ applied      (the amended lease takes its scope)
//!    └──▶ refused | expired | revoked
//! exhausted | expired ──a renewal approved──▶ renewed
//! ```
//!
//! Every other transition is refused ([`State::can_become`]). Approving needs a verified
//! approver signature over the signed ticket's canonical bytes: the caller of [`activate`],
//! [`activate_renewal`] and [`apply_amendment`] (the approval service) verifies it before
//! calling them. The one lease granted with no signature is a fetch-only ticket under
//! `unsigned_fetch` templates ([`activate_unsigned`], M7.9.7), never amended or renewed.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::PolicyConfig;
use crate::names::{KeyFingerprint, RepoName, TicketId};
use crate::net::Source;
use crate::ticket::Operation;
use crate::ticket::Ticket;
use crate::units::{Duration, Timestamp};
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
    /// A renewal of it was signed: the renewal is the lease in force now.
    Renewed,
}

impl State {
    pub const ALL: [State; 9] = [
        State::Pending,
        State::Refused,
        State::Active,
        State::Applied,
        State::Closed,
        State::Exhausted,
        State::Expired,
        State::Revoked,
        State::Renewed,
    ];

    /// The transitions of the lifecycle; nothing else is allowed. A lease that expired or was
    /// used up can still be renewed (within `renew_grace`); nothing else leaves an end.
    pub fn can_become(self, next: State) -> bool {
        use State::*;
        matches!(
            (self, next),
            (Pending, Active | Applied | Refused | Expired | Revoked)
                | (Active, Closed | Exhausted | Expired | Revoked | Renewed)
                | (Exhausted | Expired, Renewed)
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
            State::Renewed => "renewed",
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
    #[error("the signed ticket doesn't fit its template: {0}")]
    Fit(#[from] fit::FitError),
    #[error("the approval's namespace is {0:?}, not {APPROVAL_NAMESPACE:?}")]
    Namespace(String),
    #[error("the ticket expired before it was signed")]
    ExpiredBeforeApproval,
    #[error("an amendment is applied to its lease, not activated")]
    ActivatingAmendment,
    #[error("ticket {ticket} does not amend lease {lease}")]
    AmendsAnotherLease { ticket: TicketId, lease: TicketId },
    #[error("lease {0} is no longer active")]
    LeaseNotActive(TicketId),
    #[error("an amendment must keep the lease's session key")]
    SessionKeyChanged,
    #[error("the feedback is empty")]
    FeedbackEmpty,
    #[error("the feedback is longer than {max} characters", max = crate::signed::MAX_FEEDBACK_CHARS)]
    FeedbackTooLong,
    /// The session process the lease is bound to (`subject.caller`) is part of what the
    /// daemon watches to revoke it: an amendment can't drop, add or move it.
    #[error("an amendment must keep the lease's subject (session key and process)")]
    SubjectChanged,
    /// An amendment changes a lease's scope, not its time: the certificate keeps the lease's
    /// end (M3.6).
    #[error(
        "the amendment ends at {amendment}, after its lease ({lease}): an amendment can't move a lease's end; renew it instead"
    )]
    AmendmentOutlivesLease {
        amendment: Timestamp,
        lease: Timestamp,
    },
    #[error("a renewal is activated with the lease it renews")]
    RenewalWithoutLease,
    #[error("ticket {ticket} does not renew lease {lease}")]
    RenewsAnotherLease { ticket: TicketId, lease: TicketId },
    /// A lease granted with no signature (M7.9.7) is never amended or renewed: the work it
    /// plans gets a ticket of its own.
    #[error(
        "lease {0} was granted with no signature (unsigned_fetch): it is never amended or renewed; submit a ticket of its own"
    )]
    Unsigned(TicketId),
    /// Only a ticket whose every repository is under an `unsigned_fetch` template is granted
    /// with no signature.
    #[error(
        "the ticket is not under unsigned_fetch templates only: it needs an approver's signature"
    )]
    NotUnsigned,
    /// Why the lease can't be renewed (any more), or the renewal doesn't stay within it.
    #[error("{}", .0.join("; "))]
    Renewal(Vec<String>),
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

/// What granted a lease: an approver's verified signature, or the policy itself, for a
/// fetch-only ticket under `unsigned_fetch` templates (M7.9.7), whose terms name them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantedBy {
    Approver(Approval),
    /// No signature: the signed policy's `unsigned_fetch` templates stand for it.
    Policy,
}

impl GrantedBy {
    /// The approval, when an approver signed.
    pub fn approval(&self) -> Option<&Approval> {
        match self {
            GrantedBy::Approver(approval) => Some(approval),
            GrantedBy::Policy => None,
        }
    }

    /// The approver who signed, if one did.
    pub fn approver(&self) -> Option<&KeyFingerprint> {
        self.approval().map(|a| &a.approver)
    }

    /// Whether it was granted with no signature.
    pub fn is_unsigned(&self) -> bool {
        matches!(self, GrantedBy::Policy)
    }
}

/// A submitted ticket and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRecord {
    /// As submitted, or as signed once approved.
    pub ticket: Ticket,
    pub state: State,
    /// The approver's feedback, once refused.
    pub feedback: Option<String>,
    /// Who signed the refusal. `None`: nobody (a daemon with `decisions: open`), so the
    /// feedback may not be the approver's words, and is labeled so wherever it goes.
    pub feedback_by: Option<KeyFingerprint>,
    /// Once approved.
    pub approval: Option<Approval>,
    /// Granted with no signature (M7.9.7): a lease under `unsigned_fetch` templates, never
    /// pending, with no approval. The daemon's own record, not read back from the policy.
    pub unsigned: bool,
    /// Where it was submitted from: the daemon's own fact, never signed (`None` where nobody
    /// recorded one, as in a test's record).
    pub source: Option<Source>,
}

impl TicketRecord {
    /// A freshly submitted ticket.
    pub fn pending(ticket: Ticket) -> Self {
        Self {
            ticket,
            state: State::Pending,
            feedback: None,
            feedback_by: None,
            approval: None,
            unsigned: false,
            source: None,
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
    pub granted_by: GrantedBy,
    pub state: State,
    /// Serial of the session certificate issued for it.
    pub cert_serial: u64,
    /// The lease it renews, as it was signed: kept outside the terms, which an amendment
    /// replaces with its own (that can't renew: the review after M7.6, C-2).
    pub renews: Option<TicketId>,
}

impl Lease {
    /// Whether the lease grants anything at `now`: active and not past `expires_at`.
    pub fn is_in_force(&self, now: Timestamp) -> bool {
        self.state == State::Active && !self.ticket.is_expired(now)
    }
}

/// What a lease has used so far, gathered by the daemon from the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    /// Each repository's counts (a repository with none used yet may be missing).
    pub repos: BTreeMap<RepoName, RepoUsage>,
    /// Allowed operations in the last [`crate::policy::RATE_WINDOW_SECONDS`], every
    /// repository together (one rate per lease).
    pub ops_last_minute: u32,
}

/// What a lease used in one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepoUsage {
    pub signatures: u32,
    pub pushes: u32,
}

impl Usage {
    /// The counts of `repo` (zero when none is used yet).
    pub fn of(&self, repo: &RepoName) -> RepoUsage {
        self.repos.get(repo).copied().unwrap_or_default()
    }

    /// Every repository's counts added up (for the report and the approver's screen).
    pub fn total(&self) -> RepoUsage {
        self.repos
            .values()
            .fold(RepoUsage::default(), |sum, used| RepoUsage {
                signatures: sum.signatures.saturating_add(used.signatures),
                pushes: sum.pushes.saturating_add(used.pushes),
            })
    }
}

/// Feedback a refusal may carry: not blank, at most
/// [`MAX_FEEDBACK_CHARS`](crate::signed::MAX_FEEDBACK_CHARS) characters.
pub fn check_feedback(feedback: &str) -> Result<(), LifecycleError> {
    if feedback.trim().is_empty() {
        return Err(LifecycleError::FeedbackEmpty);
    }
    if feedback.chars().count() > crate::signed::MAX_FEEDBACK_CHARS {
        return Err(LifecycleError::FeedbackTooLong);
    }
    Ok(())
}

/// Refuses a pending ticket with feedback, signed by the approver `by` (or by nobody).
pub fn refuse(
    record: &TicketRecord,
    feedback: String,
    by: Option<KeyFingerprint>,
) -> Result<TicketRecord, LifecycleError> {
    transition(record.state, State::Refused)?;
    check_feedback(&feedback)?;
    Ok(TicketRecord {
        state: State::Refused,
        feedback: Some(feedback),
        feedback_by: by,
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
        return Err(LifecycleError::ActivatingAmendment);
    }
    if record.ticket.text.renews.is_some() {
        return Err(LifecycleError::RenewalWithoutLease);
    }
    check_approval(config, &record.ticket, &signed, &approval, now)?;
    Ok(Lease {
        id: signed.id.clone(),
        ticket: signed,
        granted_by: GrantedBy::Approver(approval),
        state: State::Active,
        cert_serial,
        renews: None,
    })
}

/// Turns a ticket just submitted under `unsigned_fetch` templates into an active lease with
/// no signature (M7.9.7): fetch only (the templates allow nothing else), never an amendment
/// or a renewal, within its templates under `config`.
pub fn activate_unsigned(
    config: &PolicyConfig,
    record: &TicketRecord,
    cert_serial: u64,
    now: Timestamp,
) -> Result<Lease, LifecycleError> {
    transition(record.state, State::Active)?;
    if record.ticket.text.amends.is_some() {
        return Err(LifecycleError::ActivatingAmendment);
    }
    if record.ticket.text.renews.is_some() {
        return Err(LifecycleError::RenewalWithoutLease);
    }
    fit::fits(config, &record.ticket)?;
    if !fit::unsigned(config, &record.ticket) {
        return Err(LifecycleError::NotUnsigned);
    }
    if record.ticket.is_expired(now) {
        return Err(LifecycleError::ExpiredBeforeApproval);
    }
    Ok(Lease {
        id: record.ticket.id.clone(),
        ticket: record.ticket.clone(),
        granted_by: GrantedBy::Policy,
        state: State::Active,
        cert_serial,
        renews: None,
    })
}

/// The lease a renewal renews, as the daemon found it, and how many renewals it already is
/// (0 for a lease that renews nothing).
#[derive(Debug, Clone, Copy)]
pub struct Renewed<'a> {
    pub lease: &'a Lease,
    pub renewals: u32,
    /// How long after its `expires_at` an expired or used-up lease can still be renewed
    /// (`writd.yaml`'s `renew_grace`).
    pub grace: Duration,
}

/// Turns a pending renewal into an active lease once its approval is verified, checking again
/// that the lease it renews can still be renewed and that the signed renewal stays within it
/// ([`fit::check_renewal`]). Returns the new lease and the state the renewed lease moves to
/// ([`State::Renewed`]).
pub fn activate_renewal(
    config: &PolicyConfig,
    record: &TicketRecord,
    signed: Ticket,
    approval: Approval,
    cert_serial: u64,
    renewed: Renewed<'_>,
    now: Timestamp,
) -> Result<Lease, LifecycleError> {
    transition(record.state, State::Active)?;
    if record.ticket.text.amends.is_some() {
        return Err(LifecycleError::ActivatingAmendment);
    }
    if record.ticket.text.renews.as_ref() != Some(&renewed.lease.id) {
        return Err(LifecycleError::RenewsAnotherLease {
            ticket: record.ticket.id.clone(),
            lease: renewed.lease.id.clone(),
        });
    }
    transition(renewed.lease.state, State::Renewed)?;
    if renewed.lease.granted_by.is_unsigned() {
        return Err(LifecycleError::Unsigned(renewed.lease.id.clone()));
    }
    check_approval(config, &record.ticket, &signed, &approval, now)?;
    fit::check_renewal(config, &signed, renewed, now).map_err(LifecycleError::Renewal)?;
    Ok(Lease {
        id: signed.id.clone(),
        ticket: signed,
        granted_by: GrantedBy::Approver(approval),
        state: State::Active,
        cert_serial,
        renews: Some(renewed.lease.id.clone()),
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
        return Err(LifecycleError::AmendsAnotherLease {
            ticket: amendment.ticket.id.clone(),
            lease: lease.id.clone(),
        });
    }
    if !lease.is_in_force(now) {
        return Err(LifecycleError::LeaseNotActive(lease.id.clone()));
    }
    if lease.granted_by.is_unsigned() {
        return Err(LifecycleError::Unsigned(lease.id.clone()));
    }
    if signed.subject.session_key != lease.ticket.subject.session_key {
        return Err(LifecycleError::SessionKeyChanged);
    }
    if signed.subject != lease.ticket.subject {
        return Err(LifecycleError::SubjectChanged);
    }
    if signed.limits.expires_at > lease.ticket.limits.expires_at {
        return Err(LifecycleError::AmendmentOutlivesLease {
            amendment: signed.limits.expires_at,
            lease: lease.ticket.limits.expires_at,
        });
    }
    check_approval(config, &amendment.ticket, &signed, &approval, now)?;
    let applied = TicketRecord {
        ticket: signed.clone(),
        state: State::Applied,
        feedback: None,
        feedback_by: None,
        approval: Some(approval.clone()),
        unsigned: false,
        source: amendment.source,
    };
    let updated = Lease {
        ticket: signed,
        granted_by: GrantedBy::Approver(approval),
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
    fit::fits(config, signed)?;
    if fit::unsigned(config, signed) {
        // Granted when submitted, never pending, so never signed: a signature over one would
        // be a second path to a grant that needs none (M7.9.7).
        return Err(LifecycleError::Fit(fit::FitError {
            reasons: vec![
                "the ticket is under unsigned_fetch templates: it is granted when submitted, \
                 never signed"
                    .to_owned(),
            ],
        }));
    }
    if signed.is_expired(now) {
        return Err(LifecycleError::ExpiredBeforeApproval);
    }
    Ok(())
}

/// Whether every operation the lease allows is used up, in every repository: signatures
/// (with `commit_sign`) and pushes (with `push`). `fetch` has no count, so a repository that
/// allows it is never used up: the lease ends by expiry, closing or revocation. (This keeps
/// exhaustion monotone: dropping an operation while narrowing never revives a used-up lease.)
pub fn is_exhausted(ticket: &Ticket, usage: &Usage) -> bool {
    !ticket.repos.is_empty()
        && ticket.repos.iter().all(|(repo, terms)| {
            let has = |op| terms.operations.contains(&op);
            let (signs, pushes) = (has(Operation::CommitSign), has(Operation::Push));
            let used = usage.of(repo);
            !has(Operation::Fetch)
                && (signs || pushes)
                && (!signs || used.signatures >= terms.limits.max_signatures)
                && (!pushes || used.pushes >= terms.limits.max_pushes)
        })
}

/// The state an active lease should move to now, if any (`expired` first, then `exhausted`).
pub fn due_transition(lease: &Lease, usage: &Usage, now: Timestamp) -> Option<State> {
    if lease.state != State::Active {
        return None;
    }
    if lease.ticket.is_expired(now) {
        Some(State::Expired)
    } else if is_exhausted(&lease.ticket, usage) {
        Some(State::Exhausted)
    } else {
        None
    }
}

/// A pending ticket whose `expires_at` passed can no longer be signed.
pub fn pending_due(record: &TicketRecord, now: Timestamp) -> Option<State> {
    (record.state == State::Pending && record.ticket.is_expired(now)).then_some(State::Expired)
}
