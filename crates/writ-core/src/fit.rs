//! Template fit and ticket submission.
//!
//! Every ticket must fit a template (Q14 in `docs/decisions.md`): [`fits`] says whether a
//! complete ticket stays within its template and the registry, with every reason when it
//! doesn't. [`submit`] completes an agent's [`TicketRequest`] into a [`Ticket`], picking the
//! template, or rejects it before it reaches the approver.

use std::collections::BTreeSet;

use crate::config::{PolicyConfig, PushMode, Template};
use crate::lease::{Lease, State, TicketRecord};
use crate::names::{KeyFingerprint, TemplateName, TicketId};
use crate::ticket::Operation;
use crate::ticket::{Limits, Scope, Subject, Ticket, TicketKind, TicketRequest, TicketText};
use crate::units::{Duration, Timestamp};

/// Bounds on the agent-written text, so a ticket stays reviewable.
pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_TASK_CHARS: usize = 4_000;
/// The most lines in the task: past it, agent text could bury the scope on the approver's
/// screen (the display is bounded too).
pub const MAX_TASK_LINES: usize = 100;
pub const MAX_PLAN_STEPS: usize = 50;
pub const MAX_PLAN_STEP_CHARS: usize = 500;
pub const MAX_EXPECTED_PATHS: usize = 100;
pub const MAX_ORIGIN_HINT_CHARS: usize = 100;
/// The shortest lease a ticket may ask for. A pending ticket holds one of the approver's
/// waiting slots until it expires: a 1-second ticket would free its slot every second, and
/// let one submitter notify the approver without end. (The approver may still narrow a lease
/// below it when signing.)
pub const MIN_TTL: Duration = Duration::from_seconds(5 * 60);

/// A ticket the daemon won't put in front of the approver, with every reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ticket rejected: {}", .reasons.join("; "))]
pub struct Rejection {
    pub reasons: Vec<String>,
}

impl Rejection {
    fn one(reason: impl Into<String>) -> Self {
        Self {
            reasons: vec![reason.into()],
        }
    }
}

/// Why a complete ticket doesn't fit its template or the registry, with every reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .reasons.join("; "))]
pub struct FitError {
    pub reasons: Vec<String>,
}

/// Checks that a complete ticket fits its template and the registry. Used at submission, at
/// approval (on the signed ticket) and on every request (against the current config).
pub fn fits(config: &PolicyConfig, ticket: &Ticket) -> Result<(), FitError> {
    let Some(template) = config.template(&ticket.template) else {
        return Err(FitError {
            reasons: vec![format!("template {} does not exist", ticket.template)],
        });
    };
    let mut reasons = Vec::new();
    let scope = &ticket.scope;

    if scope.repos.is_empty() {
        reasons.push("scope.repos is empty".to_owned());
    }
    for repo in &scope.repos {
        if config.repo(repo).is_none() {
            reasons.push(format!("repo {repo} is not in the registry"));
        } else if !template.repos.contains(repo) {
            reasons.push(format!("repo {repo} is not allowed by the template"));
        }
    }
    if scope.operations.is_empty() {
        reasons.push("scope.operations is empty".to_owned());
    }
    for op in scope.operations.difference(&template.operations) {
        reasons.push(format!("operation {op} is not allowed by the template"));
    }
    let signs = scope.operations.contains(&Operation::CommitSign);
    let pushes = scope.operations.contains(&Operation::Push);
    if (signs || pushes) && scope.branches.is_empty() {
        reasons.push("commit_sign and push need at least one branch".to_owned());
    }
    for branch in &scope.branches {
        if !template
            .branches
            .iter()
            .any(|allowed| allowed.covers(branch))
        {
            reasons.push(format!(
                "branch {branch} is not within the template's branches ({})",
                join(&template.branches)
            ));
        }
    }
    if scope.force_push && !template.force_push {
        reasons.push("force_push is not allowed by the template".to_owned());
    }
    for email in scope
        .committer_emails
        .difference(&template.committer_emails)
    {
        reasons.push(format!(
            "committer email {email} is not allowed by the template"
        ));
    }
    if signs && scope.committer_emails.is_empty() {
        reasons.push("commit_sign needs at least one committer email".to_owned());
    }
    // Without commit_sign the key is unused: None, or still the template's after a narrowing
    // dropped commit_sign.
    let key_ok = match &scope.signing_key {
        None => !signs,
        Some(key) => template.signing_key.as_ref() == Some(key),
    };
    if !key_ok {
        reasons.push("scope.signing_key must be the template's signing key".to_owned());
    }
    if pushes {
        for repo in &scope.repos {
            if let Some(entry) = config.repo(repo)
                && push_modes(&entry.push_modes, template).is_empty()
            {
                reasons.push(format!(
                    "repo {repo} has no push mode allowed by both the registry and the template"
                ));
            }
        }
    }

    check_limits(ticket, template, &mut reasons);
    check_text(ticket, template, &mut reasons);
    if let Some(caller) = &ticket.subject.caller
        && caller.validate().is_err()
    {
        reasons.push("subject.caller.descends_from.executable must be absolute".to_owned());
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(FitError { reasons })
    }
}

/// The push modes a lease under `template` may use on a repo with `registry_modes`.
pub fn push_modes(registry_modes: &BTreeSet<PushMode>, template: &Template) -> BTreeSet<PushMode> {
    registry_modes
        .intersection(&template.push_modes)
        .copied()
        .collect()
}

fn check_limits(ticket: &Ticket, template: &Template, reasons: &mut Vec<String>) {
    let limits = &ticket.limits;
    let ttl = ticket.created_at.seconds_until(limits.expires_at);
    if ttl <= 0 {
        reasons.push("limits.expires_at must be after created_at".to_owned());
    } else if u64::try_from(ttl).map_or(true, |ttl| ttl > template.max_ttl.seconds()) {
        reasons.push(format!(
            "the lease would last {ttl}s, over the template's max_ttl ({})",
            template.max_ttl
        ));
    }
    let mut cap = |name: &str, value: u64, max: u64| {
        if value > max {
            reasons.push(format!(
                "limits.{name} is {value}, over the template's {max}"
            ));
        }
    };
    cap(
        "max_signatures",
        limits.max_signatures.into(),
        template.max_signatures.into(),
    );
    cap(
        "max_pushes",
        limits.max_pushes.into(),
        template.max_pushes.into(),
    );
    cap(
        "max_ops_per_minute",
        limits.max_ops_per_minute.into(),
        template.max_ops_per_minute.into(),
    );
    cap(
        "max_push_size",
        limits.max_push_size.bytes(),
        template.max_push_size.bytes(),
    );
    if limits.max_ops_per_minute == 0 {
        reasons.push("limits.max_ops_per_minute must be at least 1".to_owned());
    }
}

fn check_text(ticket: &Ticket, template: &Template, reasons: &mut Vec<String>) {
    let text = &ticket.text;
    let mut bound = |name: &str, len: usize, max: usize| {
        if len > max {
            reasons.push(format!("{name} is too long ({len}, at most {max})"));
        }
    };
    bound("ticket.title", text.title.chars().count(), MAX_TITLE_CHARS);
    bound("ticket.task", text.task.chars().count(), MAX_TASK_CHARS);
    bound("ticket.plan", text.plan.len(), MAX_PLAN_STEPS);
    for step in &text.plan {
        bound("a plan step", step.chars().count(), MAX_PLAN_STEP_CHARS);
    }
    bound(
        "ticket.expected_paths",
        text.expected_paths.len(),
        MAX_EXPECTED_PATHS,
    );
    if let Some(hint) = &ticket.subject.origin_hint {
        bound("origin_hint", hint.chars().count(), MAX_ORIGIN_HINT_CHARS);
    }
    let task_lines = text.task.split('\n').count();
    if task_lines > MAX_TASK_LINES {
        reasons.push(format!(
            "ticket.task has {task_lines} lines, at most {MAX_TASK_LINES}"
        ));
    }
    if text.title.contains(['\n', '\r']) {
        reasons.push("ticket.title must be one line".to_owned());
    }
    if text.plan.iter().any(|step| step.contains(['\n', '\r'])) {
        reasons.push("a plan step must be one line".to_owned());
    }
    if text.title.trim().is_empty() {
        reasons.push("ticket.title is empty".to_owned());
    }
    if text.revision == 0 {
        reasons.push("ticket.revision starts at 1".to_owned());
    }
    if template.require_expected_paths && text.expected_paths.is_empty() {
        reasons.push("the template requires ticket.expected_paths".to_owned());
    }
}

/// What the daemon knows about a submission, besides the request itself.
#[derive(Debug, Clone)]
pub struct Submission<'a> {
    /// A fresh id for the ticket.
    pub id: TicketId,
    pub now: Timestamp,
    /// Fingerprint of the session public key sent with the request.
    pub session_key: KeyFingerprint,
    /// The lease named by `ticket.amends`, as found in the store.
    pub amends: Option<&'a Lease>,
    /// The ticket named by `ticket.revises`, as found in the store.
    pub revises: Option<&'a TicketRecord>,
}

/// Completes a request into a ticket that fits exactly one template (the named one, or the
/// only one it fits), or rejects it with every reason.
pub fn submit(
    config: &PolicyConfig,
    request: &TicketRequest,
    submission: &Submission<'_>,
) -> Result<Ticket, Rejection> {
    let (revision, previous_feedback) = check_links(request, submission)?;

    let candidates: Vec<&TemplateName> = match &request.template {
        Some(name) if config.template(name).is_some() => vec![name],
        Some(name) => return Err(Rejection::one(format!("template {name} does not exist"))),
        None => config.templates().keys().collect(),
    };

    let mut fitting = Vec::new();
    let mut reasons = Vec::new();
    for name in candidates {
        let Some(template) = config.template(name) else {
            continue;
        };
        let ticket = build(
            request,
            submission,
            name,
            template,
            revision,
            previous_feedback.clone(),
        )?;
        match fits(config, &ticket) {
            Ok(()) => fitting.push(ticket),
            Err(why) => reasons.push(format!("{name}: {why}")),
        }
    }
    match fitting.len() {
        1 => Ok(fitting.remove(0)),
        0 if reasons.is_empty() => Err(Rejection::one("there are no templates")),
        0 => Err(Rejection {
            reasons: std::iter::once("the ticket fits no template".to_owned())
                .chain(reasons)
                .collect(),
        }),
        _ => {
            let names: Vec<String> = fitting.iter().map(|t| t.template.to_string()).collect();
            Err(Rejection::one(format!(
                "the ticket fits several templates ({}): name one with `template:`",
                names.join(", ")
            )))
        }
    }
}

/// Checks `amends` and `revises` against what the store found; returns the revision number
/// and the feedback to carry.
fn check_links(
    request: &TicketRequest,
    submission: &Submission<'_>,
) -> Result<(u32, Option<String>), Rejection> {
    match (&request.ticket.amends, submission.amends) {
        (None, None) => {}
        // The session first: to another session the lease doesn't exist, whatever its state
        // (answering "not active" would tell it what became of someone else's lease).
        (Some(id), Some(lease))
            if &lease.id == id && lease.ticket.subject.session_key == submission.session_key =>
        {
            if !lease.is_in_force(submission.now) {
                return Err(Rejection::one(format!(
                    "ticket {id} can't be amended: its lease is not active"
                )));
            }
        }
        (Some(id), _) => {
            return Err(Rejection::one(format!(
                "ticket {id} (amends) does not exist"
            )));
        }
        (None, Some(_)) => return Err(Rejection::one("unexpected amended lease")),
    }
    match (&request.ticket.revises, submission.revises) {
        (None, None) => Ok((1, None)),
        // Like an amendment: only the session the feedback was written for sees the ticket;
        // to any other, it doesn't exist, whatever its state.
        (Some(id), Some(previous))
            if &previous.ticket.id == id
                && previous.ticket.subject.session_key == submission.session_key =>
        {
            if previous.state != State::Refused {
                return Err(Rejection::one(format!(
                    "ticket {id} can't be revised: it was not refused"
                )));
            }
            if previous.ticket.text.amends != request.ticket.amends {
                return Err(Rejection::one(format!(
                    "a revision of {id} must amend the same lease as {id}"
                )));
            }
            let revision = previous
                .ticket
                .text
                .revision
                .checked_add(1)
                .ok_or_else(|| Rejection::one("too many revisions"))?;
            Ok((revision, previous.feedback.clone()))
        }
        (Some(id), _) => Err(Rejection::one(format!(
            "ticket {id} (revises) does not exist"
        ))),
        (None, Some(_)) => Err(Rejection::one("unexpected revised ticket")),
    }
}

/// Fills a ticket from the request and the template's defaults.
fn build(
    request: &TicketRequest,
    submission: &Submission<'_>,
    name: &TemplateName,
    template: &Template,
    revision: u32,
    previous_feedback: Option<String>,
) -> Result<Ticket, Rejection> {
    let operations: BTreeSet<Operation> = request.scope.operations.iter().copied().collect();
    let signs = operations.contains(&Operation::CommitSign);
    let committer_emails = if !request.scope.committer_emails.is_empty() {
        request.scope.committer_emails.iter().cloned().collect()
    } else if signs {
        template.committer_emails.clone()
    } else {
        BTreeSet::new()
    };
    let limits = &request.limits;
    let ttl = limits.ttl.unwrap_or(template.max_ttl);
    if ttl < MIN_TTL {
        return Err(Rejection::one(format!(
            "limits.ttl is {ttl}, under the minimum of {MIN_TTL}"
        )));
    }
    let expires_at = submission
        .now
        .checked_add(ttl)
        .ok_or_else(|| Rejection::one("limits.ttl is too long"))?;
    Ok(Ticket {
        kind: TicketKind::V1,
        id: submission.id.clone(),
        created_at: submission.now,
        template: name.clone(),
        subject: Subject {
            session_key: submission.session_key.clone(),
            origin_hint: request.origin_hint.clone(),
            caller: request.caller.clone(),
        },
        scope: Scope {
            repos: request.scope.repos.iter().cloned().collect(),
            operations,
            branches: request.scope.branches.iter().cloned().collect(),
            force_push: request.scope.force_push,
            committer_emails,
            signing_key: if signs {
                template.signing_key.clone()
            } else {
                None
            },
        },
        text: TicketText {
            title: request.ticket.title.clone(),
            task: request.ticket.task.clone(),
            plan: request.ticket.plan.clone(),
            expected_paths: request.ticket.expected_paths.iter().cloned().collect(),
            amends: request.ticket.amends.clone(),
            revises: request.ticket.revises.clone(),
            revision,
            previous_feedback,
        },
        limits: Limits {
            expires_at,
            max_signatures: limits.max_signatures.unwrap_or(template.max_signatures),
            max_pushes: limits.max_pushes.unwrap_or(template.max_pushes),
            max_ops_per_minute: limits
                .max_ops_per_minute
                .unwrap_or(template.max_ops_per_minute),
            max_push_size: limits.max_push_size.unwrap_or(template.max_push_size),
        },
        on_violation: request.on_violation,
    })
}

fn join<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
