//! Narrowing: the approver may sign a ticket narrower than the one submitted (shorter TTL,
//! fewer repos, branches or operations, lower limits), never a wider one.
//!
//! [`check`] accepts the signed ticket only if every field is the same as submitted or
//! narrower. Identity, subject, template and text must be identical.

use crate::ticket::Ticket;

/// Why a signed ticket is not a narrowing of the submitted one. Lists every difference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the signed ticket is not a narrowing of the submitted one: {}", .reasons.join("; "))]
pub struct NarrowingError {
    pub reasons: Vec<String>,
}

/// Checks that `signed` grants nothing `submitted` did not.
pub fn check(submitted: &Ticket, signed: &Ticket) -> Result<(), NarrowingError> {
    let mut reasons = Vec::new();
    let mut same = |name: &str, equal: bool| {
        if !equal {
            reasons.push(format!("{name} changed"));
        }
    };
    same("kind", submitted.kind == signed.kind);
    same("id", submitted.id == signed.id);
    same("created_at", submitted.created_at == signed.created_at);
    same("template", submitted.template == signed.template);
    same("subject", submitted.subject == signed.subject);
    same(
        "scope.signing_key",
        submitted.scope.signing_key == signed.scope.signing_key,
    );
    let (a, b) = (&submitted.ticket, &signed.ticket);
    same("ticket.title", a.title == b.title);
    same("ticket.task", a.task == b.task);
    same("ticket.plan", a.plan == b.plan);
    same("ticket.amends", a.amends == b.amends);
    same("ticket.revises", a.revises == b.revises);
    same("ticket.revision", a.revision == b.revision);
    same(
        "ticket.previous_feedback",
        a.previous_feedback == b.previous_feedback,
    );

    let (a, b) = (&submitted.scope, &signed.scope);
    for repo in b.repos.difference(&a.repos) {
        reasons.push(format!("scope.repos adds {repo}"));
    }
    for op in b.operations.difference(&a.operations) {
        reasons.push(format!("scope.operations adds {op}"));
    }
    for branch in &b.branches {
        if !a.branches.iter().any(|mine| mine.covers(branch)) {
            reasons.push(format!("scope.branches adds {branch}"));
        }
    }
    if b.force_push && !a.force_push {
        reasons.push("scope.force_push turned on".to_owned());
    }
    for email in b.committer_emails.difference(&a.committer_emails) {
        reasons.push(format!("scope.committer_emails adds {email}"));
    }

    // An empty expected_paths turns the path check off, so emptying it widens.
    let (a, b) = (
        &submitted.ticket.expected_paths,
        &signed.ticket.expected_paths,
    );
    if !a.is_empty() {
        if b.is_empty() {
            reasons.push("ticket.expected_paths emptied (turns the path check off)".to_owned());
        }
        for path in b.difference(a) {
            reasons.push(format!("ticket.expected_paths adds {path}"));
        }
    }

    let (a, b) = (&submitted.limits, &signed.limits);
    let mut at_most = |name: &str, narrower: bool| {
        if !narrower {
            reasons.push(format!("limits.{name} raised"));
        }
    };
    at_most("expires_at", b.expires_at <= a.expires_at);
    at_most("max_signatures", b.max_signatures <= a.max_signatures);
    at_most("max_pushes", b.max_pushes <= a.max_pushes);
    at_most(
        "max_ops_per_minute",
        b.max_ops_per_minute <= a.max_ops_per_minute,
    );
    at_most("max_push_size", b.max_push_size <= a.max_push_size);
    if signed.on_violation < submitted.on_violation {
        reasons.push("on_violation made less strict".to_owned());
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(NarrowingError { reasons })
    }
}
