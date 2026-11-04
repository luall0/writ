//! Narrowing: the approver may sign a ticket narrower than the one submitted (shorter TTL,
//! fewer repos, branches or operations, lower limits), never a wider one, repository by
//! repository.
//!
//! [`check`] accepts the signed ticket only if every field is the same as submitted or
//! narrower. Identity, subject, each repository's template and the text must be identical.

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
    same("subject", submitted.subject == signed.subject);
    same(
        "common.signing_key",
        submitted.common.signing_key == signed.common.signing_key,
    );
    let (a, b) = (&submitted.text, &signed.text);
    same("ticket.title", a.title == b.title);
    same("ticket.task", a.task == b.task);
    same("ticket.plan", a.plan == b.plan);
    same("ticket.estimate", a.estimate == b.estimate);
    same("ticket.amends", a.amends == b.amends);
    same("ticket.renews", a.renews == b.renews);
    same("ticket.revises", a.revises == b.revises);
    same("ticket.revision", a.revision == b.revision);
    same(
        "ticket.previous_feedback",
        a.previous_feedback == b.previous_feedback,
    );

    for (repo, b) in &signed.repos {
        if let Some(a) = submitted.terms(repo) {
            if a.template != b.template {
                reasons.push(format!("repos.{repo}.template changed"));
            }
            let (a, b) = (&a.limits, &b.limits);
            let mut at_most = |name: &str, narrower: bool| {
                if !narrower {
                    reasons.push(format!("repos.{repo}.limits.{name} raised"));
                }
            };
            at_most("max_signatures", b.max_signatures <= a.max_signatures);
            at_most("max_pushes", b.max_pushes <= a.max_pushes);
            at_most("max_push_size", b.max_push_size <= a.max_push_size);
        }
    }
    reasons.extend(widenings(submitted, signed));

    let (a, b) = (&submitted.limits, &signed.limits);
    let mut at_most = |name: &str, narrower: bool| {
        if !narrower {
            reasons.push(format!("limits.{name} raised"));
        }
    };
    at_most("expires_at", b.expires_at <= a.expires_at);
    at_most(
        "max_ops_per_minute",
        b.max_ops_per_minute <= a.max_ops_per_minute,
    );

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(NarrowingError { reasons })
    }
}

/// Everything `next` allows that `previous` didn't, in scope, expected paths and
/// `on_violation` (limits and time aside): what a narrowing, and a renewal of a lease, may
/// never do. Empty when `next` stays within `previous`.
pub fn widenings(previous: &Ticket, next: &Ticket) -> Vec<String> {
    let mut reasons = Vec::new();
    for (repo, b) in &next.repos {
        let Some(a) = previous.terms(repo) else {
            reasons.push(format!("repos adds {repo}"));
            continue;
        };
        let at = format!("repos.{repo}");
        for op in b.operations.difference(&a.operations) {
            reasons.push(format!("{at}.operations adds {op}"));
        }
        for branch in &b.branches {
            if !a.branches.iter().any(|mine| mine.covers(branch)) {
                reasons.push(format!("{at}.branches adds {branch}"));
            }
        }
        if b.force_push && !a.force_push {
            reasons.push(format!("{at}.force_push turned on"));
        }
        // An empty expected_paths turns the path check off, so emptying it widens.
        let (a, b) = (&a.expected_paths, &b.expected_paths);
        if !a.is_empty() {
            if b.is_empty() {
                reasons.push(format!(
                    "{at}.expected_paths emptied (turns the path check off)"
                ));
            }
            for path in b.difference(a) {
                reasons.push(format!("{at}.expected_paths adds {path}"));
            }
        }
    }
    let (a, b) = (&previous.common, &next.common);
    for email in b.committer_emails.difference(&a.committer_emails) {
        reasons.push(format!("common.committer_emails adds {email}"));
    }
    // Another name, or none where there was one, is another identity: never by narrowing or
    // renewal.
    if b.committer_name != a.committer_name {
        reasons.push("common.committer_name changed".to_owned());
    }
    if next.on_violation < previous.on_violation {
        reasons.push("on_violation made less strict".to_owned());
    }
    reasons
}
