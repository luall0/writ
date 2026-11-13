//! Narrowing: the approver may sign a ticket narrower than the one submitted (shorter TTL,
//! fewer repos, branches or operations, lower limits), never a wider one, repository by
//! repository.
//!
//! [`check`] accepts the signed ticket only if every field is the same as submitted or
//! narrower. Identity, subject, each repository's template and the text must be identical.

use crate::ticket::{Common, Limits, RepoLimits, RepoTerms, Ticket, TicketText};

/// Why a signed ticket is not a narrowing of the submitted one. Lists every difference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the signed ticket is not a narrowing of the submitted one: {}", .reasons.join("; "))]
pub struct NarrowingError {
    pub reasons: Vec<String>,
}

/// Checks that `signed` grants nothing `submitted` did not.
pub fn check(submitted: &Ticket, signed: &Ticket) -> Result<(), NarrowingError> {
    // Every field placed (the review after M7.6, U-4): one added to the ticket doesn't compile
    // until it is checked here. The ones bound to `_` are checked by [`widenings`].
    let Ticket {
        kind,
        id,
        created_at,
        // Compared whole: a field added to it is compared too.
        subject,
        common:
            Common {
                committer_emails: _,
                committer_name: _,
                signing_key,
            },
        repos,
        text:
            TicketText {
                title,
                task,
                plan,
                estimate,
                amends,
                renews,
                revises,
                revision,
                previous_feedback,
            },
        limits: Limits {
            expires_at,
            max_ops_per_minute,
        },
        on_violation: _,
    } = signed;
    let mut reasons = Vec::new();
    let mut same = |name: &str, equal: bool| {
        if !equal {
            reasons.push(format!("{name} changed"));
        }
    };
    same("kind", submitted.kind == *kind);
    same("id", submitted.id == *id);
    same("created_at", submitted.created_at == *created_at);
    same("subject", submitted.subject == *subject);
    same(
        "common.signing_key",
        submitted.common.signing_key == *signing_key,
    );
    let a = &submitted.text;
    same("ticket.title", a.title == *title);
    same("ticket.task", a.task == *task);
    same("ticket.plan", a.plan == *plan);
    same("ticket.estimate", a.estimate == *estimate);
    same("ticket.amends", a.amends == *amends);
    same("ticket.renews", a.renews == *renews);
    same("ticket.revises", a.revises == *revises);
    same("ticket.revision", a.revision == *revision);
    same(
        "ticket.previous_feedback",
        a.previous_feedback == *previous_feedback,
    );

    for (repo, b) in repos {
        // The scope's fields (`_`) are checked by [`widenings`].
        let RepoTerms {
            template,
            operations: _,
            branches: _,
            force_push: _,
            expected_paths: _,
            limits:
                RepoLimits {
                    max_signatures,
                    max_pushes,
                    max_push_size,
                },
        } = b;
        if let Some(a) = submitted.terms(repo) {
            if a.template != *template {
                reasons.push(format!("repos.{repo}.template changed"));
            }
            let a = &a.limits;
            let mut at_most = |name: &str, narrower: bool| {
                if !narrower {
                    reasons.push(format!("repos.{repo}.limits.{name} raised"));
                }
            };
            at_most("max_signatures", *max_signatures <= a.max_signatures);
            at_most("max_pushes", *max_pushes <= a.max_pushes);
            at_most("max_push_size", *max_push_size <= a.max_push_size);
        }
    }
    reasons.extend(widenings(submitted, signed));

    let a = &submitted.limits;
    let mut at_most = |name: &str, narrower: bool| {
        if !narrower {
            reasons.push(format!("limits.{name} raised"));
        }
    };
    at_most("expires_at", *expires_at <= a.expires_at);
    at_most(
        "max_ops_per_minute",
        *max_ops_per_minute <= a.max_ops_per_minute,
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
    // renewal. A ticket that signs nothing names nobody (the review after M7.6, C-3: a push-only
    // renewal has no name, which is no other identity).
    let signs = next.repos.values().any(|terms| {
        terms
            .operations
            .contains(&crate::ticket::Operation::CommitSign)
    });
    if signs && b.committer_name != a.committer_name {
        reasons.push("common.committer_name changed".to_owned());
    }
    if next.on_violation < previous.on_violation {
        reasons.push("on_violation made less strict".to_owned());
    }
    reasons
}
