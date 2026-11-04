//! Template fit and ticket submission.
//!
//! Every ticket must fit its templates (Q14 in `docs/decisions.md`; per repository since
//! M6.1.5): [`fits`] says whether a complete ticket stays within them and the registry, with
//! every reason when it doesn't. [`submit`] completes an agent's [`TicketRequest`] into a
//! [`Ticket`], picking each repository's template, or rejects it before it reaches the
//! approver.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{PolicyConfig, PushMode, Template};
use crate::lease::{Lease, Renewed, State, TicketRecord};
use crate::names::{CommitterName, Email, KeyFingerprint, KeyId, RepoName, TemplateName, TicketId};
use crate::ticket::Operation;
use crate::ticket::{
    Common, Limits, RepoLimits, RepoTerms, RequestRepo, Subject, Ticket, TicketKind,
    TicketRequest, TicketText,
};
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
/// The bytes of every `expected_paths` pattern together: the set is matched against each
/// commit's paths, so its size bounds that work (the review after M5.5, S8).
pub const MAX_EXPECTED_PATHS_BYTES: usize = 16 * 1024;
/// The branches a ticket may list for one repository (each within the template's): what the
/// approver reads, and what each push is compared with.
pub const MAX_BRANCHES: usize = 50;
pub const MAX_ORIGIN_HINT_CHARS: usize = 100;
/// What precedes feedback from a refusal nobody signed, in a revision's `previous_feedback`.
pub const UNSIGNED_FEEDBACK: &str = "[not signed by an approver] ";
/// The shortest lease a ticket may ask for, by default (`writd.yaml`'s `min_ttl`). A pending
/// ticket holds one of the approver's waiting slots until it expires: a 1-second ticket would
/// free its slot every second, and let one submitter notify the approver without end. At 5
/// minutes, `max_pending` caps those notifications. (The approver may still narrow a lease
/// below it when signing.)
pub const DEFAULT_MIN_TTL: Duration = Duration::from_seconds(5 * 60);
/// The least `min_ttl` may be: below it, only the submission rates bound the notifications
/// (docs/threat-model.md).
pub const MIN_TTL_FLOOR: Duration = Duration::from_seconds(10);
/// The most `min_ttl` may be.
pub const MIN_TTL_CEILING: Duration = Duration::from_seconds(86_400);
/// How long after its `expires_at` an expired or used-up lease can be renewed, by default
/// (`writd.yaml`'s `renew_grace`): long enough for a night's wait on CI.
pub const DEFAULT_RENEW_GRACE: Duration = Duration::from_seconds(86_400);
/// The most `renew_grace` may be.
pub const RENEW_GRACE_CEILING: Duration = Duration::from_seconds(7 * 86_400);
/// The most one phase of `ticket.estimate` may say.
pub const MAX_ESTIMATE: Duration = Duration::from_seconds(30 * 86_400);

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

/// The most repositories one ticket may name: each is a block the approver reads.
pub const MAX_REPOS: usize = 16;

/// A template, by name, as the policy has it.
type Named<'a> = (&'a RepoName, &'a TemplateName, &'a Template);

/// Checks that a complete ticket fits its templates and the registry: each repository's terms
/// within its template ([`check_repo`]), the lease's terms within every one of them (one
/// signing key, one committer name, the strictest `max_ttl` and `max_ops_per_minute`). Used at
/// submission, at approval (on the signed ticket) and on every request (against the current
/// config).
pub fn fits(config: &PolicyConfig, ticket: &Ticket) -> Result<(), FitError> {
    let mut reasons = Vec::new();
    if ticket.repos.is_empty() {
        reasons.push("repos is empty: name at least one repository".to_owned());
    }
    if ticket.repos.len() > MAX_REPOS {
        reasons.push(format!(
            "repos names {} repositories, at most {MAX_REPOS}",
            ticket.repos.len()
        ));
    }
    let mut named: Vec<Named<'_>> = Vec::new();
    for (repo, terms) in &ticket.repos {
        match config.template(&terms.template) {
            None => reasons.push(format!(
                "repos.{repo}: template {} does not exist",
                terms.template
            )),
            Some(template) => {
                check_repo(
                    config,
                    repo,
                    terms,
                    template,
                    Some(&ticket.common.committer_emails),
                    &mut reasons,
                );
                named.push((repo, &terms.template, template));
            }
        }
    }
    check_common(ticket, &named, &mut reasons);
    check_lease_limits(ticket, &named, &mut reasons);
    check_text(ticket, &mut reasons);
    if let Some(caller) = &ticket.subject.caller
        && let Err(e) = caller.validate()
    {
        reasons.push(format!("subject.caller: {e}"));
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(FitError { reasons })
    }
}

/// Checks one repository's terms against its template and the registry (`emails`: the
/// lease's committer emails, checked against the template when the repository signs; `None`
/// while they are still to be chosen). Every reason, prefixed `repos.<repo>`.
fn check_repo(
    config: &PolicyConfig,
    repo: &RepoName,
    terms: &RepoTerms,
    template: &Template,
    emails: Option<&BTreeSet<Email>>,
    reasons: &mut Vec<String>,
) {
    let at = format!("repos.{repo}");
    let registry = config.repo(repo);
    if registry.is_none() {
        reasons.push(format!("{at}: repo {repo} is not in the registry"));
    } else if !template.repos.contains(repo) {
        reasons.push(format!(
            "{at}: repo {repo} is not allowed by the template {}",
            terms.template
        ));
    }
    if terms.operations.is_empty() {
        reasons.push(format!("{at}.operations is empty"));
    }
    for op in terms.operations.difference(&template.operations) {
        reasons.push(format!("{at}: operation {op} is not allowed by the template"));
    }
    let signs = terms.operations.contains(&Operation::CommitSign);
    let pushes = terms.operations.contains(&Operation::Push);
    if (signs || pushes) && terms.branches.is_empty() {
        reasons.push(format!("{at}: commit_sign and push need at least one branch"));
    }
    if terms.branches.len() > MAX_BRANCHES {
        reasons.push(format!(
            "{at}.branches is too long ({}, at most {MAX_BRANCHES})",
            terms.branches.len()
        ));
    }
    for branch in &terms.branches {
        if !template
            .branches
            .iter()
            .any(|allowed| allowed.covers(branch))
        {
            reasons.push(format!(
                "{at}: branch {branch} is not within the template's branches ({})",
                join(&template.branches)
            ));
        }
    }
    if terms.force_push && !template.force_push {
        reasons.push(format!("{at}: force_push is not allowed by the template"));
    }
    if let (true, Some(emails)) = (signs, emails) {
        for email in emails.difference(&template.committer_emails) {
            reasons.push(format!(
                "{at}: committer email {email} is not allowed by the template {}",
                terms.template
            ));
        }
    }
    if pushes
        && let Some(entry) = registry
        && push_modes(&entry.push_modes, template).is_empty()
    {
        reasons.push(format!(
            "{at}: repo {repo} has no push mode allowed by both the registry and the template"
        ));
    }
    let limits = &terms.limits;
    let mut cap = |name: &str, value: u64, max: u64| {
        if value > max {
            reasons.push(format!(
                "{at}.limits.{name} is {value}, over the template's {max}"
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
        "max_push_size",
        limits.max_push_size.bytes(),
        template.max_push_size.bytes(),
    );
    // git reads a `receive.maxInputSize` of 0 as no limit (the review after M5.5, S7).
    if pushes && limits.max_push_size.bytes() == 0 {
        reasons.push(format!("{at}.limits.max_push_size must be at least 1 byte"));
    }
    if terms.expected_paths.len() > MAX_EXPECTED_PATHS {
        reasons.push(format!(
            "{at}.expected_paths is too long ({}, at most {MAX_EXPECTED_PATHS})",
            terms.expected_paths.len()
        ));
    }
    if template.require_expected_paths && terms.expected_paths.is_empty() {
        reasons.push(format!(
            "{at}: the template {} requires expected_paths",
            terms.template
        ));
    }
}

/// The push modes a lease under `template` may use on a repo with `registry_modes`.
pub fn push_modes(registry_modes: &BTreeSet<PushMode>, template: &Template) -> BTreeSet<PushMode> {
    registry_modes
        .intersection(&template.push_modes)
        .copied()
        .collect()
}

/// The lease's terms that must agree across its templates: the committer emails (needed when
/// a repository signs), one signing key and one committer name.
fn check_common(ticket: &Ticket, named: &[Named<'_>], reasons: &mut Vec<String>) {
    let common = &ticket.common;
    let signing: Vec<&Named<'_>> = named
        .iter()
        .filter(|(repo, _, _)| ticket.allows(repo, Operation::CommitSign))
        .collect();
    if signing.is_empty() {
        // Nothing signs: no key or name, or still a template's after a narrowing dropped
        // commit_sign.
        let key_ok = common.signing_key.as_ref().is_none_or(|key| {
            named.iter().any(|(_, _, t)| t.signing_key.as_ref() == Some(key))
        });
        let name_ok = common.committer_name.as_ref().is_none_or(|name| {
            named.iter().any(|(_, _, t)| t.committer_name.as_ref() == Some(name))
        });
        if !key_ok {
            reasons.push("common.signing_key must be a template's signing key".to_owned());
        }
        if !name_ok {
            reasons.push("common.committer_name must be a template's committer_name".to_owned());
        }
        return;
    }
    if common.committer_emails.is_empty() {
        reasons.push("commit_sign needs at least one committer email".to_owned());
    }
    let keys: BTreeSet<Option<&KeyId>> = signing.iter().map(|(_, _, t)| t.signing_key.as_ref()).collect();
    if keys.len() > 1 {
        let each: Vec<String> = signing
            .iter()
            .map(|(repo, name, t)| {
                let key = t.signing_key.as_ref().map_or("none".to_owned(), |k| k.to_string());
                format!("{repo} (template {name}, key {key})")
            })
            .collect();
        reasons.push(format!(
            "the repositories sign with different keys: {}; a lease signs with one key (ask \
             one lease per repository)",
            each.join(", ")
        ));
    } else if keys.first().copied().flatten() != common.signing_key.as_ref() {
        reasons.push("common.signing_key must be the templates' signing key".to_owned());
    }
    let names: BTreeSet<Option<&CommitterName>> = signing
        .iter()
        .map(|(_, _, t)| t.committer_name.as_ref())
        .collect();
    if names.len() > 1 {
        let each: Vec<String> = signing
            .iter()
            .map(|(repo, name, t)| {
                let set = t
                    .committer_name
                    .as_ref()
                    .map_or("none".to_owned(), |n| format!("{n:?}"));
                format!("{repo} (template {name}, committer_name {set})")
            })
            .collect();
        reasons.push(format!(
            "the repositories' templates set different committer names: {}; a lease has one \
             (ask one lease per repository)",
            each.join(", ")
        ));
    } else if names.first().copied().flatten() != common.committer_name.as_ref() {
        reasons.push(
            "common.committer_name must be the templates' committer_name".to_owned(),
        );
    }
}

/// The lease's limits within the strictest of its templates: its TTL within every
/// `max_ttl`, its rate within every `max_ops_per_minute`.
fn check_lease_limits(ticket: &Ticket, named: &[Named<'_>], reasons: &mut Vec<String>) {
    let limits = &ticket.limits;
    let ttl = ticket.created_at.seconds_until(limits.expires_at);
    if ttl <= 0 {
        reasons.push("limits.expires_at must be after created_at".to_owned());
    }
    let mut seen: BTreeSet<&TemplateName> = BTreeSet::new();
    for (_, name, template) in named {
        if !seen.insert(name) {
            continue;
        }
        if ttl > 0 && u64::try_from(ttl).map_or(true, |ttl| ttl > template.max_ttl.seconds()) {
            reasons.push(format!(
                "the lease would last {ttl}s, over the template {name}'s max_ttl ({})",
                template.max_ttl
            ));
        }
        if limits.max_ops_per_minute > template.max_ops_per_minute {
            reasons.push(format!(
                "limits.max_ops_per_minute is {}, over the template {name}'s {}",
                limits.max_ops_per_minute, template.max_ops_per_minute
            ));
        }
    }
    if limits.max_ops_per_minute == 0 {
        reasons.push("limits.max_ops_per_minute must be at least 1".to_owned());
    }
}

/// The agent's words and links, as a request and a complete ticket both hold them: what the
/// text bounds are checked on, the same way for both ([`check_request`] and [`fits`]).
struct Words<'a> {
    title: &'a str,
    task: &'a str,
    plan: &'a [String],
    /// Every repository's expected paths: their bytes in all are bounded.
    expected_paths: Vec<&'a str>,
    origin_hint: Option<&'a str>,
    estimate: Option<&'a crate::ticket::Estimate>,
    amends: bool,
    renews: bool,
}

fn check_words(words: &Words<'_>, reasons: &mut Vec<String>) {
    let mut bound = |name: &str, len: usize, max: usize| {
        if len > max {
            reasons.push(format!("{name} is too long ({len}, at most {max})"));
        }
    };
    bound("ticket.title", words.title.chars().count(), MAX_TITLE_CHARS);
    bound("ticket.task", words.task.chars().count(), MAX_TASK_CHARS);
    bound("ticket.plan", words.plan.len(), MAX_PLAN_STEPS);
    for step in words.plan {
        bound("a plan step", step.chars().count(), MAX_PLAN_STEP_CHARS);
    }
    let path_bytes = words
        .expected_paths
        .iter()
        .fold(0usize, |sum, p| sum.saturating_add(p.len()));
    bound(
        "expected_paths (bytes in all, every repository)",
        path_bytes,
        MAX_EXPECTED_PATHS_BYTES,
    );
    if let Some(hint) = words.origin_hint {
        bound("origin_hint", hint.chars().count(), MAX_ORIGIN_HINT_CHARS);
    }
    let task_lines = words.task.split('\n').count();
    if task_lines > MAX_TASK_LINES {
        reasons.push(format!(
            "ticket.task has {task_lines} lines, at most {MAX_TASK_LINES}"
        ));
    }
    if words.title.contains(['\n', '\r']) {
        reasons.push("ticket.title must be one line".to_owned());
    }
    if words.plan.iter().any(|step| step.contains(['\n', '\r'])) {
        reasons.push("a plan step must be one line".to_owned());
    }
    if words.title.trim().is_empty() {
        reasons.push("ticket.title is empty".to_owned());
    }
    if let Some(estimate) = words.estimate {
        for (name, phase) in [
            ("coding", estimate.coding),
            ("checks", estimate.checks),
            ("ci", estimate.ci),
        ] {
            if phase.is_some_and(|d| d > MAX_ESTIMATE) {
                reasons.push(format!("ticket.estimate.{name} is over {MAX_ESTIMATE}"));
            }
        }
    }
    if words.amends && words.renews {
        reasons.push("a ticket can't both amend and renew a lease".to_owned());
    }
}

fn check_text(ticket: &Ticket, reasons: &mut Vec<String>) {
    let text = &ticket.text;
    check_words(
        &Words {
            title: &text.title,
            task: &text.task,
            plan: &text.plan,
            expected_paths: ticket
                .repos
                .values()
                .flat_map(|t| t.expected_paths.iter().map(|p| p.as_str()))
                .collect(),
            origin_hint: ticket.subject.origin_hint.as_deref(),
            estimate: text.estimate.as_ref(),
            amends: text.amends.is_some(),
            renews: text.renews.is_some(),
        },
        reasons,
    );
    if text.revision == 0 {
        reasons.push("ticket.revision starts at 1".to_owned());
    }
}

/// What a ticket file can be checked for without the daemon (`writ check`): the bounds of its
/// text, what each repository's operations need, the shortest TTL any daemon takes
/// ([`MIN_TTL_FLOOR`]; the daemon's own `min_ttl` may be longer). Fitting the templates, and
/// the links (`amends`, `renews`, `revises`), only the daemon can check. Every reason, or
/// none.
pub fn check_request(request: &TicketRequest) -> Vec<String> {
    let mut reasons = Vec::new();
    if request.repos.is_empty() {
        reasons.push("repos is empty: name at least one repository".to_owned());
    }
    if request.repos.len() > MAX_REPOS {
        reasons.push(format!(
            "repos names {} repositories, at most {MAX_REPOS}",
            request.repos.len()
        ));
    }
    for (repo, asked) in &request.repos {
        let at = format!("repos.{repo}");
        if asked.operations.is_empty() {
            reasons.push(format!("{at}.operations is empty"));
        }
        let needs_branch = asked
            .operations
            .iter()
            .any(|op| matches!(op, Operation::CommitSign | Operation::Push));
        if needs_branch && asked.branches.is_empty() {
            reasons.push(format!("{at}: commit_sign and push need at least one branch"));
        }
        let branches = asked.branches.iter().collect::<BTreeSet<_>>().len();
        if branches > MAX_BRANCHES {
            reasons.push(format!(
                "{at}.branches is too long ({branches}, at most {MAX_BRANCHES})"
            ));
        }
        let paths = asked.expected_paths.iter().collect::<BTreeSet<_>>().len();
        if paths > MAX_EXPECTED_PATHS {
            reasons.push(format!(
                "{at}.expected_paths is too long ({paths}, at most {MAX_EXPECTED_PATHS})"
            ));
        }
        if let (true, Some(size)) = (
            asked.operations.contains(&Operation::Push),
            asked.limits.max_push_size,
        ) && size.bytes() == 0
        {
            reasons.push(format!("{at}.limits.max_push_size must be at least 1 byte"));
        }
    }
    let text = &request.ticket;
    check_words(
        &Words {
            title: &text.title,
            task: &text.task,
            plan: &text.plan,
            expected_paths: request
                .repos
                .values()
                .flat_map(|r| r.expected_paths.iter().map(|p| p.as_str()))
                .collect(),
            origin_hint: request.origin_hint.as_deref(),
            estimate: text.estimate.as_ref(),
            amends: text.amends.is_some(),
            renews: text.renews.is_some(),
        },
        &mut reasons,
    );
    if let Some(ttl) = request.limits.ttl
        && ttl < MIN_TTL_FLOOR
    {
        reasons.push(format!(
            "limits.ttl is {ttl}, under {MIN_TTL_FLOOR}, the least any daemon takes"
        ));
    }
    if request.limits.max_ops_per_minute == Some(0) {
        reasons.push("limits.max_ops_per_minute must be at least 1".to_owned());
    }
    if let Some(caller) = &request.caller
        && let Err(e) = caller.validate()
    {
        reasons.push(format!("caller: {e}"));
    }
    reasons
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
    /// The lease named by `ticket.renews`, as found in the store, with its renewals so far
    /// and the daemon's `renew_grace`.
    pub renews: Option<Renewed<'a>>,
    /// The ticket named by `ticket.revises`, as found in the store.
    pub revises: Option<&'a TicketRecord>,
    /// The shortest TTL a ticket may ask for (`writd.yaml`'s `min_ttl`).
    pub min_ttl: Duration,
}

/// Completes a request into a ticket: each repository's terms fitting exactly one template
/// (the named one, the renewed lease's for that repository, or the only one that allows the
/// repository and fits), then the lease's terms from the templates picked, the whole checked
/// by [`fits`]; or rejects it with every reason.
pub fn submit(
    config: &PolicyConfig,
    request: &TicketRequest,
    submission: &Submission<'_>,
) -> Result<Ticket, Rejection> {
    let (revision, previous_feedback) = check_links(request, submission)?;
    if request.repos.is_empty() {
        return Err(Rejection::one("repos is empty: name at least one repository"));
    }
    if request.repos.len() > MAX_REPOS {
        return Err(Rejection::one(format!(
            "repos names {} repositories, at most {MAX_REPOS}",
            request.repos.len()
        )));
    }
    let renewed = submission.renews.map(|r| &r.lease.ticket);
    let emails: Option<BTreeSet<Email>> = (!request.common.committer_emails.is_empty())
        .then(|| request.common.committer_emails.iter().cloned().collect());
    let mut repos = BTreeMap::new();
    let mut reasons = Vec::new();
    for (repo, asked) in &request.repos {
        let kept = renewed.and_then(|t| t.terms(repo)).map(|t| &t.template);
        let candidates: Vec<&TemplateName> = match (&asked.template, kept) {
            (Some(name), Some(kept)) if name != kept => {
                reasons.push(format!(
                    "repos.{repo}: a renewal keeps its lease's template ({kept}), not {name}"
                ));
                continue;
            }
            (_, Some(kept)) => vec![kept],
            (Some(name), None) => vec![name],
            (None, None) => config
                .templates()
                .iter()
                .filter(|(_, t)| t.repos.contains(repo))
                .map(|(name, _)| name)
                .collect(),
        };
        let mut fitting: Vec<RepoTerms> = Vec::new();
        let mut why: Vec<String> = Vec::new();
        for name in &candidates {
            let Some(template) = config.template(name) else {
                why.push(format!("template {name} does not exist"));
                continue;
            };
            let previous = renewed.and_then(|t| t.terms(repo));
            let terms = build_terms(asked, name, template, previous);
            let mut r = Vec::new();
            check_repo(config, repo, &terms, template, emails.as_ref(), &mut r);
            if r.is_empty() {
                fitting.push(terms);
            } else {
                why.push(format!("{name}: {}", r.join("; ")));
            }
        }
        match fitting.len() {
            1 => {
                if let Some(terms) = fitting.pop() {
                    repos.insert(repo.clone(), terms);
                }
            }
            0 if candidates.is_empty() => reasons.push(format!(
                "repos.{repo} fits no template: no template allows repo {repo}"
            )),
            0 => reasons.push(format!("repos.{repo} fits no template: {}", why.join("; "))),
            _ => {
                let names: Vec<String> = fitting.iter().map(|t| t.template.to_string()).collect();
                reasons.push(format!(
                    "repos.{repo} fits several templates ({}): name one in repos.{repo}.template",
                    names.join(", ")
                ));
            }
        }
    }
    if !reasons.is_empty() {
        return Err(Rejection { reasons });
    }
    let ticket = build(
        config,
        request,
        submission,
        repos,
        emails,
        revision,
        previous_feedback,
    )?;
    fits(config, &ticket).map_err(|e| Rejection { reasons: e.reasons })?;
    if let Some(renewed) = submission.renews {
        check_renewal(config, &ticket, renewed, submission.now)
            .map_err(|reasons| Rejection { reasons })?;
    }
    Ok(ticket)
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
    match (&request.ticket.renews, submission.renews) {
        (None, None) => {}
        (Some(_), _) if request.ticket.amends.is_some() => {
            return Err(Rejection::one(
                "a ticket can't both amend and renew a lease",
            ));
        }
        // As for an amendment: to another session the lease doesn't exist.
        (Some(id), Some(renewed))
            if &renewed.lease.id == id
                && renewed.lease.ticket.subject.session_key == submission.session_key =>
        {
            renewable(renewed, submission.now).map_err(Rejection::one)?;
        }
        (Some(id), _) => {
            return Err(Rejection::one(format!(
                "ticket {id} (renews) does not exist"
            )));
        }
        (None, Some(_)) => return Err(Rejection::one("unexpected renewed lease")),
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
            if previous.ticket.text.renews != request.ticket.renews {
                return Err(Rejection::one(format!(
                    "a revision of {id} must renew the same lease as {id}"
                )));
            }
            let revision = previous
                .ticket
                .text
                .revision
                .checked_add(1)
                .ok_or_else(|| Rejection::one("too many revisions"))?;
            // Feedback nobody signed (`decisions: open`) is labeled by the daemon, so neither
            // the agent nor the approver takes it for the approver's words.
            let feedback = previous
                .feedback
                .as_ref()
                .map(|f| match previous.feedback_by {
                    Some(_) => f.clone(),
                    None => format!("{UNSIGNED_FEEDBACK}{f}"),
                });
            Ok((revision, feedback))
        }
        (Some(id), _) => Err(Rejection::one(format!(
            "ticket {id} (revises) does not exist"
        ))),
        (None, Some(_)) => Err(Rejection::one("unexpected revised ticket")),
    }
}

/// One repository's terms from the request and its template's defaults (a renewal's omitted
/// paths are its lease's: it continues the same work).
fn build_terms(
    asked: &RequestRepo,
    name: &TemplateName,
    template: &Template,
    previous: Option<&RepoTerms>,
) -> RepoTerms {
    let expected_paths = match (asked.expected_paths.is_empty(), previous) {
        (true, Some(previous)) => previous.expected_paths.clone(),
        _ => asked.expected_paths.iter().cloned().collect(),
    };
    let limits = &asked.limits;
    RepoTerms {
        template: name.clone(),
        operations: asked.operations.iter().copied().collect(),
        branches: asked.branches.iter().cloned().collect(),
        force_push: asked.force_push,
        expected_paths,
        limits: RepoLimits {
            max_signatures: limits.max_signatures.unwrap_or(template.max_signatures),
            max_pushes: limits.max_pushes.unwrap_or(template.max_pushes),
            max_push_size: limits.max_push_size.unwrap_or(template.max_push_size),
        },
    }
}

/// Fills the ticket around its repositories' terms: the lease's terms from the templates
/// picked (the emails asked, else the renewed lease's, else those every signing template
/// allows; the signing key and committer name of the signing templates; the TTL and rate
/// asked, else the strictest of the templates').
fn build(
    config: &PolicyConfig,
    request: &TicketRequest,
    submission: &Submission<'_>,
    repos: BTreeMap<RepoName, RepoTerms>,
    emails: Option<BTreeSet<Email>>,
    revision: u32,
    previous_feedback: Option<String>,
) -> Result<Ticket, Rejection> {
    let templates: Vec<&Template> = repos
        .values()
        .filter_map(|terms| config.template(&terms.template))
        .collect();
    let signing: Vec<&Template> = repos
        .values()
        .filter(|terms| terms.operations.contains(&Operation::CommitSign))
        .filter_map(|terms| config.template(&terms.template))
        .collect();
    let renewed = submission.renews.map(|r| &r.lease.ticket);
    let committer_emails = match (emails, renewed, signing.as_slice()) {
        (Some(emails), _, _) => emails,
        (None, _, []) => BTreeSet::new(),
        (None, Some(renewed), _) => renewed.common.committer_emails.clone(),
        (None, None, [first, rest @ ..]) => first
            .committer_emails
            .iter()
            .filter(|e| rest.iter().all(|t| t.committer_emails.contains(*e)))
            .cloned()
            .collect(),
    };
    let first_signing = signing.first();
    let strictest_ttl = templates.iter().map(|t| t.max_ttl).min();
    let strictest_rate = templates.iter().map(|t| t.max_ops_per_minute).min();
    let limits = &request.limits;
    let ttl = limits
        .ttl
        .or(strictest_ttl)
        .ok_or_else(|| Rejection::one("no template for the lease's TTL"))?;
    if ttl < submission.min_ttl {
        return Err(Rejection::one(format!(
            "limits.ttl is {ttl}, under the minimum of {}",
            submission.min_ttl
        )));
    }
    let expires_at = submission
        .now
        .checked_add(ttl)
        .ok_or_else(|| Rejection::one("limits.ttl is too long"))?;
    // An amendment changes scope, not time: it ends with its lease (M3.6).
    let expires_at = match submission.amends {
        Some(lease) => expires_at.min(lease.ticket.limits.expires_at),
        None => expires_at,
    };
    Ok(Ticket {
        kind: TicketKind::V3,
        id: submission.id.clone(),
        created_at: submission.now,
        subject: Subject {
            session_key: submission.session_key.clone(),
            origin_hint: request.origin_hint.clone(),
            caller: request.caller.clone(),
        },
        common: Common {
            committer_emails,
            committer_name: first_signing.and_then(|t| t.committer_name.clone()),
            signing_key: first_signing.and_then(|t| t.signing_key.clone()),
        },
        repos,
        text: TicketText {
            title: request.ticket.title.clone(),
            task: request.ticket.task.clone(),
            plan: request.ticket.plan.clone(),
            estimate: request.ticket.estimate,
            amends: request.ticket.amends.clone(),
            renews: request.ticket.renews.clone(),
            revises: request.ticket.revises.clone(),
            revision,
            previous_feedback,
        },
        limits: Limits {
            expires_at,
            max_ops_per_minute: limits
                .max_ops_per_minute
                .or(strictest_rate)
                .unwrap_or(1),
        },
        on_violation: request.on_violation,
    })
}

/// Whether the lease can be renewed at `now`: active, or expired or used up no longer than
/// `renew_grace` ago (counted from its `expires_at`); never revoked, closed or renewed.
pub fn renewable(renewed: Renewed<'_>, now: Timestamp) -> Result<(), String> {
    let lease = renewed.lease;
    let id = &lease.id;
    match lease.state {
        State::Active | State::Expired | State::Exhausted => {}
        State::Renewed => {
            return Err(format!(
                "lease {id} can't be renewed: it was renewed already"
            ));
        }
        state => return Err(format!("lease {id} can't be renewed: it is {state}")),
    }
    let end = lease.ticket.limits.expires_at;
    let last = end
        .checked_add(renewed.grace)
        .ok_or_else(|| format!("lease {id} can't be renewed: its end is out of range"))?;
    // From `last` on, the grace is over (the same "at or past" as an expiry): with a grace of
    // 0s, only a lease still in force can be renewed.
    if (lease.state != State::Active || lease.ticket.is_expired(now)) && now >= last {
        return Err(format!(
            "lease {id} can't be renewed: it ended at {end}, more than renew_grace ({}) ago",
            renewed.grace
        ));
    }
    Ok(())
}

/// Checks a renewal against the lease it renews, at submission and again at approval: the
/// lease can still be renewed ([`renewable`]), the renewal keeps each repository's template
/// and its subject, stays within its terms (repositories, operations, branches, force push,
/// committer emails, expected paths, `on_violation`:
/// [`narrow::widenings`](crate::narrow::widenings)), and every template's `max_renewals`
/// holds. Every reason, or none.
pub fn check_renewal(
    config: &PolicyConfig,
    ticket: &Ticket,
    renewed: Renewed<'_>,
    now: Timestamp,
) -> Result<(), Vec<String>> {
    let lease = renewed.lease;
    let id = &lease.id;
    let mut reasons = Vec::new();
    if let Err(why) = renewable(renewed, now) {
        reasons.push(why);
    }
    if ticket.text.renews.as_ref() != Some(id) {
        reasons.push(format!("the ticket does not renew lease {id}"));
    }
    for (repo, terms) in &ticket.repos {
        if let Some(kept) = lease.ticket.terms(repo)
            && kept.template != terms.template
        {
            reasons.push(format!(
                "repos.{repo}: a renewal keeps its lease's template ({}), not {}",
                kept.template, terms.template
            ));
        }
    }
    if ticket.subject != lease.ticket.subject {
        reasons.push(format!(
            "a renewal keeps lease {id}'s subject (session key and process)"
        ));
    }
    for widening in crate::narrow::widenings(&lease.ticket, ticket) {
        reasons.push(format!("wider than lease {id}: {widening}"));
    }
    // The strictest of the templates: each one's max_renewals holds.
    for name in ticket.templates() {
        match config.template(name).map(|t| t.max_renewals) {
            Some(Some(max)) if renewed.renewals >= max => reasons.push(format!(
                "template {name} allows {max} renewals of a lease, and lease {id} is renewal {} of its chain",
                renewed.renewals
            )),
            Some(_) => {}
            None => reasons.push(format!("template {name} does not exist")),
        }
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

fn join<T: std::fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
