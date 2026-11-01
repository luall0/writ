//! Policy decisions, as pure functions: request facts + lease + config + usage + caller facts
//! + time → allowed (with warnings) or denied (with a reason the agent can read).
//!
//! The daemon gathers the facts (certificate, parsed commit, ref updates, ledger entries,
//! counters) and applies the result; nothing here does I/O. Every decision fails closed: a
//! missing fact, a missing template or repo, or anything unexpected denies.
//!
//! The order of checks in every decision: the lease is live, the caller fits, the operation
//! and repo are in scope, the lease still fits its template under the current config, then
//! the operation's own checks, then the counts and the rate.

use std::collections::BTreeSet;
use std::fmt;

use crate::caller::{self, CallerFacts};
use crate::config::{
    ObjectFormat, PathsCheck, PolicyConfig, PushMode, RepoEntry, Template, TicketLink,
};
use crate::fit;
use crate::lease::{Lease, State, Usage, is_exhausted};
use crate::names::{CommitId, KeyFingerprint, RepoName, TicketId};
use crate::pattern::{PathSet, RefName};
use crate::text;
use crate::ticket::Operation;
use crate::units::Timestamp;

/// The window of `max_ops_per_minute`.
pub const RATE_WINDOW_SECONDS: i64 = 60;

/// How many paths a denial or warning lists before "and N more".
const PATHS_SHOWN: usize = 5;

/// The most characters of one agent-supplied value (a committer email, a path) in a denial
/// or a warning: past it, cut with `…`, so a request can't make a message or a log line
/// large.
const VALUE_SHOWN: usize = 256;

/// Why a request was denied, in a few stable categories (for the audit log and the
/// violation policy). Each code's text ([`DenyCode::as_str`]) is the audit log's `code` and
/// never changes; [`DenyCode::is_violation`] says which ones are the agent overstepping its
/// ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyCode {
    /// No lease matches the certificate (`no_lease`).
    NoLease,
    /// More than one lease matches: deny rather than pick (`ambiguous_lease`).
    AmbiguousLease,
    /// The lease is pending, refused, revoked, closed… anything but active (`not_active`).
    NotActive,
    /// The lease is past `expires_at` (`expired`).
    Expired,
    /// Every signature and push the lease allows is used (`exhausted`).
    Exhausted,
    /// The caller doesn't meet the lease's caller constraint (`caller`).
    Caller,
    /// The operation is not in the lease (`operation`, a violation).
    Operation,
    /// The repo is not in the lease (`repo`, a violation).
    Repo,
    /// The lease no longer fits the configuration: its template or repo changed (`config`).
    Config,
    /// The push mode is not allowed for the repo (`push_mode`, a violation).
    PushMode,
    /// Only commits are signed: not a tag, tree or blob (`object_type`, a violation).
    ObjectType,
    /// The committer email is not in the lease (`committer`, a violation).
    Committer,
    /// The commit's object format isn't its repo's (`object_format`). Not a violation: a
    /// repository of the other format, never anything the ticket allowed.
    ObjectFormat,
    /// The `Writ:` trailer is missing or names another lease (`ticket_link`, a violation).
    TicketLink,
    /// The commit touches paths outside `expected_paths` with `paths_check: deny` (`paths`,
    /// a violation).
    Paths,
    /// The ref is not a branch the lease allows (`ref`, a violation).
    Ref,
    /// The ref is protected in the repo registry (`protected_ref`, a violation).
    ProtectedRef,
    /// A deletion or non-fast-forward without `force_push` (`force_push`, a violation).
    ForcePush,
    /// A pushed commit was not signed under this lease for this repo (`unsigned`, a
    /// violation).
    Unsigned,
    /// A pushed commit touches other paths than the ones checked when it was signed, computed
    /// again from the objects git verified (`paths_changed`, a violation: the objects aren't
    /// the ones the daemon saw).
    PathsChanged,
    /// The push is over `max_push_size` (`size`, a violation).
    Size,
    /// A count limit is reached: signatures or pushes (`limit`).
    Limit,
    /// Over `max_ops_per_minute` (`rate`).
    Rate,
    /// The request itself is malformed, or the daemon can't decide (an internal fault): fail
    /// closed (`invalid`).
    Invalid,
}

impl DenyCode {
    /// Out-of-scope requests: these trigger the lease's `on_violation`. Running out of time or
    /// counts, a bad caller or a config change are not the agent overstepping its ticket.
    pub fn is_violation(self) -> bool {
        matches!(
            self,
            DenyCode::Operation
                | DenyCode::Repo
                | DenyCode::PushMode
                | DenyCode::ObjectType
                | DenyCode::Committer
                | DenyCode::TicketLink
                | DenyCode::Paths
                | DenyCode::Ref
                | DenyCode::ProtectedRef
                | DenyCode::ForcePush
                | DenyCode::Unsigned
                | DenyCode::PathsChanged
                | DenyCode::Size
        )
    }

    /// The code as the audit log writes it (`no_lease`, `protected_ref`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            DenyCode::NoLease => "no_lease",
            DenyCode::AmbiguousLease => "ambiguous_lease",
            DenyCode::NotActive => "not_active",
            DenyCode::Expired => "expired",
            DenyCode::Exhausted => "exhausted",
            DenyCode::Caller => "caller",
            DenyCode::Operation => "operation",
            DenyCode::Repo => "repo",
            DenyCode::Config => "config",
            DenyCode::PushMode => "push_mode",
            DenyCode::ObjectType => "object_type",
            DenyCode::ObjectFormat => "object_format",
            DenyCode::Committer => "committer",
            DenyCode::TicketLink => "ticket_link",
            DenyCode::Paths => "paths",
            DenyCode::Ref => "ref",
            DenyCode::ProtectedRef => "protected_ref",
            DenyCode::ForcePush => "force_push",
            DenyCode::Unsigned => "unsigned",
            DenyCode::PathsChanged => "paths_changed",
            DenyCode::Size => "size",
            DenyCode::Limit => "limit",
            DenyCode::Rate => "rate",
            DenyCode::Invalid => "invalid",
        }
    }
}

impl fmt::Display for DenyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A denied request: a code, a reason the agent can read, and a hint on what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub code: DenyCode,
    pub reason: String,
    pub hint: Option<String>,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)?;
        if let Some(hint) = &self.hint {
            write!(f, ". {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Denial {}

impl Denial {
    /// A denial without a hint.
    pub fn new(code: DenyCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            hint: None,
        }
    }

    /// The daemon failed inside: all the agent reads (the cause goes to the daemon's log).
    pub fn internal() -> Self {
        Self::new(DenyCode::Invalid, INTERNAL_ERROR)
    }
}

/// What the agent reads when the daemon failed inside.
pub const INTERNAL_ERROR: &str = "internal error in the daemon";

fn deny(code: DenyCode, reason: impl Into<String>) -> Denial {
    Denial::new(code, reason)
}

/// An out-of-scope denial, with the amendment hint.
fn outside(lease: &TicketId, code: DenyCode, what: impl fmt::Display) -> Denial {
    Denial {
        code,
        reason: format!("outside ticket {lease}: {what}"),
        hint: Some(format!(
            "If needed, submit an amendment (ticket.amends: {lease})"
        )),
    }
}

/// Whether the lease allows `operation`; outside it, an out-of-scope denial with the
/// amendment hint.
pub fn check_operation(lease: &Lease, operation: Operation) -> Result<(), Denial> {
    if lease.ticket.allows(operation) {
        Ok(())
    } else {
        Err(outside(
            &lease.id,
            DenyCode::Operation,
            format_args!("{operation} not allowed"),
        ))
    }
}

/// Whether the lease names `repo`; outside it, an out-of-scope denial with the amendment
/// hint.
pub fn check_repo(lease: &Lease, repo: &RepoName) -> Result<(), Denial> {
    if lease.ticket.scope.repos.contains(repo) {
        Ok(())
    } else {
        Err(outside(
            &lease.id,
            DenyCode::Repo,
            format_args!("repo {repo} not allowed"),
        ))
    }
}

/// An allowed request, possibly with warnings for the activity report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowed {
    pub warnings: Vec<String>,
}

/// What the session certificate of a request says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertIdentity {
    /// The certificate's key id: the lease id.
    pub key_id: String,
    pub serial: u64,
    /// Fingerprint of the certified session key.
    pub session_key: KeyFingerprint,
}

/// Finds the single lease a certificate stands for. None or more than one: denied. The
/// lease's state is not checked here (the decisions do, with a clearer reason).
pub fn resolve_lease<'a>(
    leases: impl IntoIterator<Item = &'a Lease>,
    cert: &CertIdentity,
) -> Result<&'a Lease, Denial> {
    let mut found = leases.into_iter().filter(|lease| {
        lease.id.as_str() == cert.key_id
            && lease.cert_serial == cert.serial
            && lease.ticket.subject.session_key == cert.session_key
    });
    match (found.next(), found.next()) {
        (Some(lease), None) => Ok(lease),
        (None, _) => Err(deny(DenyCode::NoLease, "no lease matches this certificate")),
        (Some(_), Some(_)) => Err(deny(
            DenyCode::AmbiguousLease,
            "more than one lease matches this certificate",
        )),
    }
}

/// Everything a decision needs besides the request.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub config: &'a PolicyConfig,
    pub lease: &'a Lease,
    pub usage: &'a Usage,
    pub caller: &'a CallerFacts,
    pub now: Timestamp,
}

/// The kind of git object a sign request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tag,
    Tree,
    Blob,
    /// Not a git object git signs (a push certificate, anything else).
    Other,
}

/// A commit-signing request, as parsed by the daemon from the object bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// The repo the commit is for. It picks the repo's rules (ticket link) and is recorded in
    /// the ledger; a push to another repo won't find the commit signed for it.
    pub repo: RepoName,
    pub object: ObjectKind,
    /// The commit's object format (from the length of its ids); `None` when it isn't a commit.
    pub object_format: Option<ObjectFormat>,
    /// The committer email from the commit object.
    pub committer_email: String,
    /// The values of every `Writ:` trailer in the commit message.
    pub writ_trailers: Vec<String>,
    /// Paths the commit changes relative to its parents, if the daemon could compute them.
    pub touched_paths: Option<Vec<String>>,
}

/// A push: ref updates read from receive-pack, new commits found in quarantine, with what the
/// ledger says about each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRequest {
    pub repo: RepoName,
    pub mode: PushMode,
    pub updates: Vec<RefUpdate>,
    /// Every commit the push brings that the daemon's mirror didn't have.
    pub commits: Vec<PushedCommit>,
    pub pack_size: u64,
}

/// One ref update. `None` is the zero id: `old: None` creates, `new: None` deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The ref name as sent by git, checked here.
    pub name: String,
    pub old: Option<CommitId>,
    pub new: Option<CommitId>,
    /// Whether `old` is an ancestor of `new` (computed by the daemon with git).
    pub fast_forward: bool,
    /// Whether the ref is new and another ref of the repo has the same name ignoring case
    /// (computed by the daemon with git): on a file system that folds case they would be one.
    pub case_twin: bool,
}

/// A new commit in a push, and the ledger entries for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedCommit {
    pub id: CommitId,
    pub signed_under: Vec<LedgerRef>,
    /// The digest of the paths it touches, computed again from the objects git verified in
    /// the push (`None`: they couldn't be computed).
    pub paths: Option<String>,
}

/// One ledger entry for a commit: signed under this lease, for this repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRef {
    pub lease: TicketId,
    pub repo: RepoName,
    /// The digest of the paths it touched as signing saw them (`None`: unknown then).
    pub paths: Option<String>,
}

/// A fetch from a repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub repo: RepoName,
}

/// The checks every operation starts with. Returns the template and the repo entry.
fn admit<'a>(
    ctx: &Context<'a>,
    operation: Operation,
    repo: &RepoName,
) -> Result<(&'a Template, &'a RepoEntry), Denial> {
    let lease = ctx.lease;
    let id = &lease.id;
    match lease.state {
        State::Active => {}
        State::Expired => return Err(deny(DenyCode::Expired, format!("lease {id} expired"))),
        State::Exhausted => {
            return Err(deny(DenyCode::Exhausted, format!("lease {id} is used up")));
        }
        other => return Err(deny(DenyCode::NotActive, format!("lease {id} is {other}"))),
    }
    if lease.ticket.is_expired(ctx.now) {
        return Err(deny(DenyCode::Expired, format!("lease {id} expired")));
    }
    if is_exhausted(&lease.ticket, ctx.usage) {
        return Err(deny(DenyCode::Exhausted, format!("lease {id} is used up")));
    }
    caller::check(lease.ticket.subject.caller.as_ref(), ctx.caller)
        .map_err(|e| deny(DenyCode::Caller, e.to_string()))?;
    check_operation(lease, operation)?;
    check_repo(lease, repo)?;
    let (Some(template), Some(entry)) = (
        ctx.config.template(&lease.ticket.template),
        ctx.config.repo(repo),
    ) else {
        return Err(deny(
            DenyCode::Config,
            format!("lease {id}: its template or repo {repo} is no longer configured"),
        ));
    };
    fit::fits(ctx.config, &lease.ticket).map_err(|why| {
        deny(
            DenyCode::Config,
            format!(
                "lease {id} no longer fits template {}: {why}",
                lease.ticket.template
            ),
        )
    })?;
    Ok((template, entry))
}

/// The rate check, last in every decision.
fn check_rate(ctx: &Context<'_>) -> Result<(), Denial> {
    let max = ctx.lease.ticket.limits.max_ops_per_minute;
    if ctx.usage.ops_last_minute >= max {
        Err(deny(
            DenyCode::Rate,
            format!(
                "lease {}: over {max} operations per minute, retry shortly",
                ctx.lease.id
            ),
        ))
    } else {
        Ok(())
    }
}

/// May the daemon sign this object under the lease?
pub fn decide_sign(ctx: &Context<'_>, request: &SignRequest) -> Result<Allowed, Denial> {
    let (template, entry) = admit(ctx, Operation::CommitSign, &request.repo)?;
    let lease = ctx.lease;
    let id = &lease.id;
    let mut allowed = Allowed::default();

    match request.object {
        ObjectKind::Commit => {}
        // Asking for a tag is a choice (a violation); anything else (a push certificate,
        // bytes that are no git object) is a malformed request.
        ObjectKind::Tag => {
            return Err(deny(
                DenyCode::ObjectType,
                "only commits are signed (no tags: releases stay a human act)",
            ));
        }
        ObjectKind::Tree | ObjectKind::Blob | ObjectKind::Other => {
            return Err(deny(
                DenyCode::Invalid,
                "only commits are signed: this is not a commit",
            ));
        }
    }
    if request.object_format != Some(entry.object_format) {
        let found = request
            .object_format
            .map_or("an unknown", ObjectFormat::as_str);
        return Err(deny(
            DenyCode::ObjectFormat,
            format!(
                "repo {} is {} (object_format in the registry), the commit is {found}",
                request.repo, entry.object_format
            ),
        ));
    }
    if lease.ticket.scope.signing_key.is_none() {
        return Err(deny(
            DenyCode::Config,
            format!("lease {id} has no signing key"),
        ));
    }
    let email_allowed = lease
        .ticket
        .scope
        .committer_emails
        .iter()
        .any(|e| e.as_str() == request.committer_email);
    if !email_allowed {
        return Err(outside(
            id,
            DenyCode::Committer,
            format_args!(
                "committer email {:?} not allowed",
                text::shown(&request.committer_email, VALUE_SHOWN)
            ),
        ));
    }
    if entry.ticket_link == TicketLink::Trailer {
        match request.writ_trailers.as_slice() {
            [one] if one == id.as_str() => {}
            [] => {
                return Err(deny(
                    DenyCode::TicketLink,
                    format!(
                        "repo {} needs a `Writ: {id}` trailer in the commit message",
                        request.repo
                    ),
                ));
            }
            _ => {
                return Err(deny(
                    DenyCode::TicketLink,
                    format!("the commit needs exactly one `Writ: {id}` trailer"),
                ));
            }
        }
    }
    check_paths(ctx, template, request, &mut allowed)?;
    if ctx.usage.signatures >= lease.ticket.limits.max_signatures {
        return Err(deny(
            DenyCode::Limit,
            format!(
                "lease {id}: all {} signatures used",
                lease.ticket.limits.max_signatures
            ),
        ));
    }
    check_rate(ctx)?;
    Ok(allowed)
}

fn check_paths(
    ctx: &Context<'_>,
    template: &Template,
    request: &SignRequest,
    allowed: &mut Allowed,
) -> Result<(), Denial> {
    let expected = &ctx.lease.ticket.text.expected_paths;
    if template.paths_check == PathsCheck::Off || expected.is_empty() {
        return Ok(());
    }
    let id = &ctx.lease.id;
    let set = PathSet::new(expected).map_err(|e| deny(DenyCode::Config, e.to_string()))?;
    let outside_paths: Vec<&str> = match &request.touched_paths {
        None => {
            return match template.paths_check {
                PathsCheck::Deny => Err(deny(
                    DenyCode::Paths,
                    "the commit's paths could not be checked against expected_paths",
                )),
                _ => {
                    allowed.warnings.push("paths not checked".to_owned());
                    Ok(())
                }
            };
        }
        Some(paths) => paths
            .iter()
            .map(String::as_str)
            .filter(|path| !set.matches(path))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    if outside_paths.is_empty() {
        return Ok(());
    }
    let listed = list_paths(&outside_paths);
    match template.paths_check {
        PathsCheck::Deny => Err(outside(
            id,
            DenyCode::Paths,
            format_args!("files outside expected_paths: {listed}"),
        )),
        _ => {
            allowed
                .warnings
                .push(format!("files outside expected_paths: {listed}"));
            Ok(())
        }
    }
}

fn list_paths(paths: &[&str]) -> String {
    let shown: Vec<String> = paths
        .iter()
        .take(PATHS_SHOWN)
        .map(|path| text::shown(path, VALUE_SHOWN))
        .collect();
    let mut text = shown.join(", ");
    if paths.len() > PATHS_SHOWN {
        text.push_str(&format!(
            " and {} more",
            paths.len().saturating_sub(PATHS_SHOWN)
        ));
    }
    text
}

/// May this push go upstream under the lease?
pub fn decide_push(ctx: &Context<'_>, request: &PushRequest) -> Result<Allowed, Denial> {
    let (template, entry) = admit(ctx, Operation::Push, &request.repo)?;
    let lease = ctx.lease;
    let id = &lease.id;
    let scope = &lease.ticket.scope;

    match request.mode {
        PushMode::Gateway | PushMode::Proxy => {}
        PushMode::DirectSsh => {
            return Err(deny(
                DenyCode::PushMode,
                "direct_ssh pushes don't go through the gateway",
            ));
        }
    }
    if !fit::push_modes(&entry.push_modes, template).contains(&request.mode) {
        return Err(outside(
            id,
            DenyCode::PushMode,
            format_args!(
                "push mode {} not allowed for repo {}",
                request.mode, request.repo
            ),
        ));
    }
    if request.updates.is_empty() {
        return Err(deny(DenyCode::Invalid, "the push updates no ref"));
    }
    let mut seen = BTreeSet::new();
    for update in &request.updates {
        let name: RefName = update
            .name
            .parse()
            .map_err(|e: crate::pattern::PatternError| deny(DenyCode::Invalid, e.to_string()))?;
        // Ignoring case: two refs that differ only in case are one on APFS.
        if !seen.insert(name.as_str().to_ascii_lowercase()) {
            return Err(deny(DenyCode::Invalid, format!("{name} is updated twice")));
        }
        if update.case_twin {
            return Err(deny(
                DenyCode::Invalid,
                format!("{name} differs only in case from a ref the repo has"),
            ));
        }
        if entry.protected_refs.iter().any(|p| p.protects(&name)) {
            return Err(deny(
                DenyCode::ProtectedRef,
                format!("{name} is protected in repo {}", request.repo),
            ));
        }
        if name.branch().is_none() {
            return Err(outside(
                id,
                DenyCode::Ref,
                format_args!("{name} is not a branch"),
            ));
        }
        if !scope.branches.iter().any(|b| b.matches_ref(&name)) {
            let branch = name.branch().unwrap_or(name.as_str());
            return Err(outside(
                id,
                DenyCode::Ref,
                format_args!("branch {branch} not allowed"),
            ));
        }
        match (&update.old, &update.new) {
            (None, None) => {
                return Err(deny(DenyCode::Invalid, format!("{name}: empty update")));
            }
            (Some(_), None) if !scope.force_push => {
                return Err(outside(
                    id,
                    DenyCode::ForcePush,
                    format_args!("deleting {name} needs force_push"),
                ));
            }
            (Some(_), Some(_)) if !update.fast_forward && !scope.force_push => {
                return Err(outside(
                    id,
                    DenyCode::ForcePush,
                    format_args!("force push to {name} not allowed"),
                ));
            }
            _ => {}
        }
    }
    for commit in &request.commits {
        let Some(entry) = commit
            .signed_under
            .iter()
            .find(|entry| &entry.lease == id && entry.repo == request.repo)
        else {
            return Err(outside(
                id,
                DenyCode::Unsigned,
                format_args!(
                    "commit {} was not signed under this lease for repo {}",
                    commit.id, request.repo
                ),
            ));
        };
        // The paths checked at signing came from objects the agent sent; the push brings the
        // objects git verified. Different paths mean different objects under the same ids.
        if let Some(signed) = &entry.paths
            && commit.paths.as_ref() != Some(signed)
        {
            return Err(outside(
                id,
                DenyCode::PathsChanged,
                format_args!(
                    "commit {}: the paths it touches are not the ones checked when it was signed",
                    commit.id
                ),
            ));
        }
    }
    let max_size = lease
        .ticket
        .limits
        .max_push_size
        .bytes()
        .min(template.max_push_size.bytes());
    if request.pack_size > max_size {
        return Err(outside(
            id,
            DenyCode::Size,
            format_args!("the push is {} bytes, over {max_size}", request.pack_size),
        ));
    }
    if ctx.usage.pushes >= lease.ticket.limits.max_pushes {
        return Err(deny(
            DenyCode::Limit,
            format!(
                "lease {id}: all {} pushes used",
                lease.ticket.limits.max_pushes
            ),
        ));
    }
    check_rate(ctx)?;
    Ok(Allowed::default())
}

/// May the agent fetch this repo under the lease?
pub fn decide_fetch(ctx: &Context<'_>, request: &FetchRequest) -> Result<Allowed, Denial> {
    admit(ctx, Operation::Fetch, &request.repo)?;
    check_rate(ctx)?;
    Ok(Allowed::default())
}
