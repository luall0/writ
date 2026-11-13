//! Running a lease holder's command (`git-upload-pack`, `git-receive-pack`, `writ-sign`):
//! for git, the lease checked again for the operation and the repo against the lease, then
//! [`git`]; for signing, [`sign`], where the approval service makes every check and logs the
//! outcome once. Every refusal made here is logged before the agent is told.

mod git;
mod sign;

use russh::Channel;
use russh::server::Msg;
use writ_approval::GatewayDenial;
use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::names::RepoName;
use writ_core::policy::CertIdentity;

use crate::Gateway;
use crate::channel::{fail, finish, refuse};
use crate::command::LeaseCommand;
use crate::hook::PushContext;

/// What a client sends `receive-pack` when it has nothing to push: one flush packet.
const FLUSH_ONLY: u64 = 4;

/// What [`run`] needs to log a refusal it makes itself.
struct Refusing<'a> {
    gateway: &'a Gateway,
    cert: &'a CertIdentity,
    facts: &'a CallerFacts,
    command: &'a LeaseCommand,
}

impl Refusing<'_> {
    /// Logs the refusal (the command's event, denied), then returns the reason for the agent.
    async fn deny(&self, reason: String, repo: Option<&RepoName>) -> String {
        let mut denial = GatewayDenial::new(self.command.event(), reason.clone()).cert(self.cert);
        if let Some(repo) = repo {
            denial = denial.repo(repo);
        }
        self.gateway.log_denial(denial, self.facts.clone()).await;
        reason
    }
}

/// A lease holder's command, with who sent it.
pub(crate) struct LeaseRequest {
    pub(crate) cert: CertIdentity,
    pub(crate) facts: CallerFacts,
    pub(crate) command: LeaseCommand,
    /// The connection it came on (the gateway's number for it).
    pub(crate) connection: u64,
}

pub(crate) async fn run(gateway: Gateway, request: LeaseRequest, channel: Channel<Msg>) {
    let LeaseRequest {
        cert,
        facts,
        command,
        connection,
    } = request;
    let refusing = Refusing {
        gateway: &gateway,
        cert: &cert,
        facts: &facts,
        command: &command,
    };
    match &command {
        LeaseCommand::UploadPack { repo } | LeaseCommand::ReceivePack { repo } => {
            run_git(&refusing, &command, repo, channel, connection).await;
        }
        LeaseCommand::Sign { repo, format } => {
            let (mut rx, tx) = channel.split();
            let request = sign::SignCommand {
                cert: &cert,
                facts: &facts,
                repo,
                format: *format,
            };
            match sign::sign(&gateway, request, &mut rx).await {
                Ok(signed) => {
                    let _ = tx.data_bytes(signed.signature.into_bytes()).await;
                    finish(&tx, 0).await;
                }
                // The service logged its decision.
                Err(sign::Refused::Denied(denial)) => fail(&tx, &denial.to_string()).await,
                Err(sign::Refused::Gateway(reason)) => {
                    fail(&tx, &refusing.deny(reason, Some(repo)).await).await;
                }
            }
            // A violation may have revoked the lease: its other sessions are dropped now,
            // and this one ends once the agent has read why (anything more it asks is
            // refused by the deny list meanwhile).
            if gateway.service().is_revoked(cert.serial) {
                gateway.drop_sessions_except(cert.serial, connection);
            }
        }
    }
}

/// `git-upload-pack` or `git-receive-pack` on a repo of the lease: authorized, prepared, run.
async fn run_git(
    refusing: &Refusing<'_>,
    command: &LeaseCommand,
    repo: &RepoName,
    channel: Channel<Msg>,
    connection: u64,
) {
    let ready = match authorize(refusing, command, repo, connection).await {
        Ok(lease) => prepare(refusing, command, repo, connection)
            .await
            .map(|prepared| (lease, prepared)),
        Err(refusal) => Err(refusal),
    };
    match ready {
        Ok((lease, prepared)) => {
            // The smaller of the lease's and the template's in force, as the hook decides it;
            // never 0, which git reads as no limit (refused at load and at submission).
            let policy = refusing.gateway.service().policy();
            let max_push_size = lease
                .ticket
                .terms(repo)
                .and_then(|terms| {
                    policy
                        .template(&terms.template)
                        .map(|template| writ_core::policy::max_push_size(terms, template))
                })
                .filter(|max| *max > 0);
            match max_push_size {
                Some(max) => run_prepared(refusing, repo, max, prepared, channel).await,
                None => {
                    let reason = format!(
                        "lease {}: repo {repo}'s template is no longer configured",
                        lease.id
                    );
                    let reason = refusing.deny(reason, Some(repo)).await;
                    refuse(channel, reason).await;
                }
            }
        }
        Err(refusal) => {
            let reason = match refusal {
                Refusal::Logged(reason) => reason,
                Refusal::Unlogged(reason) => refusing.deny(reason, Some(repo)).await,
            };
            refuse(channel, reason).await;
        }
    }
}

/// Why a git command is refused before git runs, for the agent: logged already (a lease
/// decision the service logged), or to log now.
enum Refusal {
    Logged(String),
    Unlogged(String),
}

/// The lease, checked for the command: a fetch is the policy's decision and an operation of
/// the rate window (the service logs the outcome); a push is checked again for its operation
/// (only a refusal is logged: the push is decided whole, and logged once, at the pre-receive
/// hook). A violation may have revoked the lease: its other sessions go now. Then the repo
/// must be the lease's.
async fn authorize(
    refusing: &Refusing<'_>,
    command: &LeaseCommand,
    repo: &RepoName,
    connection: u64,
) -> Result<Lease, Refusal> {
    let gateway = refusing.gateway;
    let decided = match command {
        LeaseCommand::UploadPack { .. } => gateway.fetch(refusing.cert, refusing.facts, repo).await,
        _ => gateway.may_push(refusing.cert, refusing.facts, repo).await,
    };
    let lease = decided.map_err(|denial| {
        if gateway.service().is_revoked(refusing.cert.serial) {
            gateway.drop_sessions_except(refusing.cert.serial, connection);
        }
        Refusal::Logged(denial.to_string())
    })?;
    if !lease.ticket.repos.contains_key(repo) {
        return Err(Refusal::Unlogged(format!(
            "outside ticket {}: repo {repo} is not in the lease",
            lease.id
        )));
    }
    Ok(lease)
}

/// What git runs on: the repo's mirror, and for a push its registration.
struct Prepared<'a> {
    path: std::path::PathBuf,
    push: Option<git::Push<'a>>,
}

/// The mirror, synced first unless it is fresh (a fetch serves what upstream has, and a push
/// starts from it; a sync that fails refuses the command with its reason, fail closed); a
/// push registered, and refused without its hook in place (git would take it with no check
/// at all).
async fn prepare<'a>(
    refusing: &Refusing<'a>,
    command: &LeaseCommand,
    repo: &RepoName,
    connection: u64,
) -> Result<Prepared<'a>, Refusal> {
    let gateway = refusing.gateway;
    let path = git::repo_path(gateway, repo)
        .ok_or_else(|| Refusal::Unlogged(format!("unknown repo {repo}")))?;
    let mirrors = gateway.mirrors().map_err(Refusal::Unlogged)?;
    if let Err(e) = mirrors.sync_if_stale(repo).await {
        // The whole error in the audit line (and the log); no upstream URL, host or proxy for
        // the agent (the review after M7.6, M-5).
        tracing::debug!(repo = %repo, error = %e, "cannot sync from upstream");
        refusing
            .deny(format!("cannot sync from upstream: {e}"), Some(repo))
            .await;
        return Err(Refusal::Logged(format!(
            "cannot sync from upstream: {}",
            e.for_agent()
        )));
    }
    let LeaseCommand::ReceivePack { .. } = command else {
        return Ok(Prepared { path, push: None });
    };
    let context = PushContext {
        cert: refusing.cert.clone(),
        repo: repo.clone(),
        caller: refusing.facts.clone(),
        connection,
        held: std::sync::Arc::new(std::sync::Mutex::new(None)),
        decided: std::sync::Arc::default(),
    };
    let push = git::Push::register(gateway, context).map_err(Refusal::Unlogged)?;
    if !push.hook_in_place() {
        tracing::error!("the pre-receive hook is missing or not executable: pushes are refused");
        return Err(Refusal::Unlogged(
            "internal error: the push hook is missing or can't be run".to_owned(),
        ));
    }
    Ok(Prepared {
        path,
        push: Some(push),
    })
}

/// Runs git bridged to the channel. A push's mirror is released when git exits; a push git
/// refused before its hook ran is logged, and the mirror marked stale.
async fn run_prepared(
    refusing: &Refusing<'_>,
    repo: &RepoName,
    max_push_size: u64,
    prepared: Prepared<'_>,
    channel: Channel<Msg>,
) {
    let gateway = refusing.gateway;
    let Prepared { path, push } = prepared;
    let cmd = match &push {
        Some(push) => push.receive_pack(&path, max_push_size),
        None => git::upload_pack(gateway, &path),
    };
    let child = match git::spawn(cmd) {
        Ok(child) => child,
        Err(reason) => {
            tracing::error!(%reason, "cannot run git");
            return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
        }
    };
    let bound = match &push {
        Some(_) => git::InputBound::Push {
            max_pack: max_push_size,
        },
        None => git::InputBound::Fetch,
    };
    let bridged = git::bridge(child, channel, bound, || {
        if let Some(push) = &push {
            push.release_mirror();
        }
    })
    .await;
    // Stopped by the gateway (over its bound, or its deadline): the reason went to the agent,
    // and to the audit log, unless the hook decided the push and logged it already.
    if let Some(reason) = &bridged.stopped
        && push.as_ref().is_none_or(|push| !push.decided())
    {
        refusing.deny(reason.clone(), Some(repo)).await;
    }
    // The client sent ref updates (more than the flush of a push with nothing to send) and
    // the hook never saw them: git refused the push before its checks. Its reason went to the
    // agent; the refusal goes to the audit log.
    if let Some(push) = &push
        && bridged.from_client > FLUSH_ONLY
        && !push.decided()
    {
        if bridged.stopped.is_none() {
            let reason = format!(
                "the push ended before its checks (exit {}): git refused it (a pack too large, \
                 an object fsck refuses), or the client went away",
                bridged.code
            );
            refusing.deny(reason, Some(repo)).await;
        }
        // Whatever git did without a decision, the next fetch or push syncs the mirror first:
        // a ref upstream doesn't have is pruned. A mirror busy past its deadline is synced
        // anyway once `fresh_for` has passed.
        if let Ok(mirrors) = gateway.mirrors() {
            match mirrors.lock(repo).await {
                Ok(mut guard) => guard.mark_stale(),
                Err(e) => tracing::warn!(%repo, error = %e, "cannot mark the mirror stale"),
            }
        }
    }
    // Dropping the push unregisters its token.
    drop(push);
}
