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
    pub(crate) git_protocol: Option<String>,
    /// The connection it came on (the gateway's number for it).
    pub(crate) connection: u64,
}

pub(crate) async fn run(gateway: Gateway, request: LeaseRequest, channel: Channel<Msg>) {
    let LeaseRequest {
        cert,
        facts,
        command,
        git_protocol,
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
            run_git(&refusing, &command, repo, git_protocol, channel, connection).await;
        }
        LeaseCommand::Sign { repo } => {
            let (mut rx, tx) = channel.split();
            let request = sign::SignCommand {
                cert: &cert,
                facts: &facts,
                repo,
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

/// `git-upload-pack` or `git-receive-pack` on a repo of the lease.
async fn run_git(
    refusing: &Refusing<'_>,
    command: &LeaseCommand,
    repo: &RepoName,
    git_protocol: Option<String>,
    channel: Channel<Msg>,
    connection: u64,
) {
    let gateway = refusing.gateway;
    let lease = match command {
        // A fetch: the policy's decision and an operation of the rate window (the service
        // logs the outcome).
        LeaseCommand::UploadPack { .. } => {
            match gateway.fetch(refusing.cert, refusing.facts, repo).await {
                Ok(lease) => lease,
                Err(denial) => {
                    refuse(channel, denial.to_string()).await;
                    // A violation may have revoked the lease: its other sessions go now.
                    if gateway.service().is_revoked(refusing.cert.serial) {
                        gateway.drop_sessions_except(refusing.cert.serial, connection);
                    }
                    return;
                }
            }
        }
        // A push: the lease may have ended since the connection was authenticated, check it
        // again (only a refusal is logged: the push is decided whole, and logged once, at the
        // pre-receive hook).
        _ => match gateway.may_push(refusing.cert, refusing.facts, repo).await {
            Ok(lease) => lease,
            Err(denial) => {
                refuse(channel, denial.to_string()).await;
                if gateway.service().is_revoked(refusing.cert.serial) {
                    gateway.drop_sessions_except(refusing.cert.serial, connection);
                }
                return;
            }
        },
    };
    if !lease.ticket.scope.repos.contains(repo) {
        let reason = format!(
            "outside ticket {}: repo {repo} is not in the lease",
            lease.id
        );
        return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
    }
    let Some(path) = git::repo_path(gateway, repo) else {
        let reason = refusing
            .deny(format!("unknown repo {repo}"), Some(repo))
            .await;
        return refuse(channel, reason).await;
    };
    // A fetch serves what upstream has, and a push starts from it: the mirror is synced first
    // unless it is fresh. A sync that fails refuses the command (fail closed), with its reason.
    if let Err(e) = gateway.shared.config.mirrors.sync_if_stale(repo).await {
        let reason = format!("cannot sync from upstream: {e}");
        return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
    }
    let push = match command {
        LeaseCommand::ReceivePack { .. } => {
            let context = PushContext {
                cert: refusing.cert.clone(),
                repo: repo.clone(),
                caller: refusing.facts.clone(),
                connection,
                held: std::sync::Arc::new(std::sync::Mutex::new(None)),
                decided: std::sync::Arc::default(),
            };
            match git::Push::register(gateway, context) {
                Ok(push) => Some(push),
                Err(reason) => {
                    return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
                }
            }
        }
        _ => None,
    };
    // A push runs only with its hook in place: without it, git would take the push with no
    // check at all (fail closed, whatever happened to the hooks directory).
    if let Some(push) = &push
        && !push.hook_in_place()
    {
        tracing::error!("the pre-receive hook is missing: pushes are refused");
        let reason = "internal error: the push hook is missing".to_owned();
        return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
    }
    let cmd = match &push {
        Some(push) => push.receive_pack(
            &path,
            git_protocol,
            lease.ticket.limits.max_push_size.bytes(),
        ),
        None => git::upload_pack(&path, git_protocol),
    };
    match git::spawn(cmd) {
        Ok(child) => {
            let bridged = git::bridge(child, channel).await;
            // The client sent ref updates (more than the flush of a push with nothing to
            // send) and the hook never saw them: git refused the push before its checks. Its
            // reason went to the agent; the refusal goes to the audit log.
            if let Some(push) = &push
                && bridged.from_client > FLUSH_ONLY
                && !push.decided()
            {
                let reason = format!(
                    "the push ended before its checks (exit {}): git refused it (a pack too \
                     large, an object fsck refuses), or the client went away",
                    bridged.code
                );
                refusing.deny(reason, Some(repo)).await;
                // Whatever git did without a decision, the next fetch or push syncs the mirror
                // first: a ref upstream doesn't have is pruned.
                if let Ok(mut guard) = gateway.shared.config.mirrors.lock(repo).await {
                    guard.mark_stale();
                }
            }
        }
        Err(reason) => {
            tracing::error!(%reason, "cannot run git");
            refuse(channel, refusing.deny(reason, Some(repo)).await).await;
        }
    }
    // Dropping the push unregisters its token.
    drop(push);
}
