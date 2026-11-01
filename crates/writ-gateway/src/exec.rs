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
            run_git(&refusing, &command, repo, git_protocol, channel).await;
        }
        LeaseCommand::Sign { namespace, repo } => {
            let (mut rx, tx) = channel.split();
            let request = sign::SignCommand {
                cert: &cert,
                facts: &facts,
                namespace,
                repo,
            };
            match sign::sign(&gateway, request, &mut rx).await {
                Ok(signed) => {
                    let _ = tx.data_bytes(signed.signature.into_bytes()).await;
                    finish(&tx, 0).await;
                }
                // The service logged its decision.
                Err(sign::Refused::Denied(denial)) => fail(&tx, &denial.to_string()).await,
                Err(sign::Refused::Unreadable(reason)) => {
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
) {
    let gateway = refusing.gateway;
    // The lease may have ended since the connection was authenticated: check it again, with
    // the operation the command needs (the service logs the outcome).
    let lease = match gateway
        .authorize(refusing.cert, refusing.facts, Some(command.operation()))
        .await
    {
        Ok(lease) => lease,
        Err(denial) => return refuse(channel, denial.to_string()).await,
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
    let push = match command {
        LeaseCommand::ReceivePack { .. } => {
            let context = PushContext {
                cert: refusing.cert.clone(),
                repo: repo.clone(),
                caller: refusing.facts.clone(),
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
    let cmd = match &push {
        Some(push) => push.receive_pack(
            &path,
            git_protocol,
            lease.ticket.limits.max_push_size.bytes(),
        ),
        None => git::upload_pack(&path, git_protocol),
    };
    match git::spawn(cmd) {
        Ok(child) => git::bridge(child, channel).await,
        Err(reason) => {
            tracing::error!(%reason, "cannot run git");
            refuse(channel, refusing.deny(reason, Some(repo)).await).await;
        }
    }
    // Dropping the push unregisters its token.
    drop(push);
}
