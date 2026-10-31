//! Running a lease holder's command (`git-upload-pack`, `git-receive-pack`, `writ-sign`):
//! the lease checked again for the operation, the repo checked against the lease, then
//! [`git`] or [`sign`]. Every refusal made here is logged before the agent is told.

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

pub(crate) async fn run(
    gateway: Gateway,
    cert: CertIdentity,
    facts: CallerFacts,
    command: LeaseCommand,
    git_protocol: Option<String>,
    channel: Channel<Msg>,
) {
    // The lease may have ended since the connection was authenticated: check it again, with
    // the operation the command needs (the service logs the outcome).
    let lease = match gateway
        .authorize(&cert, &facts, Some(command.operation()))
        .await
    {
        Ok(lease) => lease,
        Err(denial) => return refuse(channel, denial.to_string()).await,
    };
    let refusing = Refusing {
        gateway: &gateway,
        cert: &cert,
        facts: &facts,
        command: &command,
    };
    match &command {
        LeaseCommand::UploadPack { repo } | LeaseCommand::ReceivePack { repo } => {
            if !lease.ticket.scope.repos.contains(repo) {
                let reason = format!(
                    "outside ticket {}: repo {repo} is not in the lease",
                    lease.id
                );
                return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
            }
            let Some(path) = git::repo_path(&gateway, repo) else {
                let reason = refusing
                    .deny(format!("unknown repo {repo}"), Some(repo))
                    .await;
                return refuse(channel, reason).await;
            };
            let push = match &command {
                LeaseCommand::ReceivePack { .. } => {
                    let context = PushContext {
                        cert: cert.clone(),
                        repo: repo.clone(),
                        caller: facts.clone(),
                    };
                    match git::Push::register(&gateway, context) {
                        Ok(push) => Some(push),
                        Err(reason) => {
                            return refuse(channel, refusing.deny(reason, Some(repo)).await).await;
                        }
                    }
                }
                _ => None,
            };
            let cmd = match &push {
                Some(push) => push.receive_pack(&path, git_protocol),
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
        LeaseCommand::Sign { namespace } => {
            let (mut rx, tx) = channel.split();
            match sign::sign(&gateway, namespace, &mut rx).await {
                Ok(armored) => {
                    let _ = tx.data_bytes(armored.into_bytes()).await;
                    finish(&tx, 0).await;
                }
                Err(reason) => fail(&tx, &refusing.deny(reason, None).await).await,
            }
        }
    }
}
