//! Running an accepted command over an SSH channel.

use std::process::Stdio;
use std::sync::Arc;

use russh::Channel;
use russh::server::Msg;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use writ_approval::{EventKind, GatewayDenial, Service};
use writ_core::caller::CallerFacts;
use writ_core::config::Operation;
use writ_core::names::RepoName;
use writ_crypto::sshsig;
use writ_proto::{ApiError, MAX_BODY};

use crate::handler::Identity;
use crate::hook::PushContext;
use crate::{Command, Gateway};

/// Largest object accepted for signing.
const MAX_SIGN_INPUT: u64 = 16 * 1024 * 1024;

pub(crate) async fn run(
    gateway: Gateway,
    identity: Identity,
    facts: CallerFacts,
    command: Command,
    git_protocol: Option<String>,
    channel: Channel<Msg>,
) {
    let (operation, kind) = match &command {
        Command::Writ(writ) => {
            return run_writ(gateway, identity, facts, writ.clone(), channel).await;
        }
        Command::UploadPack { .. } => (Operation::Fetch, EventKind::Fetch),
        Command::ReceivePack { .. } => (Operation::Push, EventKind::Push),
        Command::Sign { .. } => (Operation::CommitSign, EventKind::Sign),
    };
    let Identity::Lease(cert) = identity else {
        // The handler only lets lease holders run git and sign commands.
        let denial = GatewayDenial::new(EventKind::Command, "command not allowed here");
        gateway.log_denial(denial, facts).await;
        return refuse(channel, "command not allowed here".into()).await;
    };
    // The lease may have ended since the connection was authenticated: check it again, with
    // the operation the command needs (the service logs the outcome).
    let lease = match gateway.authorize(&cert, &facts, Some(operation)).await {
        Ok(lease) => lease,
        Err(denial) => return refuse(channel, denial.to_string()).await,
    };
    // Denied here, by the gateway: logged, then the agent is told why.
    let deny = |reason: String, repo: Option<&RepoName>| {
        let mut denial = GatewayDenial::new(kind, reason.clone()).cert(&cert);
        if let Some(repo) = repo {
            denial = denial.repo(repo);
        }
        let (gateway, facts) = (gateway.clone(), facts.clone());
        async move {
            gateway.log_denial(denial, facts).await;
            reason
        }
    };
    match command {
        Command::UploadPack { repo } | Command::ReceivePack { repo }
            if !lease.ticket.scope.repos.contains(&repo) =>
        {
            let reason = format!(
                "outside ticket {}: repo {repo} is not in the lease",
                lease.id
            );
            refuse(channel, deny(reason, Some(&repo)).await).await;
        }
        Command::UploadPack { repo } => {
            let Some(path) = repo_path(&gateway, &repo) else {
                let reason = deny(format!("unknown repo {repo}"), Some(&repo)).await;
                return refuse(channel, reason).await;
            };
            let mut cmd = git(git_protocol);
            cmd.arg("upload-pack").arg("--strict").arg(path);
            bridge(cmd, channel).await;
        }
        Command::ReceivePack { repo } => {
            let Some(path) = repo_path(&gateway, &repo) else {
                let reason = deny(format!("unknown repo {repo}"), Some(&repo)).await;
                return refuse(channel, reason).await;
            };
            let Ok(token) = writ_crypto::keys::random_hex(16) else {
                let reason = deny("internal error: no randomness".into(), Some(&repo)).await;
                return refuse(channel, reason).await;
            };
            let context = PushContext {
                cert: cert.clone(),
                repo: repo.clone(),
                caller: facts.clone(),
            };
            let registered = match gateway.shared.pushes.lock() {
                Ok(mut pushes) => {
                    pushes.insert(token.clone(), context);
                    true
                }
                Err(_) => false,
            };
            if !registered {
                let reason = deny(
                    "internal error: the push table is poisoned".into(),
                    Some(&repo),
                );
                return refuse(channel, reason.await).await;
            }
            let mut cmd = git(git_protocol);
            cmd.arg("-c")
                .arg(format!(
                    "core.hooksPath={}",
                    gateway.shared.hooks_dir.display()
                ))
                .arg("receive-pack")
                .arg(path)
                .env("WRIT_HOOK_SOCKET", &gateway.shared.hook_socket)
                .env("WRIT_HOOK_TOKEN", &token);
            bridge(cmd, channel).await;
            if let Ok(mut pushes) = gateway.shared.pushes.lock() {
                pushes.remove(&token);
            }
        }
        Command::Sign { namespace } => {
            if let Err(reason) = sign(&gateway, &namespace, channel).await {
                deny(reason, None).await;
            }
        }
        Command::Writ(_) => {}
    }
}

/// Runs a lease or approval command: a JSON reply on stdout, the reason on stderr if it
/// failed, exit status 0 or 1.
async fn run_writ(
    gateway: Gateway,
    identity: Identity,
    facts: CallerFacts,
    command: writ_proto::Command,
    channel: Channel<Msg>,
) {
    use writ_proto::Command as W;
    let (mut rx, tx) = channel.split();
    let service = gateway.service().clone();
    let result = match (command, identity) {
        (W::Request, Identity::SessionKey(key)) => match read_body(&mut rx).await {
            Ok(body) => encoded(blocking(move || service.submit(&key, &body, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        (W::Wait { id }, Identity::SessionKey(key)) => encoded(service.wait(&id, &key).await),
        (approval, Identity::Approver) if approval.is_approval() => {
            let body = if approval_has_body(&approval) {
                match read_body(&mut rx).await {
                    Ok(body) => body,
                    Err(e) => return reply(tx, encoded::<()>(Err(e))).await,
                }
            } else {
                Vec::new()
            };
            approval_reply(service, facts, approval, body).await
        }
        _ => encoded::<()>(Err(ApiError::new("command not allowed here"))),
    };
    reply(tx, result).await;
}

/// Writes a reply on the channel: stdout, the reason on stderr, the exit status.
async fn reply(tx: russh::ChannelWriteHalf<Msg>, (stdout, failure): (Vec<u8>, Option<String>)) {
    let _ = tx.data_bytes(stdout).await;
    let code = match failure {
        Some(reason) => {
            let _ = tx
                .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
                .await;
            1
        }
        None => 0,
    };
    finish(&tx, code).await;
}

/// Whether an approval command reads a JSON body.
pub(crate) fn approval_has_body(command: &writ_proto::Command) -> bool {
    use writ_proto::Command as W;
    matches!(
        command,
        W::Approve { .. } | W::Refuse { .. } | W::Revoke { .. }
    )
}

/// Runs an approval command, the same over SSH and HTTPS: the reply bytes, and the failure
/// to report. `body` is the command's JSON body (empty when it has none).
pub(crate) async fn approval_reply(
    service: Arc<Service>,
    facts: CallerFacts,
    command: writ_proto::Command,
    body: Vec<u8>,
) -> (Vec<u8>, Option<String>) {
    use writ_proto::Command as W;
    let empty = body.iter().all(u8::is_ascii_whitespace);
    match command {
        W::Info => encoded(Ok(service.info())),
        W::List { all } => encoded(blocking(move || service.list(all)).await),
        W::Show { id } => encoded(blocking(move || service.show(&id)).await),
        W::Approve { id } => match writ_proto::decode_body(&body) {
            Ok(request) => encoded(blocking(move || service.approve(&id, &request, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        W::Refuse { id } => match writ_proto::decode_body(&body) {
            Ok(request) => encoded(blocking(move || service.refuse(&id, &request, &facts)).await),
            Err(e) => encoded::<()>(Err(e)),
        },
        W::Revoke { id } => {
            let request = if empty {
                Ok(writ_proto::RevokeRequest::default())
            } else {
                writ_proto::decode_body(&body)
            };
            match request {
                Ok(request) => {
                    encoded(blocking(move || service.revoke(&id, &request, &facts)).await)
                }
                Err(e) => encoded::<()>(Err(e)),
            }
        }
        W::Request | W::Wait { .. } => {
            encoded::<()>(Err(ApiError::new("command not allowed here")))
        }
    }
}

/// The reply bytes, and the failure to show on stderr.
pub(crate) fn encoded<T: Serialize>(result: Result<T, ApiError>) -> (Vec<u8>, Option<String>) {
    let failure = result.as_ref().err().map(ToString::to_string);
    (writ_proto::encode_reply(&result), failure)
}

/// Runs a service call (SQLite, fsync) off the async threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(ApiError::new("internal error in the daemon")))
}

/// Reads the command's body (stdin, until EOF), at most [`MAX_BODY`] bytes.
async fn read_body(rx: &mut russh::ChannelReadHalf) -> Result<Vec<u8>, ApiError> {
    let mut body = Vec::new();
    let limit = u64::try_from(MAX_BODY).unwrap_or(u64::MAX);
    rx.make_reader()
        .take(limit + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|e| ApiError::new(format!("cannot read the request: {e}")))?;
    if body.len() > MAX_BODY {
        return Err(ApiError::new(format!(
            "the request is larger than {MAX_BODY} bytes"
        )));
    }
    Ok(body)
}

/// Fails the command with a reason the agent sees on stderr.
pub(crate) async fn refuse(channel: Channel<Msg>, reason: String) {
    let (_, tx) = channel.split();
    let _ = tx
        .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
        .await;
    finish(&tx, 1).await;
}

/// The repo's bare repository: `<repos_root>/<name>.git`.
fn repo_path(gateway: &Gateway, repo: &RepoName) -> Option<std::path::PathBuf> {
    let path = gateway.shared.config.repos_root.join(format!("{repo}.git"));
    path.is_dir().then_some(path)
}

/// Environment variables git keeps from the daemon's; everything else is dropped.
const GIT_ENV_KEPT: [&str; 2] = ["PATH", "TMPDIR"];

/// A `git` with a clean environment: only [`GIT_ENV_KEPT`], no system or global config (the
/// daemon user's git config must not change what the gateway runs), and `GIT_PROTOCOL` if the
/// client asked for one.
fn git(git_protocol: Option<String>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.env_clear();
    for name in GIT_ENV_KEPT {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(protocol) = git_protocol {
        cmd.env("GIT_PROTOCOL", protocol);
    }
    cmd
}

/// Connects a process's stdin, stdout and stderr to the channel, then reports its exit code.
async fn bridge(mut cmd: tokio::process::Command, channel: Channel<Msg>) {
    let (mut rx, tx) = channel.split();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("writ gateway: cannot start git: {e}");
            let _ = tx
                .extended_data_bytes(1, b"writ: internal error\n".to_vec())
                .await;
            return finish(&tx, 1).await;
        }
    };
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdin_task = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            let mut reader = rx.make_reader();
            let _ = tokio::io::copy(&mut reader, &mut stdin).await;
            let _ = stdin.shutdown().await;
        }
    });
    let out = async {
        if let Some(mut stdout) = stdout {
            let mut writer = tx.make_writer();
            tokio::io::copy(&mut stdout, &mut writer).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let err = async {
        if let Some(mut stderr) = stderr {
            let mut writer = tx.make_writer_ext(Some(1));
            tokio::io::copy(&mut stderr, &mut writer).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let (out, err) = tokio::join!(out, err);
    if let Err(e) = out.and(err) {
        eprintln!("writ gateway: channel write failed: {e}");
    }
    let code = match child.wait().await {
        Ok(status) => status
            .code()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(1),
        Err(_) => 1,
    };
    stdin_task.abort();
    finish(&tx, code).await;
}

/// Reads the object to sign from stdin and writes the armored SSHSIG to stdout. A refusal is
/// returned (for the audit log) after the agent has been told.
async fn sign(gateway: &Gateway, namespace: &str, channel: Channel<Msg>) -> Result<(), String> {
    let (mut rx, tx) = channel.split();
    let mut object = Vec::new();
    let read = rx
        .make_reader()
        .take(MAX_SIGN_INPUT + 1)
        .read_to_end(&mut object)
        .await;
    let result = match read {
        Ok(_) if object.len() as u64 > MAX_SIGN_INPUT => Err("object too large to sign".to_owned()),
        Ok(_) => sshsig::sign(&gateway.shared.config.signing_key, namespace, &object)
            .map_err(|e| e.to_string()),
        Err(e) => Err(format!("cannot read the object: {e}")),
    };
    match result {
        Ok(armored) => {
            let _ = tx.data_bytes(armored.into_bytes()).await;
            finish(&tx, 0).await;
            Ok(())
        }
        Err(reason) => {
            let _ = tx
                .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
                .await;
            finish(&tx, 1).await;
            Err(reason)
        }
    }
}

async fn finish(tx: &russh::ChannelWriteHalf<Msg>, code: u32) {
    let _ = tx.exit_status(code).await;
    let _ = tx.eof().await;
    let _ = tx.close().await;
}
