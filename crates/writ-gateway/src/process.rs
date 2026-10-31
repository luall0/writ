//! Running an accepted command over an SSH channel.

use std::process::Stdio;

use russh::Channel;
use russh::server::Msg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use writ_crypto::sshsig;

use crate::handler::Identity;
use crate::hook::PushContext;
use crate::{Command, Gateway};

/// Largest object accepted for signing.
const MAX_SIGN_INPUT: u64 = 16 * 1024 * 1024;

pub(crate) async fn run(
    gateway: Gateway,
    identity: Identity,
    command: Command,
    git_protocol: Option<String>,
    channel: Channel<Msg>,
) {
    match command {
        Command::UploadPack { repo } => {
            let Some(path) = repo_path(&gateway, &repo) else {
                return refuse(channel, format!("unknown repo {repo}")).await;
            };
            let mut cmd = git(git_protocol);
            cmd.arg("upload-pack").arg("--strict").arg(path);
            bridge(cmd, channel).await;
        }
        Command::ReceivePack { repo } => {
            let Some(path) = repo_path(&gateway, &repo) else {
                return refuse(channel, format!("unknown repo {repo}")).await;
            };
            let token = writ_crypto::keys::random_hex(16);
            let context = PushContext {
                lease: identity.lease.clone(),
                repo: repo.clone(),
            };
            let registered = match gateway.shared.pushes.lock() {
                Ok(mut pushes) => {
                    pushes.insert(token.clone(), context);
                    true
                }
                Err(_) => false,
            };
            if !registered {
                return refuse(channel, "internal error".into()).await;
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
        Command::Sign { namespace } => sign(&gateway, &namespace, channel).await,
    }
}

/// Fails the command with a reason the agent sees on stderr.
pub(crate) async fn refuse(channel: Channel<Msg>, reason: String) {
    let (_, tx) = channel.split();
    let _ = tx
        .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
        .await;
    finish(&tx, 1).await;
}

fn repo_path(gateway: &Gateway, repo: &str) -> Option<std::path::PathBuf> {
    let path = gateway.shared.config.repos_root.join(repo);
    path.is_dir().then_some(path)
}

fn git(git_protocol: Option<String>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
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

/// Reads the object to sign from stdin and writes the armored SSHSIG to stdout.
async fn sign(gateway: &Gateway, namespace: &str, channel: Channel<Msg>) {
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
        }
        Err(reason) => {
            let _ = tx
                .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
                .await;
            finish(&tx, 1).await;
        }
    }
}

async fn finish(tx: &russh::ChannelWriteHalf<Msg>, code: u32) {
    let _ = tx.exit_status(code).await;
    let _ = tx.eof().await;
    let _ = tx.close().await;
}
