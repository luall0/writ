//! git `upload-pack` and `receive-pack` on the daemon's repositories, bridged to the SSH
//! channel. git runs with a clean environment and without the daemon user's git config.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use russh::Channel;
use russh::server::Msg;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use writ_core::names::RepoName;

use crate::Gateway;
use crate::channel::finish;
use crate::hook::PushContext;

/// Environment variables git keeps from the daemon's; everything else is dropped.
const GIT_ENV_KEPT: [&str; 2] = ["PATH", "TMPDIR"];

/// The repo's bare repository, `<repos_root>/<name>.git`, if it exists.
pub(super) fn repo_path(gateway: &Gateway, repo: &RepoName) -> Option<PathBuf> {
    let path = gateway.shared.config.repos_root.join(format!("{repo}.git"));
    path.is_dir().then_some(path)
}

/// `git upload-pack` (fetch) on the repository at `path`.
pub(super) fn upload_pack(path: &Path, git_protocol: Option<String>) -> tokio::process::Command {
    let mut cmd = git(git_protocol);
    cmd.arg("upload-pack").arg("--strict").arg(path);
    cmd
}

/// A push in progress: its token is known to the hook server until this is dropped.
pub(super) struct Push<'a> {
    gateway: &'a Gateway,
    token: String,
}

impl<'a> Push<'a> {
    /// Registers the push under a new random token.
    pub(super) fn register(gateway: &'a Gateway, context: PushContext) -> Result<Self, String> {
        let token = writ_crypto::keys::random_hex(16)
            .map_err(|_| "internal error: no randomness".to_owned())?;
        gateway
            .shared
            .pushes
            .lock()
            .map_err(|_| "internal error: the push table is poisoned".to_owned())?
            .insert(token.clone(), context);
        Ok(Self { gateway, token })
    }

    /// `git receive-pack` on the repository at `path`, with the gateway's pre-receive hook,
    /// which asks the daemon about the ref updates with this push's token.
    pub(super) fn receive_pack(
        &self,
        path: &Path,
        git_protocol: Option<String>,
    ) -> tokio::process::Command {
        let shared = &self.gateway.shared;
        let mut cmd = git(git_protocol);
        cmd.arg("-c")
            .arg(format!("core.hooksPath={}", shared.hooks_dir.display()))
            .arg("receive-pack")
            .arg(path)
            .env("WRIT_HOOK_SOCKET", &shared.hook_socket)
            .env("WRIT_HOOK_TOKEN", &self.token);
        cmd
    }
}

impl Drop for Push<'_> {
    fn drop(&mut self) {
        if let Ok(mut pushes) = self.gateway.shared.pushes.lock() {
            pushes.remove(&self.token);
        }
    }
}

/// A `git` with a clean environment: only [`GIT_ENV_KEPT`], no system or global config (the
/// daemon user's git config must not change what the gateway runs), no prompt, and
/// `GIT_PROTOCOL` if the client asked for one.
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

/// Starts git with its stdin, stdout and stderr piped.
pub(super) fn spawn(mut cmd: tokio::process::Command) -> Result<Child, String> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn()
        .map_err(|e| format!("internal error: cannot start git: {}", e.kind()))
}

/// Connects a process's stdin, stdout and stderr to the channel, then reports its exit code.
pub(super) async fn bridge(mut child: Child, channel: Channel<Msg>) {
    let (mut rx, tx) = channel.split();
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
