//! git `upload-pack` and `receive-pack` on the daemon's repositories, bridged to the SSH
//! channel. git runs through [`writ_mirror::git::command`]: a clean environment, no system or
//! global config, every object checked with the checks Writ relies on at error level.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use russh::Channel;
use russh::server::Msg;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use writ_core::names::RepoName;
use writ_mirror::git::Hooks;

use crate::Gateway;
use crate::channel::finish;
use crate::hook::PushContext;

/// The repo's bare repository, `<repos_root>/<name>.git`, if it exists.
pub(super) fn repo_path(gateway: &Gateway, repo: &RepoName) -> Option<PathBuf> {
    let path = gateway.shared.config.repos_root.join(format!("{repo}.git"));
    path.is_dir().then_some(path)
}

/// `git upload-pack` (fetch) on the repository at `path`.
pub(super) fn upload_pack(path: &Path, git_protocol: Option<String>) -> tokio::process::Command {
    let mut cmd = git(Hooks::None, git_protocol);
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
    /// which asks the daemon about the ref updates with this push's token. Every object is
    /// checked (`fsck`, with `.git`, `.` and `..` entries at error level: malformed objects
    /// and `.git` or `.gitmodules` tricks never land in a repository other leases fetch from),
    /// and the pack is refused past `max_bytes`.
    pub(super) fn receive_pack(
        &self,
        path: &Path,
        git_protocol: Option<String>,
        max_bytes: u64,
    ) -> tokio::process::Command {
        let shared = &self.gateway.shared;
        let mut cmd = git(Hooks::Dir(&shared.hooks_dir), git_protocol);
        cmd.arg("-c")
            .arg(format!("receive.maxInputSize={max_bytes}"))
            .arg("receive-pack")
            .arg(path)
            .env("WRIT_HOOK_SOCKET", &shared.hook_socket)
            .env("WRIT_HOOK_TOKEN", &self.token);
        cmd
    }
}

impl Drop for Push<'_> {
    fn drop(&mut self) {
        // Forgotten even from a poisoned table: a token must never outlive its push.
        self.gateway
            .shared
            .pushes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.token);
    }
}

/// The daemon's `git` ([`writ_mirror::git::command`]), with `GIT_PROTOCOL` if the client asked
/// for one (the only thing taken from the client's environment).
fn git(hooks: Hooks<'_>, git_protocol: Option<String>) -> tokio::process::Command {
    let mut cmd = writ_mirror::git::command(hooks);
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
        // The client hanging up mid-command does this: peer-caused, debug only.
        tracing::debug!(error = %e, "channel write failed");
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
