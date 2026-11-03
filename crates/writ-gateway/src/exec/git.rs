//! git `upload-pack` and `receive-pack` on the daemon's repositories, bridged to the SSH
//! channel. git runs through [`writ_mirror::git::command`]: a clean environment, no system or
//! global config, every object checked with the checks Writ relies on at error level.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use russh::Channel;
use russh::server::Msg;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;
use writ_core::names::RepoName;
use writ_mirror::git::Hooks;

use crate::Gateway;
use crate::channel::finish;
use crate::hook::PushContext;

/// The repo's mirror, if the repo is registered.
pub(super) fn repo_path(gateway: &Gateway, repo: &RepoName) -> Option<PathBuf> {
    gateway.mirrors().ok()?.path(repo).map(Path::to_path_buf)
}

/// `git upload-pack` (fetch) on the repository at `path`, in protocol v0 whatever the client
/// asked for ([`writ_mirror::git::upload_pack`]).
pub(super) fn upload_pack(gateway: &Gateway, path: &Path) -> tokio::process::Command {
    writ_mirror::git::upload_pack(&git_program(gateway), path)
}

/// A push in progress: its token is known to the hook server until this is dropped (or a
/// revocation forgets it). The push keeps its own handles on what the hook sets, so a token
/// forgotten meanwhile changes neither what was decided nor which mirror to release (the
/// review after M5.5: a revocation mid-push wrote a spurious "ended before its checks").
pub(super) struct Push<'a> {
    gateway: &'a Gateway,
    token: String,
    decided: std::sync::Arc<std::sync::atomic::AtomicBool>,
    held: std::sync::Arc<std::sync::Mutex<Option<writ_mirror::MirrorGuard>>>,
}

impl<'a> Push<'a> {
    /// Whether the pre-receive hook took the push to a decision (logged by the service or as
    /// the hook's refusal).
    pub(super) fn decided(&self) -> bool {
        self.decided.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the pre-receive hook the push runs with is in place: an absolute path
    /// (`Gateway::start` refuses a relative state directory) to a regular file its owner can
    /// run. git skips a hook it can't execute without a word, and would take the push with no
    /// decision (the review after M5.5, L10).
    pub(super) fn hook_in_place(&self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let hook = self.gateway.shared.hooks_dir.join("pre-receive");
        hook.is_absolute()
            && std::fs::metadata(&hook)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o100 != 0)
    }

    /// Registers the push under a new random token.
    pub(super) fn register(gateway: &'a Gateway, context: PushContext) -> Result<Self, String> {
        let token = writ_crypto::keys::random_hex(16)
            .map_err(|_| "internal error: no randomness".to_owned())?;
        gateway
            .shared
            .pushes
            .lock()
            .map_err(|_| "internal error: the push table is poisoned".to_owned())?
            .insert(token.clone(), context.clone());
        Ok(Self {
            gateway,
            token,
            decided: context.decided,
            held: context.held,
        })
    }

    /// `git receive-pack` on the repository at `path`, with the gateway's pre-receive hook,
    /// which asks the daemon about the ref updates with this push's token. Every object is
    /// checked (`fsck`, with `.git`, `.` and `..` entries at error level: malformed objects
    /// and `.git` or `.gitmodules` tricks never land in a repository other leases fetch from),
    /// and the pack is refused past `max_bytes`.
    pub(super) fn receive_pack(&self, path: &Path, max_bytes: u64) -> tokio::process::Command {
        let shared = &self.gateway.shared;
        let mut cmd =
            writ_mirror::git::command(&git_program(self.gateway), Hooks::Dir(&shared.hooks_dir));
        cmd.arg("-c")
            .arg(format!("receive.maxInputSize={max_bytes}"))
            .arg("receive-pack")
            .arg(path)
            .env("WRIT_HOOK_SOCKET", &shared.hook_socket)
            .env("WRIT_HOOK_TOKEN", &self.token);
        cmd
    }
}

impl Push<'_> {
    /// Releases the mirror the hook held for this push: receive-pack has exited, so its refs
    /// have moved (or never will). Released even from a poisoned lock: a held mirror stops
    /// every other push and sync of the repo.
    pub(super) fn release_mirror(&self) {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
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
        // Released at receive-pack's exit already ([`Push::release_mirror`]); again here in
        // case the hook's decision put it back after that (receive-pack gone mid-decision),
        // through the push's own handle, the token forgotten or not.
        self.release_mirror();
    }
}

/// The daemon's `git` (`mirrors.git`), run through [`writ_mirror::git::command`]: nothing from
/// the client's environment reaches it (no `GIT_PROTOCOL`: `upload-pack` speaks protocol v0,
/// where `uploadpack.allow*SHA1InWant` hold; `receive-pack` has no v2 anyway).
fn git_program(gateway: &Gateway) -> PathBuf {
    // Sealed, there is no git to run: an empty path never starts (fail closed). A command is
    // only built after the service allowed it, which a sealed service never does.
    gateway
        .mirrors()
        .map(|mirrors| mirrors.git().to_path_buf())
        .unwrap_or_default()
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

/// How a bridged process ended.
pub(super) struct Bridged {
    pub code: u32,
    /// The bytes the client sent it.
    pub from_client: u64,
}

/// How long a command's output may take to reach the client once the command has exited. Past
/// it, the rest is dropped and the channel closed: a client that stops reading (its SSH window
/// kept shut) holds nothing past its command.
pub(crate) const OUTPUT_AFTER_EXIT: Duration = Duration::from_secs(30);

/// Connects a process's stdin, stdout and stderr to the channel, then reports its exit code.
/// `on_exit` runs as soon as the process has exited, before the client has read all of its
/// output: what the command held (a push's mirror) goes with the process, not with the client.
pub(super) async fn bridge(
    mut child: Child,
    channel: Channel<Msg>,
    on_exit: impl FnOnce(),
) -> Bridged {
    let (mut rx, tx) = channel.split();
    let stdin = child.stdin.take();

    let from_client = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = from_client.clone();
    let stdin_task = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            let mut reader = rx.make_reader();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                counted.fetch_add(
                    u64::try_from(n).unwrap_or(u64::MAX),
                    std::sync::atomic::Ordering::AcqRel,
                );
                if stdin
                    .write_all(buf.get(..n).unwrap_or_default())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = stdin.shutdown().await;
        }
    });
    let code = relay_output(
        &mut child,
        tx.make_writer(),
        tx.make_writer_ext(Some(1)),
        on_exit,
    )
    .await;
    stdin_task.abort();
    finish(&tx, code).await;
    Bridged {
        code,
        from_client: from_client.load(std::sync::atomic::Ordering::Acquire),
    }
}

/// Copies the process's stdout and stderr to `out` and `err` while it runs, and returns its
/// exit code. `on_exit` runs once the process has exited; the copies then get
/// [`OUTPUT_AFTER_EXIT`] to finish, and are dropped past it.
async fn relay_output(
    child: &mut Child,
    out: impl AsyncWrite + Unpin,
    err: impl AsyncWrite + Unpin,
    on_exit: impl FnOnce(),
) -> u32 {
    let copies = copy_both(child.stdout.take(), out, child.stderr.take(), err);
    tokio::pin!(copies);
    let (status, copied) = tokio::select! {
        status = child.wait() => (status, false),
        () = &mut copies => (child.wait().await, true),
    };
    on_exit();
    if !copied
        && tokio::time::timeout(OUTPUT_AFTER_EXIT, &mut copies)
            .await
            .is_err()
    {
        // The client stopped reading: peer-caused, debug only. Its command is over.
        tracing::debug!("the client did not read the command's output in time: dropped");
    }
    match status {
        Ok(status) => status
            .code()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(1),
        Err(_) => 1,
    }
}

/// Copies `stdout` to `out` and `stderr` to `err`, both to their end.
async fn copy_both(
    stdout: Option<impl AsyncRead + Unpin>,
    mut out: impl AsyncWrite + Unpin,
    stderr: Option<impl AsyncRead + Unpin>,
    mut err: impl AsyncWrite + Unpin,
) {
    let copy_out = async {
        if let Some(mut stdout) = stdout {
            tokio::io::copy(&mut stdout, &mut out).await?;
            out.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let copy_err = async {
        if let Some(mut stderr) = stderr {
            tokio::io::copy(&mut stderr, &mut err).await?;
            err.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    };
    let (copied_out, copied_err) = tokio::join!(copy_out, copy_err);
    if let Err(e) = copied_out.and(copied_err) {
        // The client hanging up mid-command does this: peer-caused, debug only.
        tracing::debug!(error = %e, "channel write failed");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::AsyncReadExt;
    use tokio::time::Instant;

    use super::*;

    /// `sh -c script`, with its output piped as the gateway runs git.
    fn sh(script: &str) -> Child {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd.spawn().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn what_a_command_holds_goes_at_its_exit_even_if_the_client_never_reads() {
        // 4 KiB of output fits the pipe, so the process exits; the client's side holds 64
        // bytes and is never read (an SSH window kept shut).
        let mut child = sh("head -c 4096 /dev/zero; echo err >&2; exit 3");
        let (out, _unread) = tokio::io::duplex(64);
        let (err, _unread_err) = tokio::io::duplex(64);
        let started = Instant::now();
        let released = AtomicU32::new(0);
        let mut released_after = None;
        let code = relay_output(&mut child, out, err, || {
            released.fetch_add(1, Ordering::AcqRel);
            released_after = Some(started.elapsed());
        })
        .await;
        assert_eq!(code, 3);
        assert_eq!(released.load(Ordering::Acquire), 1, "released once");
        // Released at the exit, long before the output's deadline...
        assert!(
            released_after.unwrap() < OUTPUT_AFTER_EXIT,
            "{released_after:?}"
        );
        // ...and the relay itself ends at that deadline, not when the client reads.
        assert!(
            started.elapsed() >= OUTPUT_AFTER_EXIT,
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_reads_gets_everything_and_the_release_still_comes_once() {
        let mut child = sh("head -c 100000 /dev/zero; printf done >&2");
        let (out, mut client_out) = tokio::io::duplex(64);
        let (err, mut client_err) = tokio::io::duplex(64);
        let reader = tokio::spawn(async move {
            let (mut got, mut got_err) = (Vec::new(), Vec::new());
            let (a, b) = tokio::join!(
                client_out.read_to_end(&mut got),
                client_err.read_to_end(&mut got_err)
            );
            a.unwrap();
            b.unwrap();
            (got.len(), got_err)
        });
        let started = Instant::now();
        let released = AtomicU32::new(0);
        let code = relay_output(&mut child, out, err, || {
            released.fetch_add(1, Ordering::AcqRel);
        })
        .await;
        assert_eq!(code, 0);
        assert_eq!(released.load(Ordering::Acquire), 1);
        assert!(started.elapsed() < OUTPUT_AFTER_EXIT, "no deadline reached");
        let (stdout_len, stderr) = reader.await.unwrap();
        assert_eq!(stdout_len, 100_000, "every byte reached the client");
        assert_eq!(stderr, b"done");
    }
}
