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
    /// Why the gateway stopped it (killed, the command refused), if it did: what the client
    /// sent was over its bound, or the operation over its deadline.
    pub stopped: Option<String>,
}

/// How long a command's output may take to reach the client once the command has exited. Past
/// it, the rest is dropped and the channel closed: a client that stops reading (its SSH window
/// kept shut) holds nothing past its command.
pub(crate) const OUTPUT_AFTER_EXIT: Duration = Duration::from_secs(30);

/// How long one git operation (a fetch or a push, from git's start) may last in all, however
/// steadily its client sends: the connection's inactivity timeout never ends one that trickles
/// (the review after M7.6, G-1). Past it, git is killed and the command refused.
pub(crate) const GIT_DEADLINE: Duration = Duration::from_secs(3600);

/// The most bytes of ref commands a client may send `receive-pack` before its pack: everything
/// up to the first flush packet (the commands, `shallow` lines, the capabilities), the hook's
/// own bound on what it reads ([`MAX_HOOK_INPUT`](crate::hook::MAX_HOOK_INPUT)). git keeps
/// every command in memory and hands them all to its hook, and `receive.maxInputSize` bounds
/// only the pack (the review after M7.6, G-1: 200,000 commands, 61 MB, were taken in).
pub(crate) const MAX_PUSH_COMMANDS: u64 = crate::hook::MAX_HOOK_INPUT as u64;

/// The most bytes a client may send `upload-pack` in all: its wants, haves and `done`
/// (about 300,000 `have` lines; git's own negotiation stops far sooner once it finds what the
/// repo has).
pub(crate) const MAX_FETCH_INPUT: u64 = 16 << 20;

/// What a client may send the git command it runs, in bytes ([`bridge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InputBound {
    /// `upload-pack`: [`MAX_FETCH_INPUT`] in all.
    Fetch,
    /// `receive-pack`: [`MAX_PUSH_COMMANDS`] of ref commands, then the pack: in all at most
    /// those and `max_pack` (git refuses a pack past `max_pack` itself).
    Push { max_pack: u64 },
}

impl InputBound {
    fn total(self) -> u64 {
        match self {
            Self::Fetch => MAX_FETCH_INPUT,
            Self::Push { max_pack } => max_pack.saturating_add(MAX_PUSH_COMMANDS),
        }
    }

    fn over(self) -> String {
        match self {
            Self::Fetch => format!("the fetch's negotiation is over {MAX_FETCH_INPUT} bytes"),
            Self::Push { max_pack } => format!(
                "the push sent more than {} bytes (its pack, at most {max_pack}, and its ref \
                 commands)",
                self.total()
            ),
        }
    }
}

/// Counts the bytes a client sends `receive-pack` until its ref commands end: the first flush
/// packet (`0000`), or anything that isn't a data packet, which ends git's reading of them as
/// well. Read as git reads pkt-lines: 4 hexadecimal digits of length, the header included.
#[derive(Debug, Default)]
pub(super) struct Commands {
    /// Bytes of the commands so far, headers included.
    seen: u64,
    header: [u8; 4],
    header_len: usize,
    /// Bytes of the current packet's payload still to come.
    payload_left: u64,
    ended: bool,
}

impl Commands {
    /// Takes the next bytes the client sent; `false` once the commands are over
    /// [`MAX_PUSH_COMMANDS`] (the bytes past it never reach git).
    pub(super) fn take(&mut self, mut bytes: &[u8], max: u64) -> bool {
        while !self.ended && !bytes.is_empty() {
            if self.payload_left > 0 {
                let n = usize::try_from(self.payload_left)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                let (_, rest) = bytes.split_at_checked(n).unwrap_or((bytes, &[]));
                bytes = rest;
                let n = u64::try_from(n).unwrap_or(u64::MAX);
                self.payload_left = self.payload_left.saturating_sub(n);
                self.seen = self.seen.saturating_add(n);
            } else {
                let Some((&byte, rest)) = bytes.split_first() else {
                    break;
                };
                bytes = rest;
                if let Some(slot) = self.header.get_mut(self.header_len) {
                    *slot = byte;
                }
                self.header_len = self.header_len.saturating_add(1);
                self.seen = self.seen.saturating_add(1);
                if self.header_len == 4 {
                    self.header_len = 0;
                    let length = std::str::from_utf8(&self.header)
                        .ok()
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok());
                    match length {
                        // A data packet: its payload follows.
                        Some(length) if length >= 4 => self.payload_left = length.saturating_sub(4),
                        // The flush (or a delimiter, or a length git refuses): the commands end.
                        _ => self.ended = true,
                    }
                }
            }
            if self.seen > max {
                return false;
            }
        }
        true
    }
}

/// Connects a process's stdin, stdout and stderr to the channel, then reports its exit code.
/// `on_exit` runs as soon as the process has exited, before the client has read all of its
/// output: what the command held (a push's mirror) goes with the process, not with the client.
/// What the client sends is bounded (`bound`) and the whole operation by [`GIT_DEADLINE`]:
/// past either, the process is killed, and the command refused with the reason.
pub(super) async fn bridge(
    mut child: Child,
    channel: Channel<Msg>,
    bound: InputBound,
    on_exit: impl FnOnce(),
) -> Bridged {
    let (mut rx, tx) = channel.split();
    let stdin = child.stdin.take();

    let from_client = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = from_client.clone();
    let mut stdin_task = tokio::spawn(async move {
        let mut stdin = stdin?;
        let mut reader = rx.make_reader();
        let mut buf = vec![0u8; 64 * 1024];
        let mut commands = Commands::default();
        let mut sent = 0u64;
        let stopped = loop {
            let n = match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
                Ok(0) | Err(_) => break None,
                Ok(n) => n,
            };
            let read = buf.get(..n).unwrap_or_default();
            counted.fetch_add(
                u64::try_from(n).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::AcqRel,
            );
            sent = sent.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if let InputBound::Push { .. } = bound
                && !commands.take(read, MAX_PUSH_COMMANDS)
            {
                break Some(format!(
                    "the push's ref commands are over {MAX_PUSH_COMMANDS} bytes"
                ));
            }
            if sent > bound.total() {
                break Some(bound.over());
            }
            if stdin.write_all(read).await.is_err() {
                break None;
            }
        };
        if stopped.is_none() {
            let _ = stdin.shutdown().await;
        }
        stopped
    });
    let stop = async {
        tokio::select! {
            stopped = &mut stdin_task => match stopped {
                Ok(Some(reason)) => reason,
                // The client's side ended within its bound: only the deadline is left.
                _ => {
                    tokio::time::sleep(GIT_DEADLINE).await;
                    deadline_passed()
                }
            },
            () = tokio::time::sleep(GIT_DEADLINE) => deadline_passed(),
        }
    };
    let (code, stopped) = relay_output(
        &mut child,
        tx.make_writer(),
        tx.make_writer_ext(Some(1)),
        on_exit,
        stop,
    )
    .await;
    stdin_task.abort();
    match &stopped {
        Some(reason) => crate::channel::fail(&tx, reason).await,
        None => finish(&tx, code).await,
    }
    Bridged {
        code,
        from_client: from_client.load(std::sync::atomic::Ordering::Acquire),
        stopped,
    }
}

/// Why a git operation over [`GIT_DEADLINE`] was stopped.
fn deadline_passed() -> String {
    format!(
        "the git operation took more than {} s",
        GIT_DEADLINE.as_secs()
    )
}

/// Copies the process's stdout and stderr to `out` and `err` while it runs, and returns its
/// exit code. `on_exit` runs once the process has exited; the copies then get
/// [`OUTPUT_AFTER_EXIT`] to finish, and are dropped past it. When `stop` ends first, the
/// process is killed (and waited for), and its reason returned.
async fn relay_output(
    child: &mut Child,
    out: impl AsyncWrite + Unpin,
    err: impl AsyncWrite + Unpin,
    on_exit: impl FnOnce(),
    stop: impl std::future::Future<Output = String>,
) -> (u32, Option<String>) {
    let copies = copy_both(child.stdout.take(), out, child.stderr.take(), err);
    tokio::pin!(copies);
    tokio::pin!(stop);
    let (mut copied, mut stopped) = (false, None);
    let status = loop {
        tokio::select! {
            status = child.wait() => break status,
            () = &mut copies, if !copied => copied = true,
            reason = &mut stop, if stopped.is_none() => {
                // Killed; its exit is waited for on the next turn.
                let _ = child.start_kill();
                stopped = Some(reason);
            }
        }
    };
    on_exit();
    if !copied
        && stopped.is_none()
        && tokio::time::timeout(OUTPUT_AFTER_EXIT, &mut copies)
            .await
            .is_err()
    {
        // The client stopped reading: peer-caused, debug only. Its command is over.
        tracing::debug!("the client did not read the command's output in time: dropped");
    }
    let code = match status {
        Ok(status) => status
            .code()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(1),
        Err(_) => 1,
    };
    (code, stopped)
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
#[allow(clippy::arithmetic_side_effects)]
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
        let (code, stopped) = relay_output(
            &mut child,
            out,
            err,
            || {
                released.fetch_add(1, Ordering::AcqRel);
                released_after = Some(started.elapsed());
            },
            std::future::pending(),
        )
        .await;
        assert_eq!((code, stopped), (3, None));
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
        let (code, stopped) = relay_output(
            &mut child,
            out,
            err,
            || {
                released.fetch_add(1, Ordering::AcqRel);
            },
            std::future::pending(),
        )
        .await;
        assert_eq!((code, stopped), (0, None));
        assert_eq!(released.load(Ordering::Acquire), 1);
        assert!(started.elapsed() < OUTPUT_AFTER_EXIT, "no deadline reached");
        let (stdout_len, stderr) = reader.await.unwrap();
        assert_eq!(stdout_len, 100_000, "every byte reached the client");
        assert_eq!(stderr, b"done");
    }

    /// The review after M7.6, G-1: a process the gateway stops (its client over a bound, or
    /// the deadline) is killed and waited for, its reason returned, what it held released.
    #[tokio::test(start_paused = true)]
    async fn a_stopped_process_is_killed_and_its_reason_returned() {
        // A git that would run forever.
        let mut child = sh("exec sleep 100000");
        let (out, _client_out) = tokio::io::duplex(64);
        let (err, _client_err) = tokio::io::duplex(64);
        let released = AtomicU32::new(0);
        let (code, stopped) = relay_output(
            &mut child,
            out,
            err,
            || {
                released.fetch_add(1, Ordering::AcqRel);
            },
            async {
                // poll: nothing; paused time (`start_paused`): the clock jumps to the deadline
                // once everything waits, nothing waits for real.
                tokio::time::sleep(GIT_DEADLINE).await;
                deadline_passed()
            },
        )
        .await;
        assert_eq!(
            stopped.as_deref(),
            Some("the git operation took more than 3600 s")
        );
        assert_ne!(code, 0, "killed");
        assert_eq!(released.load(Ordering::Acquire), 1);
        // Gone: reaped, nothing left to wait for.
        assert!(child.try_wait().unwrap().is_some());
    }

    /// pkt-line text: `<4 hex digits of length><payload>`.
    fn pkt(payload: &str) -> Vec<u8> {
        format!("{:04x}{payload}", payload.len() + 4).into_bytes()
    }

    /// A command section of exactly `size` bytes, its flush included.
    fn commands_of(size: usize) -> Vec<u8> {
        let mut section = Vec::new();
        let line = |n: usize| {
            format!(
                "{} {} refs/heads/agent/{n:06}\n",
                "0".repeat(40),
                "1".repeat(40)
            )
        };
        let mut n = 0;
        // Room is left for one more line, which the padding then fills.
        while section.len() + 2 * pkt(&line(n)).len() + 4 <= size {
            section.extend(pkt(&line(n)));
            n += 1;
        }
        // The last packet takes what is left, as padding in its ref name.
        let left = size - section.len() - 4;
        let pad = left - 4 - line(n).len();
        let last = format!(
            "{} {} refs/heads/agent/{}{n:06}\n",
            "0".repeat(40),
            "1".repeat(40),
            "p".repeat(pad)
        );
        section.extend(pkt(&last));
        section.extend(b"0000");
        assert_eq!(section.len(), size);
        section
    }

    #[test]
    fn a_push_s_commands_are_bounded_up_to_their_flush_and_never_the_pack() {
        let max = MAX_PUSH_COMMANDS;
        let size = usize::try_from(max).unwrap();
        // At the bound, whole: taken, and what follows (the pack) is never counted.
        let mut at = Commands::default();
        assert!(at.take(&commands_of(size), max));
        assert!(
            at.take(&vec![b'P'; 10 << 20], max),
            "the pack is not the commands"
        );
        // One byte over, however it arrives: refused.
        let mut over = Commands::default();
        let section = commands_of(size + 1);
        let (first, rest) = section.split_at(1000);
        assert!(over.take(first, max));
        assert!(!over.take(rest, max));
        // Fed a byte at a time, the same.
        let mut bytes = Commands::default();
        let fed = commands_of(size + 1).iter().all(|b| bytes.take(&[*b], max));
        assert!(!fed);
        // A stream that never sends its flush is cut at the bound too, and so is one packet
        // claiming a payload larger than the bound.
        let mut endless = Commands::default();
        let line = pkt(&format!(
            "{} {} refs/heads/agent/x\n",
            "0".repeat(40),
            "1".repeat(40)
        ));
        let fits = (0..20_000).all(|_| endless.take(&line, max));
        assert!(!fits);
        let mut big = Commands::default();
        assert!(!big.take(&[b"fff0".as_slice(), &vec![b'a'; 65_520]].concat(), 1000));
        // A delimiter or a malformed length ends the commands, as it ends git's reading.
        for end in [&b"0001"[..], b"0002", b"zzzz"] {
            let mut ended = Commands::default();
            assert!(ended.take(end, max));
            assert!(ended.take(&vec![b'x'; 2 << 20], max), "{end:?}");
        }
    }

    #[test]
    fn the_bounds_in_all_are_the_pack_and_the_commands_or_a_fetch_s_own() {
        assert_eq!(InputBound::Fetch.total(), 16 << 20);
        assert_eq!(
            InputBound::Push { max_pack: 1000 }.total(),
            1000 + MAX_PUSH_COMMANDS
        );
        assert_eq!(
            InputBound::Push { max_pack: u64::MAX }.total(),
            u64::MAX,
            "saturates"
        );
        assert_eq!(
            InputBound::Fetch.over(),
            "the fetch's negotiation is over 16777216 bytes"
        );
    }
}
