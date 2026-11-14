//! Running git to completion with bounds: a deadline for the whole process group (git, the
//! relay, ssh), and a cap on what is kept of its output. A process that outlives its deadline,
//! or a caller that gives up, gets the group killed: nothing it started keeps talking to
//! upstream or writing into a mirror.

use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

use crate::progress::{Progress, StderrSplit};

/// What a finished process left.
#[derive(Debug)]
pub(crate) struct Finished {
    pub status: ExitStatus,
    /// Its stdout, up to the cap (the rest is read and thrown away).
    pub stdout: Vec<u8>,
    /// Its stderr, up to [`MAX_STDERR`].
    pub stderr: Vec<u8>,
}

/// Why a process didn't finish.
#[derive(Debug)]
pub(crate) enum RunError {
    Spawn(std::io::Error),
    /// Past the deadline: the group was killed.
    Timeout,
    Wait(std::io::Error),
}

/// The most of a process's stderr that is kept.
pub(crate) const MAX_STDERR: usize = 64 * 1024;

/// Kills the process group when dropped, unless the process was reaped: a caller giving up
/// (a dropped future) takes the whole group down with it.
struct GroupGuard {
    pid: Option<Pid>,
}

impl GroupGuard {
    fn kill(&mut self) {
        if let Some(pid) = self.pid.take() {
            // Already gone is fine: the group is what must not survive.
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Runs `cmd` in its own process group with `stdin` written to it, until it exits or
/// `deadline` passes (then the group is killed). At most `max_stdout` bytes of stdout are
/// kept.
pub(crate) async fn run(
    cmd: Command,
    stdin: Option<Vec<u8>>,
    deadline: Duration,
    max_stdout: usize,
) -> Result<Finished, RunError> {
    run_with_progress(cmd, stdin, deadline, max_stdout, None).await
}

/// [`run`], with git's stderr read as it comes when `on_progress` is given: each progress part
/// handed to it, kept out of [`Finished::stderr`] ([`crate::progress`]).
pub(crate) async fn run_with_progress(
    mut cmd: Command,
    stdin: Option<Vec<u8>>,
    deadline: Duration,
    max_stdout: usize,
    on_progress: Option<&mut (dyn FnMut(Progress) + Send)>,
) -> Result<Finished, RunError> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .process_group(0)
    .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(RunError::Spawn)?;
    let mut guard = GroupGuard {
        pid: child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw),
    };
    let result =
        tokio::time::timeout(deadline, finish(&mut child, stdin, max_stdout, on_progress)).await;
    match result {
        Ok(Ok(finished)) => {
            // Reaped: its group may still hold a child it left behind (ssh); kill that too.
            guard.kill();
            Ok(finished)
        }
        Ok(Err(e)) => Err(RunError::Wait(e)),
        Err(_) => {
            guard.kill();
            let _ = child.wait().await;
            Err(RunError::Timeout)
        }
    }
}

async fn finish(
    child: &mut Child,
    stdin: Option<Vec<u8>>,
    max_stdout: usize,
    on_progress: Option<&mut (dyn FnMut(Progress) + Send)>,
) -> std::io::Result<Finished> {
    let input = child.stdin.take();
    let feed = async move {
        if let (Some(mut pipe), Some(bytes)) = (input, stdin) {
            // A process that stops reading early is its own business: its exit says why.
            let _ = pipe.write_all(&bytes).await;
            let _ = pipe.shutdown().await;
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let errors = async move {
        match on_progress {
            Some(on_progress) => read_split(stderr, on_progress).await,
            None => read_capped(stderr, MAX_STDERR).await,
        }
    };
    let ((), out, err) = tokio::join!(feed, read_capped(stdout, max_stdout), errors);
    let status = child.wait().await?;
    Ok(Finished {
        status,
        stdout: out?,
        stderr: err?,
    })
}

/// Reads a pipe to its end, keeping at most `max` bytes (the rest is drained so the process
/// never blocks on a full pipe).
async fn read_capped(pipe: Option<impl AsyncRead + Unpin>, max: usize) -> std::io::Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut kept = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = pipe.read(&mut buf).await?;
        if n == 0 {
            return Ok(kept);
        }
        let chunk = buf.get(..n).unwrap_or_default();
        let room = max.saturating_sub(kept.len());
        kept.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
    }
}

/// Reads git's stderr to its end as it comes, its progress handed to `on_progress` and the
/// rest kept, at most [`MAX_STDERR`] bytes.
async fn read_split(
    pipe: Option<impl AsyncRead + Unpin>,
    on_progress: &mut (dyn FnMut(Progress) + Send),
) -> std::io::Result<Vec<u8>> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut split = StderrSplit::new(MAX_STDERR, on_progress);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = pipe.read(&mut buf).await?;
        if n == 0 {
            return Ok(split.finish());
        }
        split.push(buf.get(..n).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[tokio::test]
    async fn output_is_kept_up_to_the_cap() {
        let done = run(
            sh("printf 1234567890; printf err >&2"),
            None,
            Duration::from_secs(30),
            10,
        )
        .await
        .unwrap();
        assert_eq!(done.stdout, b"1234567890");
        assert_eq!(done.stderr, b"err");
        let done = run(sh("printf 12345678901"), None, Duration::from_secs(30), 10)
            .await
            .unwrap();
        assert_eq!(done.stdout, b"1234567890", "cut at the cap");
    }

    #[tokio::test]
    async fn stdin_reaches_the_process() {
        let done = run(
            sh("cat"),
            Some(b"abc".to_vec()),
            Duration::from_secs(30),
            10,
        )
        .await
        .unwrap();
        assert_eq!(done.stdout, b"abc");
        assert!(done.status.success());
    }

    #[tokio::test]
    async fn progress_is_handed_on_as_it_comes_and_kept_out_of_stderr() {
        // The second report is written only once the first was seen (the file it waits for
        // is made by the callback): progress comes while the process runs, not at its end.
        let dir = tempfile::tempdir().unwrap();
        let seen_file = dir.path().join("seen");
        let script = format!(
            "printf 'Receiving objects:  50%% (1/2)\\r' >&2; \
             while [ ! -e {seen} ]; do sleep 0.01; done; \
             printf 'Receiving objects: 100%% (2/2), done.\\nfatal: boom\\n' >&2; exit 3",
            seen = seen_file.display()
        );
        let mut seen = Vec::new();
        let mut on = |p: Progress| {
            std::fs::write(&seen_file, b"").unwrap();
            seen.push((p.done, p.total));
        };
        let done = run_with_progress(
            sh(&script),
            None,
            Duration::from_secs(30),
            10,
            Some(&mut on),
        )
        .await
        .unwrap();
        assert_eq!(seen, [(1, 2), (2, 2)]);
        assert_eq!(done.stderr, b"fatal: boom\n");
        assert_eq!(done.status.code(), Some(3));
    }

    #[tokio::test]
    async fn the_whole_group_is_killed_past_the_deadline() {
        // The grandchild writes its pid, then waits forever, like ssh under git.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!(
            "sh -c 'echo $$ > {}; exec sleep 600' & wait",
            pidfile.display()
        );
        let result = run(sh(&script), None, Duration::from_millis(500), 10).await;
        assert!(matches!(result, Err(RunError::Timeout)), "{result:?}");
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The killed grandchild is reparented to init, which reaps it on its own time.
        writ_platform::testing::eventually("the grandchild to be gone", || {
            rustix::process::test_kill_process(Pid::from_raw(pid).unwrap()).is_err()
        });
    }
}
