//! `writ run -- <program> [args…]`: runs an agent harness (Claude Code, Codex…) as this
//! process's child, and makes this process the root of its session. Every `writ request` under
//! it binds the lease to it ([`bind`]: `caller: { descends_from: { pid } }`, which the daemon
//! completes from the kernel), so the lease is refused to anything outside the session and
//! revoked when it ends: when the harness quits, `writ run` exits.
//!
//! The harness gets the terminal and the environment, plus [`RUN_PID`]. SIGTERM and SIGHUP are
//! passed on to it; SIGINT and SIGQUIT come from the terminal to the whole foreground group
//! already, so `writ run` only stays for them (passing them on would hit the harness twice).
//! The exit status is the harness's, or 128 and the signal that ended it.

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitCode;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};

/// The session root's pid, set by `writ run` for what runs under it.
pub const RUN_PID: &str = "WRIT_RUN_PID";

/// Runs `command` under this session: its exit status.
pub fn run(command: &[OsString]) -> ExitCode {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start")
        .and_then(|runtime| runtime.block_on(supervise(command)));
    match outcome {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("writ: {}", crate::display::clean_lines(&format!("{e:#}")));
            ExitCode::from(crate::Exit::Error as u8)
        }
    }
}

/// Starts the harness and waits for it, passing SIGTERM and SIGHUP on.
async fn supervise(command: &[OsString]) -> anyhow::Result<u8> {
    let Some((program, args)) = command.split_first() else {
        bail!("writ run needs the program to run: writ run -- <program> [args…]");
    };
    // Taken before the harness starts: none of them ends this process meanwhile.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut quit = signal(SignalKind::quit())?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env(RUN_PID, std::process::id().to_string())
        .spawn()
        .with_context(|| format!("cannot run {}", program.to_string_lossy()))?;
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(rustix::process::Pid::from_raw)
        .context("the harness has no pid")?;
    let status = loop {
        let forward = tokio::select! {
            status = child.wait() => break status?,
            _ = terminate.recv() => Some(rustix::process::Signal::TERM),
            _ = hangup.recv() => Some(rustix::process::Signal::HUP),
            _ = interrupt.recv() => None,
            _ = quit.recv() => None,
        };
        if let Some(sig) = forward {
            // Gone meanwhile: its status comes next.
            let _ = rustix::process::kill_process(pid, sig);
        }
    };
    Ok(match (status.code(), status.signal()) {
        (Some(code), _) => u8::try_from(code).unwrap_or(u8::MAX),
        (None, Some(sig)) => u8::try_from(sig).map_or(u8::MAX, |sig| sig.saturating_add(128)),
        (None, None) => crate::Exit::Error as u8,
    })
}

/// The session `writ run` started this process in ([`RUN_PID`]), if any.
pub fn session() -> anyhow::Result<Option<u32>> {
    match std::env::var_os(RUN_PID) {
        None => Ok(None),
        Some(value) => match value.to_str().and_then(|v| v.parse::<u32>().ok()) {
            Some(pid) if pid > 0 => Ok(Some(pid)),
            _ => bail!(
                "{RUN_PID} is not a pid ({}): it is `writ run`'s to set",
                crate::display::clean(&value.to_string_lossy())
            ),
        },
    }
}

/// The ticket `text` bound to the session `pid`: a `caller` added in front (after a leading
/// `---`). A ticket that names its own `caller` is left as it is.
pub fn bind(text: &str, pid: u32) -> String {
    let caller = format!("caller:\n  descends_from: {{ pid: {pid} }}\n");
    match text.strip_prefix("---\n") {
        Some(rest) => format!("---\n{caller}{rest}"),
        None => format!("{caller}{text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use writ_core::ticket::TicketRequest;

    const TICKET: &str =
        "repos:\n  demo:\n    operations: [fetch]\nticket:\n  title: T\n  task: T\n";

    #[test]
    fn a_ticket_is_bound_to_the_session_as_a_pid() {
        for text in [
            TICKET.to_owned(),
            format!("---\n{TICKET}"),
            format!("# A ticket\n{TICKET}"),
        ] {
            let bound = TicketRequest::from_yaml(&bind(&text, 4242)).unwrap();
            assert_eq!(bound.caller.unwrap().descends_from.pid, 4242, "{text}");
            assert_eq!(bound.repos.len(), 1);
        }
    }

    #[test]
    fn a_harness_s_status_is_writ_run_s() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sh = |script: &str| -> Vec<OsString> {
            ["/bin/sh", "-c", script]
                .iter()
                .map(OsString::from)
                .collect()
        };
        assert_eq!(runtime.block_on(supervise(&sh("exit 7"))).unwrap(), 7);
        // Ended by a signal: 128 and its number.
        assert_eq!(
            runtime.block_on(supervise(&sh("kill -TERM $$"))).unwrap(),
            128 + 15
        );
        // The session's pid, given to what runs: this process's.
        assert_eq!(
            runtime
                .block_on(supervise(&sh(&format!(
                    "test \"${RUN_PID}\" = {} || exit 9",
                    std::process::id()
                ))))
                .unwrap(),
            0
        );
        let error = crate::error_of(runtime.block_on(supervise(&[])));
        assert_eq!(
            error,
            "writ run needs the program to run: writ run -- <program> [args…]"
        );
    }
}
