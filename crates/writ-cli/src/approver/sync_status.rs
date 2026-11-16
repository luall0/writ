//! The mirrors' sync status: `writ admin repo status [<repo>]`, and the line `writ admin repo
//! check` keeps up to date while its sync runs. What the daemon says is shown in Writ's words,
//! its text (a failure's reason, a key's name) cleaned, each row at most [`WIDTH`] columns.

use std::fmt::Write as _;
use std::io::{IsTerminal as _, Write as _};
use std::time::Duration;

use writ_core::names::RepoName;
use writ_proto::{
    Command, SyncEnded, SyncPhase, SyncResult, SyncRunning, SyncStatus, SyncStatuses,
};

use super::connect;
use crate::client::Approvals;
use crate::display::{WIDTH, about_bytes as bytes, clean, one_row, rows_after};
use crate::{Exit, Paths};

/// How often `writ admin repo check` asks the sync status while it runs.
const POLL_EVERY: Duration = Duration::from_secs(2);
/// How often the sync's line is printed when stdout is no terminal (a log).
const LOGGED_EVERY: Duration = Duration::from_secs(60);

/// `writ admin repo status [<repo>]`: every repo, or the one named, its status in rows of at
/// most [`WIDTH`] columns (a long one wraps: its progress is never cut away).
pub async fn status(paths: &Paths, url: &str, repo: Option<&str>) -> anyhow::Result<Exit> {
    let repo: Option<RepoName> = repo.map(str::parse).transpose()?;
    let statuses: SyncStatuses = connect(paths, url)
        .await?
        .run(async |session| {
            Ok(session
                .call(&Command::RepoStatus { repo: repo.clone() }, b"")
                .await??)
        })
        .await?;
    let mut out = String::new();
    for status in &statuses.repos {
        let name = clean(status.repo.as_str());
        rows_after(&mut out, &format!("{name}: "), &said(status));
    }
    if statuses.repos.is_empty() {
        out.push_str("No repo in the registry.\n");
    }
    print!("{out}");
    Ok(Exit::Ok)
}

/// Runs `work` (the check), showing the sync of `repo` while it runs: asked every
/// [`POLL_EVERY`] on the same connection; on a terminal one line rewritten in place, otherwise
/// a line every [`LOGGED_EVERY`]. A status the daemon can't give (an older daemon) shows
/// nothing.
pub(super) async fn while_syncing<T>(
    session: &Approvals,
    repo: &RepoName,
    work: impl Future<Output = T>,
) -> T {
    tokio::pin!(work);
    let terminal = std::io::stdout().is_terminal();
    let start = tokio::time::Instant::now();
    let mut poll = tokio::time::interval_at(start + POLL_EVERY, POLL_EVERY);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shown = false;
    let mut logged: Option<tokio::time::Instant> = None;
    let ask = Command::RepoStatus {
        repo: Some(repo.clone()),
    };
    loop {
        tokio::select! {
            done = &mut work => {
                if shown {
                    clear_line();
                }
                return done;
            }
            _ = poll.tick() => {
                let running = match session.call::<SyncStatuses>(&ask, b"").await {
                    Ok(Ok(statuses)) => statuses.repos.into_iter().next().and_then(|s| s.running),
                    _ => None,
                };
                let Some(run) = running else {
                    if shown {
                        clear_line();
                        shown = false;
                    }
                    continue;
                };
                let line = one_row(&format!("  sync: {}", running_said(&run)), WIDTH, "");
                if terminal {
                    print!("\r\x1b[K{line}");
                    let _ = std::io::stdout().flush();
                    shown = true;
                } else if logged.is_none_or(|at| at.elapsed() >= LOGGED_EVERY) {
                    println!("{line}");
                    logged = Some(tokio::time::Instant::now());
                }
            }
        }
    }
}

/// Takes the sync's line off the terminal.
fn clear_line() {
    print!("\r\x1b[K");
    let _ = std::io::stdout().flush();
}

/// A repo's status in one line of Writ's words.
pub(crate) fn said(status: &SyncStatus) -> String {
    match (&status.running, &status.last) {
        (Some(run), Some(last)) => format!("{}; last {}", running_said(run), ended_said(last)),
        (Some(run), None) => running_said(run),
        (None, Some(last)) => ended_said(last),
        (None, None) => "not synced since the daemon started".to_owned(),
    }
}

/// The sync running: `first sync running for 6m 12s (cut at 1h): receiving objects 45%
/// (4500/10000), 412 MiB of at most 1 GiB`.
pub(crate) fn running_said(run: &SyncRunning) -> String {
    let which = if run.first { "first sync" } else { "sync" };
    let elapsed = span(run.elapsed_seconds);
    let limit = writ_core::units::Duration::from_seconds(run.limit_seconds);
    if run.waiting {
        return format!(
            "{which} waiting for a sync slot for {elapsed} (cut at {limit} once it runs)"
        );
    }
    let mut out = format!("{which} running for {elapsed} (cut at {limit})");
    if let Some(progress) = run.progress {
        let phase = match progress.phase {
            SyncPhase::Preparing => "upstream preparing objects",
            SyncPhase::Receiving => "receiving objects",
            SyncPhase::Resolving => "resolving deltas",
        };
        let percent = if progress.total == 0 {
            100
        } else {
            u128::from(progress.done.min(progress.total)) * 100 / u128::from(progress.total)
        };
        let _ = write!(
            out,
            ": {phase} {percent}% ({}/{}),",
            progress.done.min(progress.total),
            progress.total
        );
    } else {
        out.push(':');
    }
    let _ = write!(
        out,
        " {} of at most {}",
        bytes(run.received_bytes),
        bytes(run.max_bytes)
    );
    out
}

/// How a sync ended: `synced 2m ago in 4s, 3 refs moved`, `failed 1m ago after 5m: <why>`.
pub(crate) fn ended_said(last: &SyncEnded) -> String {
    let which = if last.first { "first sync" } else { "sync" };
    let (ago, took) = (span(last.ago_seconds), span(last.took_seconds));
    match &last.result {
        SyncResult::Synced { moved } => {
            let refs = if *moved == 1 { "ref" } else { "refs" };
            let synced = if last.first { "first synced" } else { "synced" };
            format!("{synced} {ago} ago in {took}, {moved} {refs} moved")
        }
        SyncResult::Failed { reason } => {
            format!("{which} failed {ago} ago after {took}: {}", clean(reason))
        }
        SyncResult::Interrupted => format!("{which} interrupted {ago} ago after {took}"),
    }
}

/// A span of time to read: `45s`, `6m 12s`, `1h 2m`, `2d 3h`.
fn span(seconds: u64) -> String {
    let (d, h, m, s) = (
        seconds / 86_400,
        seconds % 86_400 / 3_600,
        seconds % 3_600 / 60,
        seconds % 60,
    );
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) if s == 0 => format!("{m}m"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) if m == 0 => format!("{h}h"),
        (0, _, _) => format!("{h}h {m}m"),
        (_, 0, _) => format!("{d}d"),
        _ => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use writ_proto::SyncProgress;

    fn running() -> SyncRunning {
        SyncRunning {
            first: true,
            waiting: false,
            elapsed_seconds: 372,
            limit_seconds: 3_600,
            limit_key: "mirrors.first_sync_timeout".to_owned(),
            received_bytes: 412 << 20,
            max_bytes: 1 << 30,
            progress: Some(SyncProgress {
                phase: SyncPhase::Receiving,
                done: 4_500,
                total: 10_000,
            }),
        }
    }

    #[test]
    fn a_running_sync_is_said_with_its_limit_progress_and_bytes() {
        assert_eq!(
            running_said(&running()),
            "first sync running for 6m 12s (cut at 1h): receiving objects 45% (4500/10000), \
             412 MiB of at most 1.0 GiB"
        );
        let waiting = SyncRunning {
            waiting: true,
            first: false,
            limit_seconds: 300,
            ..running()
        };
        assert_eq!(
            running_said(&waiting),
            "sync waiting for a sync slot for 6m 12s (cut at 5m once it runs)"
        );
        let no_progress = SyncRunning {
            progress: None,
            received_bytes: 0,
            ..running()
        };
        assert!(
            running_said(&no_progress).ends_with("(cut at 1h): 0 bytes of at most 1.0 GiB"),
            "{}",
            running_said(&no_progress)
        );
        // Counts the daemon got from upstream, whatever they are: never past their total, and
        // a percent that never overflows.
        let lying = SyncRunning {
            progress: Some(SyncProgress {
                phase: SyncPhase::Preparing,
                done: u64::MAX,
                total: 3,
            }),
            ..running()
        };
        assert!(running_said(&lying).contains("upstream preparing objects 100% (3/3)"));
        let huge = SyncRunning {
            progress: Some(SyncProgress {
                phase: SyncPhase::Resolving,
                done: u64::MAX - 1,
                total: u64::MAX,
            }),
            ..running()
        };
        assert!(running_said(&huge).contains("resolving deltas 99%"));
    }

    #[test]
    fn an_ended_sync_is_said_and_a_reason_never_reaches_the_terminal_raw() {
        let ended = |first, result| SyncEnded {
            ago_seconds: 120,
            took_seconds: 4,
            first,
            result,
        };
        assert_eq!(
            ended_said(&ended(false, SyncResult::Synced { moved: 3 })),
            "synced 2m ago in 4s, 3 refs moved"
        );
        assert_eq!(
            ended_said(&ended(true, SyncResult::Synced { moved: 1 })),
            "first synced 2m ago in 4s, 1 ref moved"
        );
        assert_eq!(
            ended_said(&ended(false, SyncResult::Interrupted)),
            "sync interrupted 2m ago after 4s"
        );
        let failed = ended_said(&ended(
            true,
            SyncResult::Failed {
                reason: "repo demo: upstream did not finish\u{1b}[2J\nwithin 1h".to_owned(),
            },
        ));
        assert!(
            !failed.contains('\u{1b}') && !failed.contains('\n'),
            "{failed}"
        );
        assert!(failed.starts_with("first sync failed 2m ago after 4s: repo demo"));
        let status = SyncStatus {
            repo: "demo".parse().unwrap(),
            running: None,
            last: None,
        };
        assert_eq!(said(&status), "not synced since the daemon started");
    }

    #[test]
    fn a_long_status_wraps_and_keeps_its_progress() {
        let status = SyncStatus {
            repo: "big".parse().unwrap(),
            running: Some(running()),
            last: None,
        };
        let mut out = String::new();
        rows_after(&mut out, "big: ", &said(&status));
        // As the daily operations page shows it (`docs/operators/sealing.md`).
        assert_eq!(
            out,
            "big: first sync running for 6m 12s (cut at 1h): receiving objects 45%\n     \
             │ (4500/10000), 412 MiB of at most 1.0 GiB\n"
        );
        assert!(
            out.lines().all(|row| crate::display::width(row) <= WIDTH),
            "{out}"
        );
    }

    #[test]
    fn spans_and_sizes_read_as_people_say_them() {
        for (seconds, said) in [
            (0, "0s"),
            (45, "45s"),
            (60, "1m"),
            (372, "6m 12s"),
            (3_600, "1h"),
            (3_720, "1h 2m"),
            (86_400, "1d"),
            (97_200, "1d 3h"),
            (u64::MAX, "213503982334601d 7h"),
        ] {
            assert_eq!(span(seconds), said, "{seconds}");
        }
        for (n, said) in [
            (0, "0 bytes"),
            (1023, "1023 bytes"),
            (1024, "1.0 KiB"),
            (412 << 20, "412 MiB"),
            (1 << 30, "1.0 GiB"),
            (64 << 30, "64 GiB"),
            (u64::MAX, "16 EiB"),
        ] {
            assert_eq!(bytes(n), said, "{n}");
        }
    }
}
