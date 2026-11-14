//! Each mirror's sync status (`writ admin repo status`): the sync running, if one is, and how
//! the last one ended. Kept beside the mirror's lock under a lock of its own, so it is read
//! while a sync holds the mirror; carried over by a registry change with the lock; in memory
//! only (a restart starts it over).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;
use writ_core::names::RepoName;

use super::Limit;
use crate::progress::Progress;

/// A repo's sync status, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub repo: RepoName,
    /// The sync running now, if one is.
    pub running: Option<RunningSync>,
    /// How the last sync since the daemon started ended, if one did.
    pub last: Option<LastSync>,
}

/// The sync running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningSync {
    /// The mirror holds no branch or tag yet: its first sync.
    pub first: bool,
    /// Waiting for one of the daemon's sync slots.
    pub waiting: bool,
    /// Since the sync started (its slot waited for included).
    pub elapsed: Duration,
    /// Its upstream operation's limit, and the key that set it.
    pub limit: Limit,
    /// What upstream sent so far, counted by the operation's byte-capping proxy.
    pub received: u64,
    /// The most it may send (`mirrors.max_fetch`).
    pub max: u64,
    /// git's last progress report, if it made one.
    pub progress: Option<Progress>,
}

/// How a sync ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastSync {
    /// How long ago it ended.
    pub ago: Duration,
    /// How long it took.
    pub took: Duration,
    /// It was the mirror's first.
    pub first: bool,
    pub outcome: SyncOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Synced: how many refs moved.
    Synced { moved: usize },
    /// Failed: why, as `writ admin repo check` says it.
    Failed { reason: String },
    /// Dropped before its end (its caller gone, the daemon stopping).
    Interrupted,
}

/// What is kept of a mirror's syncs.
#[derive(Debug, Default)]
pub(super) struct StatusCell {
    running: Option<Run>,
    last: Option<Last>,
}

#[derive(Debug)]
struct Run {
    started: Instant,
    first: bool,
    waiting: bool,
    limit: Limit,
    received: Option<Arc<AtomicU64>>,
    max: u64,
    progress: Option<Progress>,
}

#[derive(Debug)]
struct Last {
    ended: Instant,
    took: Duration,
    first: bool,
    outcome: SyncOutcome,
}

pub(super) type SharedStatus = Arc<Mutex<StatusCell>>;

impl StatusCell {
    /// The status as it stands now.
    pub(super) fn read(&self, repo: &RepoName) -> SyncStatus {
        SyncStatus {
            repo: repo.clone(),
            running: self.running.as_ref().map(|run| RunningSync {
                first: run.first,
                waiting: run.waiting,
                elapsed: run.started.elapsed(),
                limit: run.limit,
                received: run
                    .received
                    .as_ref()
                    .map_or(0, |count| count.load(Ordering::Acquire)),
                max: run.max,
                progress: run.progress,
            }),
            last: self.last.as_ref().map(|last| LastSync {
                ago: last.ended.elapsed(),
                took: last.took,
                first: last.first,
                outcome: last.outcome.clone(),
            }),
        }
    }
}

/// A sync recorded in its mirror's status while it runs: [`Recording::end`] records how it
/// ended; dropped before, it is recorded as interrupted.
pub(super) struct Recording {
    cell: SharedStatus,
    started: Instant,
    first: bool,
    ended: bool,
}

impl Recording {
    /// A sync starting, waiting for its slot.
    pub(super) fn begin(cell: SharedStatus, first: bool, limit: Limit, max: u64) -> Self {
        let started = Instant::now();
        let recording = Self {
            cell,
            started,
            first,
            ended: false,
        };
        recording.with(|cell| {
            cell.running = Some(Run {
                started,
                first,
                waiting: true,
                limit,
                received: None,
                max,
                progress: None,
            });
        });
        recording
    }

    /// Its slot taken: fetching.
    pub(super) fn fetching(&self) {
        self.with(|cell| {
            if let Some(run) = cell.running.as_mut() {
                run.waiting = false;
            }
        });
    }

    /// What its byte-capping proxy counts.
    pub(super) fn counting(&self, received: Arc<AtomicU64>) {
        self.with(|cell| {
            if let Some(run) = cell.running.as_mut() {
                run.received = Some(received);
            }
        });
    }

    /// git's progress.
    pub(super) fn progress(&self, progress: Progress) {
        self.with(|cell| {
            if let Some(run) = cell.running.as_mut() {
                run.progress = Some(progress);
            }
        });
    }

    pub(super) fn end(mut self, outcome: SyncOutcome) {
        self.finish(outcome);
    }

    fn finish(&mut self, outcome: SyncOutcome) {
        self.ended = true;
        let (started, first) = (self.started, self.first);
        self.with(|cell| {
            cell.running = None;
            cell.last = Some(Last {
                ended: Instant::now(),
                took: started.elapsed(),
                first,
                outcome,
            });
        });
    }

    /// Changes the status; a poisoned lock leaves it as it was (the status is only shown: a
    /// sync never fails over it, and its reader refuses it).
    fn with(&self, change: impl FnOnce(&mut StatusCell)) {
        // poisoned: the status stays as it was; it decides nothing, and `Mirrors::status`
        // refuses to read it (`StatusUnavailable`).
        if let Ok(mut cell) = self.cell.lock() {
            change(&mut cell);
        }
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        if !self.ended {
            self.finish(SyncOutcome::Interrupted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit() -> Limit {
        Limit {
            duration: Duration::from_secs(3600),
            key: "mirrors.first_sync_timeout",
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_sync_is_running_while_recorded_and_its_end_kept() {
        let cell = SharedStatus::default();
        let repo: RepoName = "demo".parse().unwrap();
        let read = || cell.lock().unwrap().read(&repo);
        assert_eq!(read().running, None);
        assert_eq!(read().last, None);

        let recording = Recording::begin(cell.clone(), true, limit(), 1 << 30);
        let running = read().running.unwrap();
        assert!(running.waiting && running.first);
        assert_eq!((running.received, running.progress), (0, None));

        tokio::time::advance(Duration::from_secs(5)).await;
        recording.fetching();
        let count = Arc::new(AtomicU64::new(0));
        recording.counting(count.clone());
        count.store(4096, Ordering::Release);
        let progress = Progress {
            phase: crate::progress::Phase::Receiving,
            done: 1,
            total: 2,
        };
        recording.progress(progress);
        let running = read().running.unwrap();
        assert!(!running.waiting);
        assert_eq!(running.elapsed, Duration::from_secs(5));
        assert_eq!(running.received, 4096);
        assert_eq!(running.progress, Some(progress));
        assert_eq!(running.limit, limit());

        tokio::time::advance(Duration::from_secs(2)).await;
        recording.end(SyncOutcome::Synced { moved: 3 });
        tokio::time::advance(Duration::from_secs(60)).await;
        let status = read();
        assert_eq!(status.running, None);
        assert_eq!(
            status.last,
            Some(LastSync {
                ago: Duration::from_secs(60),
                took: Duration::from_secs(7),
                first: true,
                outcome: SyncOutcome::Synced { moved: 3 },
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_sync_dropped_before_its_end_is_interrupted() {
        let cell = SharedStatus::default();
        let repo: RepoName = "demo".parse().unwrap();
        drop(Recording::begin(cell.clone(), false, limit(), 1));
        let status = cell.lock().unwrap().read(&repo);
        assert_eq!(status.running, None);
        assert_eq!(status.last.unwrap().outcome, SyncOutcome::Interrupted);
    }
}
