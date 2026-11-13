//! The daemon's background tasks (the sweeper, the mirrors' sync), supervised (the review
//! after M7.6, D-6): each runs in a set `writd run` owns, never spawned loose. A task that ends
//! (it never should: a panic, a sweep that failed) is logged with why and started again; one
//! that keeps ending ([`MAX_RESTARTS`] times) stops the daemon in order. The orderly stop ends
//! them first ([`Supervisor::shutdown`]), before it waits for what is in flight.
//!
//! A task asked for later (the mirrors' sync, at unseal) comes through a [`Spawner`], whose
//! requests the supervisor takes while it waits.

use std::collections::HashMap;

use tokio::sync::mpsc;
use tokio::task::{Id, JoinSet};
use writ_platform::BoxFuture;

/// How many times a task is started again after it ended; the next end stops the daemon.
pub const MAX_RESTARTS: u32 = 3;

/// Makes a task's future, each time it is (re)started.
pub type Make = Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

struct Task {
    name: &'static str,
    make: Make,
}

/// Asks the supervisor to run a task. Cloned where tasks are started.
#[derive(Clone)]
pub struct Spawner(mpsc::UnboundedSender<Task>);

impl Spawner {
    /// Runs `make()`'s future under the supervisor, as `name` (in its lines). Asked while
    /// the daemon stops, it is never started.
    pub fn spawn(&self, name: &'static str, make: Make) {
        if self.0.send(Task { name, make }).is_err() {
            tracing::debug!(task = name, "not started: the daemon is stopping");
        }
    }
}

/// The supervised tasks: the set they run in, and how each is made again.
pub struct Supervisor {
    asked: mpsc::UnboundedReceiver<Task>,
    tasks: JoinSet<()>,
    running: HashMap<Id, &'static str>,
    makers: HashMap<&'static str, (Make, u32)>,
}

impl Supervisor {
    pub fn new() -> (Spawner, Self) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Spawner(tx),
            Self {
                asked: rx,
                tasks: JoinSet::new(),
                running: HashMap::new(),
                makers: HashMap::new(),
            },
        )
    }

    fn start(&mut self, name: &'static str) {
        if let Some((make, _)) = self.makers.get(name) {
            let id = self.tasks.spawn(make()).id();
            self.running.insert(id, name);
        }
    }

    /// Runs the tasks asked for, starting again each one that ends, until one has ended more
    /// than [`MAX_RESTARTS`] times: why the daemon stops then. Never returns otherwise.
    pub async fn until_failed(&mut self) -> String {
        loop {
            tokio::select! {
                Some(task) = self.asked.recv() => {
                    // Asked again (a second unseal never happens, but a name is one task).
                    self.makers.insert(task.name, (task.make, 0));
                    self.start(task.name);
                }
                Some(ended) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    let (id, why) = match ended {
                        Ok((id, ())) => (id, "it returned".to_owned()),
                        Err(e) if e.is_panic() => (e.id(), "it panicked".to_owned()),
                        Err(e) => (e.id(), e.to_string()),
                    };
                    let Some(name) = self.running.remove(&id) else {
                        continue;
                    };
                    let restarts = match self.makers.get_mut(name) {
                        Some((_, restarts)) => {
                            *restarts = restarts.saturating_add(1);
                            *restarts
                        }
                        None => continue,
                    };
                    if restarts > MAX_RESTARTS {
                        return format!(
                            "the {name} ended {restarts} times ({why}): the daemon stops"
                        );
                    }
                    tracing::error!(task = name, %why, restarts, "a background task ended: started again");
                    self.start(name);
                }
                else => std::future::pending::<()>().await,
            }
        }
    }

    /// Ends every task (the orderly stop's first step) and takes no more.
    pub async fn shutdown(&mut self) {
        self.asked.close();
        self.tasks.shutdown().await;
        self.running.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A task that ends at once, counting its starts.
    fn ending(starts: &Arc<AtomicU32>, panics: bool) -> Make {
        let starts = starts.clone();
        Box::new(move || {
            let starts = starts.clone();
            Box::pin(async move {
                starts.fetch_add(1, Ordering::SeqCst);
                if panics {
                    panic!("a sweep that overflowed");
                }
            })
        })
    }

    /// The review after M7.6 (D-6): a task that ends is started again, at most
    /// [`MAX_RESTARTS`] times (a panic as much as a return); the next end stops the daemon,
    /// naming the task.
    #[tokio::test]
    async fn a_task_that_keeps_ending_is_started_again_then_stops_the_daemon() {
        for panics in [false, true] {
            let (spawner, mut supervisor) = Supervisor::new();
            let starts = Arc::new(AtomicU32::new(0));
            spawner.spawn("sweeper", ending(&starts, panics));
            let why = supervisor.until_failed().await;
            let said = if panics { "it panicked" } else { "it returned" };
            assert_eq!(
                why,
                format!("the sweeper ended 4 times ({said}): the daemon stops")
            );
            assert_eq!(starts.load(Ordering::SeqCst), MAX_RESTARTS + 1);
        }
    }

    /// A task that keeps running is never restarted, a task asked for later is started, and
    /// the shutdown ends them all and takes no more.
    #[tokio::test]
    async fn tasks_run_until_the_shutdown_which_ends_them() {
        let (spawner, mut supervisor) = Supervisor::new();
        let (started, mut seen) = mpsc::unbounded_channel::<&'static str>();
        for name in ["sweeper", "mirror sync"] {
            let started = started.clone();
            spawner.spawn(
                name,
                Box::new(move || {
                    let started = started.clone();
                    Box::pin(async move {
                        let _ = started.send(name);
                        std::future::pending::<()>().await;
                    })
                }),
            );
        }
        // Both started while the supervisor waits; neither ends, so it never returns.
        let waited = tokio::select! {
            why = supervisor.until_failed() => Some(why),
            () = async {
                assert_eq!(seen.recv().await, Some("sweeper"));
                assert_eq!(seen.recv().await, Some("mirror sync"));
            } => None,
        };
        assert_eq!(waited, None);
        supervisor.shutdown().await;
        assert!(supervisor.tasks.is_empty());
        // Asked after the shutdown: never started.
        let starts = Arc::new(AtomicU32::new(0));
        spawner.spawn("late", ending(&starts, false));
        assert!(supervisor.asked.recv().await.is_none());
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }
}
