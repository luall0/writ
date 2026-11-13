//! [`KqueueWatcher`]: local mode's session watcher on macOS. One kqueue, one thread waiting
//! on it, a `NOTE_EXIT` watch per watched pid (several leases bound to one session share
//! it). A process already ended, or whose pid now runs another generation, is said at once;
//! the generation is checked again once the watch is set, so a process that ended in between
//! is never missed. If the kqueue fails, every watch fires: a session it can no longer watch
//! revokes its leases (fail closed).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use writ_core::caller::ProcessRef;
use writ_platform::{OnExit, PlatformError, Result, SessionWatcher, WatchHandle};

use crate::sys;
use crate::sys::kqueue::{Event, Kqueue};

/// Local mode's session watcher on macOS.
pub struct KqueueWatcher {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for KqueueWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KqueueWatcher")
    }
}

struct Shared {
    queue: Kqueue,
    watches: Mutex<Watches>,
}

#[derive(Default)]
struct Watches {
    next: u64,
    /// The watches of each pid: their id, the generation watched, the callback.
    by_pid: HashMap<u32, Vec<(u64, u32, OnExit)>>,
    /// The watcher was dropped: its thread ends.
    stopping: bool,
}

impl Shared {
    fn watches(&self) -> MutexGuard<'_, Watches> {
        // Poisoned: a callback panicked outside the lock, the map is whole.
        self.watches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes watch `id` of `pid` out, if it is still there: whoever takes it calls it.
    fn take(&self, pid: u32, id: u64) -> Option<OnExit> {
        let mut watches = self.watches();
        let list = watches.by_pid.get_mut(&pid)?;
        let index = list.iter().position(|(watch, _, _)| *watch == id)?;
        let (_, _, on_exit) = list.swap_remove(index);
        if list.is_empty() {
            watches.by_pid.remove(&pid);
            self.queue.unwatch(pid);
        }
        Some(on_exit)
    }
}

impl KqueueWatcher {
    /// A watcher with its kqueue and its thread.
    pub fn new() -> Result<Self> {
        let shared = Arc::new(Shared {
            queue: Kqueue::new()?,
            watches: Mutex::new(Watches::default()),
        });
        let looping = shared.clone();
        std::thread::Builder::new()
            .name("writ-session-watcher".to_owned())
            .spawn(move || wait_for_exits(&looping))?;
        Ok(Self { shared })
    }
}

impl Drop for KqueueWatcher {
    fn drop(&mut self) {
        self.shared.watches().stopping = true;
        let _ = self.shared.queue.wake();
    }
}

/// The thread: each exit calls the watches of its pid still on that generation's process.
fn wait_for_exits(shared: &Shared) {
    loop {
        let events = match shared.queue.wait() {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "the session watcher's kqueue failed: every watched session counts as ended");
                let all: Vec<OnExit> = shared
                    .watches()
                    .by_pid
                    .drain()
                    .flat_map(|(_, list)| list.into_iter().map(|(_, _, on_exit)| on_exit))
                    .collect();
                all.into_iter().for_each(writ_platform::watch::say_exit);
                return;
            }
        };
        for event in events {
            match event {
                Event::Woken => {
                    if shared.watches().stopping {
                        return;
                    }
                }
                Event::Exited(pid) => {
                    let ended = ended(shared, pid);
                    ended.into_iter().for_each(writ_platform::watch::say_exit);
                }
            }
        }
    }
}

/// The watches of `pid` its exit ends. One set on the pid reused since (another generation,
/// running) stays, watched again: an exit said late never ends the process after it.
fn ended(shared: &Shared, pid: u32) -> Vec<OnExit> {
    let now = sys::process::proc_info(pid)
        .ok()
        .map(|info| info.generation);
    let mut watches = shared.watches();
    let Some(list) = watches.by_pid.remove(&pid) else {
        return Vec::new();
    };
    let (kept, ended): (Vec<_>, Vec<_>) = list
        .into_iter()
        .partition(|(_, generation, _)| now == Some(*generation));
    if !kept.is_empty() {
        match shared.queue.watch_exit(pid) {
            Ok(()) => {
                watches.by_pid.insert(pid, kept);
            }
            // Gone too, or not watchable: ended with the others.
            Err(_) => {
                drop(watches);
                return ended
                    .into_iter()
                    .chain(kept)
                    .map(|(_, _, on_exit)| on_exit)
                    .collect();
            }
        }
    }
    ended.into_iter().map(|(_, _, on_exit)| on_exit).collect()
}

impl SessionWatcher for KqueueWatcher {
    fn watch(&self, process: &ProcessRef, on_exit: OnExit) -> Result<WatchHandle> {
        let pid = process.pid;
        let running = |generation: u32| {
            sys::process::proc_info(pid).is_ok_and(|info| info.generation == generation)
        };
        let Some(generation) = u32::try_from(process.generation)
            .ok()
            .filter(|generation| running(*generation))
        else {
            // Ended, or the pid is another process's: said at once.
            writ_platform::watch::call_soon(on_exit);
            return Ok(WatchHandle::new(|| {}));
        };
        let id = {
            let mut watches = self.shared.watches();
            let id = watches.next;
            watches.next = id.wrapping_add(1);
            watches
                .by_pid
                .entry(pid)
                .or_default()
                .push((id, generation, on_exit));
            id
        };
        match self.shared.queue.watch_exit(pid) {
            Ok(()) => {}
            // Ended before the watch was set.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                drop(self.shared.take(pid, id));
                return Err(PlatformError::Io(e));
            }
        }
        // Checked again with the watch set: one that ended in between is said now.
        if !running(generation)
            && let Some(on_exit) = self.shared.take(pid, id)
        {
            writ_platform::watch::call_soon(on_exit);
        }
        let shared = self.shared.clone();
        Ok(WatchHandle::new(move || drop(shared.take(pid, id))))
    }
}
