//! [`PidfdWatcher`]: local mode's session watcher on Linux (`session_watcher: linux`). One
//! epoll set, one thread waiting on it, one pidfd per watched process (several leases bound
//! to one session share it). A pidfd names one process whatever happens to its pid, and turns
//! readable when that process exits. The start time is checked once the pidfd is held, so a
//! process that ended, or a pid now running another process, is said at once and an exit in
//! between is never missed. If the epoll set fails, every watch fires: a session it can no
//! longer watch revokes its leases (fail closed).

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::event::{EventfdFlags, epoll, eventfd};
use writ_core::caller::ProcessRef;
use writ_platform::{OnExit, PlatformError, Result, SessionWatcher, WatchHandle};

use crate::procfs;

/// The epoll token of the watcher's own wake-up (no process key is 0: keys count from 1).
const WAKE: u64 = 0;

/// Local mode's session watcher on Linux.
pub struct PidfdWatcher {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for PidfdWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PidfdWatcher")
    }
}

struct Shared {
    epoll: OwnedFd,
    wake: OwnedFd,
    watches: Mutex<Watches>,
}

#[derive(Default)]
struct Watches {
    next_key: u64,
    next_id: u64,
    /// Each watched process (its pid and start time): its epoll key.
    keys: HashMap<(u32, u64), u64>,
    /// Each epoll key: its pidfd and the watches on it (their id, the callback).
    entries: HashMap<u64, (OwnedFd, Vec<(u64, OnExit)>)>,
    /// The watcher was dropped: its thread ends.
    stopping: bool,
}

impl Shared {
    fn watches(&self) -> MutexGuard<'_, Watches> {
        // Poisoned: a callback panicked outside the lock, the maps are whole.
        self.watches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes watch `id` out of `key`, if it is still there: whoever takes it calls it.
    fn take(&self, process: (u32, u64), key: u64, id: u64) -> Option<OnExit> {
        let mut watches = self.watches();
        let (_, list) = watches.entries.get_mut(&key)?;
        let index = list.iter().position(|(watch, _)| *watch == id)?;
        let (_, on_exit) = list.swap_remove(index);
        if list.is_empty() {
            if let Some((pidfd, _)) = watches.entries.remove(&key) {
                let _ = epoll::delete(&self.epoll, &pidfd);
            }
            watches.keys.remove(&process);
        }
        Some(on_exit)
    }
}

/// Calls `on_exit` off the caller's thread: a watch is often set under the state lock that
/// the callback (a revocation) takes.
fn call_soon(on_exit: OnExit) {
    if let Err(e) = std::thread::Builder::new()
        .name("writ-session-exit".to_owned())
        .spawn(on_exit)
    {
        tracing::error!(error = %e, "cannot start a thread to say a session ended");
    }
}

impl PidfdWatcher {
    /// A watcher with its epoll set and its thread.
    pub fn new() -> Result<Self> {
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(std::io::Error::from)?;
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
            .map_err(std::io::Error::from)?;
        epoll::add(
            &epoll,
            &wake,
            epoll::EventData::new_u64(WAKE),
            epoll::EventFlags::IN,
        )
        .map_err(std::io::Error::from)?;
        let shared = Arc::new(Shared {
            epoll,
            wake,
            watches: Mutex::new(Watches {
                next_key: 1,
                ..Watches::default()
            }),
        });
        let looping = shared.clone();
        std::thread::Builder::new()
            .name("writ-session-watcher".to_owned())
            .spawn(move || wait_for_exits(&looping))?;
        Ok(Self { shared })
    }
}

impl Drop for PidfdWatcher {
    fn drop(&mut self) {
        self.shared.watches().stopping = true;
        let _ = rustix::io::write(&self.shared.wake, &1u64.to_ne_bytes());
    }
}

/// The thread: each pidfd turned readable ends the watches on it.
fn wait_for_exits(shared: &Shared) {
    let mut events = Vec::with_capacity(64);
    loop {
        events.clear();
        match epoll::wait(
            &shared.epoll,
            rustix::buffer::spare_capacity(&mut events),
            None,
        ) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                tracing::error!(error = %e, "the session watcher's epoll failed: every watched session counts as ended");
                let all: Vec<OnExit> = {
                    let mut watches = shared.watches();
                    watches.keys.clear();
                    watches
                        .entries
                        .drain()
                        .flat_map(|(_, (_, list))| list.into_iter().map(|(_, on_exit)| on_exit))
                        .collect()
                };
                all.into_iter().for_each(|on_exit| on_exit());
                return;
            }
        }
        for event in &events {
            let key = event.data.u64();
            if key == WAKE {
                if shared.watches().stopping {
                    return;
                }
                continue;
            }
            let ended: Vec<OnExit> = {
                let mut watches = shared.watches();
                let Some((pidfd, list)) = watches.entries.remove(&key) else {
                    continue;
                };
                let _ = epoll::delete(&shared.epoll, &pidfd);
                watches.keys.retain(|_, k| *k != key);
                list.into_iter().map(|(_, on_exit)| on_exit).collect()
            };
            ended.into_iter().for_each(|on_exit| on_exit());
        }
    }
}

impl SessionWatcher for PidfdWatcher {
    fn watch(&self, process: &ProcessRef, on_exit: OnExit) -> Result<WatchHandle> {
        let pid = process.pid;
        let generation = process.generation;
        // Held first, then its start time read: a match means the pidfd is that process's.
        let pidfd = match procfs::hold(pid) {
            Ok(pidfd) => pidfd,
            Err(procfs::ReadError::Gone(_)) => {
                call_soon(on_exit);
                return Ok(WatchHandle::new(|| {}));
            }
            Err(procfs::ReadError::Unreadable(why)) => {
                return Err(PlatformError::Io(std::io::Error::other(why)));
            }
        };
        let same = match procfs::stat(pid) {
            Ok(stat) => stat.start == generation,
            Err(procfs::ReadError::Gone(_)) => false,
            Err(procfs::ReadError::Unreadable(why)) => {
                return Err(PlatformError::Io(std::io::Error::other(why)));
            }
        };
        if !same || !procfs::running(&pidfd)? {
            // Ended, or the pid is another process's: said at once.
            call_soon(on_exit);
            return Ok(WatchHandle::new(|| {}));
        }
        let identity = (pid, generation);
        let (key, id) = {
            let mut watches = self.shared.watches();
            let id = watches.next_id;
            watches.next_id = id.wrapping_add(1);
            let key = match watches.keys.get(&identity) {
                Some(key) => *key,
                None => {
                    let key = watches.next_key;
                    watches.next_key = key.wrapping_add(1).max(1);
                    // Level-triggered: an exit before this call is reported at the next wait.
                    epoll::add(
                        &self.shared.epoll,
                        &pidfd,
                        epoll::EventData::new_u64(key),
                        epoll::EventFlags::IN,
                    )
                    .map_err(std::io::Error::from)?;
                    watches.keys.insert(identity, key);
                    watches.entries.insert(key, (pidfd, Vec::new()));
                    key
                }
            };
            match watches.entries.get_mut(&key) {
                Some((_, list)) => list.push((id, on_exit)),
                // Never: a key and its entry go together, under this lock. Said, not lost.
                None => {
                    drop(watches);
                    call_soon(on_exit);
                    return Ok(WatchHandle::new(|| {}));
                }
            }
            (key, id)
        };
        let shared = self.shared.clone();
        Ok(WatchHandle::new(move || {
            drop(shared.take(identity, key, id))
        }))
    }
}
