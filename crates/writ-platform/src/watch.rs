//! A notice when a session's root process exits, to revoke its lease: the [`SessionWatcher`]
//! interface and its [`WatchHandle`].
//!
//! Portable implementation: [`none::NoSessionWatcher`], for platforms that can't watch
//! processes.

pub mod none;

use writ_core::caller::ProcessRef;

use crate::Result;

/// Called once when the watched process ends. It must not take a lock the caller of
/// [`SessionWatcher::watch`] may hold: a watcher that can't start a thread to call it calls it
/// in place ([`call_soon`]).
pub type OnExit = Box<dyn FnOnce() + Send + 'static>;

/// Calls `on_exit` and survives it: a callback that panics is logged, and the watcher's thread
/// goes on saying the other exits (the review after M7.6, L-6: one panic ended it for good,
/// and every later exit was missed).
pub fn say_exit(on_exit: OnExit) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(on_exit)).is_err() {
        tracing::error!("a session's exit notice panicked; the watcher goes on");
    }
}

/// Calls `on_exit` off the caller's thread (a watch is often set under a lock the callback
/// takes); when no thread can start, in place rather than never (fail closed: a notice lost
/// would leave a lease bound to an ended session in force).
pub fn call_soon(on_exit: OnExit) {
    // The callback is handed back when the thread can't start: `spawn` drops its closure.
    let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(on_exit)));
    let theirs = slot.clone();
    let started = std::thread::Builder::new()
        .name("writ-session-exit".to_owned())
        .spawn(move || {
            // poisoned: the callback is taken all the same (a reduction of privilege).
            let taken = theirs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(on_exit) = taken {
                say_exit(on_exit);
            }
        });
    if let Err(e) = started {
        tracing::error!(error = %e, "cannot start a thread to say a session ended: said in place");
        let taken = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(on_exit) = taken {
            say_exit(on_exit);
        }
    }
}

/// Calls back once when a process ends (kqueue `NOTE_EXIT` on macOS, a pidfd on Linux).
pub trait SessionWatcher: Send + Sync {
    /// Watches `process` (pid and generation: a reused pid is another process). `on_exit` is
    /// called exactly once when it ends, or promptly if it already ended or its generation
    /// doesn't match. Dropping the returned handle cancels the watch: `on_exit` is then never
    /// called. Implementations that can't watch processes return
    /// [`PlatformError::Unsupported`] for every call.
    fn watch(&self, process: &ProcessRef, on_exit: OnExit) -> Result<WatchHandle>;
}

/// A watch in progress. Dropping it cancels the watch.
pub struct WatchHandle {
    cancel: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl WatchHandle {
    /// A handle whose drop runs `cancel`.
    pub fn new(cancel: impl FnOnce() + Send + 'static) -> Self {
        Self {
            cancel: Some(Box::new(cancel)),
        }
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

impl std::fmt::Debug for WatchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WatchHandle")
    }
}
