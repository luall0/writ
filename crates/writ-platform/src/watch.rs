//! A notice when a session's root process exits, to revoke its lease: the [`SessionWatcher`]
//! interface and [`NoSessionWatcher`], for platforms that can't watch processes.

use writ_core::caller::ProcessRef;

use crate::{PlatformError, Result};

/// Called once when the watched process ends.
pub type OnExit = Box<dyn FnOnce() + Send + 'static>;

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

/// The detached mode's watcher: a container can't see the agent's processes, so every watch is
/// [`PlatformError::Unsupported`] and no callback is ever called.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSessionWatcher;

impl NoSessionWatcher {
    pub fn new() -> Self {
        Self
    }
}

impl SessionWatcher for NoSessionWatcher {
    fn watch(&self, _process: &ProcessRef, _on_exit: OnExit) -> Result<WatchHandle> {
        Err(PlatformError::Unsupported("session watching"))
    }
}
