//! [`NoSessionWatcher`]: for platforms that can't watch processes.

use writ_core::caller::ProcessRef;

use super::{OnExit, SessionWatcher, WatchHandle};
use crate::{PlatformError, Result};

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
