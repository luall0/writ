//! Bounds on what a peer can make the gateway hold, whoever it is: connections per listener
//! and per source, time to authenticate, channels per connection, time to send a request
//! body, and the length of what it chose that ends up in the audit log before it is
//! authenticated. Denials before authentication are coalesced per source: one audit line a
//! minute with the count of the others, so a flood can't fill the disk.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Open connections per listener.
pub(crate) const MAX_CONNECTIONS: usize = 256;
/// Open connections per source address (all local callers count as one source).
pub(crate) const MAX_CONNECTIONS_PER_SOURCE: usize = 16;
/// How long a client has to authenticate (SSH) or finish its handshake (TLS).
pub(crate) const AUTH_DEADLINE: Duration = Duration::from_secs(20);
/// Channels open at once on one SSH connection.
pub(crate) const MAX_CHANNELS: usize = 4;
/// How long a client has to send a request body.
pub(crate) const BODY_DEADLINE: Duration = Duration::from_secs(30);
/// A connection with no traffic at all for this long is closed.
pub(crate) const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
/// The longest text chosen by an unauthenticated peer (a certificate's key id) that is logged.
pub(crate) const MAX_LOGGED_TEXT: usize = 64;
/// One audit line per source and kind of denial in this window; the rest are counted.
const DENIAL_WINDOW: Duration = Duration::from_secs(60);
/// Sources tracked for coalescing; past it the table starts over (each source then logs once
/// more, which bounds the table without losing a denial).
const MAX_TRACKED_SOURCES: usize = 4096;

/// `text` cut to `max` characters (with `…`), for what an unauthenticated peer chose.
pub(crate) fn shown(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let mut out: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// The connection slots of one listener.
pub(crate) struct Slots {
    total: Arc<Semaphore>,
    per_source: Arc<Mutex<HashMap<Option<IpAddr>, usize>>>,
}

/// A taken slot, given back when the connection ends.
pub(crate) struct Slot {
    _total: OwnedSemaphorePermit,
    source: Option<IpAddr>,
    per_source: Arc<Mutex<HashMap<Option<IpAddr>, usize>>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        // poisoned: the count stays up, so the source gets fewer connections (fail closed).
        if let Ok(mut counts) = self.per_source.lock()
            && let Some(count) = counts.get_mut(&self.source)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

impl Slots {
    pub(crate) fn new() -> Self {
        Self::with(MAX_CONNECTIONS)
    }

    fn with(total: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_source: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A slot for a connection from `source`, or why there is none.
    pub(crate) fn take(&self, source: Option<IpAddr>) -> Result<Slot, &'static str> {
        let total = self
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many open connections")?;
        // A poisoned table fails closed: no slot.
        let mut counts = self
            .per_source
            .lock()
            .map_err(|_| "too many open connections")?;
        let count = counts.entry(source).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SOURCE {
            return Err("too many open connections from this address");
        }
        *count += 1;
        Ok(Slot {
            _total: total,
            source,
            per_source: self.per_source.clone(),
        })
    }
}

/// Coalesces denials before authentication: per source and kind, the first in a window is
/// logged, the others counted and reported with the next one logged.
pub(crate) struct DenialThrottle {
    windows: Mutex<HashMap<(Option<IpAddr>, &'static str), Window>>,
}

struct Window {
    started: Instant,
    suppressed: u64,
}

impl DenialThrottle {
    pub(crate) fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Whether to log this denial now: `Some(n)` with the number of the same denials not
    /// logged since the last line, `None` to only count it. A poisoned table logs everything.
    pub(crate) fn admit(&self, source: Option<IpAddr>, kind: &'static str) -> Option<u64> {
        let Ok(mut windows) = self.windows.lock() else {
            return Some(0);
        };
        let now = Instant::now();
        if windows.len() >= MAX_TRACKED_SOURCES && !windows.contains_key(&(source, kind)) {
            windows.clear();
        }
        match windows.get_mut(&(source, kind)) {
            Some(window) if now.duration_since(window.started) < DENIAL_WINDOW => {
                window.suppressed += 1;
                None
            }
            Some(window) => {
                let suppressed = window.suppressed;
                *window = Window {
                    started: now,
                    suppressed: 0,
                };
                Some(suppressed)
            }
            None => {
                windows.insert(
                    (source, kind),
                    Window {
                        started: now,
                        suppressed: 0,
                    },
                );
                Some(0)
            }
        }
    }
}

/// The reason to log for a coalesced denial.
pub(crate) fn with_suppressed(reason: String, suppressed: u64) -> String {
    if suppressed == 0 {
        reason
    } else {
        format!("{reason} (and {suppressed} more from this address since the last line)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn each_source_gets_its_share_and_the_listener_its_total() {
        let slots = Slots::with(MAX_CONNECTIONS_PER_SOURCE + 1);
        let a: Vec<Slot> = (0..MAX_CONNECTIONS_PER_SOURCE)
            .map(|_| slots.take(ip("10.0.0.1")).unwrap())
            .collect();
        assert_eq!(
            slots.take(ip("10.0.0.1")).err(),
            Some("too many open connections from this address")
        );
        let b = slots.take(ip("10.0.0.2")).unwrap();
        assert_eq!(
            slots.take(ip("10.0.0.3")).err(),
            Some("too many open connections")
        );
        drop(b);
        drop(a);
        // Given back when the connections end.
        assert!(slots.take(ip("10.0.0.1")).is_ok());
        assert!(slots.per_source.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn denials_from_one_source_are_coalesced_per_window() {
        let throttle = DenialThrottle::new();
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), Some(0));
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        // Another source, or another kind, has its own window.
        assert_eq!(throttle.admit(ip("10.0.0.2"), "cap"), Some(0));
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cert"), Some(0));
        tokio::time::advance(DENIAL_WINDOW - Duration::from_secs(1)).await;
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            throttle.admit(ip("10.0.0.1"), "cap"),
            Some(3),
            "the count is kept"
        );
        assert_eq!(
            with_suppressed("over the cap".into(), 3),
            "over the cap (and 3 more from this address since the last line)"
        );
        assert_eq!(with_suppressed("over the cap".into(), 0), "over the cap");
    }

    #[test]
    fn long_text_from_a_stranger_is_cut() {
        assert_eq!(shown("short", 64), "short");
        assert_eq!(shown(&"k".repeat(64), 64), "k".repeat(64));
        assert_eq!(shown(&"k".repeat(65), 64), format!("{}…", "k".repeat(64)));
        assert_eq!(shown("ééé", 2), "éé…");
    }
}
