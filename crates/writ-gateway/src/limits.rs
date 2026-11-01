//! Bounds on what a peer can make the gateway hold, whoever it is: connections per listener
//! and per source, time to authenticate, channels per connection, time to send a request
//! body, sign requests held at once, and the length of what it chose that ends up in the
//! audit log before it is authenticated. Denials before authentication are coalesced per source: one audit line a
//! minute with the count of the others, so a flood can't fill the disk.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
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
/// How long a lease holder has to send a sign request's body (up to 16 MiB, over a VPN).
pub(crate) const SIGN_BODY_DEADLINE: Duration = Duration::from_secs(60);
/// Sign requests the daemon holds at once, all lease holders together, from reading the body
/// to the answer: each holds up to 16 MiB, and the signer's queue takes no more than this.
pub(crate) const MAX_SIGN_REQUESTS: usize = 16;
/// A connection with no traffic at all for this long is closed.
pub(crate) const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
/// The longest text chosen by an unauthenticated peer (a certificate's key id) that is logged.
pub(crate) const MAX_LOGGED_TEXT: usize = 64;
/// One audit line per source and kind of denial in this window; the rest are counted.
const DENIAL_WINDOW: Duration = Duration::from_secs(60);
/// Audit lines for denials before authentication, all sources together, per window: past it,
/// denials are only counted (many sources at once can't fill the disk either).
const MAX_DENIAL_LINES: u32 = 60;
/// Sources tracked for coalescing; past it the table starts over (each source then logs once
/// more, which bounds the table without losing a denial).
const MAX_TRACKED_SOURCES: usize = 4096;

/// `text` cut to `max` characters (with `…`), for what an unauthenticated peer chose.
pub(crate) use writ_core::text::shown;

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

    /// A slot for a connection from `source` (counted by its group: an IPv6 /64), or why
    /// there is none.
    pub(crate) fn take(&self, source: Option<IpAddr>) -> Result<Slot, &'static str> {
        let source = source.map(writ_core::net::source_group);
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

/// Reads `reader` to its end within `deadline`, keeping at most `max + 1` bytes: one more
/// than `max` tells the caller the body was over it, without reading the rest.
pub(crate) async fn read_within(
    reader: impl AsyncRead + Unpin,
    max: usize,
    deadline: Duration,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    match tokio::time::timeout(deadline, reader.take(limit).read_to_end(&mut body)).await {
        Err(_) => Err("the request body took too long to arrive".to_owned()),
        Ok(Err(e)) => Err(format!("cannot read the request: {e}")),
        Ok(Ok(_)) => Ok(body),
    }
}

/// The daemon's sign request slots ([`MAX_SIGN_REQUESTS`]): one is taken before a body is
/// read and kept until the request is answered. None free: refused at once, never queued.
pub(crate) struct SignSlots {
    slots: Arc<Semaphore>,
    max: usize,
}

impl SignSlots {
    pub(crate) fn new() -> Self {
        Self::with(MAX_SIGN_REQUESTS)
    }

    fn with(max: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max)),
            max,
        }
    }

    /// A slot, or why there is none.
    pub(crate) fn take(&self) -> Result<OwnedSemaphorePermit, String> {
        self.slots.clone().try_acquire_owned().map_err(|_| {
            format!(
                "the daemon already holds {} sign requests; retry shortly",
                self.max
            )
        })
    }
}

/// Coalesces denials before authentication: per source and kind, the first in a window is
/// logged, the others counted and reported with the next one logged.
pub(crate) struct DenialThrottle {
    windows: Mutex<HashMap<(Option<IpAddr>, &'static str), Window>>,
    /// Lines logged in the current global window, and denials not logged for its budget.
    global: Mutex<GlobalWindow>,
}

struct GlobalWindow {
    started: Instant,
    logged: u32,
    suppressed: u64,
}

struct Window {
    started: Instant,
    suppressed: u64,
}

impl DenialThrottle {
    pub(crate) fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            global: Mutex::new(GlobalWindow {
                started: Instant::now(),
                logged: 0,
                suppressed: 0,
            }),
        }
    }

    /// Whether to log this denial now: `Some(n)` with the number of denials not logged since
    /// the last line (this source's, and any the global budget held back), `None` to only
    /// count it. Sources are grouped (an IPv6 /64). A poisoned table logs everything.
    pub(crate) fn admit(&self, source: Option<IpAddr>, kind: &'static str) -> Option<u64> {
        let suppressed = self.admit_source(source.map(writ_core::net::source_group), kind)?;
        // poisoned: every line is logged then (fail toward the audit log, never silence).
        let Ok(mut global) = self.global.lock() else {
            return Some(suppressed);
        };
        let now = Instant::now();
        if now.duration_since(global.started) >= DENIAL_WINDOW {
            global.started = now;
            global.logged = 0;
        }
        if global.logged >= MAX_DENIAL_LINES {
            global.suppressed = global
                .suppressed
                .saturating_add(suppressed.saturating_add(1));
            return None;
        }
        global.logged = global.logged.saturating_add(1);
        Some(suppressed.saturating_add(std::mem::take(&mut global.suppressed)))
    }

    fn admit_source(&self, source: Option<IpAddr>, kind: &'static str) -> Option<u64> {
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
        // An IPv6 host is its /64: rotating addresses inside it is one source.
        assert_eq!(throttle.admit(ip("2001:db8::1"), "cap"), Some(0));
        assert_eq!(throttle.admit(ip("2001:db8::2"), "cap"), None);
        assert_eq!(
            with_suppressed("over the cap".into(), 3),
            "over the cap (and 3 more from this address since the last line)"
        );
        assert_eq!(with_suppressed("over the cap".into(), 0), "over the cap");
    }

    #[tokio::test(start_paused = true)]
    async fn many_sources_at_once_still_log_a_bounded_number_of_lines() {
        let throttle = DenialThrottle::new();
        let source = |n: u32| Some(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)));
        let logged = (0..MAX_DENIAL_LINES + 10)
            .filter(|&n| throttle.admit(source(n), "cap").is_some())
            .count();
        assert_eq!(logged, MAX_DENIAL_LINES as usize, "the global budget holds");
        // In the next window, the next line carries the count of those not logged.
        tokio::time::advance(DENIAL_WINDOW).await;
        assert_eq!(throttle.admit(source(1_000), "cap"), Some(10));
    }

    #[test]
    fn an_ipv6_host_gets_one_share_of_slots() {
        let slots = Slots::with(MAX_CONNECTIONS);
        let addr = |n: u16| {
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, n,
            )))
        };
        let held: Vec<Slot> = (0..u16::try_from(MAX_CONNECTIONS_PER_SOURCE).unwrap())
            .map(|n| slots.take(addr(n)).unwrap())
            .collect();
        assert_eq!(
            slots.take(addr(999)).err(),
            Some("too many open connections from this address"),
            "another address in the same /64"
        );
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_is_read_within_its_deadline_and_refused_past_it() {
        const MAX: usize = 8;
        let deadline = Duration::from_secs(60);
        // Sends `first`, waits `pause`, sends `rest`, then ends the stream (EOF).
        let read = |first: &'static [u8], pause: Duration, rest: &'static [u8]| async move {
            let (mut client, server) = tokio::io::duplex(64);
            let sender = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                client.write_all(first).await.unwrap();
                // poll: nothing; paused time (`start_paused`): this moves the test clock to
                // the next deadline at once, nothing waits for real.
                tokio::time::sleep(pause).await;
                // The reader may have given up: a refused write is the point then.
                let _ = client.write_all(rest).await;
            });
            let read = read_within(server, MAX, deadline).await;
            sender.abort();
            read
        };
        let second = Duration::from_secs(1);
        // Up to the limit, and one byte more (the caller refuses it for its size).
        assert_eq!(read(b"1234", second, b"5678").await.unwrap(), b"12345678");
        assert_eq!(read(b"1234", second, b"56789").await.unwrap(), b"123456789");
        // Never more than one byte over, however much is sent.
        assert_eq!(
            read(b"1234", second, b"56789abcdef").await.unwrap().len(),
            MAX + 1
        );
        // The last byte just in time, then just too late.
        assert!(read(b"1234", deadline - second, b"5678").await.is_ok());
        assert_eq!(
            read(b"1234", deadline + second, b"5678").await,
            Err("the request body took too long to arrive".to_owned())
        );
        // A body that never ends (no EOF) is cut at the deadline too.
        assert_eq!(
            read(b"1234", Duration::from_secs(3600), b"").await,
            Err("the request body took too long to arrive".to_owned())
        );
    }

    #[test]
    fn sign_slots_are_bounded_and_given_back() {
        let slots = SignSlots::with(3);
        let held: Vec<OwnedSemaphorePermit> = (0..3).map(|_| slots.take().unwrap()).collect();
        assert_eq!(
            slots.take().err(),
            Some("the daemon already holds 3 sign requests; retry shortly".to_owned())
        );
        drop(held);
        assert!(
            slots.take().is_ok(),
            "a slot comes back when its request ends"
        );
        assert_eq!(SignSlots::new().max, MAX_SIGN_REQUESTS);
    }

    #[test]
    fn long_text_from_a_stranger_is_cut() {
        assert_eq!(shown("short", 64), "short");
        assert_eq!(shown(&"k".repeat(64), 64), "k".repeat(64));
        assert_eq!(shown(&"k".repeat(65), 64), format!("{}…", "k".repeat(64)));
        assert_eq!(shown("ééé", 2), "éé…");
    }
}
