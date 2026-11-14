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
use zeroize::Zeroizing;

/// Open connections per listener.
pub(crate) const MAX_CONNECTIONS: usize = 256;
/// Open connections per source: a network address (its group, an IPv6 /64), or on a Unix
/// socket the caller process the kernel attested (the review after M7.6, G-2: every local
/// caller counted as one source, so one agent could hold all of the approver's slots).
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
pub const MAX_SIGN_REQUESTS: usize = 16;
/// Sign requests one lease may have held at once, unless the operator says otherwise
/// (`sign_requests.per_lease`, 1 to [`MAX_SIGN_REQUESTS`]): one lease can't take every slot.
pub const DEFAULT_SIGN_REQUESTS_PER_LEASE: usize = 4;
/// Watches (`writ watch`, M7.8) held at once, all readers together: each holds a connection
/// for up to `WATCH_LIMIT`, so the approval popup's and a few terminals' fit, and no more.
pub(crate) const MAX_WATCHES: usize = 16;
/// A connection with no traffic at all for this long is closed.
pub(crate) const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
/// The longest text chosen by an unauthenticated peer (a certificate's key id) that is logged.
pub(crate) const MAX_LOGGED_TEXT: usize = 64;
/// One audit line per source and kind of denial in this window; the rest are counted.
pub(crate) const DENIAL_WINDOW: Duration = Duration::from_secs(60);
/// Audit lines for denials before authentication, all sources together, per window: past it,
/// denials are only counted (many sources at once can't fill the disk either).
const MAX_DENIAL_LINES: u32 = 60;
/// Sources tracked for coalescing; past it the table starts over (each source then logs once
/// more, which bounds the table without losing a denial).
const MAX_TRACKED_SOURCES: usize = 4096;

/// `text` cut to `max` characters (with `…`), for what an unauthenticated peer chose.
pub(crate) use writ_core::text::shown;

/// Who a connection counts against for [`MAX_CONNECTIONS_PER_SOURCE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SlotSource {
    /// A network peer: its address's group (an IPv6 /64); `None` for a local caller nothing
    /// is known of (they all share one share then).
    Address(Option<IpAddr>),
    /// A local caller: its process, by pid and generation (a reused pid is another process).
    Process { pid: u32, generation: u64 },
}

impl SlotSource {
    /// The source of a caller: its address when it has one (TCP, unchanged); else the first
    /// process of its attested chain (a Unix socket); else what the kernel's peer credentials
    /// say of the process (an approval listener's caller without a chain, L-7); else the one
    /// shared local source.
    pub(crate) fn of(
        facts: &writ_core::caller::CallerFacts,
        peer: &writ_platform::PeerInfo,
    ) -> Self {
        if let Some(address) = facts.source_addr {
            return Self::Address(Some(writ_core::net::source_group(address)));
        }
        if let Some(caller) = facts.process_chain.as_ref().and_then(|chain| chain.first()) {
            return Self::Process {
                pid: caller.pid,
                generation: caller.generation,
            };
        }
        match peer {
            writ_platform::PeerInfo::Unix {
                pid: Some(pid),
                generation,
                ..
            } => Self::Process {
                pid: *pid,
                generation: generation.unwrap_or(0),
            },
            _ => Self::Address(None),
        }
    }
}

/// The connection slots of one listener.
pub(crate) struct Slots {
    total: Arc<Semaphore>,
    per_source: Arc<Mutex<HashMap<SlotSource, usize>>>,
}

/// A taken slot, given back when the connection ends.
pub(crate) struct Slot {
    _total: OwnedSemaphorePermit,
    source: SlotSource,
    per_source: Arc<Mutex<HashMap<SlotSource, usize>>>,
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

    /// A slot for a connection from `source` ([`SlotSource::of`]), or why there is none.
    pub(crate) fn take(&self, source: SlotSource) -> Result<Slot, &'static str> {
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
            return Err(match source {
                SlotSource::Address(_) => "too many open connections from this address",
                SlotSource::Process { .. } => "too many open connections from this process",
            });
        }
        *count = count.saturating_add(1);
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
) -> Result<Zeroizing<Vec<u8>>, String> {
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    match tokio::time::timeout(deadline, read_wiped(reader.take(limit))).await {
        Err(_) => Err("the request body took too long to arrive".to_owned()),
        Ok(Err(e)) => Err(format!("cannot read the request: {e}")),
        Ok(Ok(body)) => Ok(body),
    }
}

/// Everything `reader` gives, in memory wiped on drop at every step: a body may hold the
/// keystore's passphrase (`writ unseal`), and a `Vec` growing by itself frees each smaller
/// buffer unwiped. Each one is wiped here before it goes (the review after M5.5).
async fn read_wiped(mut reader: impl AsyncRead + Unpin) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = reader.read(&mut chunk[..]).await?;
        if n == 0 {
            return Ok(body);
        }
        let read = chunk.get(..n).unwrap_or_default();
        let needed = body.len().saturating_add(n);
        if needed > body.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(
                needed.max(body.capacity().saturating_mul(2)),
            ));
            bigger.extend_from_slice(&body);
            body = bigger;
        }
        body.extend_from_slice(read);
    }
}

/// The daemon's sign request slots: [`MAX_SIGN_REQUESTS`] in all, and the operator's number
/// per lease (by its certificate's serial), so one lease can't hold them all. One is taken
/// before a body is read and kept until the request is answered. None free: refused at
/// once, never queued.
pub(crate) struct SignSlots {
    total: Arc<Semaphore>,
    max: usize,
    per_lease: usize,
    leases: Arc<Mutex<HashMap<u64, usize>>>,
}

/// A taken sign slot, given back (in all and for its lease) when dropped.
pub(crate) struct SignSlot {
    _total: OwnedSemaphorePermit,
    serial: u64,
    leases: Arc<Mutex<HashMap<u64, usize>>>,
}

impl Drop for SignSlot {
    fn drop(&mut self) {
        // poisoned: the lease's count stays up, so it gets fewer slots (fail closed).
        if let Ok(mut counts) = self.leases.lock()
            && let Some(count) = counts.get_mut(&self.serial)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.serial);
            }
        }
    }
}

impl SignSlots {
    /// `per_lease` slots per lease, from 1 to [`MAX_SIGN_REQUESTS`].
    pub(crate) fn new(per_lease: usize) -> Result<Self, String> {
        Self::with(MAX_SIGN_REQUESTS, per_lease)
    }

    fn with(max: usize, per_lease: usize) -> Result<Self, String> {
        if !(1..=max).contains(&per_lease) {
            return Err(format!(
                "sign_requests.per_lease: {per_lease}, must be from 1 to {max}"
            ));
        }
        Ok(Self {
            total: Arc::new(Semaphore::new(max)),
            max,
            per_lease,
            leases: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// A slot for a request of the lease whose certificate has `serial`, or why there is none.
    pub(crate) fn take(&self, serial: u64) -> Result<SignSlot, String> {
        let total = self.total.clone().try_acquire_owned().map_err(|_| {
            format!(
                "the daemon already holds {} sign requests; retry shortly",
                self.max
            )
        })?;
        let busy = || {
            format!(
                "this lease already has {} sign requests in progress; retry shortly",
                self.per_lease
            )
        };
        // A poisoned table fails closed: no slot.
        let mut counts = self.leases.lock().map_err(|_| busy())?;
        let count = counts.entry(serial).or_insert(0);
        if *count >= self.per_lease {
            return Err(busy());
        }
        *count = count.saturating_add(1);
        Ok(SignSlot {
            _total: total,
            serial,
            leases: self.leases.clone(),
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

    /// Whether to log this denial now: `Some` with the denials not logged since the last line,
    /// this source's apart from those the global budget held back (from any source: the
    /// review after M7.6, G-11, a line credited them all to the source it named), `None` to
    /// only count it. Sources are grouped (an IPv6 /64). A poisoned table logs everything.
    pub(crate) fn admit(&self, source: Option<IpAddr>, kind: &'static str) -> Option<Suppressed> {
        let own = self.admit_source(source.map(writ_core::net::source_group), kind)?;
        // poisoned: every line is logged then (fail toward the audit log, never silence).
        let Ok(mut global) = self.global.lock() else {
            return Some(Suppressed { own, others: 0 });
        };
        let now = Instant::now();
        if now.duration_since(global.started) >= DENIAL_WINDOW {
            global.started = now;
            global.logged = 0;
        }
        if global.logged >= MAX_DENIAL_LINES {
            // Held back: this one and the source's count go to the next line logged, from
            // whatever source, as others'.
            global.suppressed = global.suppressed.saturating_add(own.saturating_add(1));
            return None;
        }
        global.logged = global.logged.saturating_add(1);
        Some(Suppressed {
            own,
            others: std::mem::take(&mut global.suppressed),
        })
    }

    fn admit_source(&self, source: Option<IpAddr>, kind: &'static str) -> Option<u64> {
        let Ok(mut windows) = self.windows.lock() else {
            return Some(0);
        };
        let now = Instant::now();
        if windows.len() >= MAX_TRACKED_SOURCES && !windows.contains_key(&(source, kind)) {
            // The table is full: emptied, and every count it held carried to the next line
            // logged, so no denial is lost (the review after M5.5).
            let carried = windows
                .drain()
                .fold(0u64, |sum, (_, w)| sum.saturating_add(w.suppressed));
            // poisoned: the counts are plain numbers; the last ones written stand.
            let mut global = self
                .global
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            global.suppressed = global.suppressed.saturating_add(carried);
        }
        match windows.get_mut(&(source, kind)) {
            Some(window) if now.duration_since(window.started) < DENIAL_WINDOW => {
                window.suppressed = window.suppressed.saturating_add(1);
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

impl DenialThrottle {
    /// The denials counted and never logged so far: those of windows that ended without a
    /// later denial from their source to carry them, and those the global budget held back.
    /// Called once a window by the gateway, which logs them as one line, so a source that goes
    /// quiet still has its count written.
    pub(crate) fn flush(&self) -> u64 {
        let now = Instant::now();
        let mut expired = 0u64;
        // poisoned: the counts are plain numbers; the last ones written stand.
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, w| {
                let over = now.duration_since(w.started) >= DENIAL_WINDOW;
                if over {
                    expired = expired.saturating_add(w.suppressed);
                }
                !over
            });
        let held = std::mem::take(
            &mut self
                .global
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .suppressed,
        );
        expired.saturating_add(held)
    }
}

/// The denials a line logged now stands for besides its own ([`DenialThrottle::admit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Suppressed {
    /// This source's, of this kind, since its last line.
    pub own: u64,
    /// Those the global budget held back, or a full table carried, from any source.
    pub others: u64,
}

/// The reason to log for a coalesced denial: the source's own count apart from the others'.
pub(crate) fn with_suppressed(reason: String, suppressed: Suppressed) -> String {
    match (suppressed.own, suppressed.others) {
        (0, 0) => reason,
        (own, 0) => format!("{reason} (and {own} more from this address since the last line)"),
        (0, others) => format!(
            "{reason} (and {others} more from any address held back by the line budget since the \
             last line)"
        ),
        (own, others) => format!(
            "{reason} (and {own} more from this address, and {others} from any address held \
             back by the line budget, since the last line)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    /// A TCP peer's slot source, as [`SlotSource::of`] makes it.
    fn tcp(text: &str) -> SlotSource {
        let address: IpAddr = text.parse().unwrap();
        let facts = writ_core::caller::CallerFacts {
            source_addr: Some(address),
            process_chain: None,
        };
        SlotSource::of(
            &facts,
            &writ_platform::PeerInfo::Tcp {
                remote: std::net::SocketAddr::new(address, 40_000),
            },
        )
    }

    #[test]
    fn each_source_gets_its_share_and_the_listener_its_total() {
        let slots = Slots::with(MAX_CONNECTIONS_PER_SOURCE + 1);
        let a: Vec<Slot> = (0..MAX_CONNECTIONS_PER_SOURCE)
            .map(|_| slots.take(tcp("10.0.0.1")).unwrap())
            .collect();
        assert_eq!(
            slots.take(tcp("10.0.0.1")).err(),
            Some("too many open connections from this address")
        );
        let b = slots.take(tcp("10.0.0.2")).unwrap();
        assert_eq!(
            slots.take(tcp("10.0.0.3")).err(),
            Some("too many open connections")
        );
        drop(b);
        drop(a);
        // Given back when the connections end.
        assert!(slots.take(tcp("10.0.0.1")).is_ok());
        assert!(slots.per_source.lock().unwrap().is_empty());
    }

    /// The review after M7.6, G-2: on a Unix socket every caller was the one source `None`, so
    /// one local process holding 16 connections shut the approver out. Each attested process
    /// now has its own share, under the listener's total; a pid reused is another process.
    #[test]
    fn on_a_unix_socket_each_caller_process_gets_its_own_share() {
        use writ_core::caller::{CallerFacts, ProcessRef};
        let unix = |pid: u32, generation: u64| {
            let facts = CallerFacts {
                source_addr: None,
                process_chain: Some(vec![
                    ProcessRef {
                        pid,
                        generation,
                        executable: "/usr/bin/agent".into(),
                        code_identity: None,
                        unbindable: None,
                    },
                    ProcessRef {
                        pid: 1,
                        generation: 1,
                        executable: "/sbin/launchd".into(),
                        code_identity: None,
                        unbindable: None,
                    },
                ]),
            };
            let peer = writ_platform::PeerInfo::Unix {
                uid: 501,
                gid: 20,
                pid: Some(pid),
                generation: Some(generation),
            };
            SlotSource::of(&facts, &peer)
        };
        assert_eq!(
            unix(100, 7),
            SlotSource::Process {
                pid: 100,
                generation: 7
            }
        );
        let slots = Slots::with(2 * MAX_CONNECTIONS_PER_SOURCE + 1);
        let agent: Vec<Slot> = (0..MAX_CONNECTIONS_PER_SOURCE)
            .map(|_| slots.take(unix(100, 7)).unwrap())
            .collect();
        // At its share, and one past it.
        assert_eq!(
            slots.take(unix(100, 7)).err(),
            Some("too many open connections from this process")
        );
        // The approver's `writ`, another process of the same user, still gets in; so does a
        // process that got the agent's pid back (another generation).
        let approver: Vec<Slot> = (0..MAX_CONNECTIONS_PER_SOURCE)
            .map(|_| slots.take(unix(200, 1)).unwrap())
            .collect();
        let reused = slots.take(unix(100, 8)).unwrap();
        // The listener's total still holds, whatever the processes.
        assert_eq!(
            slots.take(unix(300, 1)).err(),
            Some("too many open connections")
        );
        drop((agent, approver, reused));
        assert!(slots.per_source.lock().unwrap().is_empty());

        // Without a chain (an approval listener whose process reader broke, L-7), the
        // kernel's peer credentials still name the process; with nothing at all, the callers
        // share one source, as before.
        let peer = |pid| writ_platform::PeerInfo::Unix {
            uid: 501,
            gid: 20,
            pid,
            generation: Some(3),
        };
        assert_eq!(
            SlotSource::of(&CallerFacts::default(), &peer(Some(42))),
            SlotSource::Process {
                pid: 42,
                generation: 3
            }
        );
        assert_eq!(
            SlotSource::of(&CallerFacts::default(), &peer(None)),
            SlotSource::Address(None)
        );
        // A TCP peer is its address group, whatever else is known.
        assert_eq!(tcp("10.0.0.1"), SlotSource::Address(ip("10.0.0.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn denials_from_one_source_are_coalesced_per_window() {
        let throttle = DenialThrottle::new();
        let own = |own| Some(Suppressed { own, others: 0 });
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), own(0));
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        // Another source, or another kind, has its own window.
        assert_eq!(throttle.admit(ip("10.0.0.2"), "cap"), own(0));
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cert"), own(0));
        tokio::time::advance(DENIAL_WINDOW - Duration::from_secs(1)).await;
        assert_eq!(throttle.admit(ip("10.0.0.1"), "cap"), None);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            throttle.admit(ip("10.0.0.1"), "cap"),
            own(3),
            "the count is kept"
        );
        // An IPv6 host is its /64: rotating addresses inside it is one source.
        assert_eq!(throttle.admit(ip("2001:db8::1"), "cap"), own(0));
        assert_eq!(throttle.admit(ip("2001:db8::2"), "cap"), None);
        assert_eq!(
            with_suppressed("over the cap".into(), Suppressed { own: 3, others: 0 }),
            "over the cap (and 3 more from this address since the last line)"
        );
        assert_eq!(
            with_suppressed("over the cap".into(), Suppressed { own: 0, others: 0 }),
            "over the cap"
        );
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
        assert_eq!(
            throttle.admit(source(1_000), "cap"),
            Some(Suppressed { own: 0, others: 10 }),
            "the others' count, not this source's"
        );
    }

    /// The review after M7.6, G-11: after a flood from many sources, the next line named one
    /// address with every denial the budget held back. Its own count is now apart.
    #[tokio::test(start_paused = true)]
    async fn a_line_counts_its_source_s_denials_apart_from_the_others() {
        let throttle = DenialThrottle::new();
        let source = |n: u32| Some(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)));
        // The budget spent by as many sources, then 5 more held back.
        for n in 0..MAX_DENIAL_LINES + 5 {
            throttle.admit(source(n), "cap");
        }
        // 10.9.9.9 is denied twice more in its window (counted), then logs in the next one.
        let quiet = ip("10.9.9.9");
        tokio::time::advance(DENIAL_WINDOW).await;
        assert_eq!(
            throttle.admit(quiet, "cap"),
            Some(Suppressed { own: 0, others: 5 })
        );
        assert_eq!(throttle.admit(quiet, "cap"), None);
        assert_eq!(throttle.admit(quiet, "cap"), None);
        tokio::time::advance(DENIAL_WINDOW).await;
        let suppressed = throttle.admit(quiet, "cap").unwrap();
        assert_eq!(suppressed, Suppressed { own: 2, others: 0 });
        assert_eq!(
            with_suppressed("over the cap".into(), Suppressed { own: 0, others: 5 }),
            "over the cap (and 5 more from any address held back by the line budget since the \
             last line)"
        );
        assert_eq!(
            with_suppressed("over the cap".into(), Suppressed { own: 2, others: 5 }),
            "over the cap (and 2 more from this address, and 5 from any address held back by \
             the line budget, since the last line)"
        );
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
            .map(|n| {
                slots
                    .take(SlotSource::Address(
                        addr(n).map(writ_core::net::source_group),
                    ))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            slots
                .take(SlotSource::Address(
                    addr(999).map(writ_core::net::source_group)
                ))
                .err(),
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
        assert_eq!(
            read(b"1234", second, b"5678").await.unwrap().as_slice(),
            b"12345678"
        );
        assert_eq!(
            read(b"1234", second, b"56789").await.unwrap().as_slice(),
            b"123456789"
        );
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
    fn sign_slots_are_bounded_in_all_and_per_lease() {
        let slots = SignSlots::with(5, 2).unwrap();
        // A lease gets its share, not one more; another lease still gets in.
        let first: Vec<SignSlot> = (0..2).map(|_| slots.take(1).unwrap()).collect();
        assert_eq!(
            slots.take(1).err(),
            Some("this lease already has 2 sign requests in progress; retry shortly".to_owned())
        );
        let second: Vec<SignSlot> = (0..2).map(|_| slots.take(2).unwrap()).collect();
        // In all: 5, whatever the leases.
        let fifth = slots.take(3).unwrap();
        assert_eq!(
            slots.take(4).err(),
            Some("the daemon already holds 5 sign requests; retry shortly".to_owned())
        );
        // A lease turned away by its own share holds no slot in all meanwhile.
        drop(fifth);
        assert_eq!(
            slots.take(1).err(),
            Some("this lease already has 2 sign requests in progress; retry shortly".to_owned())
        );
        assert!(slots.take(4).is_ok(), "the refused take gave its slot back");
        // A slot comes back when its request ends, for its lease too.
        drop(first);
        let again = slots.take(1).unwrap();
        assert_eq!(slots.leases.lock().unwrap().get(&1), Some(&1));
        drop(again);
        assert!(slots.leases.lock().unwrap().get(&1).is_none());
        drop(second);
        assert!(
            slots.leases.lock().unwrap().get(&2).is_none(),
            "forgotten at 0"
        );
    }

    #[test]
    fn the_operator_s_share_per_lease_is_bounded() {
        assert!(SignSlots::new(1).is_ok());
        assert!(SignSlots::new(MAX_SIGN_REQUESTS).is_ok());
        assert_eq!(
            SignSlots::new(0).err(),
            Some("sign_requests.per_lease: 0, must be from 1 to 16".to_owned())
        );
        assert_eq!(
            SignSlots::new(MAX_SIGN_REQUESTS + 1).err(),
            Some("sign_requests.per_lease: 17, must be from 1 to 16".to_owned())
        );
        assert_eq!(SignSlots::new(4).unwrap().max, MAX_SIGN_REQUESTS);
    }

    #[test]
    fn long_text_from_a_stranger_is_cut() {
        assert_eq!(shown("short", 64), "short");
        assert_eq!(shown(&"k".repeat(64), 64), "k".repeat(64));
        assert_eq!(shown(&"k".repeat(65), 64), format!("{}…", "k".repeat(64)));
        assert_eq!(shown("ééé", 2), "éé…");
    }

    /// The review after M5.5: emptying the full table dropped every count it held. Every
    /// denial is now a line, or counted in one, or handed out by `flush`: none is lost.
    #[test]
    fn no_denial_is_lost_when_the_table_is_full() {
        let throttle = DenialThrottle::new();
        let (mut denials, mut accounted) = (0u64, 0u64);
        let mut deny = |source: Option<IpAddr>| {
            denials += 1;
            if let Some(more) = throttle.admit(source, "cap") {
                accounted += 1 + more.own + more.others;
            }
        };
        // Two denials from each of a table's worth of sources, then one from a new source,
        // which empties the full table.
        for i in 0..MAX_TRACKED_SOURCES {
            let [.., hi, lo] = u32::try_from(i).unwrap().to_be_bytes();
            let source = Some(IpAddr::from([10, 1, hi, lo]));
            deny(source);
            deny(source);
        }
        deny(ip("192.0.2.1"));
        let flushed = throttle.flush();
        assert!(flushed > 0, "the global budget held some back");
        assert_eq!(accounted + flushed, denials, "every denial counted once");
        assert_eq!(throttle.flush(), 0, "handed out once");
    }
}
