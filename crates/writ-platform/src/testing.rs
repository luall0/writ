//! Fakes of every platform interface, for the core crates' tests (feature `testing`): the core
//! is tested without any real platform. Each fake passes the same [contract](crate::contract)
//! as the real implementations (see this crate's tests).
//!
//! | Fake | Stands for |
//! |---|---|
//! | [`FakeTransport`] + [`FakeConnector`] | a [`Transport`] over in-memory pipes, any [`PeerInfo`] |
//! | [`FakeAttestor`] | a [`CallerAttestor`] with chosen facts, failing, or network-like |
//! | [`FakeWatcher`] | a [`SessionWatcher`] whose processes the test starts and ends |
//! | [`FakeUnwrap`] + [`FakeRecipient`] | a [`KeystoreUnwrap`] standing for a hardware key: a stanza of its own, refusing on demand, every use counted |
//! | [`RecordingNotifier`] | a [`Notifier`] that records what it delivers, or always fails |
//! | [`FakeClock`] | a [`Clock`] moved by hand |

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use writ_core::caller::{CallerFacts, ProcessRef};

use crate::contract::ProcessDriver;
use crate::{
    BoxFuture, CallerAttestor, Clock, Connection, KeystoreUnwrap, Notification, Notifier, OnExit,
    PeerInfo, PlatformError, Result, SessionWatcher, Transport, WatchHandle,
};

/// Each in-memory connection can buffer this much in each direction.
const DUPLEX_BUFFER: usize = 1024 * 1024;

/// Locks a mutex even if a panicking test poisoned it (the state stays usable for asserts).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ----- Transport -----

/// An in-memory [`Transport`]: each [`FakeConnector::connect`] gives the client end of a pipe,
/// and [`Transport::accept`] the server end with the peer given to `connect`.
pub struct FakeTransport {
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<(DuplexStream, PeerInfo)>>,
}

/// Opens connections to a [`FakeTransport`]. Once every connector is dropped, `accept` fails.
#[derive(Clone)]
pub struct FakeConnector {
    outgoing: mpsc::UnboundedSender<(DuplexStream, PeerInfo)>,
}

impl FakeTransport {
    pub fn new() -> (FakeTransport, FakeConnector) {
        let (outgoing, incoming) = mpsc::unbounded_channel();
        (
            FakeTransport {
                incoming: tokio::sync::Mutex::new(incoming),
            },
            FakeConnector { outgoing },
        )
    }
}

impl FakeConnector {
    /// Connects as `peer` (exactly what the server side's [`Connection::peer`] will be) and
    /// returns the client end. Fails if the transport was dropped.
    pub async fn connect(&self, peer: PeerInfo) -> std::io::Result<DuplexStream> {
        let (client, server) = tokio::io::duplex(DUPLEX_BUFFER);
        self.outgoing.send((server, peer)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "the fake transport was dropped",
            )
        })?;
        Ok(client)
    }
}

impl std::fmt::Debug for FakeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeTransport")
    }
}

impl std::fmt::Debug for FakeConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeConnector")
    }
}

impl Transport for FakeTransport {
    fn accept(&self) -> BoxFuture<'_, Result<Connection>> {
        Box::pin(async move {
            let next = self.incoming.lock().await.recv().await;
            match next {
                Some((stream, peer)) => Ok(Connection {
                    stream: Box::new(stream),
                    peer,
                }),
                None => Err(PlatformError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "every fake connector was dropped",
                ))),
            }
        })
    }

    fn describe(&self) -> String {
        "fake (in memory)".to_owned()
    }
}

// ----- CallerAttestor -----

#[derive(Debug, Clone)]
enum AttestorMode {
    Fixed(CallerFacts),
    Failing,
    NetworkLike,
}

/// A [`CallerAttestor`] whose answers the test picks. Clones share their state.
#[derive(Debug, Clone)]
pub struct FakeAttestor {
    mode: Arc<Mutex<AttestorMode>>,
}

impl FakeAttestor {
    /// Returns `facts` for every peer (e.g. a process chain, to test caller constraints).
    pub fn fixed(facts: CallerFacts) -> Self {
        Self::with_mode(AttestorMode::Fixed(facts))
    }

    /// Fails for every peer.
    pub fn failing() -> Self {
        Self::with_mode(AttestorMode::Failing)
    }

    /// Like [`crate::attest::network::NetworkAttestor`] (a TCP peer's source address, never a process
    /// chain), and also accepts [`PeerInfo::Memory`] with no facts at all. Fails for other
    /// peers.
    pub fn network_like() -> Self {
        Self::with_mode(AttestorMode::NetworkLike)
    }

    /// From now on, returns `facts` for every peer.
    pub fn set_facts(&self, facts: CallerFacts) {
        *lock(&self.mode) = AttestorMode::Fixed(facts);
    }

    /// From now on, fails for every peer.
    pub fn set_failing(&self) {
        *lock(&self.mode) = AttestorMode::Failing;
    }

    fn with_mode(mode: AttestorMode) -> Self {
        Self {
            mode: Arc::new(Mutex::new(mode)),
        }
    }
}

impl CallerAttestor for FakeAttestor {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts> {
        match &*lock(&self.mode) {
            AttestorMode::Fixed(facts) => Ok(facts.clone()),
            AttestorMode::Failing => Err(PlatformError::Attestation(
                "the fake attestor is set to fail".to_owned(),
            )),
            AttestorMode::NetworkLike => match peer {
                PeerInfo::Tcp { remote } => Ok(CallerFacts {
                    source_addr: Some(remote.ip()),
                    process_chain: None,
                }),
                PeerInfo::Memory { .. } => Ok(CallerFacts::default()),
                _ => Err(PlatformError::Attestation(
                    "the network-like fake attestor only attests TCP and memory peers".to_owned(),
                )),
            },
        }
    }
}

// ----- SessionWatcher -----

type ProcessKey = (u32, u64);

#[derive(Default)]
struct WatcherState {
    next_id: u64,
    watches: HashMap<u64, (ProcessKey, OnExit)>,
    /// Processes started with [`FakeWatcher::start`] and not ended.
    running: HashMap<u32, u64>,
    exited: HashSet<ProcessKey>,
    /// Next pid handed out by the [`ProcessDriver`] implementation.
    next_pid: u32,
}

/// A [`SessionWatcher`] whose processes the test controls: [`FakeWatcher::exit`] ends one.
/// Clones share their state, so a test keeps a clone to drive the one it gave the code under
/// test.
///
/// - [`FakeWatcher::exit`] calls the matching callbacks synchronously, in the caller's thread.
/// - A watch on a process already marked exited, or on a pid started with
///   [`FakeWatcher::start`] under another generation, calls back promptly on a separate
///   thread (as a real watcher would), never inside `watch` itself.
/// - A watch on a process the fake knows nothing about waits for `exit`.
/// - Dropping the [`WatchHandle`] cancels the watch.
/// - No callback is ever called while the fake's lock is held.
#[derive(Clone)]
pub struct FakeWatcher {
    state: Option<Arc<Mutex<WatcherState>>>,
}

impl std::fmt::Debug for FakeWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            None => f.write_str("FakeWatcher(unsupported)"),
            Some(_) => write!(f, "FakeWatcher({} active watches)", self.active_watches()),
        }
    }
}

impl Default for FakeWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeWatcher {
    pub fn new() -> Self {
        Self {
            state: Some(Arc::new(Mutex::new(WatcherState {
                next_pid: 10_000,
                ..WatcherState::default()
            }))),
        }
    }

    /// A watcher that, like [`crate::watch::none::NoSessionWatcher`], can't watch anything.
    pub fn unsupported() -> Self {
        Self { state: None }
    }

    /// Marks `pid` as running under `generation` (optional: only needed to test a watch with
    /// the wrong generation).
    pub fn start(&self, pid: u32, generation: u64) {
        if let Some(state) = &self.state {
            let mut state = lock(state);
            state.running.insert(pid, generation);
            state.exited.remove(&(pid, generation));
        }
    }

    /// Ends the process: calls the callback of every pending watch on `(pid, generation)` once,
    /// in this thread, and makes later watches on it call back promptly.
    pub fn exit(&self, pid: u32, generation: u64) {
        let Some(state) = &self.state else {
            return;
        };
        let callbacks: Vec<OnExit> = {
            let mut state = lock(state);
            if state.running.get(&pid) == Some(&generation) {
                state.running.remove(&pid);
            }
            state.exited.insert((pid, generation));
            let ids: Vec<u64> = state
                .watches
                .iter()
                .filter(|(_, (key, _))| *key == (pid, generation))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| state.watches.remove(&id))
                .map(|(_, on_exit)| on_exit)
                .collect()
        };
        for on_exit in callbacks {
            on_exit();
        }
    }

    /// Watches registered and neither fired nor cancelled.
    pub fn active_watches(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |state| lock(state).watches.len())
    }
}

impl SessionWatcher for FakeWatcher {
    fn watch(&self, process: &ProcessRef, on_exit: OnExit) -> Result<WatchHandle> {
        let Some(state) = &self.state else {
            return Err(PlatformError::Unsupported("session watching"));
        };
        let key = (process.pid, process.generation);
        let mut guard = lock(state);
        let gone = guard.exited.contains(&key)
            || guard
                .running
                .get(&process.pid)
                .is_some_and(|&generation| generation != process.generation);
        if gone {
            drop(guard);
            std::thread::spawn(on_exit);
            return Ok(WatchHandle::new(|| {}));
        }
        let id = guard.next_id;
        guard.next_id += 1;
        guard.watches.insert(id, (key, on_exit));
        drop(guard);
        let weak = Arc::downgrade(state);
        Ok(WatchHandle::new(move || {
            if let Some(state) = weak.upgrade() {
                // Taken out under the lock, dropped (never called) after it.
                let cancelled = lock(&state).watches.remove(&id);
                drop(cancelled);
            }
        }))
    }
}

/// The fake drives its own simulated processes in the [contract suite](crate::contract).
impl ProcessDriver for FakeWatcher {
    fn start(&mut self) -> ProcessRef {
        let pid = match &self.state {
            Some(state) => {
                let mut state = lock(state);
                state.next_pid += 1;
                state.next_pid
            }
            None => 0,
        };
        let generation = 7;
        FakeWatcher::start(self, pid, generation);
        ProcessRef {
            pid,
            generation,
            executable: "/usr/bin/fake-agent".into(),
            code_identity: None,
            unbindable: None,
        }
    }

    fn end(&mut self, process: &ProcessRef) {
        self.exit(process.pid, process.generation);
    }
}

// ----- KeystoreUnwrap -----

/// The stanza tag of [`FakeRecipient`]: `writ-fake <name>`, its body the file key masked
/// with the fake's pad (no secrecy: a stand-in for a hardware key in tests).
pub const FAKE_STANZA: &str = "writ-fake";

/// The recipient of a [`FakeUnwrap`] of the same name and pad.
#[derive(Debug, Clone)]
pub struct FakeRecipient {
    name: String,
    pad: [u8; 16],
}

impl FakeRecipient {
    pub fn new(name: &str, pad: [u8; 16]) -> Self {
        Self {
            name: name.to_owned(),
            pad,
        }
    }
}

fn masked(bytes: &[u8], pad: &[u8; 16]) -> Vec<u8> {
    bytes.iter().zip(pad).map(|(b, p)| b ^ p).collect()
}

impl age::Recipient for FakeRecipient {
    fn wrap_file_key(
        &self,
        file_key: &crate::unlock::FileKey,
    ) -> std::result::Result<(Vec<crate::unlock::Stanza>, HashSet<String>), age::EncryptError> {
        use age::secrecy::ExposeSecret;
        let stanza = crate::unlock::Stanza {
            tag: FAKE_STANZA.to_owned(),
            args: vec![self.name.clone()],
            body: masked(file_key.expose_secret(), &self.pad),
        };
        Ok((vec![stanza], HashSet::new()))
    }
}

/// A [`KeystoreUnwrap`] standing for a hardware key: it opens the stanzas its
/// [`FakeRecipient`] writes (its name in the stanza, a body of 16 bytes), refuses every use
/// once [`FakeUnwrap::refuse`] is called (a device that refuses, a key removed), and counts
/// each unwrap it is asked for (so a test sees a secret unwrapped per use). Clones share the
/// switch and the count.
#[derive(Debug, Clone)]
pub struct FakeUnwrap {
    name: String,
    pad: [u8; 16],
    refusing: Arc<std::sync::atomic::AtomicBool>,
    uses: Arc<std::sync::atomic::AtomicUsize>,
}

impl FakeUnwrap {
    pub fn new(name: &str, pad: [u8; 16]) -> Self {
        Self {
            name: name.to_owned(),
            pad,
            refusing: Arc::default(),
            uses: Arc::default(),
        }
    }

    pub fn recipient(&self) -> FakeRecipient {
        FakeRecipient::new(&self.name, self.pad)
    }

    /// From now on, every stanza of its own is refused.
    pub fn refuse(&self) {
        self.refusing
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many of its own stanzas it was asked to unwrap.
    pub fn uses(&self) -> usize {
        self.uses.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl KeystoreUnwrap for FakeUnwrap {
    fn name(&self) -> &str {
        &self.name
    }

    fn unwrap(&self, stanzas: &[crate::unlock::Stanza]) -> Result<Option<crate::unlock::FileKey>> {
        let Some(stanza) = stanzas
            .iter()
            .find(|s| s.tag == FAKE_STANZA && s.args.first() == Some(&self.name))
        else {
            return Ok(None);
        };
        self.uses.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.refusing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PlatformError::Unlock("the fake device refuses".to_owned()));
        }
        if stanza.args.len() != 1 {
            return Err(PlatformError::Unlock("a damaged fake stanza".to_owned()));
        }
        let key: [u8; 16] = masked(&stanza.body, &self.pad)
            .try_into()
            .map_err(|_| PlatformError::Unlock("a damaged fake stanza".to_owned()))?;
        Ok(Some(crate::unlock::FileKey::new(Box::new(key))))
    }
}

// ----- Notifier -----

/// A [`Notifier`] that records every notification it delivers, neutralized as a real one
/// would send it ([`Notification::neutralized`]), or fails every time. Clones share the
/// record.
#[derive(Debug, Clone, Default)]
pub struct RecordingNotifier {
    delivered: Arc<(Mutex<Vec<Notification>>, std::sync::Condvar)>,
    failing: bool,
}

impl RecordingNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fails every delivery and records nothing (a sink that's down).
    pub fn failing() -> Self {
        Self {
            delivered: Arc::default(),
            failing: true,
        }
    }

    /// Everything delivered so far, oldest first.
    pub fn notifications(&self) -> Vec<Notification> {
        lock(&self.delivered.0).clone()
    }

    /// Waits until `count` notifications were delivered (woken by each delivery, no polling)
    /// and returns them. Panics after [`WAIT_LIMIT`]: a test fails, it never hangs.
    pub fn wait_for(&self, count: usize) -> Vec<Notification> {
        let (delivered, arrived) = &*self.delivered;
        let guard = lock(delivered);
        let (guard, timeout) = arrived
            .wait_timeout_while(guard, WAIT_LIMIT, |d| d.len() < count)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "{count} notification(s) expected, {} delivered",
            guard.len()
        );
        guard.clone()
    }
}

impl Notifier for RecordingNotifier {
    fn notify(&self, notification: &Notification) -> Result<()> {
        if self.failing {
            return Err(PlatformError::Notify(
                "the recording notifier is set to fail".to_owned(),
            ));
        }
        let (delivered, arrived) = &*self.delivered;
        lock(delivered).push(notification.neutralized());
        arrived.notify_all();
        Ok(())
    }
}

/// The longest any test helper waits for something that happens on another thread or in
/// another process. Reaching it fails the test: a deadline bounds how long a test looks, it
/// never decides what the test checks.
pub const WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Waits until `check` holds, checking again every few milliseconds, for things that give no
/// signal (another process's socket, a file). Panics after [`WAIT_LIMIT`], naming `what`.
pub fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + WAIT_LIMIT;
    while !check() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        // poll: the one sanctioned poll, for what gives no signal; bounded by WAIT_LIMIT.
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// [`eventually`], in async code.
pub async fn eventually_async(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + WAIT_LIMIT;
    while !check() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        // poll: the async form of the same sanctioned poll, bounded by WAIT_LIMIT.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// A [`Clock`] moved by hand: time passes only when the test says so.
#[derive(Debug, Default)]
pub struct FakeClock(std::sync::atomic::AtomicU64);

impl FakeClock {
    /// Stopped at `seconds` after the Unix epoch.
    pub fn at_unix(seconds: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(
            seconds.saturating_mul(1000),
        ))
    }

    /// Moves time forward by `seconds` (saturating, never wrapping).
    pub fn advance(&self, seconds: u64) {
        let step = seconds.saturating_mul(1000);
        let ordering = std::sync::atomic::Ordering::SeqCst;
        let mut current = self.0.load(ordering);
        while let Err(actual) =
            self.0
                .compare_exchange_weak(current, current.saturating_add(step), ordering, ordering)
        {
            current = actual;
        }
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
