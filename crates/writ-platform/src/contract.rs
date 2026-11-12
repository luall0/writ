//! Contract suites (feature `testing`): one per interface, run by every implementation,
//! portable or platform-only, and by every fake. Each is a plain function that panics with a
//! clear message on the first broken rule; the caller supplies what only it can know (how to
//! connect, which peers it attests, how to start and end a process, the right secret).
//!
//! | Interface | Suite |
//! |---|---|
//! | [`Clock`] | [`clock`] |
//! | [`Transport`] | [`transport`] (async) |
//! | [`CallerAttestor`] | [`attestor`] |
//! | [`SessionWatcher`] | [`session_watcher`] |
//! | [`KeystoreUnlock`] | [`keystore_unlock`], or [`keystore_unlock_passphrase`] |
//! | [`Notifier`] | [`notifier`] and [`notifier_unreachable`] |
//! | [`ProcessHardening`](crate::ProcessHardening) | [`process_hardening`] (in a test binary of its own: it changes the process) |

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use writ_core::caller::{CallerFacts, ProcessRef};

use crate::{
    AsyncStream, BoxFuture, CallerAttestor, Clock, KeystoreUnlock, Notification, Notifier,
    Passphrase, PeerInfo, PlatformError, Priority, SessionWatcher, Transport, UnsealRequest,
};

/// How long a step may take before the suite fails instead of hanging.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a callback gets to arrive.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the suite waits to be confident a callback won't come.
const QUIET_PERIOD: Duration = Duration::from_millis(300);

// ----- Clock -----

/// 2020-01-01T00:00:00Z, in milliseconds: no clock the daemon runs on reads earlier.
const CLOCK_FLOOR_MS: u64 = 1_577_836_800_000;

/// The [`Clock`] contract.
///
/// - it reads after 2020-01-01 (a clock that doesn't know the date would make every lease
///   look unexpired) and within the range a `Timestamp` holds;
/// - it never runs backwards between reads in a row;
/// - with `advance` (a clock the test moves), moving it by `n` seconds moves the reading by
///   exactly `n * 1000` milliseconds, and nothing else moves it.
pub fn clock<C: Clock + ?Sized>(clock: &C, advance: Option<&dyn Fn(u64)>) {
    let first = clock.now_ms();
    assert!(
        first >= CLOCK_FLOOR_MS,
        "the clock reads {first} ms, before 2020-01-01"
    );
    assert!(
        i64::try_from(first / 1000).is_ok(),
        "the clock reads {first} ms, out of range"
    );
    let mut previous = first;
    for _ in 0..1000 {
        let now = clock.now_ms();
        assert!(
            now >= previous,
            "the clock ran backwards: {previous} then {now}"
        );
        previous = now;
    }
    if let Some(advance) = advance {
        let before = clock.now_ms();
        assert_eq!(
            clock.now_ms(),
            before,
            "a clock moved by hand moved by itself"
        );
        advance(90);
        assert_eq!(
            clock.now_ms(),
            before + 90_000,
            "advance(90) must add 90 s exactly"
        );
        advance(0);
        assert_eq!(
            clock.now_ms(),
            before + 90_000,
            "advance(0) must not move it"
        );
    }
}

// ----- Transport -----

/// What a `connect` closure gives the [`transport`] suite: the client end of a new connection,
/// and the peer the transport must report for it when the test can know it.
pub type Connected = std::io::Result<(Box<dyn AsyncStream>, Option<PeerInfo>)>;

/// The [`Transport`] contract. `connect` opens one client connection to `transport`.
///
/// - `describe()` is not empty;
/// - several connections are accepted, one after the other and concurrently;
/// - bytes flow both ways unchanged (every byte value, large payloads);
/// - concurrent connections never mix their bytes;
/// - each accepted connection reports the expected peer (when `connect` gives one);
/// - a client closing its end gives EOF on the server side.
///
/// Needs a Tokio runtime (`#[tokio::test]`).
pub async fn transport<T, C>(transport: T, connect: C)
where
    T: Transport + 'static,
    C: Fn() -> BoxFuture<'static, Connected>,
{
    assert!(
        !transport.describe().trim().is_empty(),
        "Transport::describe() must not be empty"
    );

    let (events_tx, mut events_rx) = mpsc::unbounded_channel::<ServerEvent>();
    let transport = Arc::new(transport);
    let acceptor = tokio::spawn({
        let transport = Arc::clone(&transport);
        async move {
            loop {
                let connection = match transport.accept().await {
                    Ok(connection) => connection,
                    Err(e) => {
                        let _ = events_tx.send(ServerEvent::AcceptFailed(e.to_string()));
                        return;
                    }
                };
                tokio::spawn(serve(connection.stream, connection.peer, events_tx.clone()));
            }
        }
    });

    let mut events = ServerEvents::default();

    // One after the other.
    for id in 0..3u64 {
        let (stream, expected) = within(connect(), "connect").await.expect("connect");
        within(
            exchange(stream, id, payload(id, 4096 + id as usize * 1000)),
            "exchange",
        )
        .await;
        events.check_connection(&mut events_rx, id, expected).await;
    }

    // Concurrently, with payloads large enough to interleave.
    let mut clients = Vec::new();
    let mut expected_peers = HashMap::new();
    for id in 10..18u64 {
        let (stream, expected) = within(connect(), "connect").await.expect("connect");
        expected_peers.insert(id, expected);
        clients.push(tokio::spawn(exchange(
            stream,
            id,
            payload(id, 256 * 1024 + id as usize),
        )));
    }
    for client in clients {
        within(client, "concurrent exchange")
            .await
            .expect("a concurrent client panicked");
    }
    for (id, expected) in expected_peers {
        events.check_connection(&mut events_rx, id, expected).await;
    }

    acceptor.abort();
}

enum ServerEvent {
    Peer(u64, PeerInfo),
    Eof(u64),
    Failed(u64, String),
    AcceptFailed(String),
}

#[derive(Default)]
struct ServerEvents {
    peers: HashMap<u64, PeerInfo>,
    eofs: std::collections::HashSet<u64>,
}

impl ServerEvents {
    /// Waits until the server side reported `id`'s peer and EOF, and checks the peer.
    async fn check_connection(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<ServerEvent>,
        id: u64,
        expected: Option<PeerInfo>,
    ) {
        while !(self.peers.contains_key(&id) && self.eofs.contains(&id)) {
            let event = within(rx.recv(), "server events")
                .await
                .expect("the accept loop stopped");
            match event {
                ServerEvent::Peer(i, peer) => {
                    self.peers.insert(i, peer);
                }
                ServerEvent::Eof(i) => {
                    self.eofs.insert(i);
                }
                ServerEvent::Failed(i, why) => panic!("server side of connection {i}: {why}"),
                ServerEvent::AcceptFailed(why) => panic!("Transport::accept failed: {why}"),
            }
        }
        if let Some(expected) = expected {
            assert_eq!(
                self.peers[&id], expected,
                "connection {id}: the transport must report the client's real peer"
            );
        }
    }
}

/// A deterministic payload containing every byte value.
fn payload(seed: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u64).wrapping_mul(31).wrapping_add(seed * 7) as u8)
        .collect()
}

fn trailer(id: u64) -> Vec<u8> {
    format!("server says bye to {id:08}").into_bytes()
}

/// Server side: reads the id and a length-prefixed payload, echoes it, sends a trailer, then
/// waits for EOF.
async fn serve(
    mut stream: Box<dyn AsyncStream>,
    peer: PeerInfo,
    events: mpsc::UnboundedSender<ServerEvent>,
) {
    let mut id = u64::MAX;
    let result: std::io::Result<()> = async {
        id = stream.read_u64().await?;
        let _ = events.send(ServerEvent::Peer(id, peer));
        let len = stream.read_u32().await? as usize;
        let mut remaining = len;
        let mut buf = vec![0u8; 16 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            let n = stream.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            stream.write_all(&buf[..n]).await?;
            remaining -= n;
        }
        stream.write_all(&trailer(id)).await?;
        stream.flush().await?;
        let mut rest = [0u8; 1];
        match stream.read(&mut rest).await? {
            0 => Ok(()),
            _ => Err(std::io::Error::other("unexpected bytes after the payload")),
        }
    }
    .await;
    let _ = events.send(match result {
        Ok(()) => ServerEvent::Eof(id),
        Err(e) => ServerEvent::Failed(id, e.to_string()),
    });
}

/// Client side: sends the id and payload while reading the echo, checks it byte for byte and
/// the trailer, then closes its write side.
async fn exchange(stream: Box<dyn AsyncStream>, id: u64, payload: Vec<u8>) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let len = payload.len();
    let sent = payload.clone();
    let write = async move {
        writer.write_u64(id).await.expect("client write");
        writer
            .write_u32(u32::try_from(len).expect("payload length"))
            .await
            .expect("client write");
        for chunk in sent.chunks(7919) {
            writer.write_all(chunk).await.expect("client write");
        }
        writer.flush().await.expect("client flush");
        writer
    };
    let read = async move {
        let mut echoed = vec![0u8; len];
        reader
            .read_exact(&mut echoed)
            .await
            .expect("client read of the echo");
        let mut bye = vec![0u8; trailer(id).len()];
        reader
            .read_exact(&mut bye)
            .await
            .expect("client read of the trailer");
        (echoed, bye)
    };
    let (mut writer, (echoed, bye)) = tokio::join!(write, read);
    assert!(
        echoed == payload,
        "connection {id}: bytes changed or mixed between connections on the way"
    );
    assert_eq!(
        bye,
        trailer(id),
        "connection {id}: server-to-client bytes changed"
    );
    writer.shutdown().await.expect("client shutdown");
}

async fn within<F: std::future::Future>(future: F, what: &str) -> F::Output {
    tokio::time::timeout(STEP_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("{what} took more than {STEP_TIMEOUT:?}"))
}

// ----- CallerAttestor -----

/// The [`CallerAttestor`] contract. `cases` are peers with what the attestor must say about
/// them: `Some(facts)` exactly those facts, `None` an error (a peer kind it doesn't handle:
/// it must refuse, never invent facts). Platform implementations supply their own peers
/// (e.g. a Unix peer of a live process and its expected chain).
///
/// - the same peer twice gives the same answer;
/// - every case gives the expected answer;
/// - for a TCP peer, the facts' `source_addr` is that peer's IP and there is never a process
///   chain;
/// - a process chain only comes from a kernel source: when `kernel_process_chain` is false,
///   no answer ever has one.
pub fn attestor<A: CallerAttestor + ?Sized>(
    attestor: &A,
    cases: &[(PeerInfo, Option<CallerFacts>)],
    kernel_process_chain: bool,
) {
    assert!(
        !cases.is_empty(),
        "the attestor suite needs at least one case"
    );
    for (peer, expected) in cases {
        let first = attestor.attest(peer);
        let second = attestor.attest(peer);
        match (&first, &second) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{peer:?}: the same peer must give the same facts"),
            (Err(_), Err(_)) => {}
            _ => panic!("{peer:?}: the same peer must give the same answer twice"),
        }
        match (expected, first) {
            (Some(expected), Ok(facts)) => {
                assert_eq!(&facts, expected, "{peer:?}: wrong facts");
                check_fact_sources(peer, &facts, kernel_process_chain);
            }
            (Some(_), Err(e)) => panic!("{peer:?}: expected facts, got an error: {e}"),
            (None, Ok(facts)) => panic!(
                "{peer:?}: a peer this attestor can't handle must be refused, not attested as {facts:?}"
            ),
            (None, Err(e)) => assert!(
                !e.to_string().trim().is_empty(),
                "{peer:?}: the refusal must say why"
            ),
        }
    }
}

fn check_fact_sources(peer: &PeerInfo, facts: &CallerFacts, kernel_process_chain: bool) {
    if let PeerInfo::Tcp { remote } = peer {
        assert_eq!(
            facts.source_addr,
            Some(remote.ip()),
            "{peer:?}: a TCP peer's source address must be its IP"
        );
        assert!(
            facts.process_chain.is_none(),
            "{peer:?}: the network can't give a process chain"
        );
    }
    if !kernel_process_chain {
        assert!(
            facts.process_chain.is_none(),
            "{peer:?}: this attestor has no kernel source, it must never give a process chain"
        );
    }
}

// ----- SessionWatcher -----

/// Starts and ends processes (real ones, or a fake's simulated ones) for the
/// [`session_watcher`] suite.
pub trait ProcessDriver {
    /// Starts a process that keeps running until [`ProcessDriver::end`], and returns it with
    /// its real pid and generation.
    fn start(&mut self) -> ProcessRef;
    /// Ends `process` and returns once it has exited.
    fn end(&mut self, process: &ProcessRef);
}

/// What the [`session_watcher`] suite checks.
pub enum WatcherKind<'a> {
    /// The implementation can't watch processes: every watch is `Unsupported`.
    Unsupported,
    /// The implementation watches the processes this driver starts and ends.
    Supported(&'a mut dyn ProcessDriver),
}

/// The [`SessionWatcher`] contract.
///
/// Unsupported: every watch returns [`PlatformError::Unsupported`] and never calls back.
///
/// Supported:
/// - no callback while the process runs, exactly one after it exits;
/// - never a callback after the handle is dropped;
/// - a prompt callback for a process that already ended, and for a wrong generation (a
///   reused pid is another process);
/// - only the watch of the process that ended fires;
/// - dropping a handle after its callback ran is harmless.
pub fn session_watcher<W: SessionWatcher + ?Sized>(watcher: &W, kind: WatcherKind<'_>) {
    match kind {
        WatcherKind::Unsupported => session_watcher_unsupported(watcher),
        WatcherKind::Supported(driver) => session_watcher_supported(watcher, driver),
    }
}

fn session_watcher_unsupported<W: SessionWatcher + ?Sized>(watcher: &W) {
    let processes = [
        ProcessRef {
            pid: std::process::id(),
            generation: 0,
            executable: "/usr/bin/agent".into(),
            code_identity: None,
            unbindable: None,
        },
        ProcessRef {
            pid: 1,
            generation: 1,
            executable: "/sbin/init".into(),
            code_identity: None,
            unbindable: None,
        },
    ];
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    for process in &processes {
        let tx = tx.clone();
        let result = watcher.watch(
            process,
            Box::new(move || {
                let _ = tx.send(());
            }),
        );
        assert!(
            matches!(result, Err(PlatformError::Unsupported(_))),
            "an unsupported watcher must return Unsupported, got {result:?}"
        );
    }
    drop(tx);
    // any error: a timeout (nothing came) or a disconnection (the callback dropped, never
    // called) both say it never called back.
    assert!(
        rx.recv_timeout(QUIET_PERIOD).is_err(),
        "an unsupported watcher must never call back"
    );
}

/// A callback that counts its calls on a channel.
fn counting_callback() -> (crate::OnExit, std::sync::mpsc::Receiver<()>) {
    let (tx, rx) = std::sync::mpsc::channel();
    (
        Box::new(move || {
            let _ = tx.send(());
        }),
        rx,
    )
}

fn assert_fires_once(rx: &std::sync::mpsc::Receiver<()>, what: &str) {
    assert!(
        rx.recv_timeout(CALLBACK_TIMEOUT).is_ok(),
        "{what}: the callback must be called within {CALLBACK_TIMEOUT:?}"
    );
    // any error: a timeout or a disconnection, no second call either way.
    assert!(
        rx.recv_timeout(QUIET_PERIOD).is_err(),
        "{what}: the callback must be called only once"
    );
}

fn assert_quiet(rx: &std::sync::mpsc::Receiver<()>, what: &str) {
    match rx.recv_timeout(QUIET_PERIOD) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        Ok(()) => panic!("{what}: the callback must not be called"),
    }
}

fn session_watcher_supported<W: SessionWatcher + ?Sized>(
    watcher: &W,
    driver: &mut dyn ProcessDriver,
) {
    // Fires exactly once, after the exit.
    let process = driver.start();
    let (on_exit, rx) = counting_callback();
    let handle = watcher
        .watch(&process, on_exit)
        .expect("watching a running process");
    assert_quiet(&rx, "a running process");
    driver.end(&process);
    assert_fires_once(&rx, "a process that exits");
    drop(handle);
    assert_quiet(&rx, "dropping the handle after the callback");

    // Never after the handle is dropped.
    let process = driver.start();
    let (on_exit, rx) = counting_callback();
    let handle = watcher
        .watch(&process, on_exit)
        .expect("watching a running process");
    drop(handle);
    driver.end(&process);
    assert_quiet(&rx, "a cancelled watch");

    // Promptly for a process that already ended.
    let process = driver.start();
    driver.end(&process);
    let (on_exit, rx) = counting_callback();
    let handle = watcher
        .watch(&process, on_exit)
        .expect("watching an ended process must still succeed, and call back");
    assert_fires_once(&rx, "a process that already ended");
    drop(handle);

    // Promptly for a wrong generation (the pid now belongs to another process).
    let process = driver.start();
    let other = ProcessRef {
        generation: process.generation.wrapping_add(1),
        ..process.clone()
    };
    let (on_exit, rx) = counting_callback();
    let handle = watcher
        .watch(&other, on_exit)
        .expect("watching with a wrong generation must still succeed, and call back");
    assert_fires_once(&rx, "a wrong generation");
    drop(handle);
    driver.end(&process);

    // Only the process that ended.
    let first = driver.start();
    let second = driver.start();
    let (on_first, rx_first) = counting_callback();
    let (on_second, rx_second) = counting_callback();
    let first_handle = watcher.watch(&first, on_first).expect("watch");
    let second_handle = watcher.watch(&second, on_second).expect("watch");
    driver.end(&first);
    assert_fires_once(&rx_first, "the process that ended");
    assert_quiet(&rx_second, "a process still running while another ends");
    driver.end(&second);
    assert_fires_once(&rx_second, "the second process");
    drop(first_handle);
    drop(second_handle);
}

// ----- KeystoreUnlock -----

/// The [`KeystoreUnlock`] contract. `right` builds a request that unlocks `expected_key`;
/// `wrong` holds requests that must fail (a wrong passphrase, a missing one, …); `secrets`
/// are strings (the passphrase) that must never appear in any `Debug` or error text (those
/// shorter than 4 bytes aren't searched for: they'd match ordinary text).
///
/// - the right request gives the expected key, twice, and so does a fresh one;
/// - every wrong request fails;
/// - the `Debug` of the requests, their passphrases, the key and the `Debug` and `Display` of
///   the errors never contain a secret or the key bytes (hex, decimal list or raw).
pub fn keystore_unlock<U: KeystoreUnlock + ?Sized>(
    unlock: &U,
    expected_key: &[u8; 32],
    right: impl Fn() -> UnsealRequest,
    wrong: Vec<UnsealRequest>,
    secrets: &[&str],
) {
    assert!(
        !wrong.is_empty(),
        "the unlock suite needs at least one wrong request"
    );
    let mut texts = Vec::new();

    let request = right();
    for attempt in ["first", "second"] {
        let key = unlock
            .unlock(&request)
            .unwrap_or_else(|e| panic!("the right request must unlock ({attempt} time): {e}"));
        assert_eq!(
            key.as_bytes(),
            expected_key,
            "the right request must give the expected key ({attempt} time)"
        );
        texts.push(format!("{key:?}"));
    }
    let fresh = unlock
        .unlock(&right())
        .unwrap_or_else(|e| panic!("a fresh right request must unlock: {e}"));
    assert_eq!(fresh.as_bytes(), expected_key, "a fresh right request");
    texts.push(format!("{request:?}"));
    if let Some(passphrase) = &request.passphrase {
        texts.push(format!("{passphrase:?}"));
    }

    for (i, request) in wrong.iter().enumerate() {
        match unlock.unlock(request) {
            Ok(_) => panic!("wrong request #{i} must not unlock the keystore"),
            Err(e) => {
                texts.push(format!("{e:?}"));
                texts.push(e.to_string());
            }
        }
        texts.push(format!("{request:?}"));
    }

    for text in &texts {
        assert_no_secret(text, expected_key, secrets);
    }
}

/// [`keystore_unlock`] for an implementation unlocked by `passphrase` alone: the wrong
/// requests are a missing passphrase, an empty one, a different one, and near misses.
pub fn keystore_unlock_passphrase<U: KeystoreUnlock + ?Sized>(
    unlock: &U,
    passphrase: &str,
    expected_key: &[u8; 32],
) {
    let with = |text: String| UnsealRequest::with_passphrase(Passphrase::new(text));
    let mut wrong = vec![
        UnsealRequest::default(),
        with(String::new()),
        with(format!("{passphrase}x")),
        with(format!(" {passphrase}")),
        with("definitely not the passphrase".to_owned()),
    ];
    if passphrase.len() > 1 {
        let mut shorter = passphrase.to_owned();
        shorter.pop();
        wrong.push(with(shorter));
    }
    keystore_unlock(
        unlock,
        expected_key,
        || with(passphrase.to_owned()),
        wrong,
        &[passphrase],
    );
}

fn assert_no_secret(text: &str, key: &[u8; 32], secrets: &[&str]) {
    for secret in secrets {
        if secret.len() >= 4 {
            assert!(
                !text.contains(secret),
                "a secret appears in a Debug or error text: {text}"
            );
        }
    }
    let hex_lower: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex_lower.to_uppercase();
    let decimal = format!("{key:?}");
    let decimal_inner = decimal.trim_start_matches('[').trim_end_matches(']');
    for encoded in [&hex_lower, &hex_upper, &decimal_inner.to_owned()] {
        assert!(
            !text.contains(encoded.as_str()),
            "the key appears in a Debug or error text: {text}"
        );
    }
    assert!(
        !text.as_bytes().windows(key.len()).any(|w| w == key),
        "the raw key bytes appear in a Debug or error text"
    );
}

// ----- Notifier -----

/// Text with every kind of character that must never reach a notification.
const HOSTILE: &str = "safe\u{1b}[31mred\u{1b}[0m\r\nX-Injected: 1\u{7}\u{0}\u{8}\t\
    \u{202E}desrever\u{202C}\u{2066}iso\u{2069}\u{200B}zw\u{200D}j\u{FEFF}bom\u{2060}wj\u{9b}csi";

/// The [`Notifier`] contract. `received` returns everything the sink got so far, oldest
/// first, decoded back into notifications (for a network sink: what a test server
/// recorded). Only the title and message are compared: how a sink renders the priority and
/// the tags (if at all) is checked by each implementation's own tests.
///
/// - plain text arrives intact, one notification per call;
/// - control characters (the message keeps `\n`), bidi controls and zero-width characters
///   never arrive, and the visible text around them does;
/// - titles and messages are capped (200 and 2000 characters).
pub fn notifier<N: Notifier + ?Sized>(notifier: &N, received: impl Fn() -> Vec<Notification>) {
    let before = received().len();
    let mut sent = 0;
    let mut deliver = |notification: &Notification| -> Notification {
        notifier
            .notify(notification)
            .unwrap_or_else(|e| panic!("delivering {notification:?}: {e}"));
        sent += 1;
        let got = received();
        assert_eq!(
            got.len(),
            before + sent,
            "each notify must deliver exactly one notification"
        );
        got.last().cloned().expect("a notification was delivered")
    };

    for (priority, tags) in [
        (Priority::Low, vec![]),
        (Priority::Default, vec!["writ".to_owned()]),
        (
            Priority::High,
            vec!["warning".to_owned(), "lock".to_owned()],
        ),
    ] {
        let plain = Notification {
            title: "Ticket wrt_01JD8X waits for approval: fix the login bug".to_owned(),
            message: "Repo: example/app\nBranch: agent/fix-login\nSigned by: claude — 3 commits, 'quotes' \"too\" & <tags> ✓".to_owned(),
            priority,
            tags,
        };
        let got = deliver(&plain);
        assert_eq!(
            (&got.title, &got.message),
            (&plain.title, &plain.message),
            "plain text must arrive intact"
        );
    }

    let hostile = Notification {
        title: HOSTILE.to_owned(),
        message: format!("line one\n{HOSTILE}\nline three"),
        priority: Priority::Default,
        tags: vec![],
    };
    let got = deliver(&hostile);
    for (field, text) in [("title", &got.title), ("message", &got.message)] {
        for c in text.chars() {
            let allowed_newline = field == "message" && c == '\n';
            assert!(
                allowed_newline || !writ_core::text::is_hidden_char(c),
                "{field}: {c:?} must never arrive (got {text:?})"
            );
        }
        for visible in [
            "safe",
            "red",
            "X-Injected: 1",
            "desrever",
            "iso",
            "zw",
            "bom",
            "wj",
        ] {
            assert!(
                text.contains(visible),
                "{field}: the visible text {visible:?} must arrive (got {text:?})"
            );
        }
    }
    assert!(!got.title.contains('\n'), "a title never has a newline");
    assert!(
        got.message.starts_with("line one\n") && got.message.ends_with("\nline three"),
        "the message keeps its newlines (got {:?})",
        got.message
    );

    let long = Notification {
        title: "t".repeat(1000),
        message: "m".repeat(10_000),
        priority: Priority::Default,
        tags: vec![],
    };
    let got = deliver(&long);
    assert!(
        got.title.chars().count() <= crate::notify::MAX_TITLE_CHARS && got.title.len() >= 100,
        "the title is capped at {} characters (got {})",
        crate::notify::MAX_TITLE_CHARS,
        got.title.chars().count()
    );
    assert!(
        got.message.chars().count() <= crate::notify::MAX_MESSAGE_CHARS
            && got.message.len() >= 1000,
        "the message is capped at {} characters (got {})",
        crate::notify::MAX_MESSAGE_CHARS,
        got.message.chars().count()
    );
}

/// The [`Notifier`] contract when the sink is down (closed port, error status, …): `notify`
/// fails with [`PlatformError::Notify`] within `max`, and keeps failing (no hang, no panic).
pub fn notifier_unreachable<N: Notifier + ?Sized>(notifier: &N, max: Duration) {
    let notification = Notification {
        title: "Writ".to_owned(),
        message: "a sink that's down".to_owned(),
        ..Notification::default()
    };
    for attempt in 0..2 {
        let start = Instant::now();
        let result = notifier.notify(&notification);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(PlatformError::Notify(_))),
            "attempt {attempt}: a sink that's down must give a Notify error, got {result:?}"
        );
        assert!(
            elapsed <= max,
            "attempt {attempt}: failing took {elapsed:?}, more than {max:?}"
        );
    }
}

/// The `ProcessHardening` contract. It hardens the calling process, so it runs in a test
/// binary of its own. Checks:
/// - every step reported once, in order;
/// - the same outcomes when applied again (idempotent);
/// - a reason for every step not applied, and a fix for one the host decides;
/// - a required step (only the process decides it) is applied or refused, never left as a
///   warning, except `NoDebugger` in a debug build (a traced process on macOS);
/// - when `NoCoreDumps` is applied, `RLIMIT_CORE` is 0, soft and hard.
///
/// Returns the outcomes, for the implementation's own checks.
pub fn process_hardening(hardening: &dyn crate::ProcessHardening) -> Vec<crate::Hardened> {
    use crate::{HardeningOutcome, HardeningStep};
    let first = hardening.harden();
    let steps: Vec<HardeningStep> = first.iter().map(|h| h.step).collect();
    assert_eq!(steps, HardeningStep::ALL, "every step once, in order");
    assert_eq!(
        hardening.harden(),
        first,
        "the same outcomes when applied again"
    );
    for hardened in &first {
        let step = hardened.step;
        match &hardened.outcome {
            HardeningOutcome::Applied => {}
            HardeningOutcome::Refused { why } | HardeningOutcome::Unavailable { why } => {
                assert!(!why.trim().is_empty(), "{step}: a reason");
            }
            HardeningOutcome::NotApplied { why, fix } => {
                assert!(!why.trim().is_empty(), "{step}: a reason");
                assert!(!fix.trim().is_empty(), "{step}: a fix");
                assert!(
                    !step.required()
                        || (step == HardeningStep::NoDebugger && cfg!(debug_assertions)),
                    "{step} is required: applied or refused, not a warning"
                );
            }
        }
        if matches!(hardened.outcome, HardeningOutcome::Unavailable { .. }) {
            assert!(!step.required(), "{step} is required: applied or refused");
        }
    }
    let core = first
        .iter()
        .find(|h| h.step == HardeningStep::NoCoreDumps)
        .unwrap();
    if core.outcome == HardeningOutcome::Applied {
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(
            (limit.current, limit.maximum),
            (Some(0), Some(0)),
            "RLIMIT_CORE 0, soft and hard"
        );
    }
    first
}
