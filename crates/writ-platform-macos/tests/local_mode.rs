//! macOS's local mode implementations with real processes: the attestor and the session
//! watcher through their contract suites, the Unix socket transport with the audit token's
//! peer, and the process chain itself: what the kernel says, whatever a process calls itself,
//! ending where a parent link no longer holds.

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use writ_core::caller::{CallerFacts, ProcessRef};
use writ_platform::contract::{self, Connected, ProcessDriver, WatcherKind};
use writ_platform::transport::unix::UnixTransport;
use writ_platform::{AsyncStream, BoxFuture, CallerAttestor, PeerInfo, SessionWatcher, Transport};
use writ_platform_macos::attest::{MAX_CHAIN, ProcessChain};
use writ_platform_macos::peer::audit_token_peer;
use writ_platform_macos::watch::KqueueWatcher;

/// A short private directory for sockets (their paths are bounded).
fn socket_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("wm")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o750),
    )
    .unwrap();
    dir
}

/// This process as the kernel names it.
fn me() -> ProcessRef {
    ProcessChain::new().current(std::process::id()).unwrap()
}

#[test]
fn the_attestor_passes_the_contract() {
    let attestor = ProcessChain::new();
    let tcp: SocketAddr = "192.0.2.7:51000".parse().unwrap();
    let me = me();
    let cases = [
        (
            PeerInfo::Tcp { remote: tcp },
            Some(CallerFacts {
                source_addr: Some(tcp.ip()),
                process_chain: None,
            }),
        ),
        // No generation (not from an audit token), another generation, no pid: refused.
        (
            PeerInfo::Unix {
                uid: 501,
                gid: 20,
                pid: Some(me.pid),
                generation: None,
            },
            None,
        ),
        (
            PeerInfo::Unix {
                uid: 501,
                gid: 20,
                pid: Some(me.pid),
                generation: Some(me.generation + 1),
            },
            None,
        ),
        (
            PeerInfo::Unix {
                uid: 501,
                gid: 20,
                pid: None,
                generation: Some(me.generation),
            },
            None,
        ),
        (
            PeerInfo::Memory {
                label: "test".to_owned(),
            },
            None,
        ),
    ];
    contract::attestor(&attestor, &cases, true);
}

#[test]
fn the_chain_goes_from_the_caller_to_launchd_each_with_its_generation() {
    let attestor = ProcessChain::new();
    let me = me();
    let facts = attestor
        .attest(&PeerInfo::Unix {
            uid: 0,
            gid: 0,
            pid: Some(me.pid),
            generation: Some(me.generation),
        })
        .unwrap();
    assert_eq!(facts.source_addr, None);
    let chain = facts.process_chain.unwrap();
    assert_eq!(chain[0], me);
    assert_eq!(
        chain[0].executable.canonicalize().unwrap(),
        std::env::current_exe().unwrap().canonicalize().unwrap()
    );
    let launchd = chain.last().unwrap();
    assert_eq!(
        (launchd.pid, launchd.executable.as_path()),
        (1, Path::new("/sbin/launchd"))
    );
    assert_eq!(
        launchd.code_identity.as_ref().unwrap().signing_id,
        "com.apple.xpc.launchd"
    );
    assert!(chain.len() >= 3 && chain.len() <= MAX_CHAIN, "{chain:?}");
    // Each one is the process running as its pid now.
    for process in &chain {
        assert_eq!(attestor.current(process.pid).unwrap(), *process);
    }
}

/// A Unix socket with the macOS peer reader, and a connection to it from `script`'s
/// processes (`sh -c`): the attested facts of the connection.
async fn attested_from(script: &str) -> (CallerFacts, Child) {
    let dir = socket_dir();
    let path = dir.path().join("t.sock");
    let transport = UnixTransport::bind(&path, audit_token_peer).unwrap();
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(script.replace("SOCKET", path.to_str().unwrap()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let connection = transport.accept().await.unwrap();
    let facts = ProcessChain::new().attest(&connection.peer).unwrap();
    (facts, child)
}

#[tokio::test]
async fn the_caller_is_its_executable_whatever_it_calls_itself() {
    // `exec -a` gives nc another argv[0]; its arguments say what they like.
    let (facts, mut child) = attested_from(
        "exec -a '/Applications/Omega Code.app/Contents/MacOS/omega' /usr/bin/nc -U SOCKET",
    )
    .await;
    let chain = facts.process_chain.unwrap();
    assert_eq!(chain[0].executable, PathBuf::from("/usr/bin/nc"));
    assert_eq!(chain[0].pid, child.id());
    assert_eq!(chain[1], me());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[tokio::test]
async fn an_orphan_s_chain_never_runs_through_the_session_it_left() {
    // nc's parent (the subshell) ends at once and launchd adopts nc: its chain stops where
    // the link breaks, or at launchd when the kernel records launchd as its parent; it
    // never holds the subshell's ancestors (this test's sh, this test).
    let (facts, mut child) =
        // Their output away from the test's pipes: the orphans outlive the test's wait.
        attested_from("( /bin/sleep 30 | /usr/bin/nc -U SOCKET >/dev/null 2>&1 & ) ; exit 0")
            .await;
    child.wait().unwrap();
    let chain = facts.process_chain.unwrap();
    assert_eq!(chain[0].executable, PathBuf::from("/usr/bin/nc"));
    let (me, sh) = (me(), child.id());
    assert!(
        chain.iter().all(|p| p.pid != me.pid && p.pid != sh),
        "{chain:?}"
    );
    assert!(chain.len() <= 3, "{chain:?}");
    let _ = Command::new("/bin/kill")
        .arg(chain[0].pid.to_string())
        .status();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_unix_transport_with_the_audit_token_passes_the_contract() {
    let dir = socket_dir();
    let path = dir.path().join("t.sock");
    let transport = UnixTransport::bind(&path, audit_token_peer).unwrap();
    let me = me();
    let expected = PeerInfo::Unix {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        pid: Some(me.pid),
        generation: Some(me.generation),
    };
    contract::transport(transport, move || -> BoxFuture<'static, Connected> {
        let (path, expected) = (path.clone(), expected.clone());
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(&path).await?;
            Ok((Box::new(stream) as Box<dyn AsyncStream>, Some(expected)))
        })
    })
    .await;
}

/// Real processes: `sleep`, ended by a kill and waited for.
#[derive(Default)]
struct Sleepers {
    running: Vec<Child>,
}

impl ProcessDriver for Sleepers {
    fn start(&mut self) -> ProcessRef {
        let child = Command::new("/bin/sleep").arg("600").spawn().unwrap();
        let process = ProcessChain::new().current(child.id()).unwrap();
        self.running.push(child);
        process
    }

    fn end(&mut self, process: &ProcessRef) {
        let index = self
            .running
            .iter()
            .position(|c| c.id() == process.pid)
            .unwrap();
        let mut child = self.running.swap_remove(index);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

impl Drop for Sleepers {
    fn drop(&mut self) {
        for child in &mut self.running {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn the_watcher_passes_the_contract() {
    let watcher = KqueueWatcher::new().unwrap();
    let mut driver = Sleepers::default();
    contract::session_watcher(&watcher, WatcherKind::Supported(&mut driver));
}

#[test]
fn watches_of_one_session_each_fire_and_a_cancelled_one_never() {
    let watcher = KqueueWatcher::new().unwrap();
    let mut driver = Sleepers::default();
    let session = driver.start();
    let fired = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let watch = |bit: u64| {
        let (fired, tx) = (fired.clone(), tx.clone());
        watcher
            .watch(
                &session,
                Box::new(move || {
                    fired.fetch_or(bit, Ordering::AcqRel);
                    let _ = tx.send(());
                }),
            )
            .unwrap()
    };
    let (first, second, cancelled) = (watch(1), watch(2), watch(4));
    drop(cancelled);
    driver.end(&session);
    for _ in 0..2 {
        rx.recv_timeout(writ_platform::testing::WAIT_LIMIT).unwrap();
    }
    // Nothing more: the two callbacks ran and went, the cancelled one was dropped uncalled,
    // so every sender is gone.
    drop(tx);
    assert_eq!(
        rx.recv_timeout(writ_platform::testing::WAIT_LIMIT),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    );
    assert_eq!(fired.load(Ordering::Acquire), 1 | 2);
    drop((first, second));
}

#[test]
fn a_watch_of_a_generation_past_what_the_kernel_counts_fires_at_once() {
    let watcher = KqueueWatcher::new().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let process = ProcessRef {
        generation: u64::MAX,
        ..me()
    };
    let _handle = watcher
        .watch(
            &process,
            Box::new(move || {
                let _ = tx.send(());
            }),
        )
        .unwrap();
    rx.recv_timeout(writ_platform::testing::WAIT_LIMIT).unwrap();
}
