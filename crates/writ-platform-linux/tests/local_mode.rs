//! Linux's local mode implementations with real processes: the attestor (reading `/proc`
//! itself, and through the process reader's protocol), the pidfd watcher and the Unix socket
//! transport with the pidfd peer, through their contract suites; the chain itself, whatever a
//! process calls itself; a peer gone before it was read; and the process reader refusing for
//! good once it can't be trusted. The tests run as one user, so `/proc` shows them their own
//! processes without a capability (and no other user's: a chain read here ends at the last
//! ancestor of theirs); the helper's capability and other users are the end-to-end
//! scenario's (`local_mode`).

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use writ_core::caller::{CallerFacts, ProcessRef};
use writ_platform::contract::{self, Connected, ProcessDriver, WatcherKind};
use writ_platform::transport::unix::UnixTransport;
use writ_platform::{AsyncStream, BoxFuture, CallerAttestor, PeerInfo, SessionWatcher, Transport};
use writ_platform_linux::attest::{MAX_CHAIN, ProcessChain};
use writ_platform_linux::helper::{self, Helper};
use writ_platform_linux::peer::pidfd_peer;
use writ_platform_linux::procfs::ReadError;
use writ_platform_linux::read::{Direct, Host, ReadLinks, ReadProcess};
use writ_platform_linux::watch::PidfdWatcher;

/// A short private directory for sockets (their paths are bounded).
fn socket_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("wl")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o750),
    )
    .unwrap();
    dir
}

fn direct() -> Arc<dyn ReadProcess> {
    Arc::new(Direct::new(Host::Myself))
}

/// This process as the kernel names it.
fn me() -> ProcessRef {
    ProcessChain::new(direct())
        .unwrap()
        .current(std::process::id())
        .unwrap()
}

/// A process reader serving on a thread over a socket pair, as `writd proc-reader` does over
/// its stdin.
fn served_helper() -> Helper {
    let (mine, theirs) = StdUnixStream::pair().unwrap();
    std::thread::spawn(move || helper::serve(theirs, &Direct::new(Host::Myself)));
    Helper::over(mine, helper::ANSWER_DEADLINE).unwrap()
}

fn contract_cases(attestor: &ProcessChain) -> Vec<(PeerInfo, Option<CallerFacts>)> {
    let tcp: SocketAddr = "192.0.2.7:51000".parse().unwrap();
    let me = attestor.current(std::process::id()).unwrap();
    let unix = |pid: Option<u32>, generation: Option<u64>| PeerInfo::Unix {
        uid: 1000,
        gid: 1000,
        pid,
        generation,
    };
    vec![
        (
            PeerInfo::Tcp { remote: tcp },
            Some(CallerFacts {
                source_addr: Some(tcp.ip()),
                process_chain: None,
            }),
        ),
        // No start time (not from a pidfd), another one, no pid: refused.
        (unix(Some(me.pid), None), None),
        (unix(Some(me.pid), Some(me.generation + 1)), None),
        (unix(None, Some(me.generation)), None),
        (
            PeerInfo::Memory {
                label: "test".to_owned(),
            },
            None,
        ),
    ]
}

#[test]
fn the_attestor_passes_the_contract_reading_proc_itself_and_through_the_process_reader() {
    for reader in [direct(), Arc::new(served_helper()) as Arc<dyn ReadProcess>] {
        let attestor = ProcessChain::new(reader).unwrap();
        contract::attestor(&attestor, &contract_cases(&attestor), true);
    }
}

#[test]
fn the_chain_goes_from_the_caller_to_pid_1_each_with_its_start_time() {
    for reader in [direct(), Arc::new(served_helper()) as Arc<dyn ReadProcess>] {
        let attestor = ProcessChain::new(Arc::clone(&reader)).unwrap();
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
        assert_eq!(chain[0].executable, std::env::current_exe().unwrap());
        // Up to pid 1, or, with no capability, to the last ancestor of this user's: the next
        // one up is another user's (on CI, the runner's agent and pid 1 are root's), whose
        // executable `/proc` won't show; never stopped earlier. As root, every one is read.
        let last = chain.last().unwrap();
        if last.pid != 1 {
            assert_ne!(rustix::process::geteuid().as_raw(), 0, "{chain:?}");
            let parent = writ_platform_linux::procfs::stat(last.pid).unwrap().ppid;
            match reader.read(parent) {
                Err(ReadError::Unreadable(why)) => assert!(
                    why.starts_with(&format!("pid {parent}: its executable: Permission denied")),
                    "{why}"
                ),
                other => panic!("the chain stopped below pid {parent}, read as {other:?}"),
            }
        }
        assert!(chain.len() >= 2 && chain.len() <= MAX_CHAIN, "{chain:?}");
        for process in &chain {
            assert_eq!(attestor.current(process.pid).unwrap(), *process);
            assert_eq!(process.code_identity, None);
            assert_eq!(process.unbindable, None, "{process:?}");
        }
        // Each parent started no later than its child.
        for pair in chain.windows(2) {
            assert!(pair[1].generation <= pair[0].generation, "{chain:?}");
        }
    }
}

/// A python program connecting to the socket named by its first argument, staying until
/// killed.
const CONNECT: &str = "import socket, sys, time\n\
                       s = socket.socket(socket.AF_UNIX)\n\
                       s.connect(sys.argv[1])\n\
                       time.sleep(600)\n";

/// A Unix socket with the pidfd peer reader, and a connection to it from `script`'s processes
/// (`bash -c`, for `exec -a`; `CONNECT` and `SOCKET` replaced): the attested facts of the
/// connection.
async fn attested_from(script: &str) -> (CallerFacts, Child) {
    let dir = socket_dir();
    let path = dir.path().join("t.sock");
    let transport = UnixTransport::bind(&path, pidfd_peer).unwrap();
    let child = Command::new("/bin/bash")
        .arg("-c")
        .arg(
            script
                .replace("CONNECT", &format!("'{CONNECT}'"))
                .replace("SOCKET", path.to_str().unwrap()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // A script that never connects fails the test, never hangs it.
    let connection = tokio::time::timeout(writ_platform::testing::WAIT_LIMIT, transport.accept())
        .await
        .expect("the script never connected")
        .unwrap();
    let facts = ProcessChain::new(direct())
        .unwrap()
        .attest(&connection.peer)
        .unwrap();
    (facts, child)
}

fn python() -> PathBuf {
    std::fs::canonicalize("/usr/bin/python3").unwrap()
}

#[tokio::test]
async fn the_caller_is_its_executable_whatever_it_calls_itself() {
    // `exec -a` gives python another argv[0]; its arguments say what they like.
    let (facts, mut child) =
        attested_from("exec -a /usr/local/bin/writ /usr/bin/python3 -c CONNECT SOCKET").await;
    let chain = facts.process_chain.unwrap();
    assert_eq!(chain[0].executable, python());
    assert_eq!(chain[0].pid, child.id());
    assert_eq!(chain[1], me());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[tokio::test]
async fn an_orphan_s_chain_never_runs_through_the_session_it_left() {
    // python's parent (the subshell) ends at once and a subreaper or pid 1 adopts it: its
    // chain goes there, never through the subshell's ancestors (this test's sh, this test).
    let (facts, mut child) = attested_from(
        "( /bin/sleep 30 | /usr/bin/python3 -c CONNECT SOCKET >/dev/null 2>&1 & ) ; exit 0",
    )
    .await;
    child.wait().unwrap();
    let chain = facts.process_chain.unwrap();
    assert_eq!(chain[0].executable, python());
    let (me, sh) = (me(), child.id());
    assert!(
        chain.iter().all(|p| p.pid != me.pid && p.pid != sh),
        "{chain:?}"
    );
    let _ = Command::new("/bin/kill")
        .arg(chain[0].pid.to_string())
        .status();
}

#[tokio::test]
async fn a_peer_that_ended_before_it_was_read_is_refused() {
    let dir = socket_dir();
    let path = dir.path().join("t.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import socket, sys\ns = socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[1])\n",
            path.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    let (stream, _) = listener.accept().await.unwrap();
    // Gone, whatever runs as its pid now: never taken for the caller.
    let refused = pidfd_peer(&stream).unwrap_err();
    assert!(!refused.to_string().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_unix_transport_with_the_pidfd_peer_passes_the_contract() {
    let dir = socket_dir();
    let path = dir.path().join("t.sock");
    let transport = UnixTransport::bind(&path, pidfd_peer).unwrap();
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

#[test]
fn this_kernel_has_what_local_mode_needs() {
    // Linux 6.5 or later, and a /proc without hidepid: CI's and the containers'.
    writ_platform_linux::kernel::check_process_chain().unwrap();
    writ_platform_linux::kernel::check_pidfds().unwrap();
}

// ----- The process reader's protocol -----

/// A fake helper on a thread: says ready, then answers the first request with `answer` and
/// keeps the connection open until the test ends (an answer starting with `CLOSE` closes it
/// once the rest is written).
fn fake_helper(answer: Vec<u8>, deadline: Duration) -> (Helper, std::sync::mpsc::Sender<()>) {
    let (mine, mut theirs) = StdUnixStream::pair().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        theirs.write_all(b"R").unwrap();
        let mut request = [0u8; 4];
        if theirs.read_exact(&mut request).is_ok() {
            match answer.strip_prefix(CLOSE) {
                Some(rest) => {
                    let _ = theirs.write_all(rest);
                    return;
                }
                None => {
                    let _ = theirs.write_all(&answer);
                }
            }
        }
        let _ = done_rx.recv();
    });
    (Helper::over(mine, deadline).unwrap(), done_tx)
}

/// Not a tag: the fake helper closes the connection after the rest of its answer.
const CLOSE: &[u8] = b"close:";

fn unreadable(result: Result<impl std::fmt::Debug, ReadError>) -> String {
    match result {
        Err(ReadError::Unreadable(why)) => why,
        other => panic!("expected an unreadable process, got {other:?}"),
    }
}

#[test]
fn a_broken_answer_ends_the_process_reader_for_good() {
    // A links answer (tag 0, the two namespaces, deleted 0) saying `length` bytes follow.
    let read = |length: u16| {
        let mut answer = vec![0u8];
        answer.extend_from_slice(&[0u8; 16]);
        answer.push(0);
        answer.extend_from_slice(&length.to_le_bytes());
        answer
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("its answer has an unknown tag 9", vec![9]),
        ("it has ended", [CLOSE, &[0, 1, 2]].concat()),
        ("its answer has a deleted flag of 2", {
            let mut a = read(0);
            a[17] = 2;
            a
        }),
        // An executable past PATH_MAX, said before its bytes.
        ("its answer holds 4097 bytes, more than 4096", read(4097)),
        ("its answer holds 513 bytes, more than 512", {
            let mut a = vec![2u8];
            a.extend_from_slice(&513u16.to_le_bytes());
            a
        }),
        ("its reason isn't UTF-8", vec![1, 1, 0, 0xff]),
        ("a host answer to a process request", {
            let mut a = vec![3u8];
            a.extend_from_slice(&[0u8; 16]);
            a
        }),
    ];
    for (why, answer) in cases {
        let (reader, _done) = fake_helper(answer, helper::ANSWER_DEADLINE);
        let first = unreadable(reader.links(42));
        assert_eq!(
            first,
            format!("the process reader can't be used any more ({why})")
        );
        // Never asked again: the same refusal, at once.
        assert_eq!(unreadable(reader.links(43)), first);
        assert_eq!(unreadable(reader.host_namespaces()), first);
    }
}

#[test]
fn a_process_reader_that_doesn_t_answer_in_time_is_not_used_again() {
    // It says ready, then never answers.
    let (mine, mut theirs) = StdUnixStream::pair().unwrap();
    theirs.write_all(b"R").unwrap();
    let reader = Helper::over(mine, Duration::from_millis(200)).unwrap();
    assert_eq!(
        unreadable(reader.links(42)),
        "the process reader can't be used any more (no answer within its deadline)"
    );
    assert_eq!(
        unreadable(reader.links(42)),
        "the process reader can't be used any more (no answer within its deadline)"
    );
    drop(theirs);
}

#[test]
fn a_process_reader_that_doesn_t_say_ready_is_refused_at_start() {
    let refused = |program: &str, args: &[&str]| match Helper::spawn(program.as_ref(), args) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("{program} {args:?}: a helper that isn't ready must be refused"),
    };
    assert_eq!(
        refused("/bin/sh", &["-c", "printf X >&0"]),
        "the process reader said something else than ready"
    );
    assert!(refused("/bin/sh", &["-c", "exit 3"]).starts_with("the process reader didn't start: "),);
    // A program that isn't there: the spawn's own error.
    match Helper::spawn("/nonexistent/writd".as_ref(), &[]) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        Ok(_) => panic!("a missing program can't be the process reader"),
    }
}

#[test]
fn the_process_reader_says_gone_and_its_host_as_the_reader_it_serves() {
    let reader = served_helper();
    let direct = Direct::new(Host::Myself);
    assert_eq!(reader.host().unwrap(), direct.host().unwrap());
    let me = std::process::id();
    assert_eq!(reader.read(me).unwrap(), direct.read(me).unwrap());
    // No process has pid 0, and a pid past the kernel's maximum is no one's.
    assert!(matches!(reader.read(0), Err(ReadError::Gone(_))));
    assert!(matches!(reader.links(0), Err(ReadError::Gone(_))));
    assert!(matches!(reader.read(u32::MAX), Err(ReadError::Gone(_))));
    // Still answering after those.
    assert_eq!(reader.read(me).unwrap(), direct.read(me).unwrap());
}

// ----- The watcher -----

/// Real processes: `sleep`, ended by a kill and waited for.
#[derive(Default)]
struct Sleepers {
    running: Vec<Child>,
}

impl ProcessDriver for Sleepers {
    fn start(&mut self) -> ProcessRef {
        let child = Command::new("/bin/sleep").arg("600").spawn().unwrap();
        let process = ProcessChain::new(direct())
            .unwrap()
            .current(child.id())
            .unwrap();
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
    let watcher = PidfdWatcher::new().unwrap();
    let mut driver = Sleepers::default();
    contract::session_watcher(&watcher, WatcherKind::Supported(&mut driver));
}

#[test]
fn watches_of_one_session_each_fire_and_a_cancelled_one_never() {
    let watcher = PidfdWatcher::new().unwrap();
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
fn a_watch_set_after_its_session_was_watched_and_ended_fires_at_once() {
    let watcher = PidfdWatcher::new().unwrap();
    let mut driver = Sleepers::default();
    let session = driver.start();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    let _kept = watcher
        .watch(
            &session,
            Box::new(move || {
                let _ = tx.send(1);
            }),
        )
        .unwrap();
    driver.end(&session);
    assert_eq!(rx.recv_timeout(writ_platform::testing::WAIT_LIMIT), Ok(1));
    let _late = watcher
        .watch(
            &session,
            Box::new(move || {
                let _ = tx2.send(2);
            }),
        )
        .unwrap();
    assert_eq!(rx.recv_timeout(writ_platform::testing::WAIT_LIMIT), Ok(2));
}
