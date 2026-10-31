//! Every session watcher, real and fake, through the watcher contract.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use writ_core::caller::ProcessRef;
use writ_platform::contract::{self, WatcherKind};
use writ_platform::testing::FakeWatcher;
use writ_platform::watch::none::NoSessionWatcher;
use writ_platform::{PlatformError, SessionWatcher};

fn process(pid: u32, generation: u64) -> ProcessRef {
    ProcessRef {
        pid,
        generation,
        executable: "/usr/bin/agent".into(),
        code_identity: None,
    }
}

fn counter() -> (Arc<AtomicUsize>, writ_platform::OnExit) {
    let count = Arc::new(AtomicUsize::new(0));
    let inner = Arc::clone(&count);
    (
        count,
        Box::new(move || {
            inner.fetch_add(1, Ordering::SeqCst);
        }),
    )
}

fn wait_for(count: &AtomicUsize, value: usize) {
    writ_platform::testing::eventually("the exit callbacks", || {
        count.load(Ordering::SeqCst) >= value
    });
    assert_eq!(count.load(Ordering::SeqCst), value);
}

#[test]
fn no_session_watcher_passes_the_contract() {
    contract::session_watcher(&NoSessionWatcher::new(), WatcherKind::Unsupported);
}

#[test]
fn no_session_watcher_says_unsupported() {
    let result = NoSessionWatcher::new().watch(&process(1, 1), Box::new(|| {}));
    assert!(matches!(result, Err(PlatformError::Unsupported(_))));
}

#[test]
fn unsupported_fake_watcher_passes_the_contract() {
    contract::session_watcher(&FakeWatcher::unsupported(), WatcherKind::Unsupported);
}

#[test]
fn fake_watcher_passes_the_contract() {
    let watcher = FakeWatcher::new();
    let mut driver = watcher.clone();
    contract::session_watcher(&watcher, WatcherKind::Supported(&mut driver));
    assert_eq!(watcher.active_watches(), 0);
}

#[test]
fn fake_watcher_counts_and_cancels_watches() {
    let watcher = FakeWatcher::new();
    let (count, on_exit) = counter();
    let handle = watcher.watch(&process(100, 1), on_exit).unwrap();
    let (other_count, other) = counter();
    let _other = watcher.watch(&process(101, 1), other).unwrap();
    assert_eq!(watcher.active_watches(), 2);
    drop(handle);
    assert_eq!(watcher.active_watches(), 1);
    watcher.exit(100, 1);
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "a cancelled watch never fires"
    );
    watcher.exit(101, 1);
    assert_eq!(other_count.load(Ordering::SeqCst), 1);
    assert_eq!(watcher.active_watches(), 0);
    watcher.exit(101, 1);
    assert_eq!(other_count.load(Ordering::SeqCst), 1, "fires once only");
}

#[test]
fn fake_watcher_exit_matches_the_generation() {
    let watcher = FakeWatcher::new();
    let (count, on_exit) = counter();
    let _handle = watcher.watch(&process(200, 2), on_exit).unwrap();
    watcher.exit(200, 3);
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "another process with the same pid"
    );
    watcher.exit(200, 2);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn fake_watcher_fires_promptly_for_an_exited_process() {
    let watcher = FakeWatcher::new();
    watcher.exit(300, 1);
    let (count, on_exit) = counter();
    let _handle = watcher.watch(&process(300, 1), on_exit).unwrap();
    wait_for(&count, 1);
    assert_eq!(watcher.active_watches(), 0);
}

#[test]
fn fake_watcher_callback_may_use_the_watcher() {
    // Callbacks never run under the fake's lock: one may call back into it.
    let watcher = FakeWatcher::new();
    let inner = watcher.clone();
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    let seen_inner = Arc::clone(&seen);
    let _handle = watcher
        .watch(
            &process(400, 1),
            Box::new(move || seen_inner.store(inner.active_watches(), Ordering::SeqCst)),
        )
        .unwrap();
    watcher.exit(400, 1);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[test]
fn fake_watcher_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakeWatcher>();
}
