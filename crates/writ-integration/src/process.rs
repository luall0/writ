//! Waiting for a child process, bounded by a deadline that fails the test instead of hanging
//! it.

use std::process::{Child, Output};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::WAIT_LIMIT;

/// Waits for the process to end and returns its output. Fails after [`WAIT_LIMIT`].
pub fn finish(child: Child) -> Output {
    let (done, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(child.wait_with_output());
    });
    ended
        .recv_timeout(WAIT_LIMIT)
        .expect("the process did not end")
        .unwrap()
}

/// Whether the process ends by itself within `limit`. A process gives no other signal while
/// the caller keeps it (to kill it later), so this checks every few milliseconds; a process
/// still running at the limit is left running. Asserting `!ends_within(…)` only says it was
/// still running when the test stopped looking.
pub fn ends_within(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        // poll: another process's exit gives this process no signal; bounded by `deadline`.
        std::thread::sleep(Duration::from_millis(5));
    }
}
