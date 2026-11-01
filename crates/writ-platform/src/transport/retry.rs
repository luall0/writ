//! Accept errors that don't mean the listener is broken: retried with a backoff, so that a
//! peer exhausting the daemon's file descriptors (or a connection reset before it was
//! accepted) can't end a listener, and with it the daemon.

use std::future::Future;
use std::io;
use std::time::Duration;

/// The first pause after a transient accept error; doubled each time, up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_millis(5);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Whether an accept error is about one connection or a passing shortage, not the listener:
/// the connection was aborted or reset before it was accepted, the call was interrupted, or
/// the process ran out of file descriptors, buffers or memory.
pub(crate) fn is_transient(error: &io::Error) -> bool {
    use io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::OutOfMemory
            | ErrorKind::WouldBlock
    ) {
        return true;
    }
    matches!(error.raw_os_error(), Some(code) if TRANSIENT_ERRNO.contains(&code))
}

/// EMFILE and ENFILE (the same numbers on Linux and macOS), ENOBUFS and EPROTO.
#[cfg(target_os = "linux")]
const TRANSIENT_ERRNO: [i32; 4] = [24, 23, 105, 71];
#[cfg(target_os = "macos")]
const TRANSIENT_ERRNO: [i32; 4] = [24, 23, 55, 100];
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const TRANSIENT_ERRNO: [i32; 2] = [24, 23];

/// Runs `accept` until it succeeds or fails for good; a transient error is retried after a
/// growing pause. Every listener's accept loop goes through this: one connection's error, or a
/// passing shortage, never ends a listener.
///
/// Any peer can cause a transient error (a connection reset before it was accepted,
/// descriptors used up by connections), so each one is logged at `debug` only: a flood can't
/// fill the daemon's log. A shortage that lasts until the pause reaches [`MAX_BACKOFF`] is
/// reported once, as a warning, per call (at most one line a second or so).
pub async fn accept_retrying<T, F, Fut>(listener: &str, mut accept: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut backoff = Backoff::new();
    loop {
        match accept().await {
            Ok(accepted) => return Ok(accepted),
            Err(e) if is_transient(&e) => {
                let next = backoff.after_error();
                tracing::debug!(listener, error = %e, "accept failed; retrying");
                if next.warn {
                    tracing::warn!(
                        listener,
                        error = %e,
                        "accept keeps failing (out of file descriptors or memory?); retrying"
                    );
                }
                tokio::time::sleep(next.pause).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// What to do after a transient error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Retry {
    pause: Duration,
    /// Whether to report the shortage as a warning (once per call, when the pause reaches
    /// [`MAX_BACKOFF`]).
    warn: bool,
}

/// The pauses of one call: [`MIN_BACKOFF`], doubled each time up to [`MAX_BACKOFF`].
struct Backoff {
    pause: Duration,
    reported: bool,
}

impl Backoff {
    fn new() -> Self {
        Self {
            pause: MIN_BACKOFF,
            reported: false,
        }
    }

    fn after_error(&mut self) -> Retry {
        let pause = self.pause;
        let warn = pause == MAX_BACKOFF && !self.reported;
        self.reported |= warn;
        self.pause = (pause * 2).min(MAX_BACKOFF);
        Retry { pause, warn }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn errno(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn running_out_of_descriptors_or_a_reset_is_transient() {
        for error in [
            errno(24), // EMFILE
            errno(23), // ENFILE
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from(io::ErrorKind::ConnectionReset),
            io::Error::from(io::ErrorKind::Interrupted),
            io::Error::from(io::ErrorKind::OutOfMemory),
        ] {
            assert!(is_transient(&error), "{error:?}");
        }
        for error in [
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::from(io::ErrorKind::InvalidInput),
            io::Error::from(io::ErrorKind::NotConnected),
            errno(9), // EBADF: the listener itself is gone
        ] {
            assert!(!is_transient(&error), "{error:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_error_is_retried_and_a_lasting_one_returned() {
        let script = Mutex::new(VecDeque::from([
            Err(errno(24)),
            Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
            Ok(7),
            Err(errno(9)),
        ]));
        let next = || {
            let item = script.lock().unwrap().pop_front().unwrap();
            async move { item }
        };
        assert_eq!(accept_retrying("test", next).await.unwrap(), 7);
        let error = accept_retrying("test", next).await.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(9));
        assert!(script.lock().unwrap().is_empty());
    }

    /// The warnings over `errors` transient errors in a row, and the pauses.
    fn after(errors: usize) -> (usize, Vec<Duration>) {
        let mut backoff = Backoff::new();
        let retries: Vec<Retry> = (0..errors).map(|_| backoff.after_error()).collect();
        let warnings = retries.iter().filter(|r| r.warn).count();
        (warnings, retries.iter().map(|r| r.pause).collect())
    }

    #[test]
    fn a_lasting_shortage_is_one_warning_per_accept() {
        // Pauses of 5 ms doubling to 1 s: the 9th error in a row is the first at 1 s. Each
        // error is one debug line (`accept_retrying`); only this decides warnings.
        let (warnings, pauses) = after(8);
        assert_eq!(warnings, 0);
        assert_eq!(pauses.first(), Some(&MIN_BACKOFF));
        assert_eq!(pauses.last(), Some(&Duration::from_millis(640)));
        let (warnings, pauses) = after(9);
        assert_eq!(warnings, 1);
        assert_eq!(pauses.last(), Some(&MAX_BACKOFF));
        // However long it lasts, one warning per accept.
        assert_eq!(after(40).0, 1);
        assert!(after(40).1.iter().all(|p| *p <= MAX_BACKOFF));
    }
}
