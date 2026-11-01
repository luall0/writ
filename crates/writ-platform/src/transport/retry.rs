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
    let mut backoff = MIN_BACKOFF;
    let mut reported = false;
    loop {
        match accept().await {
            Ok(accepted) => return Ok(accepted),
            Err(e) if is_transient(&e) => {
                tracing::debug!(listener, error = %e, "accept failed; retrying");
                if backoff == MAX_BACKOFF && !reported {
                    reported = true;
                    tracing::warn!(
                        listener,
                        error = %e,
                        "accept keeps failing (out of file descriptors or memory?); retrying"
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(e) => return Err(e),
        }
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

    /// Counts what the test's thread logs, by level.
    #[derive(Default)]
    struct Levels {
        warn: std::sync::atomic::AtomicUsize,
        debug: std::sync::atomic::AtomicUsize,
    }

    struct Counting(std::sync::Arc<Levels>);

    impl tracing::Subscriber for Counting {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            use std::sync::atomic::Ordering::SeqCst;
            match *event.metadata().level() {
                tracing::Level::WARN => self.0.warn.fetch_add(1, SeqCst),
                tracing::Level::DEBUG => self.0.debug.fetch_add(1, SeqCst),
                _ => 0,
            };
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// `errors` transient errors, then a connection: (warnings, debug lines) logged.
    async fn logged_for(errors: usize) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        let levels = std::sync::Arc::new(Levels::default());
        let _guard = tracing::subscriber::set_default(Counting(levels.clone()));
        let mut script: VecDeque<io::Result<u8>> = (0..errors)
            .map(|i| {
                Err(if i % 2 == 0 {
                    errno(24)
                } else {
                    io::Error::from(io::ErrorKind::ConnectionReset)
                })
            })
            .collect();
        script.push_back(Ok(1));
        let script = Mutex::new(script);
        let next = || {
            let item = script.lock().unwrap().pop_front().unwrap();
            async move { item }
        };
        assert_eq!(accept_retrying("test", next).await.unwrap(), 1);
        (levels.warn.load(SeqCst), levels.debug.load(SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn transient_errors_are_debug_lines_and_a_lasting_shortage_one_warning() {
        // Pauses of 5 ms doubling to 1 s: the 9th error in a row is the first at 1 s.
        assert_eq!(logged_for(3).await, (0, 3));
        assert_eq!(logged_for(8).await, (0, 8));
        assert_eq!(logged_for(9).await, (1, 9));
        // However long it lasts, one warning per accept.
        assert_eq!(logged_for(40).await, (1, 40));
    }
}
