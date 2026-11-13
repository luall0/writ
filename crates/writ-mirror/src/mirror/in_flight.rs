//! Operations in flight ([`InFlight`]), for the daemon's orderly stop: each holds a
//! [`Running`] for as long as it runs, so a daemon stopping refuses new ones and waits for
//! those running to end within their own deadline, instead of cutting an upstream push
//! mid-way. The mirrors count their upstream operations (each [`super::access::Access`]:
//! [`super::Mirrors::stop`]); the gateway counts the git operations and signatures of its
//! sessions with one of its own.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Count {
    running: usize,
    stopping: bool,
}

/// A count of operations in flight (the mirrors': shared by every `Mirrors` a registry change
/// makes, like the sync slots).
#[derive(Debug)]
pub struct InFlight {
    count: watch::Sender<Count>,
}

impl InFlight {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            count: watch::Sender::new(Count::default()),
        })
    }

    /// One more operation in flight, or `None` once the daemon is stopping.
    pub fn start(self: &Arc<Self>) -> Option<Running> {
        let mut started = false;
        self.count.send_if_modified(|count| {
            if count.stopping {
                return false;
            }
            match count.running.checked_add(1) {
                Some(running) => {
                    count.running = running;
                    started = true;
                    true
                }
                None => false,
            }
        });
        started.then(|| Running {
            in_flight: self.clone(),
        })
    }

    /// Refuses every operation from now on, and waits until none is in flight, at most
    /// `wait`: how many still were then.
    pub async fn stop(&self, wait: Duration) -> usize {
        self.close();
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(far_future);
        self.wait_until(deadline).await
    }

    /// Refuses every operation from now on (those in flight run on).
    pub fn close(&self) {
        self.count.send_modify(|count| count.stopping = true);
    }

    /// Waits until none is in flight, at most until `deadline`: how many still were then.
    pub async fn wait_until(&self, deadline: tokio::time::Instant) -> usize {
        let mut seen = self.count.subscribe();
        match tokio::time::timeout_at(deadline, seen.wait_for(|count| count.running == 0)).await {
            Ok(Ok(_)) => 0,
            // The deadline passed (the sender lives in `self`, so the wait can't fail).
            Ok(Err(_)) | Err(_) => self.count.borrow().running,
        }
    }
}

/// A deadline no wait reaches (a day from now, or now if even that overflows).
pub fn far_future() -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(Duration::from_secs(86_400)).unwrap_or(now)
}

/// One operation in flight, until dropped.
#[derive(Debug)]
pub struct Running {
    in_flight: Arc<InFlight>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.in_flight
            .count
            .send_modify(|count| count.running = count.running.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_stop_waits_for_the_operations_in_flight_and_refuses_new_ones() {
        let in_flight = InFlight::new();
        let first = in_flight.start().unwrap();
        let second = in_flight.start().unwrap();
        let stopping = tokio::spawn({
            let in_flight = in_flight.clone();
            async move { in_flight.stop(Duration::from_secs(60)).await }
        });
        // The stop is under way: no new operation starts, the running ones go on.
        tokio::task::yield_now().await;
        assert!(in_flight.start().is_none());
        assert!(!stopping.is_finished());
        drop(first);
        tokio::task::yield_now().await;
        assert!(!stopping.is_finished());
        drop(second);
        assert_eq!(stopping.await.unwrap(), 0);
    }

    /// The review after M7.6 (D-5): the orderly stop closes two counts at once (the gateway's
    /// and upstream's), then waits once for both: one deadline for the two, never one after
    /// the other.
    #[tokio::test(start_paused = true)]
    async fn two_counts_closed_at_once_are_waited_for_against_one_deadline() {
        let (operations, upstream) = (InFlight::new(), InFlight::new());
        let _git = operations.start().unwrap();
        let _push = upstream.start().unwrap();
        operations.close();
        upstream.close();
        // Both refuse at once, before any wait.
        assert!(operations.start().is_none() && upstream.start().is_none());
        let wait = Duration::from_secs(30);
        let started = tokio::time::Instant::now();
        let deadline = started.checked_add(wait).unwrap();
        assert_eq!(operations.wait_until(deadline).await, 1);
        assert_eq!(upstream.wait_until(deadline).await, 1);
        assert_eq!(started.elapsed(), wait, "one deadline for both, not two");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_gives_up_at_its_deadline_and_says_how_many_still_ran() {
        let in_flight = InFlight::new();
        let _stuck = in_flight.start().unwrap();
        let wait = Duration::from_secs(30);
        let started = tokio::time::Instant::now();
        assert_eq!(in_flight.stop(wait).await, 1);
        // Not a moment before the deadline (the clock is paused: it moves only to it).
        assert_eq!(started.elapsed(), wait);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_with_nothing_in_flight_returns_at_once() {
        let in_flight = InFlight::new();
        drop(in_flight.start().unwrap());
        let started = tokio::time::Instant::now();
        assert_eq!(in_flight.stop(Duration::from_secs(30)).await, 0);
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(in_flight.start().is_none());
    }
}
