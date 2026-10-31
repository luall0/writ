//! What time it is: the [`Clock`] interface. Every expiry, rate window and certificate
//! validity is computed from it, so tests can move time by hand ([`crate::testing::FakeClock`]).
//!
//! Portable implementation: [`system::SystemClock`], the OS's wall clock.

pub mod system;

/// Milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    /// Now, in milliseconds since the Unix epoch. A clock before the epoch reads 0.
    fn now_ms(&self) -> u64;
}
