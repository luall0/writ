//! The [`Clock`](writ_platform::Clock) contract, on the system clock and on the fake.

use writ_platform::clock::system::SystemClock;
use writ_platform::contract;
use writ_platform::testing::FakeClock;

#[test]
fn the_system_clock_passes_the_contract() {
    contract::clock(&SystemClock, None);
}

#[test]
fn the_fake_clock_passes_the_contract() {
    let clock = FakeClock::at_unix(1_800_000_000);
    contract::clock(&clock, Some(&|seconds| clock.advance(seconds)));
}

#[test]
fn the_fake_clock_reads_exactly_what_it_was_set_to() {
    let clock = FakeClock::at_unix(1_800_000_000);
    assert_eq!(writ_platform::Clock::now_ms(&clock), 1_800_000_000_000);
    clock.advance(u64::MAX);
    assert_eq!(
        writ_platform::Clock::now_ms(&clock),
        u64::MAX,
        "saturates, never wraps"
    );
}
