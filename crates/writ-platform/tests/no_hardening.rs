//! `NoHardening` against the `ProcessHardening` contract (a binary of its own: the contract
//! hardens the process it runs in, though this implementation changes nothing): every step
//! refused, with the reason.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use writ_platform::harden::none::NoHardening;
use writ_platform::{HardeningOutcome, HardeningStep};

#[test]
fn no_hardening_refuses_every_step() {
    let outcomes = writ_platform::contract::process_hardening(&NoHardening);
    for (hardened, step) in outcomes.iter().zip(HardeningStep::ALL) {
        assert_eq!(hardened.step, step);
        assert_eq!(
            hardened.outcome,
            HardeningOutcome::Refused {
                why: "this build has no process hardening for this OS (only Linux and macOS \
                      have one)"
                    .to_owned()
            }
        );
    }
}
