//! The macOS process hardening against the `ProcessHardening` contract, in a test binary of
//! its own (it hardens this process): the core limit 0, `PT_DENY_ATTACH` applied (the test
//! isn't traced), the memory lock unavailable (an info line, never a warning). A debugger
//! being refused is the manual check (docs/guides/manual-checks.md).

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use writ_platform::{HardeningOutcome, HardeningStep};
use writ_platform_macos::hardening::Hardening;

#[test]
fn the_macos_hardening_passes_the_contract_and_does_what_it_says() {
    let outcomes = writ_platform::contract::process_hardening(&Hardening);
    assert_eq!(outcomes[0].outcome, HardeningOutcome::Applied, "core limit");
    assert_eq!(
        outcomes[1].outcome,
        HardeningOutcome::Applied,
        "PT_DENY_ATTACH"
    );
    assert_eq!(outcomes[2].step, HardeningStep::MemoryLocked);
    assert!(
        matches!(&outcomes[2].outcome, HardeningOutcome::Unavailable { why } if why.starts_with("macOS has no call")),
        "{:?}",
        outcomes[2]
    );
}
