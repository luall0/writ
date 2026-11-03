//! The Linux process hardening against the `ProcessHardening` contract, in a test binary of
//! its own (it hardens this process): the core limit 0, not dumpable (what keeps a debugger
//! and `/proc/<pid>/mem` out), and the memory locked exactly when the lock limit allows it.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use rustix::process::{DumpableBehavior, Resource, getrlimit};
use writ_platform::{HardeningOutcome, HardeningStep};
use writ_platform_linux::hardening::Hardening;

/// The `VmLck` line of this process's status, in kB.
fn locked_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmLck:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn the_linux_hardening_passes_the_contract_and_does_what_it_says() {
    let lock_limit = getrlimit(Resource::Memlock);
    let outcomes = writ_platform::contract::process_hardening(&Hardening);
    assert_eq!(outcomes[0].outcome, HardeningOutcome::Applied, "core limit");
    assert_eq!(
        outcomes[1].outcome,
        HardeningOutcome::Applied,
        "not dumpable"
    );
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        DumpableBehavior::NotDumpable
    );
    // The memory lock follows the host's limit (or the capability): applied, or a warning
    // naming the limit and the fix, never a refusal.
    let memory = &outcomes[2];
    assert_eq!(memory.step, HardeningStep::MemoryLocked);
    match &memory.outcome {
        HardeningOutcome::Applied => {
            // Locked on fault: what this process has touched is locked from now on.
            let touched = vec![1u8; 1 << 20];
            assert!(locked_kb() > 0, "VmLck");
            drop(touched);
        }
        HardeningOutcome::NotApplied { why, fix } => {
            assert!(
                lock_limit.current.is_some(),
                "an unlimited limit locks: {why}"
            );
            assert!(why.starts_with("the lock limit is "), "{why}");
            assert!(fix.contains("ulimit -l unlimited"), "{fix}");
            assert_eq!(locked_kb(), 0);
        }
        other => panic!("memory lock: {other:?}"),
    }
}
