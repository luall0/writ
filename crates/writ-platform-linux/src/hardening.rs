//! [`Hardening`]: process hardening on Linux, through `rustix` (no `unsafe`).
//!
//! - No core dumps: `RLIMIT_CORE` 0, soft and hard (required).
//! - No debugger: not dumpable (`PR_SET_DUMPABLE` 0), so a process of the same user can't
//!   attach (`ptrace`) nor read `/proc/<pid>/mem`, and no core is written either (required).
//! - Memory locked: `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)`, only when the lock
//!   limit is unlimited or the process has `CAP_IPC_LOCK` (under a smaller limit, an
//!   allocation would fail once it is reached, and the process abort). Otherwise a warning
//!   naming the fix: the host decides, never Writ.

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{DumpableBehavior, Resource, Rlimit, getrlimit, setrlimit};
use rustix::thread::{CapabilitySet, capabilities};
use writ_platform::{Hardened, HardeningOutcome, HardeningStep, ProcessHardening};

/// The Linux process hardening.
#[derive(Debug, Default)]
pub struct Hardening;

impl ProcessHardening for Hardening {
    fn harden(&self) -> Vec<Hardened> {
        vec![
            Hardened {
                step: HardeningStep::NoCoreDumps,
                outcome: no_core_dumps(),
            },
            Hardened {
                step: HardeningStep::NoDebugger,
                outcome: not_dumpable(),
            },
            Hardened {
                step: HardeningStep::MemoryLocked,
                outcome: memory_locked(),
            },
        ]
    }
}

fn no_core_dumps() -> HardeningOutcome {
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    match setrlimit(Resource::Core, zero) {
        Ok(()) => HardeningOutcome::Applied,
        Err(e) => HardeningOutcome::Refused {
            why: format!("setting RLIMIT_CORE to 0 failed: {e}"),
        },
    }
}

fn not_dumpable() -> HardeningOutcome {
    let set = rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable);
    match (set, rustix::process::dumpable_behavior()) {
        (Ok(()), Ok(DumpableBehavior::NotDumpable)) => HardeningOutcome::Applied,
        (Err(e), _) | (_, Err(e)) => HardeningOutcome::Refused {
            why: format!("making the process not dumpable (PR_SET_DUMPABLE 0) failed: {e}"),
        },
        (Ok(()), Ok(other)) => HardeningOutcome::Refused {
            why: format!("the process is still dumpable ({other:?}) after PR_SET_DUMPABLE 0"),
        },
    }
}

/// What makes the memory lock optional to fix, said in every warning about it.
const LOCK_FIX: &str = "raise the daemon's lock limit to unlimited (`ulimit -l unlimited` where \
                        it starts, `LimitMEMLOCK=infinity` in a systemd unit, `ulimits: { \
                        memlock: -1 }` in a compose file) or give it CAP_IPC_LOCK; optional";

fn memory_locked() -> HardeningOutcome {
    let limit = getrlimit(Resource::Memlock);
    let unlimited = limit.current.is_none();
    let capable = capabilities(None)
        .map(|sets| sets.effective.contains(CapabilitySet::IPC_LOCK))
        .unwrap_or(false);
    if !(unlimited || capable) {
        let bytes = limit
            .current
            .map_or_else(|| "unlimited".to_owned(), |b| format!("{b} bytes"));
        return HardeningOutcome::NotApplied {
            why: format!(
                "the lock limit is {bytes}, not unlimited, and the process lacks CAP_IPC_LOCK: \
                 a partial lock would make allocations fail once it is reached"
            ),
            fix: LOCK_FIX.to_owned(),
        };
    }
    let flags = MlockAllFlags::CURRENT | MlockAllFlags::FUTURE | MlockAllFlags::ONFAULT;
    match mlockall(flags) {
        Ok(()) => HardeningOutcome::Applied,
        Err(e) => HardeningOutcome::NotApplied {
            why: format!("mlockall failed: {e}"),
            fix: LOCK_FIX.to_owned(),
        },
    }
}
