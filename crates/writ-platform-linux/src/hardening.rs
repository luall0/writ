//! [`Hardening`]: process hardening on Linux, through `rustix` (no `unsafe`).
//!
//! - No core dumps: `RLIMIT_CORE` 0, soft and hard (required).
//! - No debugger: not dumpable (`PR_SET_DUMPABLE` 0), so a process of the same user can't
//!   attach (`ptrace`) nor read `/proc/<pid>/mem`, and no core is written either; and no
//!   tracer already attached (`TracerPid` 0), which not dumpable doesn't detach (required;
//!   a debug build being developed under `gdb` or `strace` runs with a warning, as on macOS).
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
        // Not dumpable stops a new attach; one already there (`strace -f writd run`, a
        // debugger quicker than this step) goes on reading: refused then (the review after
        // M5.5, as macOS refuses a traced start).
        (Ok(()), Ok(DumpableBehavior::NotDumpable)) => untraced(tracer(), cfg!(debug_assertions)),
        (Err(e), _) | (_, Err(e)) => HardeningOutcome::Refused {
            why: format!("making the process not dumpable (PR_SET_DUMPABLE 0) failed: {e}"),
        },
        (Ok(()), Ok(other)) => HardeningOutcome::Refused {
            why: format!("the process is still dumpable ({other:?}) after PR_SET_DUMPABLE 0"),
        },
    }
}

/// The outcome once not dumpable, by the pid tracing the process (`tracer`, 0: none): applied
/// untraced; traced, refused in a release build and a warning in a `debug` one (writd being
/// developed under `gdb` or `strace`), as on macOS; unknown, refused.
fn untraced(tracer: Result<u32, String>, debug: bool) -> HardeningOutcome {
    match tracer {
        Ok(0) => HardeningOutcome::Applied,
        Ok(pid) if debug => HardeningOutcome::NotApplied {
            why: format!("the process is traced (by pid {pid}): this debug build runs anyway"),
            fix: "start it without a debugger".to_owned(),
        },
        Ok(pid) => HardeningOutcome::Refused {
            why: format!(
                "the process is traced (by pid {pid}): a release build doesn't run traced"
            ),
        },
        Err(why) => HardeningOutcome::Refused { why },
    }
}

/// The pid tracing this process (0: none), from `/proc/self/status`'s `TracerPid`.
fn tracer() -> Result<u32, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status to check for a tracer: {e}"))?;
    tracer_in(&status)
}

/// `TracerPid` in the text of `/proc/<pid>/status`.
fn tracer_in(status: &str) -> Result<u32, String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .ok_or_else(|| "no TracerPid in /proc/self/status".to_owned())?
        .trim()
        .parse()
        .map_err(|_| "an unreadable TracerPid in /proc/self/status".to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tracer_is_read_from_the_status_and_anything_odd_refuses() {
        let status =
            |tracer: &str| format!("Name:\twritd\nState:\tS\nTracerPid:\t{tracer}\nUid:\t1\n");
        assert_eq!(tracer_in(&status("0")), Ok(0));
        assert_eq!(tracer_in(&status("4242")), Ok(4242));
        for (bad, why) in [
            (status("x"), "an unreadable TracerPid"),
            (status(""), "an unreadable TracerPid"),
            ("Name:\twritd\n".to_owned(), "no TracerPid"),
        ] {
            let error = tracer_in(&bad).unwrap_err();
            assert!(error.starts_with(why), "{bad}: {error}");
        }
        // This test process isn't traced.
        assert_eq!(tracer(), Ok(0));
    }

    /// The second review after M5.5: a traced start was refused in every build, where macOS
    /// lets a debug build run under a debugger with a warning. Never a release build.
    #[test]
    fn a_traced_start_is_refused_in_a_release_build_and_a_warning_in_a_debug_one() {
        for debug in [false, true] {
            assert_eq!(untraced(Ok(0), debug), HardeningOutcome::Applied);
            assert!(
                matches!(
                    untraced(Err("no TracerPid".to_owned()), debug),
                    HardeningOutcome::Refused { ref why } if why == "no TracerPid"
                ),
                "{debug}"
            );
        }
        assert!(matches!(
            untraced(Ok(4242), false),
            HardeningOutcome::Refused { ref why }
                if why.contains("pid 4242") && why.contains("a release build doesn't run traced")
        ));
        assert!(matches!(
            untraced(Ok(4242), true),
            HardeningOutcome::NotApplied { ref why, .. } if why.contains("pid 4242")
        ));
    }
}
