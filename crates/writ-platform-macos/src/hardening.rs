//! [`Hardening`]: process hardening on macOS.
//!
//! - No core dumps: `RLIMIT_CORE` 0, soft and hard (required).
//! - No debugger: `ptrace(PT_DENY_ATTACH)` (required). It kills a process already traced, so
//!   that is checked first: a release build refuses to start traced; a debug build (writd
//!   being developed under `lldb`) skips it with a warning. No bypass in a release build.
//! - Memory locked: macOS has no call that locks a whole process (and encrypts swap): one
//!   info line, never a warning.

use rustix::process::{Resource, Rlimit, setrlimit};
use writ_platform::{Hardened, HardeningOutcome, HardeningStep, ProcessHardening};

use crate::sys;

/// The macOS process hardening.
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
                outcome: no_debugger(sys::traced(), cfg!(debug_assertions), sys::deny_attach),
            },
            Hardened {
                step: HardeningStep::MemoryLocked,
                outcome: HardeningOutcome::Unavailable {
                    why: "macOS has no call that locks a whole process's memory; it encrypts \
                          swap"
                        .to_owned(),
                },
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

/// `PT_DENY_ATTACH` (`deny`), unless the process is `traced`: refused in a release build,
/// skipped with a warning in a `debug` one.
pub(crate) fn no_debugger(
    traced: std::io::Result<bool>,
    debug: bool,
    deny: impl FnOnce() -> std::io::Result<()>,
) -> HardeningOutcome {
    match traced {
        Err(e) => HardeningOutcome::Refused {
            why: format!("cannot tell whether the process is traced: {e}"),
        },
        Ok(true) if debug => HardeningOutcome::NotApplied {
            why: "the process is traced (started under a debugger): PT_DENY_ATTACH would end \
                  it, so this debug build skips it"
                .to_owned(),
            fix: "start it without a debugger".to_owned(),
        },
        Ok(true) => HardeningOutcome::Refused {
            why: "the process is traced (started under a debugger): a release build doesn't \
                  run traced"
                .to_owned(),
        },
        Ok(false) => match deny() {
            Ok(()) => HardeningOutcome::Applied,
            Err(e) => HardeningOutcome::Refused {
                why: format!("ptrace(PT_DENY_ATTACH) failed: {e}"),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never() -> std::io::Result<()> {
        panic!("PT_DENY_ATTACH must not be called here")
    }

    #[test]
    fn a_traced_process_is_refused_in_release_and_skipped_in_debug_never_killed() {
        assert!(matches!(
            no_debugger(Ok(true), false, never),
            HardeningOutcome::Refused { why } if why.ends_with("a release build doesn't run traced")
        ));
        assert!(matches!(
            no_debugger(Ok(true), true, never),
            HardeningOutcome::NotApplied { why, fix }
                if why.ends_with("so this debug build skips it") && fix == "start it without a debugger"
        ));
        // Can't tell: refused, whatever the build.
        for debug in [false, true] {
            assert!(matches!(
                no_debugger(Err(std::io::Error::other("no info")), debug, never),
                HardeningOutcome::Refused { why } if why == "cannot tell whether the process is traced: no info"
            ));
        }
        // Not traced: applied, or refused when the call fails.
        assert_eq!(
            no_debugger(Ok(false), false, || Ok(())),
            HardeningOutcome::Applied
        );
        assert!(matches!(
            no_debugger(Ok(false), true, || Err(std::io::Error::other("denied"))),
            HardeningOutcome::Refused { why } if why == "ptrace(PT_DENY_ATTACH) failed: denied"
        ));
    }
}
