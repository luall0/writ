//! Hardens the process before it reads a secret (docs/operators/hardening.md): every `writd`
//! process that holds one (`run`, `init`, `recover`, the credential helper). A required step
//! refused stops it; a step the host forbids is a warning naming its optional fix.

use anyhow::bail;
use writ_platform::{Hardened, HardeningOutcome};

/// Where a process says how its hardening went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Say {
    /// `writd run`: its log (every step).
    Log,
    /// `writd init`, `writd recover`: stderr (the warnings).
    Stderr,
    /// The credential helper, once per git operation: only a refusal, in the error.
    Refusals,
}

/// Applies this OS's hardening to the process; an error if a required step was refused.
pub fn harden(say: Say) -> anyhow::Result<()> {
    report(crate::platform::hardening().harden(), say)
}

/// Says how each step went, and fails on the refused ones.
fn report(outcomes: Vec<Hardened>, say: Say) -> anyhow::Result<()> {
    let mut refused = Vec::new();
    for Hardened { step, outcome } in outcomes {
        match outcome {
            HardeningOutcome::Applied => {
                if say == Say::Log {
                    tracing::info!(step = %step, "process hardening applied");
                }
            }
            HardeningOutcome::Refused { why } => refused.push(format!("{step}: {why}")),
            HardeningOutcome::NotApplied { why, fix } => match say {
                Say::Log => {
                    tracing::warn!(step = %step, %why, %fix, "process hardening not applied")
                }
                Say::Stderr => eprintln!("writd: warning: {step} not applied: {why} (fix: {fix})"),
                Say::Refusals => {}
            },
            HardeningOutcome::Unavailable { why } => {
                if say == Say::Log {
                    tracing::info!(step = %step, %why, "process hardening unavailable");
                }
            }
        }
    }
    if !refused.is_empty() {
        bail!(
            "process hardening refused, so no secret is read: {}",
            refused.join("; ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use writ_platform::HardeningStep;
    use writ_platform::ProcessHardening as _;

    use super::*;

    fn outcomes(memory: HardeningOutcome, debugger: HardeningOutcome) -> Vec<Hardened> {
        vec![
            Hardened {
                step: HardeningStep::NoCoreDumps,
                outcome: HardeningOutcome::Applied,
            },
            Hardened {
                step: HardeningStep::NoDebugger,
                outcome: debugger,
            },
            Hardened {
                step: HardeningStep::MemoryLocked,
                outcome: memory,
            },
        ]
    }

    #[test]
    fn a_refused_step_stops_the_process_and_a_warning_does_not() {
        let warned = HardeningOutcome::NotApplied {
            why: "the lock limit is 8388608 bytes".to_owned(),
            fix: "ulimit -l unlimited".to_owned(),
        };
        for say in [Say::Log, Say::Stderr, Say::Refusals] {
            assert!(report(outcomes(warned.clone(), HardeningOutcome::Applied), say).is_ok());
            let refused = HardeningOutcome::Refused {
                why: "the process is traced".to_owned(),
            };
            let error = report(outcomes(warned.clone(), refused), say).unwrap_err();
            assert_eq!(
                error.to_string(),
                "process hardening refused, so no secret is read: no debugger: the process is \
                 traced"
            );
        }
        // Every refusal named.
        let error = report(
            writ_platform::harden::none::NoHardening.harden(),
            Say::Refusals,
        )
        .unwrap_err()
        .to_string();
        for step in HardeningStep::ALL {
            assert!(
                error.contains(&format!("{step}: this build has no")),
                "{error}"
            );
        }
    }
}
