//! [`NoHardening`]: for an OS this build has no hardening for. Every step is refused, so a
//! process that needs them doesn't run with its secrets unprotected.

use super::{Hardened, HardeningOutcome, HardeningStep, ProcessHardening};

/// No hardening: every step refused, naming why.
#[derive(Debug, Default)]
pub struct NoHardening;

impl ProcessHardening for NoHardening {
    fn harden(&self) -> Vec<Hardened> {
        HardeningStep::ALL
            .into_iter()
            .map(|step| Hardened {
                step,
                outcome: HardeningOutcome::Refused {
                    why: "this build has no process hardening for this OS (only Linux and \
                          macOS have one)"
                        .to_owned(),
                },
            })
            .collect()
    }
}
