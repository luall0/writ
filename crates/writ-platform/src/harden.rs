//! What a process does, first thing, so the secrets it will hold don't leave through the OS:
//! the [`ProcessHardening`] interface (docs/architecture/platform.md, docs/operators/hardening.md).
//!
//! Each step is per process, never a setting of the whole system. A step nothing but the
//! process decides (no core dump, no debugger) is required: [`HardeningOutcome::Refused`]
//! stops the process before it reads a secret. A step the host decides (memory locked out of
//! swap, under the host's lock limit) is best effort: [`HardeningOutcome::NotApplied`], a
//! warning naming the optional fix.
//!
//! Portable implementation: [`none::NoHardening`], for an OS this build has none for (every
//! step refused). Linux and macOS have theirs in `writ-platform-linux` and
//! `writ-platform-macos`.

pub mod none;

use std::fmt;

/// One step of the hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HardeningStep {
    /// No core dump when the process crashes.
    NoCoreDumps,
    /// No debugger attached to the process, no other process reading its memory.
    NoDebugger,
    /// Its memory never written to swap.
    MemoryLocked,
}

impl HardeningStep {
    pub const ALL: [HardeningStep; 3] = [Self::NoCoreDumps, Self::NoDebugger, Self::MemoryLocked];

    /// Whether only the process decides it (so it is required), not the host.
    pub fn required(self) -> bool {
        !matches!(self, Self::MemoryLocked)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCoreDumps => "no core dumps",
            Self::NoDebugger => "no debugger",
            Self::MemoryLocked => "memory locked",
        }
    }
}

impl fmt::Display for HardeningStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a step went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningOutcome {
    Applied,
    /// A required step that failed: the process stops before it reads a secret.
    Refused {
        why: String,
    },
    /// A step the host's limits decide, not allowed there (or a traced debug build): a
    /// warning, with the optional fix.
    NotApplied {
        why: String,
        fix: String,
    },
    /// The platform has no call for it: one info line.
    Unavailable {
        why: String,
    },
}

/// A step and how it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardened {
    pub step: HardeningStep,
    pub outcome: HardeningOutcome,
}

/// Applies every step this platform has to the calling process. Used as a trait object.
pub trait ProcessHardening: Send + Sync {
    /// Applies each step to the calling process (idempotent) and says how each went: every
    /// [`HardeningStep`] reported once, in [`HardeningStep::ALL`]'s order. Never fails: a
    /// step that can't be applied is an outcome.
    fn harden(&self) -> Vec<Hardened>;
}
