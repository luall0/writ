//! What the transport says about a caller ([`CallerFacts`]), and the lease's caller constraint.
//!
//! Facts come from the network or the kernel through a `CallerAttestor`, never from the client.
//! A constraint that needs a fact the platform can't provide denies: a lease bound to a
//! process ancestor can never be used over TCP.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Facts about the caller of one request, gathered by the daemon.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerFacts {
    /// Network transports: the source address (advisory, never enforced in v1).
    pub source_addr: Option<IpAddr>,
    /// Local transports with a kernel-resolved ancestry, the caller first.
    pub process_chain: Option<Vec<ProcessRef>>,
}

/// One process in a caller's ancestry, as resolved by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    /// Distinguishes a reused pid (pidversion on macOS, start time on Linux).
    pub generation: u64,
    /// Resolved by the kernel, never from the process's own name or arguments.
    pub executable: PathBuf,
    pub code_identity: Option<CodeIdentity>,
}

/// A code signature identity (macOS): the signing identifier and the team.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeIdentity {
    pub signing_id: String,
    pub team_id: Option<String>,
}

/// The caller constraint of a lease (`subject.caller`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerConstraint {
    /// The caller must have this process in its ancestry (itself included).
    pub descends_from: ProcessMatch,
}

/// A process the caller must descend from: every field must match.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMatch {
    /// Absolute executable path, compared exactly.
    pub executable: String,
    pub pid: u32,
    pub generation: u64,
    /// When set, the process's code identity must be exactly this one.
    pub code_identity: Option<CodeIdentity>,
}

/// Why a caller doesn't satisfy a constraint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallerError {
    #[error("this lease is bound to a process, but this connection gives no process chain")]
    NoProcessChain,
    #[error("the caller does not descend from {executable} (pid {pid}, generation {generation})")]
    NotDescendant {
        executable: String,
        pid: u32,
        generation: u64,
    },
    #[error("invalid caller constraint: the executable must be an absolute path")]
    InvalidConstraint,
}

impl ProcessMatch {
    fn matches(&self, process: &ProcessRef) -> bool {
        process.pid == self.pid
            && process.generation == self.generation
            && process.executable.as_path() == Path::new(&self.executable)
            && match &self.code_identity {
                None => true,
                Some(required) => process.code_identity.as_ref() == Some(required),
            }
    }
}

impl CallerConstraint {
    /// Fails if the executable path isn't absolute.
    pub fn validate(&self) -> Result<(), CallerError> {
        if self.descends_from.executable.starts_with('/') {
            Ok(())
        } else {
            Err(CallerError::InvalidConstraint)
        }
    }
}

/// Checks the facts against a lease's caller constraint. No constraint: any caller holding
/// the certificate. Missing or empty process chain with a constraint: denied.
pub fn check(
    constraint: Option<&CallerConstraint>,
    facts: &CallerFacts,
) -> Result<(), CallerError> {
    let Some(constraint) = constraint else {
        return Ok(());
    };
    constraint.validate()?;
    let chain = match &facts.process_chain {
        Some(chain) if !chain.is_empty() => chain,
        _ => return Err(CallerError::NoProcessChain),
    };
    if chain.iter().any(|p| constraint.descends_from.matches(p)) {
        Ok(())
    } else {
        let m = &constraint.descends_from;
        Err(CallerError::NotDescendant {
            executable: m.executable.clone(),
            pid: m.pid,
            generation: m.generation,
        })
    }
}
