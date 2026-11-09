//! [`ProcessChain`]: local mode's attestor on macOS. A Unix socket's caller is resolved from
//! the kernel: its pid and generation from the audit token taken at connect
//! ([`crate::peer::audit_token_peer`]), then its ancestry, each process with its executable
//! (`proc_pidpath`, never its name or arguments), its generation, and its code identity when
//! it has a valid signature. A TCP caller gets its source address and no chain, as under the
//! network attestor.
//!
//! Each parent is checked to be the one the kernel records for the child (its unique id,
//! never reused while the system runs): a parent that ended or a pid reused ends the chain
//! there (an orphan's chain stops at it, or at launchd when the kernel records launchd as
//! the parent that adopted it), so it never runs through the session the process left, and
//! a lease bound to an ancestor past the break is refused, never matched against another
//! process. A process read twice that changed
//! in between (it ended, or ran `exec`) is not vouched for either. The caller itself gone, or
//! read with another generation than its token's, is refused.

use std::collections::HashMap;
use std::sync::Mutex;

use writ_core::caller::{
    CallerFacts, CodeIdentity, MAX_SIGNING_ID_CHARS, MAX_TEAM_ID_CHARS, ProcessRef,
};
use writ_platform::{CallerAttestor, PeerInfo, PlatformError, Result};

use crate::sys;
use crate::sys::process::ProcInfo;

/// The most processes a chain holds, the caller first: deeper ancestors are left out (a
/// lease bound to one is refused).
pub const MAX_CHAIN: usize = 64;

/// The code identities kept, by pid and generation (a signature check reads the program's
/// file: each running process is checked once). Full, it starts again empty.
const MAX_IDENTITIES: usize = 1024;

/// Local mode's attestor on macOS.
#[derive(Debug, Default)]
pub struct ProcessChain {
    identities: Mutex<HashMap<(u32, u32), Option<CodeIdentity>>>,
}

impl ProcessChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// The process running as `pid` now, as a chain would hold it.
    pub fn current(&self, pid: u32) -> Result<ProcessRef> {
        self.read(pid, Link::Any)
            .map(|(process, _)| process)
            .map_err(PlatformError::Attestation)
    }

    /// The caller and its ancestry, the caller first.
    fn chain(&self, pid: u32, generation: u64) -> Result<Vec<ProcessRef>> {
        let generation = u32::try_from(generation).map_err(|_| {
            PlatformError::Attestation(format!("the caller (pid {pid}): no such generation"))
        })?;
        let (caller, mut info) = self
            .read(pid, Link::Generation(generation))
            .map_err(|why| PlatformError::Attestation(format!("the caller: {why}")))?;
        let mut chain = vec![caller];
        while info.ppid != 0 && chain.len() < MAX_CHAIN {
            match self.read(info.ppid, Link::Parent(info.puniqueid)) {
                Ok((parent, parent_info)) => {
                    chain.push(parent);
                    info = parent_info;
                }
                // The parent ended, or changed while read: the chain ends here.
                Err(_) => break,
            }
        }
        Ok(chain)
    }

    /// `pid`, if it is the process `link` names: read, then read again after its path and
    /// identity, unchanged.
    fn read(&self, pid: u32, link: Link) -> std::result::Result<(ProcessRef, ProcInfo), String> {
        let gone = |e: std::io::Error| format!("pid {pid}: {e}");
        let before = sys::process::proc_info(pid).map_err(gone)?;
        match link {
            Link::Generation(generation) if before.generation != generation => {
                return Err(format!("pid {pid} is another process now"));
            }
            Link::Parent(uniqueid) if before.uniqueid != uniqueid => {
                return Err(format!("pid {pid} is not the parent that made its child"));
            }
            _ => {}
        }
        let executable = sys::process::proc_path(pid).map_err(gone)?;
        let code_identity = self.identity(pid, before.generation);
        let after = sys::process::proc_info(pid).map_err(gone)?;
        if (after.uniqueid, after.generation) != (before.uniqueid, before.generation) {
            return Err(format!("pid {pid} changed while it was read"));
        }
        let process = ProcessRef {
            pid,
            generation: u64::from(before.generation),
            executable,
            code_identity,
        };
        Ok((process, before))
    }

    /// The code identity of `pid` at `generation`, checked once per running process.
    fn identity(&self, pid: u32, generation: u32) -> Option<CodeIdentity> {
        let key = (pid, generation);
        if let Some(known) = self.cache().get(&key) {
            return known.clone();
        }
        let identity = sys::codesign::signature(pid).and_then(|signed| {
            identity_within_bounds(CodeIdentity {
                signing_id: signed.identifier,
                team_id: signed.team,
            })
        });
        let mut cache = self.cache();
        if cache.len() >= MAX_IDENTITIES {
            cache.clear();
        }
        cache.insert(key, identity.clone());
        identity
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<(u32, u32), Option<CodeIdentity>>> {
        // Poisoned: a cache, whatever it holds is still a checked identity.
        self.identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How a process read must relate to what came before.
#[derive(Debug, Clone, Copy)]
enum Link {
    /// Whichever process runs as the pid now.
    Any,
    /// The caller: the generation its token gave.
    Generation(u32),
    /// A parent: the unique id its child records for it.
    Parent(u64),
}

/// An identity a lease could name (`writ_core::caller`'s bounds, no hidden character), or
/// none: one no constraint could match isn't worth vouching for.
fn identity_within_bounds(identity: CodeIdentity) -> Option<CodeIdentity> {
    let fits = |text: &str, most: usize| {
        !text.is_empty()
            && text.chars().count() <= most
            && !text.chars().any(writ_core::text::is_hidden_char)
    };
    let team_fits = identity
        .team_id
        .as_deref()
        .is_none_or(|team| fits(team, MAX_TEAM_ID_CHARS));
    (fits(&identity.signing_id, MAX_SIGNING_ID_CHARS) && team_fits).then_some(identity)
}

impl CallerAttestor for ProcessChain {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts> {
        match peer {
            PeerInfo::Tcp { remote } => Ok(CallerFacts {
                source_addr: Some(remote.ip()),
                process_chain: None,
            }),
            PeerInfo::Unix {
                pid: Some(pid),
                generation: Some(generation),
                ..
            } => Ok(CallerFacts {
                source_addr: None,
                process_chain: Some(self.chain(*pid, *generation)?),
            }),
            PeerInfo::Unix { .. } => Err(PlatformError::Attestation(
                "a Unix peer without its pid and generation (its audit token wasn't read)"
                    .to_owned(),
            )),
            _ => Err(PlatformError::Attestation(
                "the macOS process chain attestor attests Unix socket and TCP peers only"
                    .to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn identities_past_the_bounds_are_left_out() {
        let id = |signing: &str, team: Option<&str>| CodeIdentity {
            signing_id: signing.to_owned(),
            team_id: team.map(str::to_owned),
        };
        let at = "a".repeat(MAX_SIGNING_ID_CHARS);
        assert!(identity_within_bounds(id(&at, None)).is_some());
        let past = "a".repeat(MAX_SIGNING_ID_CHARS + 1);
        assert_eq!(identity_within_bounds(id(&past, None)), None);
        let team = "T".repeat(MAX_TEAM_ID_CHARS);
        assert!(identity_within_bounds(id("dev.writ", Some(&team))).is_some());
        let team = "T".repeat(MAX_TEAM_ID_CHARS + 1);
        assert_eq!(identity_within_bounds(id("dev.writ", Some(&team))), None);
        for hostile in ["", "dev.\u{202e}writ", "dev.writ\u{200b}"] {
            assert_eq!(
                identity_within_bounds(id(hostile, None)),
                None,
                "{hostile:?}"
            );
            assert_eq!(
                identity_within_bounds(id("dev.writ", Some(hostile))),
                None,
                "{hostile:?}"
            );
        }
    }
}
