//! Turns raw peer information into facts the policy can use: the [`CallerAttestor`]
//! interface and [`NetworkAttestor`], the detached mode's (a TCP peer's source address only).

use writ_core::caller::CallerFacts;

use crate::transport::PeerInfo;
use crate::{PlatformError, Result};

/// Turns raw peer information into [`CallerFacts`]. Facts come from the network or the
/// kernel, never from the client; a fact the implementation can't establish stays empty, and
/// a peer it can't attest at all is an error (the connection is then refused).
pub trait CallerAttestor: Send + Sync {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts>;
}

/// The detached mode's attestor: a TCP peer's source address, nothing else. It never gives a
/// process chain (the network can't), so a lease bound to a process can't be used through it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkAttestor;

impl NetworkAttestor {
    pub fn new() -> Self {
        Self
    }
}

impl CallerAttestor for NetworkAttestor {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts> {
        match peer {
            PeerInfo::Tcp { remote } => Ok(CallerFacts {
                source_addr: Some(remote.ip()),
                process_chain: None,
            }),
            _ => Err(PlatformError::Attestation(
                "the network attestor only attests TCP peers".to_owned(),
            )),
        }
    }
}
