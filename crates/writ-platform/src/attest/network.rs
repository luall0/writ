//! [`NetworkAttestor`]: the detached mode's attestor.

use writ_core::caller::CallerFacts;

use super::CallerAttestor;
use crate::transport::PeerInfo;
use crate::{PlatformError, Result};

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
