//! Turns raw peer information into facts the policy can use: the [`CallerAttestor`]
//! interface.
//!
//! Portable implementation: [`network::NetworkAttestor`], the detached mode's (a TCP peer's
//! source address only).

pub mod network;

use writ_core::caller::CallerFacts;

use crate::Result;
use crate::transport::PeerInfo;

/// Turns raw peer information into [`CallerFacts`]. Facts come from the network or the
/// kernel, never from the client; a fact the implementation can't establish stays empty, and
/// a peer it can't attest at all is an error (the connection is then refused).
pub trait CallerAttestor: Send + Sync {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts>;
}
