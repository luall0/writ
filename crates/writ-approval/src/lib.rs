//! The approval service: tickets from submission to decision, and the leases they become.
//!
//! [`Service`] holds the lease store, the audit log and the certificate authority, and serves
//! both sides of `docs/flows.md` § 1 and § 5:
//!
//! - the agent's: [`Service::submit`] (a ticket file and the session key it was sent with) and
//!   [`Service::wait`] (the decision, with the lease and its certificate once signed);
//! - the approver's: [`Service::list`], [`Service::show`], [`Service::approve`] (an SSHSIG by
//!   a key in `approvers`, namespace `writ-approval`, over the canonical bytes of the
//!   submitted ticket or a narrowing of it), [`Service::refuse`], [`Service::revoke`];
//! - the gateway's: [`Service::authorize`] (a session certificate → its single active lease),
//!   [`Service::sign`] (a commit signed under it, if the policy allows: through the
//!   [`Signer`](writ_signer::Signer), counted and recorded in the ledger),
//!   [`Service::is_revoked`] and [`Service::subscribe_revocations`] (the deny list, and the
//!   serials whose open sessions must be dropped);
//! - time: [`Service::sweep`] expires pending tickets and leases past `expires_at`.
//!
//! Decisions are `writ-core`'s; this crate gathers the facts, verifies signatures, applies the
//! result to the store and logs every grant, refusal, revocation and denial. It only sees the
//! platform traits ([`Notifier`], [`SessionWatcher`]), so its tests run on the fakes.

mod error;
mod service;
#[cfg(feature = "testing")]
pub mod testing;

pub use error::{RefusalCode, ServiceError};
pub use service::{
    DEFAULT_SUBMISSIONS_IN_ALL, DEFAULT_SUBMISSIONS_PER_SOURCE, GatewayDenial,
    MAX_SUBMISSIONS_IN_ALL, MAX_SUBMISSIONS_PER_SOURCE, Pushing, Service, ServiceConfig,
    ServicePlatform, SignObject, SignedCommit, Signing, SubmissionLimits,
};
pub use writ_store::{EventKind, PendingNote};

/// The SSH user a session certificate is valid for ([`writ_proto::LEASE_USER`]).
pub const PRINCIPAL: &str = writ_proto::LEASE_USER;

/// How many tickets may wait for the approver at once; more are rejected.
pub const DEFAULT_MAX_PENDING: usize = 20;
