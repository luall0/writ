//! The approval service: tickets from submission to decision, and the leases they become.
//!
//! [`Service`] holds the lease store, the audit log and the certificate authority, and serves
//! both sides of [Flows § 1](../../docs/flows.md#1-ticket-submit-review-sign-or-refuse) and
//! [§ 5](../../docs/flows.md#5-revoke--expire):
//!
//! - the agent's: [`Service::submit`] (a ticket file and the session key it was sent with) and
//!   [`Service::wait`] (the decision, with the lease and its certificate once signed);
//! - the approver's: [`Service::list`], [`Service::show`], [`Service::approve`] (an SSHSIG by
//!   a key in `approvers`, namespace `writ-approval`, over the canonical bytes of the
//!   submitted ticket or a narrowing of it), [`Service::refuse`], [`Service::revoke`];
//! - the gateway's: [`Service::authorize`] (a session certificate → its single active lease),
//!   [`Service::is_revoked`] and [`Service::subscribe_revocations`] (the deny list, and the
//!   serials whose open sessions must be dropped);
//! - time: [`Service::sweep`] expires pending tickets and leases past `expires_at`.
//!
//! Decisions are `writ-core`'s; this crate gathers the facts, verifies signatures, applies the
//! result to the store and logs every grant, refusal, revocation and denial. It only sees the
//! platform traits ([`Notifier`], [`SessionWatcher`]), so its tests run on the fakes.

mod service;

pub use service::{
    Clock, GatewayDenial, ManualClock, Platform, Service, ServiceConfig, SystemClock,
};
pub use writ_store::EventKind;

/// The SSH user a session certificate is valid for (`ssh://git@host`).
pub const PRINCIPAL: &str = "git";

/// How many tickets may wait for the approver at once; more are rejected.
pub const DEFAULT_MAX_PENDING: usize = 20;

/// Errors that stop the service from starting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] writ_store::StoreError),
    #[error("the clock is out of range")]
    Clock,
}

pub use writ_platform::{Notifier, SessionWatcher};
