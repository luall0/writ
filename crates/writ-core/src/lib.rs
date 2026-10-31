//! The lease model and the policy decisions, as pure functions (no I/O).
//!
//! - [`config`]: the repo registry and the templates (YAML, errors name the field).
//! - [`ticket`]: what the agent asks for, the complete ticket, its canonical bytes.
//! - [`fit`]: template fit and submission.
//! - [`narrow`]: what an approver may narrow when signing.
//! - [`lease`]: the lifecycle, approvals, amendments.
//! - [`caller`]: caller facts and the lease's caller constraint.
//! - [`policy`]: the decisions for signing, pushing and fetching.
//!
//! See docs/lease-model.md and docs/architecture/policy-and-state.md.

pub mod caller;
pub mod config;
pub mod fit;
pub mod lease;
pub mod names;
pub mod narrow;
pub mod pattern;
pub mod policy;
pub mod ticket;
pub mod units;
