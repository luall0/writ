//! The lease model and the policy decisions, as pure functions (no I/O).
//!
//! - [`config`]: the repo registry and the templates (YAML, errors name the field).
//! - [`canonical`]: the canonical bytes of every signed document.
//! - [`ticket`]: what the agent asks for, the complete ticket.
//! - [`fit`]: template fit and submission.
//! - [`narrow`]: what an approver may narrow when signing.
//! - [`lease`]: the lifecycle, approvals, amendments.
//! - [`caller`]: caller facts and the lease's caller constraint.
//! - [`policy`]: the decisions for signing, pushing and fetching.
//! - [`signed`]: the refusal and revocation documents an approver may sign.
//! - [`names`], [`pattern`], [`units`]: validated names, patterns and units.
//! - [`text`]: agent-written text made safe to show.
//! - [`yaml`]: YAML documents, with errors that name the field.
//!
//! See docs/lease-model.md and docs/architecture/policy-and-state.md.

pub mod caller;
pub mod canonical;
pub mod config;
pub mod fit;
pub mod lease;
pub mod names;
pub mod narrow;
pub mod pattern;
pub mod policy;
pub mod signed;
pub mod text;
pub mod ticket;
pub mod units;
pub mod yaml;
