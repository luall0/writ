//! The lease model and the policy decisions, as pure functions (no I/O).
//!
//! - [`authority`]: the files that grant authority, as admin changes name them.
//! - [`config`]: the repo registry and the templates (YAML, errors name the field).
//! - [`canonical`]: the canonical bytes of every signed document.
//! - [`ticket`]: what the agent asks for, the complete ticket.
//! - [`fit`]: template fit and submission.
//! - [`narrow`]: what an approver may narrow when signing.
//! - [`lease`]: the lifecycle, approvals, amendments.
//! - [`caller`]: caller facts and the lease's caller constraint.
//! - [`policy`]: the decisions for signing, pushing and fetching.
//! - [`signed`]: the other documents an approver signs: refusal, revocation, proof, unseal,
//!   admin change.
//! - [`names`], [`pattern`], [`units`]: validated names, patterns and units.
//! - [`upstream`]: an upstream's URL, read strictly.
//! - [`text`]: agent-written text made safe to show.
//! - [`yaml`]: YAML documents, with errors that name the field.
//!
//! See docs/lease-model.md and docs/architecture/policy-and-state.md.

// This crate parses untrusted input and computes limits: every arithmetic operation is
// checked, saturating, or allowed with the reason it can't overflow.
#![deny(clippy::arithmetic_side_effects)]

pub mod authority;
pub mod caller;
pub mod canonical;
pub mod config;
pub mod fit;
pub mod lease;
pub mod names;
pub mod narrow;
pub mod net;
pub mod pattern;
pub mod policy;
pub mod signed;
pub mod text;
pub mod ticket;
pub mod units;
pub mod upstream;
pub mod yaml;
