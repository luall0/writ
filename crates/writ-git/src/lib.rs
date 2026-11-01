//! Git objects as the daemon reads them, from bytes an agent sent: nothing here trusts the
//! agent, runs `git` or touches a file.
//!
//! - [`object`]: object ids and the two hash algorithms (SHA-1 with collision detection,
//!   SHA-256), computed from an object's bytes, never taken from the sender.
//! - [`commit`]: a commit object to sign, parsed strictly (its tree, parents, committer and
//!   message), and what kind of object a signing request carries.
//! - [`trailers`]: the trailers of a commit message, found the way git finds them.
//! - [`tree`]: tree objects.
//! - [`paths`]: the paths a commit touches, computed from tree and commit objects the agent
//!   sends as evidence, each one checked against its id.
//! - [`signed`]: the id of the commit git writes once the daemon's signature is in it (what
//!   the ledger records, so the commit pushed later is the one signed).
//!
//! `docs/flows.md` § 2 and `docs/lease-model.md` (rules) say how they are used.

// This crate parses untrusted input: every arithmetic operation is checked, saturating, or
// allowed with the reason it can't overflow.
#![deny(clippy::arithmetic_side_effects)]

pub mod commit;
pub mod object;
pub mod paths;
pub mod signed;
pub mod trailers;
pub mod tree;

pub use commit::Commit;
pub use object::{HashAlgo, ObjectId};
