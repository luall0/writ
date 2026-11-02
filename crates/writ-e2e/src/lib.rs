//! The end-to-end harness (docs/end-to-end.md): what every scenario in `tests/scenarios/`
//! needs to drive the stack `make e2e` starts (the `writd`, `agent` and `forgejo`
//! containers), from the runner container.
//!
//! - [`docker`]: a user on a container, reached with `docker exec`; waits with deadlines.
//! - [`forgejo`]: Forgejo's API, and the web forms it has no API for (proving a key).
//! - [`setup`]: the operator setup, from nothing, with the commands the operator guide shows.
//! - [`stack`]: the stack, set up once; shared by the scenarios, or held alone by one that
//!   stops or restarts a container.
//! - [`agent`]: an agent's host (one per scenario, its own `WRIT_HOME`), tickets, leases, the
//!   approver, and what a scenario checks: the audit log, the mirror.
//!
//! Scenarios never touch the machine running `make e2e`: everything happens in the
//! containers, which are removed afterwards. This crate only runs in tests, so it panics on
//! any failure (with a message).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

pub mod agent;
pub mod docker;
pub mod forgejo;
pub mod setup;
pub mod stack;

pub use docker::{Host, stderr, stdout};
pub use stack::Stack;
