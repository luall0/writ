//! Writ's state: the lease store and the ledger (SQLite), and the audit log (JSONL).
//!
//! - [`Store`]: tickets, leases, their counters and recent operations, and the ledger of every
//!   commit signed per lease. Tickets are stored as their canonical bytes and decoded strictly
//!   on load; state changes are compare-and-set and follow the lifecycle of `writ-core`.
//! - [`AuditLog`]: one JSON line per event, append-only, with no field that can hold a secret.
//!
//! See docs/architecture/policy-and-state.md.

mod audit;
mod store;

#[cfg(feature = "testing")]
pub use audit::{AuditBreaker, looks_secret};
pub use audit::{
    AuditEvent, AuditLine, AuditLog, EventKind, MAX_FIELD_CHARS, MAX_LINE_BYTES, MAX_LIST_ITEMS,
    Outcome, read_lines,
};
#[cfg(feature = "testing")]
pub use store::StoreBreaker;
pub use store::{
    AuthorityHead, AuthorityHow, AuthorityVersion, Counter, FIRST_MIGRATABLE, LeaseTimes,
    LedgerEntry, Migrated, OPS_KEPT_PAST_WINDOW_SECONDS, PendingNote, STATE_VERSION, Store,
};

use writ_core::lease::{LifecycleError, State};
use writ_core::names::TicketId;

/// Errors from the store and the audit log. Any of them fails the request closed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Reading or writing a file (the audit log, the database's).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt record {id}: {why}")]
    Corrupt { id: String, why: String },
    #[error("ticket {id} is not {expected}")]
    Conflict { id: TicketId, expected: State },
    #[error("ticket {0} does not exist")]
    NotFound(TicketId),
    #[error("ticket {0} already exists")]
    Duplicate(TicketId),
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    /// The state was written by a writd of a version no step migrates from: newer than this
    /// writd (no downgrade), or older than the first step.
    #[error(
        "the state is version {found}, this writd reads version {expected} and can't migrate \
         it (a newer state, or one older than its first step): run the writd that wrote it, or \
         start from a new state directory"
    )]
    OtherVersion { found: i64, expected: i64 },
    /// An older state, opened without migrating it: only `writd run` migrates.
    #[error(
        "the state is version {found}, this writd reads version {expected}: writd run migrates it \
         at its start, after a copy of it (writd check-upgrade shows what changes)"
    )]
    Older { found: i64, expected: i64 },
    /// A migration step that failed: rolled back, the copy taken before the first step kept.
    #[error("the state's migration from version {from} to {to} failed, rolled back: {why}")]
    Migration { from: i64, to: i64, why: String },
    #[error("the state holds tickets of format {found}, this writd reads {expected}")]
    OtherTicketFormat {
        found: String,
        expected: &'static str,
    },
    #[error("can't encode an audit event: {0}")]
    Encode(#[from] serde_json::Error),
    /// A token change counted against another count than the one in force (a change of the
    /// same id applied meanwhile).
    #[error("token {id}: {found} changes are in force, not {expected}")]
    TokenVersion {
        id: writ_core::names::KeyId,
        expected: u64,
        found: u64,
    },
}

pub type Result<T> = std::result::Result<T, StoreError>;
