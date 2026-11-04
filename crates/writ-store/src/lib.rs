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
    AuthorityHead, AuthorityHow, AuthorityVersion, Counter, LeaseTimes, LedgerEntry,
    OPS_KEPT_PAST_WINDOW_SECONDS, PendingNote, STATE_VERSION, Store,
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
    /// The state was written by a writd of another state version: never read, never
    /// migrated (docs/decisions.md).
    #[error(
        "the state is version {found}, this writd reads version {expected}: start this version \
         from a new state directory"
    )]
    OtherVersion { found: i64, expected: i64 },
    #[error("the state holds tickets of format {found}, this writd reads {expected}")]
    OtherTicketFormat {
        found: String,
        expected: &'static str,
    },
    #[error("can't encode an audit event: {0}")]
    Encode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
