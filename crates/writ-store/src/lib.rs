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
pub use audit::{AuditEvent, AuditLog, EventKind, MAX_FIELD_CHARS, Outcome};
#[cfg(feature = "testing")]
pub use store::StoreBreaker;
pub use store::{
    AuthorityHead, AuthorityHow, AuthorityVersion, Counter, LedgerEntry,
    OPS_KEPT_PAST_WINDOW_SECONDS, PendingNote, Store,
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
    #[error("the database schema is version {0}, newer than this writd")]
    SchemaTooNew(i64),
    #[error("can't encode an audit event: {0}")]
    Encode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;
