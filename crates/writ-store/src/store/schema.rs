//! The tables, and the state's version: one schema, written whole into a new database, and a
//! database written in another version refused (no migration chain: a format change bumps
//! [`STATE_VERSION`], and an operator starts that version from a new state directory).

use rusqlite::Connection;
use writ_core::canonical::Canonical;
use writ_core::ticket::Ticket;

use crate::{Result, StoreError};

/// The version of the state's format: the schema below, the ticket format it stores
/// ([`Ticket::KIND`]) and the policy shape its authority versions hold (10: M6.2's, keys
/// declared in the policy and repos naming their templates). Kept in `PRAGMA user_version`,
/// and the ticket format in `formats`.
pub const STATE_VERSION: i64 = 10;

/// How long a write waits for another connection's transaction before failing.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const SCHEMA: &str = "
CREATE TABLE formats (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    ticket_kind TEXT NOT NULL
) STRICT;
CREATE TABLE tickets (
    id             TEXT PRIMARY KEY,
    canonical      BLOB NOT NULL,
    state          TEXT NOT NULL,
    lease_id       TEXT NOT NULL,
    feedback       TEXT,
    feedback_by    TEXT,
    approver       TEXT,
    namespace      TEXT,
    sshsig         TEXT,
    cert_serial    INTEGER UNIQUE,
    current_ticket TEXT REFERENCES tickets(id),
    session_pubkey TEXT,
    certificate    TEXT,
    source         TEXT,
    renews         TEXT REFERENCES tickets(id),
    summary        TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX tickets_state ON tickets(state);
CREATE INDEX tickets_source ON tickets(source, state);
CREATE TABLE usage (
    lease_id   TEXT NOT NULL REFERENCES tickets(id),
    repo       TEXT NOT NULL,
    signatures INTEGER NOT NULL DEFAULT 0 CHECK (signatures >= 0),
    pushes     INTEGER NOT NULL DEFAULT 0 CHECK (pushes >= 0),
    PRIMARY KEY (lease_id, repo)
) STRICT;
CREATE TABLE ops (
    lease_id TEXT NOT NULL REFERENCES tickets(id),
    at       INTEGER NOT NULL
) STRICT;
CREATE INDEX ops_lease_at ON ops(lease_id, at);
CREATE TABLE ledger (
    commit_id       TEXT NOT NULL,
    lease_id        TEXT NOT NULL REFERENCES tickets(id),
    repo            TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    signed_at       INTEGER NOT NULL,
    paths_digest    TEXT,
    note            TEXT CHECK (note IN ('pending', 'written')),
    note_credential TEXT,
    PRIMARY KEY (commit_id, lease_id, repo)
) STRICT;
CREATE INDEX ledger_lease ON ledger(lease_id);
CREATE INDEX ledger_notes_pending ON ledger(repo) WHERE note = 'pending';
CREATE TABLE authority (
    target     TEXT NOT NULL CHECK (target IN ('policy', 'approvers', 'readers')),
    version    INTEGER NOT NULL CHECK (version >= 1),
    text       TEXT NOT NULL,
    digest     TEXT NOT NULL,
    how        TEXT NOT NULL CHECK (how IN ('init', 'admin', 'recover')),
    document   TEXT,
    signature  TEXT,
    approver   TEXT,
    applied_at INTEGER NOT NULL,
    PRIMARY KEY (target, version)
) STRICT;
CREATE TABLE authority_head (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    policy    INTEGER NOT NULL,
    approvers INTEGER NOT NULL,
    readers   INTEGER NOT NULL,
    mac       TEXT NOT NULL
) STRICT;
";

/// Sets the connection up (busy timeout, foreign keys, full sync, WAL); writes the schema
/// into a new database, and refuses one written in another version of the state.
pub(super) fn prepare(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // WAL in a file; an in-memory database keeps its own mode.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == 0 {
        let tx = conn.unchecked_transaction()?;
        // A database at version 0 that has tables isn't new: never written over.
        let tables: i64 = tx.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |r| r.get(0),
        )?;
        if tables > 0 {
            return Err(StoreError::OtherVersion {
                found: 0,
                expected: STATE_VERSION,
            });
        }
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO formats (id, ticket_kind) VALUES (1, ?1)",
            [Ticket::KIND],
        )?;
        tx.pragma_update(None, "user_version", STATE_VERSION)?;
        tx.commit()?;
        return Ok(());
    }
    if version != STATE_VERSION {
        return Err(StoreError::OtherVersion {
            found: version,
            expected: STATE_VERSION,
        });
    }
    let kind: String = conn.query_row("SELECT ticket_kind FROM formats WHERE id = 1", [], |r| {
        r.get(0)
    })?;
    if kind != Ticket::KIND {
        return Err(StoreError::OtherTicketFormat {
            found: kind,
            expected: Ticket::KIND,
        });
    }
    Ok(())
}
