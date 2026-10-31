//! The tables, and the migrations from older versions.

use rusqlite::Connection;

use crate::{Result, StoreError};

const SCHEMA_VERSION: i64 = 3;

/// How long a write waits for another connection's transaction before failing.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const SCHEMA: &str = "
CREATE TABLE tickets (
    id             TEXT PRIMARY KEY,
    canonical      BLOB NOT NULL,
    state          TEXT NOT NULL,
    lease_id       TEXT NOT NULL,
    feedback       TEXT,
    approver       TEXT,
    namespace      TEXT,
    sshsig         TEXT,
    cert_serial    INTEGER UNIQUE,
    current_ticket TEXT REFERENCES tickets(id),
    signatures     INTEGER NOT NULL DEFAULT 0 CHECK (signatures >= 0),
    pushes         INTEGER NOT NULL DEFAULT 0 CHECK (pushes >= 0),
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX tickets_state ON tickets(state);
CREATE TABLE ops (
    lease_id TEXT NOT NULL REFERENCES tickets(id),
    at       INTEGER NOT NULL
) STRICT;
CREATE INDEX ops_lease_at ON ops(lease_id, at);
CREATE TABLE ledger (
    commit_id TEXT NOT NULL,
    lease_id  TEXT NOT NULL REFERENCES tickets(id),
    repo      TEXT NOT NULL,
    key_id    TEXT NOT NULL,
    signed_at INTEGER NOT NULL,
    PRIMARY KEY (commit_id, lease_id, repo)
) STRICT;
CREATE INDEX ledger_lease ON ledger(lease_id);
";

/// Migrations, in order: `MIGRATIONS[n]` takes version `n + 1` to `n + 2`.
const MIGRATIONS: [&str; 2] = [
    // 2: the session public key of each ticket, the certificate of each lease.
    "ALTER TABLE tickets ADD COLUMN session_pubkey TEXT;
     ALTER TABLE tickets ADD COLUMN certificate TEXT;",
    // 3: who signed a refusal (none with `decisions: open`).
    "ALTER TABLE tickets ADD COLUMN feedback_by TEXT;",
];

/// Sets the connection up (busy timeout, foreign keys, full sync, WAL) and brings the schema
/// to [`SCHEMA_VERSION`]. A database from a newer version is refused.
pub(super) fn prepare(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // WAL in a file; an in-memory database keeps its own mode.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew(version));
    }
    if version < SCHEMA_VERSION {
        let tx = conn.unchecked_transaction()?;
        if version == 0 {
            tx.execute_batch(SCHEMA)?;
        }
        for migration in MIGRATIONS
            .iter()
            .skip(usize::try_from(version.max(1) - 1).unwrap_or(0))
        {
            tx.execute_batch(migration)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    }
    Ok(())
}
