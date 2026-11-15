//! The tables, and the state's version: one schema, written whole into a new database; a
//! database of an older version migrated to it in steps ([`STEPS`], one per version, each in
//! its own transaction, after a copy of the whole database), by [`migrate`] only; one of a
//! newer version, or older than the first step, refused.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, Transaction};
use writ_core::canonical::Canonical;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;

use crate::{Result, StoreError};

/// The version of the state's format: the schema below and the ticket format it stores
/// ([`Ticket::KIND`]) (10: M6.2's policy shape; 11: each credential's count of token changes,
/// the review after M7.6's A-6; 12: the record of migrations, M7.9.6). Kept in
/// `PRAGMA user_version`, and the ticket format in `formats`.
pub const STATE_VERSION: i64 = 12;

/// The oldest version a step starts from: an older state can't be migrated (it predates the
/// steps, M7.9.6).
pub const FIRST_MIGRATABLE: i64 = 11;

/// One migration step: from `to - 1` to `to`, run in one transaction.
pub(super) struct Step {
    to: i64,
    run: fn(&Transaction<'_>) -> rusqlite::Result<()>,
}

/// Every step, in order: one per version after [`FIRST_MIGRATABLE`]. A version's step comes
/// with a test that migrates a database written by the schema it starts from (kept frozen in
/// the tests) and reads every row back.
pub(super) const STEPS: &[Step] = &[Step {
    to: 12,
    run: |tx| tx.execute_batch(MIGRATIONS_TABLE),
}];

/// The record of every migration (version 12).
const MIGRATIONS_TABLE: &str = "
CREATE TABLE migrations (
    to_version   INTEGER PRIMARY KEY,
    from_version INTEGER NOT NULL CHECK (from_version = to_version - 1),
    at           INTEGER NOT NULL,
    backup       TEXT NOT NULL
) STRICT;
";

/// What [`migrate`] did to an older state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrated {
    pub from: i64,
    pub to: i64,
    /// The copy of the whole database taken before the first step.
    pub backup: PathBuf,
}

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
CREATE TABLE token_versions (
    id      TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version >= 1)
) STRICT;
CREATE TABLE migrations (
    to_version   INTEGER PRIMARY KEY,
    from_version INTEGER NOT NULL CHECK (from_version = to_version - 1),
    at           INTEGER NOT NULL,
    backup       TEXT NOT NULL
) STRICT;
";

/// Sets the connection up (busy timeout, foreign keys, full sync, WAL); writes the schema
/// into a new database, and refuses one written in another version of the state (an older
/// one with the way to migrate it: [`migrate`]).
pub(super) fn prepare(conn: &Connection) -> Result<()> {
    let version = settle(conn)?;
    if version != 0 && version < STATE_VERSION {
        return Err(older(version));
    }
    create_or_check(conn, version)
}

/// [`prepare`], an older state first migrated to [`STATE_VERSION`] in steps: the whole
/// database copied into `backups` (`state-v<version>-<time>.db`, made private, never written
/// over) before the first step, each step then in its own transaction, recorded in
/// `migrations`. A step that fails is rolled back and refuses the open, naming it; the steps
/// before it stay, the copy untouched. Nothing is done to a state already at the version.
pub(super) fn migrate(
    conn: &Connection,
    backups: &Path,
    now: Timestamp,
) -> Result<Option<Migrated>> {
    migrate_with(conn, backups, now, None)
}

/// [`migrate`], the step to version `fails_at` failing after its own work (a test's, to see
/// what a failed step leaves).
pub(super) fn migrate_with(
    conn: &Connection,
    backups: &Path,
    now: Timestamp,
    fails_at: Option<i64>,
) -> Result<Option<Migrated>> {
    let from = settle(conn)?;
    if from == 0 || from == STATE_VERSION {
        create_or_check(conn, from)?;
        return Ok(None);
    }
    if !(FIRST_MIGRATABLE..STATE_VERSION).contains(&from) {
        return Err(other(from));
    }
    let backup = backup_copy(conn, backups, from, now)?;
    let mut at = from;
    while at < STATE_VERSION {
        let Some(to) = at.checked_add(1) else {
            return Err(other(from));
        };
        let step = STEPS
            .iter()
            .find(|s| s.to == to)
            .ok_or(StoreError::Migration {
                from: at,
                to,
                why: "this writd has no step for it".to_owned(),
            })?;
        let tx = conn.unchecked_transaction()?;
        let failed = |e: rusqlite::Error| StoreError::Migration {
            from: at,
            to,
            why: e.to_string(),
        };
        (step.run)(&tx).map_err(failed)?;
        if fails_at == Some(to) {
            return Err(failed(rusqlite::Error::InvalidQuery));
        }
        tx.execute(
            "INSERT INTO migrations (to_version, from_version, at, backup) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![to, at, now.unix(), backup.to_string_lossy()],
        )
        .map_err(failed)?;
        tx.pragma_update(None, "user_version", to).map_err(failed)?;
        tx.commit().map_err(failed)?;
        at = to;
    }
    create_or_check(conn, STATE_VERSION)?;
    Ok(Some(Migrated {
        from,
        to: STATE_VERSION,
        backup,
    }))
}

/// The state's version, read without changing anything (`writd check-upgrade`): 0 for a
/// database with nothing in it yet.
pub(super) fn version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

/// The whole database copied into `to`, a new private file (`0600`, made here and never
/// written over): a consistent copy of what is committed, whatever the WAL holds.
pub(super) fn copy(conn: &Connection, to: &Path) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    conn.execute("VACUUM INTO ?1", [to.to_string_lossy()])?;
    Ok(())
}

/// The most copies of one version made in one second ([`backup_copy`]'s suffixes).
const MAX_COPIES_A_SECOND: u32 = 100;

/// The whole database copied before the steps from `version`, into `backups` (made private if
/// missing): `state-v<version>-<time>.db`, a suffix added when that name is taken (another
/// attempt in the same second), never a file written over.
fn backup_copy(conn: &Connection, backups: &Path, version: i64, now: Timestamp) -> Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(backups)?;
    let stem = format!("state-v{version}-{}", now.unix());
    for n in 0..MAX_COPIES_A_SECOND {
        let name = if n == 0 {
            format!("{stem}.db")
        } else {
            format!("{stem}-{n}.db")
        };
        let path = backups.join(name);
        match copy(conn, &path) {
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            other => return other.map(|()| path),
        }
    }
    Err(StoreError::Migration {
        from: version,
        to: version.saturating_add(1),
        why: format!("{MAX_COPIES_A_SECOND} copies of the state already made this second"),
    })
}

fn older(found: i64) -> StoreError {
    if found < FIRST_MIGRATABLE {
        other(found)
    } else {
        StoreError::Older {
            found,
            expected: STATE_VERSION,
        }
    }
}

fn other(found: i64) -> StoreError {
    StoreError::OtherVersion {
        found,
        expected: STATE_VERSION,
    }
}

/// The connection's settings (busy timeout, foreign keys, full sync, WAL), and the state's
/// version.
fn settle(conn: &Connection) -> Result<i64> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // WAL in a file; an in-memory database keeps its own mode.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    version(conn)
}

/// A new database (version 0) given the whole schema; one at [`STATE_VERSION`] checked for
/// its ticket format; any other refused.
fn create_or_check(conn: &Connection, version: i64) -> Result<()> {
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
        return Err(other(version));
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
