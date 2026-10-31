//! The SQLite lease store and ledger.
//!
//! One row per ticket. A lease is the row of its first ticket: it holds the lease's state,
//! certificate serial and counters, and points (`current_ticket`) at the row whose signed
//! terms are in force (itself, or the last applied amendment).

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, params};
use writ_core::lease::{self, APPROVAL_NAMESPACE, Approval, Lease, State, TicketRecord, Usage};
use writ_core::names::{CommitId, KeyId, RepoName, TicketId};
use writ_core::policy::RATE_WINDOW_SECONDS;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;

use crate::{Result, StoreError};

const SCHEMA_VERSION: i64 = 1;

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

/// A counted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    Signature,
    Push,
    /// Not counted against a limit; only recorded for the rate.
    Fetch,
}

/// One commit signed under a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub commit: CommitId,
    pub lease: TicketId,
    /// The repo the commit was signed for.
    pub repo: RepoName,
    /// The signer key that signed it.
    pub key: KeyId,
    pub signed_at: Timestamp,
}

/// The lease store and ledger.
pub struct Store {
    conn: Connection,
}

fn corrupt(id: &str, why: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt {
        id: id.to_owned(),
        why: why.to_string(),
    }
}

impl Store {
    /// Opens (or creates) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// A database in memory, for tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        // WAL in a file; an in-memory database keeps its own mode.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                let tx = conn.unchecked_transaction()?;
                tx.execute_batch(SCHEMA)?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                tx.commit()?;
            }
            SCHEMA_VERSION => {}
            newer => return Err(StoreError::SchemaTooNew(newer)),
        }
        Ok(Self { conn })
    }

    /// Stores a freshly submitted ticket (`pending`).
    pub fn insert_pending(&self, ticket: &Ticket, now: Timestamp) -> Result<()> {
        let bytes = ticket
            .canonical_bytes()
            .map_err(|e| corrupt(ticket.id.as_str(), e))?;
        let inserted = self.conn.execute(
            "INSERT INTO tickets (id, canonical, state, lease_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5) ON CONFLICT (id) DO NOTHING",
            params![
                ticket.id.as_str(),
                bytes,
                State::Pending.as_str(),
                ticket.lease_id().as_str(),
                now.unix()
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::Duplicate(ticket.id.clone()));
        }
        Ok(())
    }

    /// A ticket and where it stands.
    pub fn ticket(&self, id: &TicketId) -> Result<Option<TicketRecord>> {
        self.conn
            .query_row(
                "SELECT id, canonical, state, feedback, approver, namespace, sshsig
                 FROM tickets WHERE id = ?1",
                [id.as_str()],
                raw_record,
            )
            .optional()?
            .map(RawRecord::decode)
            .transpose()
    }

    /// Every ticket in a state, oldest first.
    pub fn tickets(&self, state: State) -> Result<Vec<TicketRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, canonical, state, feedback, approver, namespace, sshsig
             FROM tickets WHERE state = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([state.as_str()], raw_record)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawRecord::decode))
            .collect()
    }

    /// Refuses a pending ticket with feedback.
    pub fn refuse(&self, id: &TicketId, feedback: &str, now: Timestamp) -> Result<()> {
        lease::transition(State::Pending, State::Refused)?;
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, feedback = ?3, updated_at = ?4
             WHERE id = ?1 AND state = ?5",
            params![
                id.as_str(),
                State::Refused.as_str(),
                feedback,
                now.unix(),
                State::Pending.as_str()
            ],
        )?;
        self.expect_changed(changed, id, State::Pending)
    }

    /// Moves a ticket or lease from `from` to `to`, if it is still in `from` and the lifecycle
    /// allows it. Activation and amendments have their own methods.
    pub fn transition(&self, id: &TicketId, from: State, to: State, now: Timestamp) -> Result<()> {
        lease::transition(from, to)?;
        if matches!(to, State::Active | State::Applied | State::Refused) {
            return Err(lease::LifecycleError::Transition { from, to }.into());
        }
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, updated_at = ?3 WHERE id = ?1 AND state = ?4",
            params![id.as_str(), to.as_str(), now.unix(), from.as_str()],
        )?;
        self.expect_changed(changed, id, from)
    }

    /// Records a new lease: its pending ticket becomes active with the signed terms, the
    /// approval and the certificate serial.
    pub fn activate(&self, lease: &Lease, now: Timestamp) -> Result<()> {
        if lease.state != State::Active || lease.ticket.id != lease.id {
            return Err(corrupt(lease.id.as_str(), "not a new active lease"));
        }
        let bytes = lease
            .ticket
            .canonical_bytes()
            .map_err(|e| corrupt(lease.id.as_str(), e))?;
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, canonical = ?3, approver = ?4, namespace = ?5,
                 sshsig = ?6, cert_serial = ?7, current_ticket = id, updated_at = ?8
             WHERE id = ?1 AND state = ?9",
            params![
                lease.id.as_str(),
                State::Active.as_str(),
                bytes,
                lease.approval.approver.as_str(),
                lease.approval.namespace,
                lease.approval.sshsig,
                serial_to_sql(lease.cert_serial)?,
                now.unix(),
                State::Pending.as_str()
            ],
        )?;
        self.expect_changed(changed, &lease.id, State::Pending)
    }

    /// Applies a signed amendment: the amendment becomes `applied` with its signed terms, and
    /// the lease points at it. Both or neither.
    pub fn apply_amendment(
        &self,
        lease: &Lease,
        applied: &TicketRecord,
        now: Timestamp,
    ) -> Result<()> {
        let amendment = &applied.ticket;
        let approval = applied
            .approval
            .as_ref()
            .ok_or_else(|| corrupt(amendment.id.as_str(), "applied without an approval"))?;
        if applied.state != State::Applied
            || amendment.ticket.amends.as_ref() != Some(&lease.id)
            || lease.ticket != *amendment
        {
            return Err(corrupt(
                amendment.id.as_str(),
                "not an amendment of this lease",
            ));
        }
        let bytes = amendment
            .canonical_bytes()
            .map_err(|e| corrupt(amendment.id.as_str(), e))?;
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE tickets SET state = ?2, canonical = ?3, approver = ?4, namespace = ?5,
                 sshsig = ?6, updated_at = ?7
             WHERE id = ?1 AND state = ?8 AND lease_id = ?9",
            params![
                amendment.id.as_str(),
                State::Applied.as_str(),
                bytes,
                approval.approver.as_str(),
                approval.namespace,
                approval.sshsig,
                now.unix(),
                State::Pending.as_str(),
                lease.id.as_str()
            ],
        )?;
        self.expect_changed(changed, &amendment.id, State::Pending)?;
        let changed = tx.execute(
            "UPDATE tickets SET current_ticket = ?2, updated_at = ?3 WHERE id = ?1 AND state = ?4",
            params![
                lease.id.as_str(),
                amendment.id.as_str(),
                now.unix(),
                State::Active.as_str()
            ],
        )?;
        self.expect_changed(changed, &lease.id, State::Active)?;
        tx.commit()?;
        Ok(())
    }

    /// A lease (active or ended) with the terms in force. `None` if `id` is not a lease.
    pub fn lease(&self, id: &TicketId) -> Result<Option<Lease>> {
        self.conn
            .query_row(&lease_query("l.id = ?1"), [id.as_str()], raw_lease)
            .optional()?
            .map(RawLease::decode)
            .transpose()
    }

    /// Every lease in a state (e.g. the active ones, reloaded after unsealing).
    pub fn leases(&self, state: State) -> Result<Vec<Lease>> {
        let mut statement = self.conn.prepare(&lease_query("l.state = ?1"))?;
        let rows = statement.query_map([state.as_str()], raw_lease)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawLease::decode))
            .collect()
    }

    /// What a lease has used: its counters and its operations in the rate window ending now.
    pub fn usage(&self, id: &TicketId, now: Timestamp) -> Result<Usage> {
        let (signatures, pushes): (i64, i64) = self
            .conn
            .query_row(
                "SELECT signatures, pushes FROM tickets WHERE id = ?1 AND cert_serial IS NOT NULL",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(id.clone()))?;
        let window_start = now.unix() - RATE_WINDOW_SECONDS;
        let ops: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ops WHERE lease_id = ?1 AND at > ?2 AND at <= ?3",
            params![id.as_str(), window_start, now.unix()],
            |r| r.get(0),
        )?;
        let count =
            |v: i64| u32::try_from(v).map_err(|_| corrupt(id.as_str(), "counter out of range"));
        Ok(Usage {
            signatures: count(signatures)?,
            pushes: count(pushes)?,
            ops_last_minute: count(ops)?,
        })
    }

    /// Takes one operation from an active lease, atomically: the counter goes up only while
    /// it is under `max` (concurrent requests can't overshoot), and the operation is recorded
    /// for the rate. Returns `false` (and records nothing) when the limit is reached or the
    /// lease is not active.
    pub fn consume(
        &self,
        id: &TicketId,
        counter: Counter,
        max: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let active = State::Active.as_str();
        let max = i64::from(max);
        let taken = match counter {
            Counter::Signature => tx.execute(
                "UPDATE tickets SET signatures = signatures + 1
                 WHERE id = ?1 AND state = ?2 AND cert_serial IS NOT NULL AND signatures < ?3",
                params![id.as_str(), active, max],
            )? == 1,
            Counter::Push => tx.execute(
                "UPDATE tickets SET pushes = pushes + 1
                 WHERE id = ?1 AND state = ?2 AND cert_serial IS NOT NULL AND pushes < ?3",
                params![id.as_str(), active, max],
            )? == 1,
            Counter::Fetch => tx
                .query_row(
                    "SELECT 1 FROM tickets WHERE id = ?1 AND state = ?2 AND cert_serial IS NOT NULL",
                    params![id.as_str(), active],
                    |_| Ok(()),
                )
                .optional()?
                .is_some(),
        };
        if !taken {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO ops (lease_id, at) VALUES (?1, ?2)",
            params![id.as_str(), now.unix()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Records a signed commit. Recording the same commit, lease and repo again keeps the
    /// first entry.
    pub fn ledger_append(&self, entry: &LedgerEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ledger (commit_id, lease_id, repo, key_id, signed_at)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
            params![
                entry.commit.as_str(),
                entry.lease.as_str(),
                entry.repo.as_str(),
                entry.key.as_str(),
                entry.signed_at.unix()
            ],
        )?;
        Ok(())
    }

    /// Every ledger entry for a commit.
    pub fn ledger_entries(&self, commit: &CommitId) -> Result<Vec<LedgerEntry>> {
        self.ledger_where("commit_id = ?1", commit.as_str())
    }

    /// Every commit signed under a lease, in signing order.
    pub fn ledger_for_lease(&self, lease: &TicketId) -> Result<Vec<LedgerEntry>> {
        self.ledger_where("lease_id = ?1", lease.as_str())
    }

    fn ledger_where(&self, condition: &str, value: &str) -> Result<Vec<LedgerEntry>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT commit_id, lease_id, repo, key_id, signed_at FROM ledger
             WHERE {condition} ORDER BY signed_at, rowid"
        ))?;
        let rows = statement.query_map([value], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (commit, lease, repo, key, at) = row?;
            let bad = |e: &dyn std::fmt::Display| corrupt(&commit, format!("ledger: {e}"));
            Ok(LedgerEntry {
                commit: commit.parse().map_err(|e| bad(&e))?,
                lease: lease.parse().map_err(|e| bad(&e))?,
                repo: repo.parse().map_err(|e| bad(&e))?,
                key: key.parse().map_err(|e| bad(&e))?,
                signed_at: Timestamp::from_unix(at).map_err(|e| bad(&e))?,
            })
        })
        .collect()
    }

    fn expect_changed(&self, changed: usize, id: &TicketId, expected: State) -> Result<()> {
        match changed {
            1 => Ok(()),
            0 if self.exists(id)? => Err(StoreError::Conflict {
                id: id.clone(),
                expected,
            }),
            0 => Err(StoreError::NotFound(id.clone())),
            _ => Err(corrupt(id.as_str(), "more than one row changed")),
        }
    }

    fn exists(&self, id: &TicketId) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM tickets WHERE id = ?1", [id.as_str()], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }
}

fn serial_to_sql(serial: u64) -> Result<i64> {
    i64::try_from(serial).map_err(|_| corrupt("certificate", "serial out of range"))
}

struct RawRecord {
    id: String,
    canonical: Vec<u8>,
    state: String,
    feedback: Option<String>,
    approval: RawApproval,
}

struct RawApproval {
    approver: Option<String>,
    namespace: Option<String>,
    sshsig: Option<String>,
}

impl RawApproval {
    fn decode(self, id: &str) -> Result<Option<Approval>> {
        match (self.approver, self.namespace, self.sshsig) {
            (None, None, None) => Ok(None),
            (Some(approver), Some(namespace), Some(sshsig)) => {
                if namespace != APPROVAL_NAMESPACE {
                    return Err(corrupt(id, "approval under another namespace"));
                }
                Ok(Some(Approval {
                    approver: approver.parse().map_err(|e| corrupt(id, e))?,
                    namespace,
                    sshsig,
                }))
            }
            _ => Err(corrupt(id, "incomplete approval")),
        }
    }
}

fn raw_record(row: &Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        id: row.get(0)?,
        canonical: row.get(1)?,
        state: row.get(2)?,
        feedback: row.get(3)?,
        approval: RawApproval {
            approver: row.get(4)?,
            namespace: row.get(5)?,
            sshsig: row.get(6)?,
        },
    })
}

impl RawRecord {
    fn decode(self) -> Result<TicketRecord> {
        let ticket = Ticket::from_canonical(&self.canonical).map_err(|e| corrupt(&self.id, e))?;
        if ticket.id.as_str() != self.id {
            return Err(corrupt(&self.id, "the stored ticket has another id"));
        }
        let state: State = self.state.parse().map_err(|e| corrupt(&self.id, e))?;
        Ok(TicketRecord {
            ticket,
            state,
            feedback: self.feedback,
            approval: self.approval.decode(&self.id)?,
        })
    }
}

/// The lease row `l` joined with the row of its terms in force `c`.
fn lease_query(condition: &str) -> String {
    format!(
        "SELECT l.id, l.state, l.cert_serial, c.id, c.canonical, c.approver, c.namespace, c.sshsig
         FROM tickets l JOIN tickets c ON c.id = l.current_ticket
         WHERE {condition} AND l.cert_serial IS NOT NULL ORDER BY l.id"
    )
}

struct RawLease {
    id: String,
    state: String,
    cert_serial: i64,
    current_id: String,
    canonical: Vec<u8>,
    approval: RawApproval,
}

fn raw_lease(row: &Row<'_>) -> rusqlite::Result<RawLease> {
    Ok(RawLease {
        id: row.get(0)?,
        state: row.get(1)?,
        cert_serial: row.get(2)?,
        current_id: row.get(3)?,
        canonical: row.get(4)?,
        approval: RawApproval {
            approver: row.get(5)?,
            namespace: row.get(6)?,
            sshsig: row.get(7)?,
        },
    })
}

impl RawLease {
    fn decode(self) -> Result<Lease> {
        let id: TicketId = self.id.parse().map_err(|e| corrupt(&self.id, e))?;
        let ticket = Ticket::from_canonical(&self.canonical).map_err(|e| corrupt(&self.id, e))?;
        if ticket.id.as_str() != self.current_id || ticket.lease_id() != &id {
            return Err(corrupt(&self.id, "terms in force belong to another lease"));
        }
        let state: State = self.state.parse().map_err(|e| corrupt(&self.id, e))?;
        if matches!(state, State::Pending | State::Refused | State::Applied) {
            return Err(corrupt(&self.id, format!("a lease can't be {state}")));
        }
        let approval = self
            .approval
            .decode(&self.id)?
            .ok_or_else(|| corrupt(&self.id, "a lease without an approval"))?;
        Ok(Lease {
            id,
            ticket,
            approval,
            state,
            cert_serial: u64::try_from(self.cert_serial).map_err(|e| corrupt(&self.id, e))?,
        })
    }
}
