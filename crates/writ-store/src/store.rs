//! The SQLite lease store and ledger.
//!
//! One row per ticket. A lease is the row of its first ticket: it holds the lease's state,
//! certificate serial and counters, and points (`current_ticket`) at the row whose signed
//! terms are in force (itself, or the last applied amendment). Each row also keeps the
//! session public key it was submitted with (the ticket only holds its fingerprint), and a
//! lease's row the certificate issued for it.
//!
//! [`schema`] creates and migrates the tables, [`rows`] decodes rows strictly (fail closed:
//! a row that doesn't decode is an error), [`ledger`] holds the signed commits.

mod ledger;
mod rows;
mod schema;

pub use ledger::LedgerEntry;

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use writ_core::lease::{self, Lease, State, TicketRecord, Usage};
use writ_core::names::{KeyFingerprint, TicketId};
use writ_core::policy::RATE_WINDOW_SECONDS;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;

use self::rows::{
    RECORD_COLUMNS, RawLease, RawRecord, corrupt, lease_query, raw_lease, raw_record, serial_to_sql,
};
use crate::{Result, StoreError};
use writ_core::canonical::Canonical;

/// A counted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    Signature,
    Push,
    /// Not counted against a limit; only recorded for the rate.
    Fetch,
}

/// The lease store and ledger.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (or creates) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// A database in memory, for tests (feature `testing`).
    #[cfg(feature = "testing")]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        schema::prepare(&conn)?;
        Ok(Self { conn })
    }

    /// Stores a freshly submitted ticket (`pending`), with the session public key it was
    /// submitted with (OpenSSH text; its fingerprint is the ticket's `subject.session_key`).
    pub fn insert_pending(
        &self,
        ticket: &Ticket,
        session_pubkey: &str,
        now: Timestamp,
    ) -> Result<()> {
        let bytes = ticket
            .canonical_bytes()
            .map_err(|e| corrupt(ticket.id.as_str(), e))?;
        let inserted = self.conn.execute(
            "INSERT INTO tickets (id, canonical, state, lease_id, session_pubkey, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) ON CONFLICT (id) DO NOTHING",
            params![
                ticket.id.as_str(),
                bytes,
                State::Pending.as_str(),
                ticket.lease_id().as_str(),
                session_pubkey,
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
                &format!("SELECT {RECORD_COLUMNS} FROM tickets WHERE id = ?1"),
                [id.as_str()],
                raw_record,
            )
            .optional()?
            .map(RawRecord::decode)
            .transpose()
    }

    /// The session public key a ticket was submitted with.
    pub fn session_pubkey(&self, id: &TicketId) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT session_pubkey FROM tickets WHERE id = ?1",
                [id.as_str()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// The certificate issued for a lease.
    pub fn certificate(&self, id: &TicketId) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT certificate FROM tickets WHERE id = ?1 AND cert_serial IS NOT NULL",
                [id.as_str()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// The `limit` most recent tickets (ids are time-ordered), oldest first.
    pub fn recent_tickets(&self, limit: usize) -> Result<Vec<TicketRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(&format!(
            "SELECT * FROM (SELECT {RECORD_COLUMNS} FROM tickets ORDER BY id DESC LIMIT ?1) \
             ORDER BY id"
        ))?;
        let rows = statement.query_map([limit], raw_record)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawRecord::decode))
            .collect()
    }

    /// How many tickets are in a state.
    pub fn count(&self, state: State) -> Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tickets WHERE state = ?1",
            [state.as_str()],
            |r| r.get(0),
        )?;
        usize::try_from(n).map_err(|_| corrupt("tickets", "count out of range"))
    }

    /// Every ticket in a state, oldest first.
    pub fn tickets(&self, state: State) -> Result<Vec<TicketRecord>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM tickets WHERE state = ?1 ORDER BY id"
        ))?;
        let rows = statement.query_map([state.as_str()], raw_record)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawRecord::decode))
            .collect()
    }

    /// Refuses a pending ticket with feedback.
    pub fn refuse(
        &self,
        id: &TicketId,
        feedback: &str,
        by: Option<&KeyFingerprint>,
        now: Timestamp,
    ) -> Result<()> {
        lease::transition(State::Pending, State::Refused)?;
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, feedback = ?3, updated_at = ?4, feedback_by = ?6
             WHERE id = ?1 AND state = ?5",
            params![
                id.as_str(),
                State::Refused.as_str(),
                feedback,
                now.unix(),
                State::Pending.as_str(),
                by.map(KeyFingerprint::as_str)
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
    /// approval, the certificate serial and the certificate (OpenSSH text).
    pub fn activate(&self, lease: &Lease, certificate: &str, now: Timestamp) -> Result<()> {
        if lease.state != State::Active || lease.ticket.id != lease.id {
            return Err(corrupt(lease.id.as_str(), "not a new active lease"));
        }
        let bytes = lease
            .ticket
            .canonical_bytes()
            .map_err(|e| corrupt(lease.id.as_str(), e))?;
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, canonical = ?3, approver = ?4, namespace = ?5,
                 sshsig = ?6, cert_serial = ?7, current_ticket = id, updated_at = ?8,
                 certificate = ?10
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
                State::Pending.as_str(),
                certificate
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
            || amendment.text.amends.as_ref() != Some(&lease.id)
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
