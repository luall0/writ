//! The SQLite lease store and ledger.
//!
//! One row per ticket. A lease is the row of its first ticket: it holds the lease's state,
//! certificate serial and counters, and points (`current_ticket`) at the row whose signed
//! terms are in force (itself, or the last applied amendment). Each row also keeps the
//! session public key it was submitted with (the ticket only holds its fingerprint), and a
//! lease's row the certificate issued for it.
//!
//! [`schema`] creates and migrates the tables, [`rows`] decodes rows strictly (fail closed:
//! a row that doesn't decode is an error), [`ledger`] holds the signed commits, [`tokens`]
//! each credential's count of token changes.

mod authority;
mod ledger;
mod rows;
mod schema;
mod tokens;

pub use authority::{AuthorityHead, AuthorityHow, AuthorityVersion};
pub use ledger::{LedgerEntry, PendingNote};
pub use schema::{FIRST_MIGRATABLE, Migrated, STATE_VERSION};

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use writ_core::lease::{self, Lease, RepoUsage, State, TicketRecord, Usage};
use writ_core::names::{KeyFingerprint, RepoName, TicketId};
use writ_core::net::Source;
use writ_core::policy::RATE_WINDOW_SECONDS;
use writ_core::ticket::Ticket;
use writ_core::units::Timestamp;

use self::rows::{
    RECORD_COLUMNS, RawLease, RawRecord, corrupt, lease_query, raw_lease, raw_record, serial_to_sql,
};
use crate::{Result, StoreError};
use writ_core::canonical::Canonical;

/// The most leases [`Store::predecessors`] follows back: a bound on the work of one lookup,
/// whatever the chain (a template without `max_renewals` lets it grow).
pub const MAX_CHAIN: usize = 10_000;

/// When a ticket was submitted, and when its row last changed state (a lease's end, once it
/// ended).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTimes {
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// How long an operation stays in `ops` past the rate window before [`Store::prune_ops`]
/// deletes it: a clock set back by up to this much still finds what the window must count.
pub const OPS_KEPT_PAST_WINDOW_SECONDS: i64 = 3600;

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
    /// Set by a test to make a lease lookup fail (feature `testing` only).
    #[cfg(feature = "testing")]
    breaker: Option<std::sync::Arc<Switch>>,
}

/// What a [`StoreBreaker`] set: lookups to let through, then lookups to fail.
#[cfg(feature = "testing")]
#[derive(Debug)]
struct Switch {
    /// -1: off; n: n more lookups work, then the failures start.
    after: std::sync::atomic::AtomicI64,
    /// How many lookups fail in a row once they start.
    failures: std::sync::atomic::AtomicU32,
    /// -1: off; n: n more lease lists work, the one after fails, then off.
    lists_after: std::sync::atomic::AtomicI64,
    /// How many state changes (`transition`, `close`) fail from now, then off.
    changes: std::sync::atomic::AtomicU32,
}

/// Makes lease lookups of a [`Store`] fail, to test what a fault in the middle of an
/// operation leaves behind (feature `testing`).
#[cfg(feature = "testing")]
#[derive(Debug, Clone)]
pub struct StoreBreaker(std::sync::Arc<Switch>);

#[cfg(feature = "testing")]
impl StoreBreaker {
    /// The next `succeed` lease lookups work, the one after fails, then they work again.
    pub fn fail_lease_lookup_after(&self, succeed: u32) {
        self.fail_lease_lookups_after(succeed, 1);
    }

    /// The next `succeed` lease lookups work, the `fail` after fail, then they work again.
    pub fn fail_lease_lookups_after(&self, succeed: u32, fail: u32) {
        let ordering = std::sync::atomic::Ordering::SeqCst;
        self.0.failures.store(fail, ordering);
        self.0
            .after
            .store(if fail == 0 { -1 } else { i64::from(succeed) }, ordering);
    }

    /// The next `fail` state changes of a lease (a revocation, a close) fail, then they work
    /// again.
    pub fn fail_state_changes(&self, fail: u32) {
        self.0
            .changes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// The next `succeed` lists of leases by state work, the one after fails, then they work
    /// again.
    pub fn fail_lease_list_after(&self, succeed: u32) {
        self.0
            .lists_after
            .store(i64::from(succeed), std::sync::atomic::Ordering::SeqCst);
    }
}

impl Store {
    /// Opens (or creates) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Self::connection(path)?)
    }

    /// The database at `path`, private from creation (0600, whatever the umask; SQLite gives
    /// its WAL and shared memory files the database file's mode).
    fn connection(path: &Path) -> Result<Connection> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Connection::open(path)?)
    }

    /// [`Store::open`], an older state migrated first ([`Migrated`]): the whole database
    /// copied into `backups`, then one step per version, each in its own transaction. What
    /// `writd run` opens the state with; nothing else migrates it.
    pub fn open_migrating(
        path: &Path,
        backups: &Path,
        now: Timestamp,
    ) -> Result<(Self, Option<Migrated>)> {
        let conn = Self::connection(path)?;
        let migrated = schema::migrate(&conn, backups, now)?;
        Ok((Self::ready(conn), migrated))
    }

    /// [`Store::open_migrating`], with the step to version `fails_at` failing after its own
    /// work (feature `testing`): what a step that fails leaves behind.
    #[cfg(feature = "testing")]
    pub fn open_migrating_failing(
        path: &Path,
        backups: &Path,
        now: Timestamp,
        fails_at: i64,
    ) -> Result<(Self, Option<Migrated>)> {
        let conn = Self::connection(path)?;
        let migrated = schema::migrate_with(&conn, backups, now, Some(fails_at))?;
        Ok((Self::ready(conn), migrated))
    }

    /// The version of the state at `path`, read only (`writd check-upgrade`): 0 for a
    /// database with nothing in it.
    pub fn version_at(path: &Path) -> Result<i64> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        schema::version(&conn)
    }

    /// The whole state at `path` copied into `to`, a new private file, read only: what
    /// `writd check-upgrade` runs the steps on, never the state itself.
    pub fn copy_state(path: &Path, to: &Path) -> Result<()> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        schema::copy(&conn, to)
    }

    /// The migrations recorded in this state, oldest first.
    pub fn migrations(&self) -> Result<Vec<Migrated>> {
        let mut statement = self.conn.prepare(
            "SELECT from_version, to_version, backup FROM migrations ORDER BY to_version",
        )?;
        let rows = statement.query_map([], |r| {
            Ok(Migrated {
                from: r.get(0)?,
                to: r.get(1)?,
                backup: std::path::PathBuf::from(r.get::<_, String>(2)?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A database in memory, for tests (feature `testing`).
    #[cfg(feature = "testing")]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    /// [`Store::open`], with a [`StoreBreaker`] (feature `testing`).
    #[cfg(feature = "testing")]
    pub fn open_breakable(path: &Path) -> Result<(Self, StoreBreaker)> {
        let switch = std::sync::Arc::new(Switch {
            after: std::sync::atomic::AtomicI64::new(-1),
            failures: std::sync::atomic::AtomicU32::new(0),
            lists_after: std::sync::atomic::AtomicI64::new(-1),
            changes: std::sync::atomic::AtomicU32::new(0),
        });
        let mut store = Self::open(path)?;
        store.breaker = Some(switch.clone());
        Ok((store, StoreBreaker(switch)))
    }

    fn init(conn: Connection) -> Result<Self> {
        schema::prepare(&conn)?;
        Ok(Self::ready(conn))
    }

    fn ready(conn: Connection) -> Self {
        Self {
            conn,
            #[cfg(feature = "testing")]
            breaker: None,
        }
    }

    /// Stores a freshly submitted ticket (`pending`), with the session public key it was
    /// submitted with (OpenSSH text; its fingerprint is the ticket's `subject.session_key`)
    /// and the source it came from.
    pub fn insert_pending(
        &self,
        ticket: &Ticket,
        session_pubkey: &str,
        source: Source,
        now: Timestamp,
    ) -> Result<()> {
        let bytes = ticket
            .canonical_bytes()
            .map_err(|e| corrupt(ticket.id.as_str(), e))?;
        let inserted = self.conn.execute(
            "INSERT INTO tickets (id, canonical, state, lease_id, session_pubkey, source, renews,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8) ON CONFLICT (id) DO NOTHING",
            params![
                ticket.id.as_str(),
                bytes,
                State::Pending.as_str(),
                ticket.lease_id().as_str(),
                session_pubkey,
                source.to_string(),
                ticket.text.renews.as_ref().map(TicketId::as_str),
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
        self.broken_change()?;
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
        let Some(approval) = lease.granted_by.approval() else {
            return Err(corrupt(
                lease.id.as_str(),
                "a lease granted with no signature is recorded by insert_unsigned",
            ));
        };
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
                approval.approver.as_str(),
                approval.namespace,
                approval.sshsig,
                serial_to_sql(lease.cert_serial)?,
                now.unix(),
                State::Pending.as_str(),
                certificate
            ],
        )?;
        self.expect_changed(changed, &lease.id, State::Pending)
    }

    /// Records a lease granted with no signature (M7.9.7): its ticket inserted and active with
    /// its certificate in one transaction, never pending, no approval recorded, `unsigned`
    /// set. Only a lease granted by the policy (`GrantedBy::Policy`) that renews and amends nothing.
    pub fn insert_unsigned(
        &self,
        lease: &Lease,
        session_pubkey: &str,
        source: Source,
        certificate: &str,
        now: Timestamp,
    ) -> Result<()> {
        if lease.state != State::Active
            || lease.ticket.id != lease.id
            || !lease.granted_by.is_unsigned()
            || lease.renews.is_some()
            || lease.ticket.text.renews.is_some()
            || lease.ticket.text.amends.is_some()
        {
            return Err(corrupt(lease.id.as_str(), "not a new unsigned lease"));
        }
        self.broken_change()?;
        let bytes = lease
            .ticket
            .canonical_bytes()
            .map_err(|e| corrupt(lease.id.as_str(), e))?;
        let inserted = self.conn.execute(
            "INSERT INTO tickets (id, canonical, state, lease_id, session_pubkey, source,
                 cert_serial, current_ticket, certificate, unsigned, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?1, ?7, 1, ?8, ?8) ON CONFLICT (id) DO NOTHING",
            params![
                lease.id.as_str(),
                bytes,
                State::Active.as_str(),
                session_pubkey,
                source.to_string(),
                serial_to_sql(lease.cert_serial)?,
                certificate,
                now.unix()
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::Duplicate(lease.id.clone()));
        }
        Ok(())
    }

    /// Records a renewal's new lease (as [`Store::activate`]) and ends the lease it renews
    /// (`renewed`, from `renewed_from`), in one transaction: both or neither.
    pub fn activate_renewal(
        &self,
        lease: &Lease,
        certificate: &str,
        renewed: &TicketId,
        renewed_from: State,
        now: Timestamp,
    ) -> Result<()> {
        lease::transition(renewed_from, State::Renewed)?;
        if lease.ticket.text.renews.as_ref() != Some(renewed) {
            return Err(corrupt(lease.id.as_str(), "not a renewal of this lease"));
        }
        let tx = self.conn.unchecked_transaction()?;
        self.activate(lease, certificate, now)?;
        let changed = tx.execute(
            "UPDATE tickets SET state = ?2, updated_at = ?3
             WHERE id = ?1 AND state = ?4 AND cert_serial IS NOT NULL",
            params![
                renewed.as_str(),
                State::Renewed.as_str(),
                now.unix(),
                renewed_from.as_str()
            ],
        )?;
        self.expect_changed(changed, renewed, renewed_from)?;
        tx.commit()?;
        Ok(())
    }

    /// The leases `id` renews, the one it names first, then the one that one names, and so on
    /// (at most [`MAX_CHAIN`]); none for a lease that renews nothing.
    pub fn predecessors(&self, id: &TicketId) -> Result<Vec<TicketId>> {
        let mut statement = self.conn.prepare(
            "WITH RECURSIVE chain(id, depth) AS (
                 SELECT renews, 1 FROM tickets WHERE id = ?1 AND renews IS NOT NULL
                 UNION ALL
                 SELECT t.renews, c.depth + 1 FROM tickets t JOIN chain c ON t.id = c.id
                 WHERE t.renews IS NOT NULL AND c.depth < ?2
             )
             SELECT id FROM chain ORDER BY depth",
        )?;
        let max = i64::try_from(MAX_CHAIN).map_err(|_| corrupt("chain", "bound out of range"))?;
        let rows = statement.query_map(params![id.as_str(), max], |r| r.get::<_, String>(0))?;
        rows.map(|row| {
            let text = row?;
            text.parse().map_err(|e| corrupt(id.as_str(), e))
        })
        .collect()
    }

    /// The active leases submitted from `source`, oldest first.
    pub fn active_from(&self, source: Source) -> Result<Vec<Lease>> {
        let mut statement = self
            .conn
            .prepare(&lease_query("l.state = ?1 AND l.source = ?2"))?;
        let rows = statement.query_map(
            params![State::Active.as_str(), source.to_string()],
            raw_lease,
        )?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawLease::decode))
            .collect()
    }

    /// When a ticket was submitted and when its row last changed state.
    pub fn times(&self, id: &TicketId) -> Result<LeaseTimes> {
        let (created, updated): (i64, i64) = self
            .conn
            .query_row(
                "SELECT created_at, updated_at FROM tickets WHERE id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(id.clone()))?;
        let at = |t| Timestamp::from_unix(t).map_err(|e| corrupt(id.as_str(), e));
        Ok(LeaseTimes {
            created_at: at(created)?,
            updated_at: at(updated)?,
        })
    }

    /// Closes a lease with the agent's summary: an active one becomes `closed`; one that
    /// already ended (`from`, any end) keeps its state and gets the summary. Compare-and-set
    /// on `from`.
    pub fn close(&self, id: &TicketId, from: State, summary: &str, now: Timestamp) -> Result<()> {
        let to = if from == State::Active {
            lease::transition(from, State::Closed)?
        } else if from.is_terminal() && from != State::Applied && from != State::Refused {
            from
        } else {
            return Err(lease::LifecycleError::Transition {
                from,
                to: State::Closed,
            }
            .into());
        };
        self.broken_change()?;
        let changed = self.conn.execute(
            "UPDATE tickets SET state = ?2, summary = ?3, updated_at = CASE WHEN ?2 = ?4 THEN updated_at ELSE ?5 END
             WHERE id = ?1 AND state = ?4 AND cert_serial IS NOT NULL",
            params![id.as_str(), to.as_str(), summary, from.as_str(), now.unix()],
        )?;
        self.expect_changed(changed, id, from)
    }

    /// The summary a lease was closed with.
    pub fn summary(&self, id: &TicketId) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT summary FROM tickets WHERE id = ?1",
                [id.as_str()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
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

    /// A state change the test's breaker fails ([`StoreBreaker::fail_state_changes`]).
    fn broken_change(&self) -> Result<()> {
        #[cfg(feature = "testing")]
        if let Some(switch) = &self.breaker {
            let ordering = std::sync::atomic::Ordering::SeqCst;
            let left = switch.changes.load(ordering);
            if left > 0 {
                switch.changes.store(left.saturating_sub(1), ordering);
                return Err(StoreError::Io(std::io::Error::other(
                    "the store was broken by the test",
                )));
            }
        }
        Ok(())
    }

    /// A lease (active or ended) with the terms in force. `None` if `id` is not a lease.
    pub fn lease(&self, id: &TicketId) -> Result<Option<Lease>> {
        #[cfg(feature = "testing")]
        if let Some(switch) = &self.breaker {
            // -1: off; n: n more lookups work; 0: this one fails, then off once the failures
            // asked for are done.
            let ordering = std::sync::atomic::Ordering::SeqCst;
            match switch.after.load(ordering) {
                0 => {
                    let left = switch.failures.load(ordering).saturating_sub(1);
                    switch.failures.store(left, ordering);
                    if left == 0 {
                        switch.after.store(-1, ordering);
                    }
                    return Err(StoreError::Io(std::io::Error::other(
                        "the store was broken by the test",
                    )));
                }
                n if n > 0 => switch.after.store(n.saturating_sub(1), ordering),
                _ => {}
            }
        }
        self.conn
            .query_row(&lease_query("l.id = ?1"), [id.as_str()], raw_lease)
            .optional()?
            .map(RawLease::decode)
            .transpose()
    }

    /// Every lease in a state (e.g. the active ones, reloaded after unsealing).
    pub fn leases(&self, state: State) -> Result<Vec<Lease>> {
        #[cfg(feature = "testing")]
        if let Some(switch) = &self.breaker {
            // -1: off; n: n more lists work; 0: this one fails, then off.
            let ordering = std::sync::atomic::Ordering::SeqCst;
            match switch.lists_after.load(ordering) {
                0 => {
                    switch.lists_after.store(-1, ordering);
                    return Err(StoreError::Io(std::io::Error::other(
                        "the store was broken by the test",
                    )));
                }
                n if n > 0 => switch.lists_after.store(n.saturating_sub(1), ordering),
                _ => {}
            }
        }
        let mut statement = self.conn.prepare(&lease_query("l.state = ?1"))?;
        let rows = statement.query_map([state.as_str()], raw_lease)?;
        rows.map(|row| row.map_err(StoreError::from).and_then(RawLease::decode))
            .collect()
    }

    /// What a lease has used: each repository's counters and its operations in the rate
    /// window ending now.
    pub fn usage(&self, id: &TicketId, now: Timestamp) -> Result<Usage> {
        self.conn
            .query_row(
                "SELECT 1 FROM tickets WHERE id = ?1 AND cert_serial IS NOT NULL",
                [id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(id.clone()))?;
        let count =
            |v: i64| u32::try_from(v).map_err(|_| corrupt(id.as_str(), "counter out of range"));
        let mut repos = std::collections::BTreeMap::new();
        let mut statement = self
            .conn
            .prepare("SELECT repo, signatures, pushes FROM usage WHERE lease_id = ?1")?;
        let rows = statement.query_map([id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (repo, signatures, pushes) = row?;
            let repo: RepoName = repo
                .parse()
                .map_err(|_| corrupt(id.as_str(), "a usage row's repo is not a repo name"))?;
            repos.insert(
                repo,
                RepoUsage {
                    signatures: count(signatures)?,
                    pushes: count(pushes)?,
                },
            );
        }
        let window_start = now.unix() - RATE_WINDOW_SECONDS;
        let ops: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ops WHERE lease_id = ?1 AND at > ?2 AND at <= ?3",
            params![id.as_str(), window_start, now.unix()],
            |r| r.get(0),
        )?;
        Ok(Usage {
            repos,
            ops_last_minute: count(ops)?,
        })
    }

    /// Takes one operation in `repo` from an active lease, atomically: the repository's
    /// counter goes up only while it is under `max` (concurrent requests can't overshoot),
    /// and the operation is recorded for the lease's rate. Returns `false` (and records
    /// nothing) when the limit is reached or the lease is not active.
    pub fn consume(
        &self,
        id: &TicketId,
        repo: &RepoName,
        counter: Counter,
        max: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let active = State::Active.as_str();
        let max = i64::from(max);
        let in_force = tx
            .query_row(
                "SELECT 1 FROM tickets WHERE id = ?1 AND state = ?2 AND cert_serial IS NOT NULL",
                params![id.as_str(), active],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !in_force {
            return Ok(false);
        }
        let column = match counter {
            Counter::Signature => Some("signatures"),
            Counter::Push => Some("pushes"),
            Counter::Fetch => None,
        };
        if let Some(column) = column {
            tx.execute(
                "INSERT INTO usage (lease_id, repo) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![id.as_str(), repo.as_str()],
            )?;
            // The column is one of two fixed names, never input.
            let taken = tx.execute(
                &format!(
                    "UPDATE usage SET {column} = {column} + 1
                     WHERE lease_id = ?1 AND repo = ?2 AND {column} < ?3"
                ),
                params![id.as_str(), repo.as_str(), max],
            )? == 1;
            if !taken {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO ops (lease_id, at) VALUES (?1, ?2)",
            params![id.as_str(), now.unix()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Deletes the operations no rate window can count any more: older than the window
    /// ending `now` by [`OPS_KEPT_PAST_WINDOW_SECONDS`] or more. Returns how many.
    pub fn prune_ops(&self, now: Timestamp) -> Result<usize> {
        let before = now
            .unix()
            .saturating_sub(RATE_WINDOW_SECONDS)
            .saturating_sub(OPS_KEPT_PAST_WINDOW_SECONDS);
        Ok(self
            .conn
            .execute("DELETE FROM ops WHERE at <= ?1", params![before])?)
    }

    /// How many operations `ops` holds (feature `testing`).
    #[cfg(feature = "testing")]
    pub fn ops_rows(&self) -> Result<u64> {
        let rows: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ops", [], |r| r.get(0))?;
        u64::try_from(rows).map_err(|_| corrupt("ops", "negative count"))
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
