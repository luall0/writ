//! The ledger: every commit signed under a lease, for which repo, with which key; and, for a
//! repo whose `ticket_link` is `notes`, whether each pushed commit's note is upstream yet.

use rusqlite::params;
use writ_core::names::{CommitId, KeyId, RepoName, TicketId};
use writ_core::units::Timestamp;

use super::Store;
use super::rows::corrupt;
use crate::Result;

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
    /// The digest of the paths it touched as signing saw them (`writ_git::paths::digest`), or
    /// `None` when they were unknown; a push compares it with the paths computed again from
    /// the objects git verified.
    pub paths_digest: Option<String>,
}

/// A note waiting to be pushed: a commit upstream took, the lease it was signed under, and the
/// credential of the push that took it (the note goes upstream with it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNote {
    pub commit: CommitId,
    pub lease: TicketId,
    pub credential: KeyId,
}

impl Store {
    /// Records a signed commit. Recording the same commit, lease and repo again keeps the
    /// first entry.
    pub fn ledger_append(&self, entry: &LedgerEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ledger (commit_id, lease_id, repo, key_id, signed_at, paths_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            params![
                entry.commit.as_str(),
                entry.lease.as_str(),
                entry.repo.as_str(),
                entry.key.as_str(),
                entry.signed_at.unix(),
                entry.paths_digest.as_deref()
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

    /// Marks the commits a push took upstream as waiting for their note, pushed with
    /// `credential`: only the ledger's entries for the pushing lease (or a lease it renews:
    /// `leases`) and repo (a commit nobody signed here gets no note), and a note already
    /// written stays written. One transaction.
    pub fn notes_add_pending(
        &self,
        leases: &[TicketId],
        repo: &RepoName,
        commits: &[CommitId],
        credential: &KeyId,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut statement = tx.prepare(
                "UPDATE ledger SET note = 'pending', note_credential = ?4
                 WHERE lease_id = ?1 AND repo = ?2 AND commit_id = ?3
                   AND (note IS NULL OR note = 'pending')",
            )?;
            for lease in leases {
                for commit in commits {
                    statement.execute(params![
                        lease.as_str(),
                        repo.as_str(),
                        commit.as_str(),
                        credential.as_str()
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The notes waiting on `repo`, oldest signature first, at most `limit`.
    pub fn notes_pending(&self, repo: &RepoName, limit: usize) -> Result<Vec<PendingNote>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT commit_id, lease_id, note_credential FROM ledger
             WHERE repo = ?1 AND note = 'pending' ORDER BY signed_at, rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![repo.as_str(), limit], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (commit, lease, credential) = row?;
            let bad = |e: &dyn std::fmt::Display| corrupt(&commit, format!("ledger note: {e}"));
            let credential = credential.ok_or_else(|| bad(&"a pending note without credential"))?;
            Ok(PendingNote {
                commit: commit.parse().map_err(|e| bad(&e))?,
                lease: lease.parse().map_err(|e| bad(&e))?,
                credential: credential.parse().map_err(|e| bad(&e))?,
            })
        })
        .collect()
    }

    /// The ledger's commits for `repo` with no note state yet (signed, not known to be
    /// upstream; or from before the repo asked for notes), newest first, at most `limit`,
    /// each with its lease.
    pub fn notes_unrecorded(
        &self,
        repo: &RepoName,
        limit: usize,
    ) -> Result<Vec<(CommitId, TicketId)>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT commit_id, lease_id FROM ledger
             WHERE repo = ?1 AND note IS NULL ORDER BY signed_at DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![repo.as_str(), limit], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (commit, lease) = row?;
            let bad = |e: &dyn std::fmt::Display| corrupt(&commit, format!("ledger: {e}"));
            Ok((
                commit.parse().map_err(|e| bad(&e))?,
                lease.parse().map_err(|e| bad(&e))?,
            ))
        })
        .collect()
    }

    /// Marks `notes` of `repo` written: upstream has them. One transaction.
    pub fn notes_written(&self, repo: &RepoName, notes: &[PendingNote]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut statement = tx.prepare(
                "UPDATE ledger SET note = 'written'
                 WHERE repo = ?1 AND commit_id = ?2 AND lease_id = ?3 AND note = 'pending'",
            )?;
            for note in notes {
                statement.execute(params![
                    repo.as_str(),
                    note.commit.as_str(),
                    note.lease.as_str()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn ledger_where(&self, condition: &str, value: &str) -> Result<Vec<LedgerEntry>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT commit_id, lease_id, repo, key_id, signed_at, paths_digest FROM ledger
             WHERE {condition} ORDER BY signed_at, rowid"
        ))?;
        let rows = statement.query_map([value], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (commit, lease, repo, key, at, paths_digest) = row?;
            let bad = |e: &dyn std::fmt::Display| corrupt(&commit, format!("ledger: {e}"));
            Ok(LedgerEntry {
                commit: commit.parse().map_err(|e| bad(&e))?,
                lease: lease.parse().map_err(|e| bad(&e))?,
                repo: repo.parse().map_err(|e| bad(&e))?,
                key: key.parse().map_err(|e| bad(&e))?,
                signed_at: Timestamp::from_unix(at).map_err(|e| bad(&e))?,
                paths_digest,
            })
        })
        .collect()
    }
}
