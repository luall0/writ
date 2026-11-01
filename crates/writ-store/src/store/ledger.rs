//! The ledger: every commit signed under a lease, for which repo, with which key.

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
