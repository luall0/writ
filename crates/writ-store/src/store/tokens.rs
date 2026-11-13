//! How many token changes (`writ-token/3`) the daemon applied for each credential id: a
//! number that only grows, never deleted, not even when the id leaves the policy and its token
//! file goes with it, so a signed change applies once (the review after M7.6, A-6: the first
//! change of an id, `previous: none`, came back once its file was deleted). Kept by the id as
//! a file system that folds case names its file (ASCII lowercase), so two spellings of one
//! file share one count.

use rusqlite::{OptionalExtension, params};
use writ_core::names::KeyId;

use super::Store;
use super::rows::corrupt;
use crate::{Result, StoreError};

/// The row a credential's count is kept under.
fn key(id: &KeyId) -> String {
    id.as_str().to_ascii_lowercase()
}

impl Store {
    /// How many token changes of `id` were applied: 0 for an id never given one.
    pub fn token_version(&self, id: &KeyId) -> Result<u64> {
        let version: Option<i64> = self
            .conn
            .query_row(
                "SELECT version FROM token_versions WHERE id = ?1",
                [key(id)],
                |r| r.get(0),
            )
            .optional()?;
        match version {
            None => Ok(0),
            Some(version) => u64::try_from(version)
                .ok()
                .filter(|v| *v >= 1)
                .ok_or_else(|| corrupt(&format!("token_versions {id}"), "a version below 1")),
        }
    }

    /// Counts one more token change of `id`, in one transaction: refused unless the count is
    /// still `from` (a change applied meanwhile). The new count.
    pub fn bump_token_version(&self, id: &KeyId, from: u64) -> Result<u64> {
        let tx = self.conn.unchecked_transaction()?;
        let found = self.token_version(id)?;
        if found != from {
            return Err(StoreError::TokenVersion {
                id: id.clone(),
                expected: from,
                found,
            });
        }
        let next = from
            .checked_add(1)
            .and_then(|next| i64::try_from(next).ok())
            .ok_or_else(|| corrupt(&format!("token_versions {id}"), "version out of range"))?;
        tx.execute(
            "INSERT INTO token_versions (id, version) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET version = ?2",
            params![key(id), next],
        )?;
        tx.commit()?;
        u64::try_from(next)
            .map_err(|_| corrupt(&format!("token_versions {id}"), "version out of range"))
    }
}
