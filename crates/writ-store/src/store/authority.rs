//! The authority files in force (the policy, `approvers`, `readers`) and every earlier
//! version, and the head: which version of each is in force, with the keystore's MAC over
//! it (made and checked by the daemon: the store holds it as text).

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::names::KeyFingerprint;
use writ_core::units::Timestamp;

use super::Store;
use super::rows::corrupt;
use crate::{Result, StoreError};

/// How a version came to be in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityHow {
    /// `writd init` (or the development keystore's first start): the files as the operator
    /// wrote them.
    Init,
    /// An approver's signed admin change.
    Admin,
    /// `writd recover` on the host, with the passphrase.
    Recover,
}

impl AuthorityHow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Admin => "admin",
            Self::Recover => "recover",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Init, Self::Admin, Self::Recover]
            .into_iter()
            .find(|h| h.as_str() == text)
    }
}

/// One version of an authority file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityVersion {
    pub target: AdminTarget,
    pub version: u64,
    pub text: String,
    pub digest: TextDigest,
    pub how: AuthorityHow,
    /// The signed `writ-admin/1` document and its SSHSIG, and who signed (an admin change).
    pub document: Option<String>,
    pub signature: Option<String>,
    pub approver: Option<KeyFingerprint>,
    pub applied_at: Timestamp,
}

/// Which version of each file is in force, and the MAC over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityHead {
    pub versions: BTreeMap<AdminTarget, u64>,
    pub mac: String,
}

impl Store {
    /// The head and the version of each file it names; `None` before `writd init` recorded
    /// any. A head naming a version the table lacks, or a text whose digest isn't its own, is
    /// corrupt.
    pub fn authority_in_force(
        &self,
    ) -> Result<Option<(AuthorityHead, BTreeMap<AdminTarget, AuthorityVersion>)>> {
        let head = self
            .conn
            .query_row(
                "SELECT policy, approvers, readers, mac FROM authority_head WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((policy, approvers, readers, mac)) = head else {
            return Ok(None);
        };
        let mut versions = BTreeMap::new();
        let mut in_force = BTreeMap::new();
        for (target, version) in [
            (AdminTarget::Policy, policy),
            (AdminTarget::Approvers, approvers),
            (AdminTarget::Readers, readers),
        ] {
            let version = u64::try_from(version)
                .map_err(|_| corrupt("authority_head", "a negative version"))?;
            let row = self.authority_version(target, version)?.ok_or_else(|| {
                corrupt(
                    "authority_head",
                    format!("{target} version {version} is missing"),
                )
            })?;
            versions.insert(target, version);
            in_force.insert(target, row);
        }
        Ok(Some((AuthorityHead { versions, mac }, in_force)))
    }

    /// Version `version` of `target`, its digest checked against its text.
    pub fn authority_version(
        &self,
        target: AdminTarget,
        version: u64,
    ) -> Result<Option<AuthorityVersion>> {
        let version_i64 =
            i64::try_from(version).map_err(|_| corrupt("authority", "version out of range"))?;
        let row = self
            .conn
            .query_row(
                "SELECT text, digest, how, document, signature, approver, applied_at
                 FROM authority WHERE target = ?1 AND version = ?2",
                params![target.as_str(), version_i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((text, digest, how, document, signature, approver, applied_at)) = row else {
            return Ok(None);
        };
        let id = format!("authority {target} {version}");
        let digest = TextDigest::try_from(digest).map_err(|e| corrupt(&id, e))?;
        if TextDigest::of(&text) != digest {
            return Err(corrupt(&id, "its text is not the one its digest names"));
        }
        Ok(Some(AuthorityVersion {
            target,
            version,
            text,
            digest,
            how: AuthorityHow::parse(&how).ok_or_else(|| corrupt(&id, "unknown origin"))?,
            document,
            signature,
            approver: approver
                .map(|a| a.parse())
                .transpose()
                .map_err(|e| corrupt(&id, e))?,
            applied_at: Timestamp::from_unix(applied_at).map_err(|e| corrupt(&id, e))?,
        }))
    }

    /// Records new versions and the head that puts them in force, in one transaction. Each
    /// new version must follow the one the old head named for its file (the first, 1); the
    /// head must name a version of every file. Anything else changes nothing.
    pub fn record_authority(&self, new: &[AuthorityVersion], head: &AuthorityHead) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let old: BTreeMap<AdminTarget, u64> = match self.authority_in_force()? {
            Some((old, _)) => old.versions,
            None => BTreeMap::new(),
        };
        for version in new {
            let expected = old
                .get(&version.target)
                .map_or(Some(1), |v| v.checked_add(1));
            if Some(version.version) != expected {
                return Err(StoreError::Corrupt {
                    id: format!("authority {}", version.target),
                    why: format!(
                        "version {} does not follow the one in force",
                        version.version
                    ),
                });
            }
            tx.execute(
                "INSERT INTO authority (target, version, text, digest, how, document, signature,
                                        approver, applied_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    version.target.as_str(),
                    i64::try_from(version.version)
                        .map_err(|_| corrupt("authority", "version out of range"))?,
                    version.text,
                    version.digest.as_str(),
                    version.how.as_str(),
                    version.document,
                    version.signature,
                    version.approver.as_ref().map(KeyFingerprint::as_str),
                    version.applied_at.unix(),
                ],
            )?;
        }
        let at = |target| -> Result<i64> {
            let version = head
                .versions
                .get(&target)
                .copied()
                .ok_or_else(|| corrupt("authority_head", format!("no version of {target}")))?;
            i64::try_from(version).map_err(|_| corrupt("authority_head", "version out of range"))
        };
        tx.execute(
            "INSERT INTO authority_head (id, policy, approvers, readers, mac)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT (id) DO UPDATE SET policy = ?1, approvers = ?2, readers = ?3, mac = ?4",
            params![
                at(AdminTarget::Policy)?,
                at(AdminTarget::Approvers)?,
                at(AdminTarget::Readers)?,
                head.mac
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}
