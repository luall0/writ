//! The upstream check (`writ admin repo check`): the repo's upstream reached with its
//! credential through the daemon's own git, as a sync and a push reach it, each step bounded
//! by the sync's deadline and output caps: read access (`ls-remote`), the mirror synced (its
//! object format compared with the policy's), write access (a `push --dry-run` deleting a ref
//! no one has, [`PROBE_REF`]: receive-pack answers, nothing is sent; an empty repository
//! takes it too). Only a repo the
//! registry names; what upstream says comes back cleaned.

use super::{MAX_FETCH_OUTPUT, MirrorGuard, Mirrors, SyncReport};
use crate::Result;
use writ_core::names::RepoName;

/// The ref the write step's dry run deletes: one no remote holds (outside branches and tags),
/// so even without `--dry-run` nothing would change.
const PROBE_REF: &str = ":refs/writ-check/none";

/// One step of a check: what it was, whether it passed, what it found or why it didn't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckStep {
    pub what: &'static str,
    pub ok: bool,
    pub said: String,
}

/// `1 ref`, `2 refs`.
fn refs(count: usize) -> String {
    match count {
        1 => "1 ref".to_owned(),
        n => format!("{n} refs"),
    }
}

impl Mirrors {
    /// Checks `repo`'s upstream: read, sync, write, in order, until one fails. The mirror is
    /// held for each step apart, as long as a sync or a push holds it (the review after M7.6,
    /// M-9: held throughout, three upstream operations and a sync's local work, it kept
    /// agents' fetches and pushes waiting past the lock's deadline); nothing a sync or a push
    /// does between the steps changes what they check.
    pub async fn check(&self, repo: &RepoName) -> Result<Vec<CheckStep>> {
        let mut steps = Vec::new();
        let failed = |what, error: crate::MirrorError| CheckStep {
            what,
            ok: false,
            said: error.to_string(),
        };
        let read = match self.lock(repo).await {
            Ok(guard) => guard.read_refs().await,
            Err(e) => Err(e),
        };
        match read {
            Ok(count) => steps.push(CheckStep {
                what: "read",
                ok: true,
                said: format!("upstream answers with its credential, {}", refs(count)),
            }),
            Err(e) => {
                steps.push(failed("read", e));
                return Ok(steps);
            }
        }
        let format = match self.shared.repos.get(repo) {
            Some(found) => found.format.as_str().to_owned(),
            None => return Err(crate::MirrorError::UnknownRepo(repo.clone())),
        };
        let synced = match self.lock(repo).await {
            Ok(mut guard) => guard.sync().await,
            Err(e) => Err(e),
        };
        match synced {
            Ok(SyncReport::Synced { moved, more }) => steps.push(CheckStep {
                what: "sync",
                ok: true,
                said: format!(
                    "the mirror synced, {} moved, in its object format ({})",
                    refs(moved.len().saturating_add(more)),
                    format
                ),
            }),
            Ok(SyncReport::Fresh) => steps.push(CheckStep {
                what: "sync",
                ok: true,
                said: "the mirror is up to date".to_owned(),
            }),
            Err(e) => {
                steps.push(failed("sync", e));
                return Ok(steps);
            }
        }
        let written = match self.lock(repo).await {
            Ok(guard) => guard.dry_push().await,
            Err(e) => Err(e),
        };
        match written {
            Ok(()) => steps.push(CheckStep {
                what: "write",
                ok: true,
                said: "upstream takes pushes with its credential (nothing pushed)".to_owned(),
            }),
            Err(e) => steps.push(failed("write", e)),
        }
        Ok(steps)
    }
}

impl MirrorGuard {
    /// `git ls-remote --heads --tags` against upstream: how many refs it lists.
    async fn read_refs(&self) -> Result<usize> {
        let access = self.reach_upstream().await?;
        let upstream = self.repo.reach.url().to_owned();
        let finished = self
            .run_upstream(
                &access,
                &["ls-remote", "--heads", "--tags", "--", &upstream],
                None,
                self.shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await?;
        if !finished.status.success() {
            return Err(self.classify(&access, &finished.stderr, "check"));
        }
        Ok(String::from_utf8_lossy(&finished.stdout).lines().count())
    }

    /// A push deleting [`PROBE_REF`], `--dry-run`: git reaches upstream's receive-pack (which
    /// refuses a key without write access), reads its refs and sends nothing.
    async fn dry_push(&self) -> Result<()> {
        let access = self.reach_upstream().await?;
        let upstream = self.repo.reach.url().to_owned();
        let finished = self
            .run_upstream(
                &access,
                &[
                    "push",
                    "--dry-run",
                    "--porcelain",
                    "--no-verify",
                    "--no-recurse-submodules",
                    "--",
                    &upstream,
                    PROBE_REF,
                ],
                None,
                self.shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await?;
        if !finished.status.success() {
            return Err(self.classify(&access, &finished.stderr, "check"));
        }
        Ok(())
    }
}
