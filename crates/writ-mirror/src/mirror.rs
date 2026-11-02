//! The mirrors: one bare repository per registered repo, `<root>/<name>.git`, created by the
//! daemon in the repo's object format with the reftable ref format, and synced from upstream.
//!
//! One lock per mirror ([`MirrorGuard`]) serializes everything that changes it: a sync, and
//! (from the gateway) a push from its decision until git has moved the refs. At most
//! [`MAX_SYNCS`] syncs run at once, daemon-wide.
//!
//! - [`open`]: opening the mirrors at startup;
//! - [`access`]: how one operation reaches upstream, and git run through it;
//! - [`sync`]: syncing from upstream; [`push`]: the upstream push; [`notes`]: the daemon's
//!   notes, written and pushed upstream (`ticket_link: notes`);
//! - [`classify`]: what a failure says, and upstream's words made safe to show.

mod access;
mod classify;
mod notes;
mod open;
mod push;
mod sync;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ssh_key::PublicKey;
use tokio::sync::{Mutex, OwnedMutexGuard, Semaphore};
use tokio::time::Instant;
use writ_core::config::ObjectFormat;
use writ_core::names::{KeyId, RepoName};
use writ_signer::Signer;

use crate::credential::UpstreamToken;
use crate::known_hosts::PinnedHosts;
use crate::upstream::{HttpsUrl, SshUrl};
use crate::{MirrorError, Result};

pub use notes::{MAX_LOOKUPS, MAX_NOTE_TEXT, MAX_NOTES, NOTES_AUTHOR, Note, NotesPushed};

/// Syncs that may run at once, all mirrors together.
pub const MAX_SYNCS: usize = 4;
/// Ref moves a sync report keeps (the rest are counted).
pub const MAX_MOVES_KEPT: usize = 20;
/// Packs a mirror may hold before a sync repacks it (every sync that brings objects adds one).
pub const MAX_PACKS: usize = 50;
/// The most of a sync's output read (its ref moves).
const MAX_FETCH_OUTPUT: usize = 1 << 20;
/// The most of upstream's `HEAD` read (one or two lines).
const MAX_HEAD_OUTPUT: usize = 4096;
/// The longest local work done under a mirror's lock may take: a repack after a sync, or the
/// gateway reading a push in its quarantine.
pub const LOCAL_WORK_DEADLINE: Duration = Duration::from_secs(600);

/// What the mirrors need.
#[derive(Debug, Clone)]
pub struct MirrorConfig {
    /// The directory holding the mirrors (`<name>.git`).
    pub root: PathBuf,
    /// A private directory for the daemon's upstream files: the pinned host keys as ssh reads
    /// them, the credentials' public keys, the CA certificates as git reads them, the sockets
    /// of each operation.
    pub run_dir: PathBuf,
    /// The daemon's own program (`writd`), run by git as `writd upstream-ssh …` (the relay)
    /// and `writd upstream-credential …` (the credential helper).
    pub relay: PathBuf,
    /// The system's git, by absolute path (checked at startup, never looked up in `PATH`).
    pub git: PathBuf,
    /// The system's ssh, by absolute path.
    pub ssh: PathBuf,
    /// The upstream host keys the operator pinned.
    pub pinned: PinnedHosts,
    /// The CA certificates (PEM) an HTTPS upstream's certificate must chain to; `None`: the
    /// system's.
    pub ca_certs: Option<String>,
    /// A mirror synced this recently is fresh: a fetch or a push doesn't sync it again.
    pub fresh_for: Duration,
    /// The longest one sync (or upstream push) may take; past it, git and ssh are killed.
    pub timeout: Duration,
    /// The most bytes one sync may take from upstream.
    pub max_fetch_bytes: u64,
}

/// One ref a sync moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefMove {
    /// git's flag: `*` new, ` ` fast-forward, `+` forced, `-` pruned, `t` tag update.
    pub flag: char,
    pub name: String,
    pub old: String,
    pub new: String,
}

/// One ref update to make upstream, as the push decision accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUpdate {
    pub name: String,
    /// What the agent's push started from (`None`: the ref is new).
    pub old: Option<String>,
    /// Where it goes (`None`: the ref is deleted).
    pub new: Option<String>,
}

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncReport {
    /// The mirror was fresh: no sync ran.
    Fresh,
    /// Synced: the refs it moved (at most [`MAX_MOVES_KEPT`]), and how many more.
    Synced { moved: Vec<RefMove>, more: usize },
}

/// The mirrors of every registered repo.
#[derive(Clone)]
pub struct Mirrors {
    shared: Arc<Shared>,
}

struct Shared {
    config: MirrorConfig,
    signer: Arc<dyn Signer>,
    repos: BTreeMap<RepoName, Arc<Repo>>,
    /// The sockets of each operation (agent, credential, proxy).
    socket_dir: PathBuf,
    known_hosts: PathBuf,
    /// The CA certificates as git reads them, when the operator gave some, and the empty
    /// directory git is given as its CA path with them ([`CaCerts`]).
    ca_certs: Option<CaCerts>,
    /// An empty private directory: the `HOME` of an HTTPS operation's git (no `.netrc`).
    home: PathBuf,
    syncs: Semaphore,
}

struct Repo {
    name: RepoName,
    path: PathBuf,
    reach: Reach,
    format: ObjectFormat,
    state: Arc<Mutex<SyncState>>,
}

/// The operator's CA certificates, as git is given them: the file (`http.sslCAInfo`), and an
/// empty directory as the CA path (`http.sslCAPath`). curl built with a default CA path (Debian's
/// is) keeps trusting it when only the file is set: with the empty one, the operator's CAs are
/// the only ones.
struct CaCerts {
    file: PathBuf,
    empty_dir: PathBuf,
}

/// How a repo's upstream is reached.
enum Reach {
    /// `ssh://`, with a key in the upstream signer.
    Ssh {
        url: SshUrl,
        credential: KeyId,
        public: PublicKey,
        /// The credential's public key file, which picks it in the agent.
        identity: PathBuf,
    },
    /// `https://`, with a token from the keystore.
    Https {
        url: HttpsUrl,
        credential: KeyId,
        token: Arc<UpstreamToken>,
    },
}

impl Reach {
    fn url(&self) -> &str {
        match self {
            Self::Ssh { url, .. } => url.as_str(),
            Self::Https { url, .. } => url.as_str(),
        }
    }

    /// The registry's credential id for this upstream.
    fn credential(&self) -> &KeyId {
        match self {
            Self::Ssh { credential, .. } | Self::Https { credential, .. } => credential,
        }
    }
}

#[derive(Debug, Default)]
struct SyncState {
    synced_at: Option<Instant>,
}

/// A mirror held for its owner alone: nothing else syncs or pushes to it until dropped.
pub struct MirrorGuard {
    shared: Arc<Shared>,
    repo: Arc<Repo>,
    state: OwnedMutexGuard<SyncState>,
}

impl Mirrors {
    /// The mirror's directory, for a registered repo.
    pub fn path(&self, repo: &RepoName) -> Option<&Path> {
        self.shared.repos.get(repo).map(|r| r.path.as_path())
    }

    /// The daemon's git (`mirrors.git`), which everything run on a mirror uses: the gateway's
    /// `upload-pack` and `receive-pack`, the reads of a push.
    pub fn git(&self) -> &Path {
        &self.shared.config.git
    }

    /// The registered repos.
    pub fn repos(&self) -> impl Iterator<Item = &RepoName> {
        self.shared.repos.keys()
    }

    /// Holds the mirror of `repo`, waiting for a sync or a push in progress, at most
    /// [`Mirrors::lock_deadline`]: past it the mirror is busy ([`MirrorError::Busy`]), refused
    /// with the reason rather than waited on forever.
    pub async fn lock(&self, repo: &RepoName) -> Result<MirrorGuard> {
        let found = self
            .shared
            .repos
            .get(repo)
            .ok_or_else(|| MirrorError::UnknownRepo(repo.clone()))?
            .clone();
        let deadline = self.lock_deadline();
        let state = tokio::time::timeout(deadline, found.state.clone().lock_owned())
            .await
            .map_err(|_| MirrorError::Busy {
                repo: repo.clone(),
                seconds: deadline.as_secs(),
            })?;
        Ok(MirrorGuard {
            shared: self.shared.clone(),
            repo: found,
            state,
        })
    }

    /// How long [`Mirrors::lock`] waits: a holder doing its job keeps a mirror for one upstream
    /// operation (`timeout`) and the local work around it ([`LOCAL_WORK_DEADLINE`]), a sync's
    /// repack or the reading of a push.
    pub fn lock_deadline(&self) -> Duration {
        self.shared
            .config
            .timeout
            .saturating_add(LOCAL_WORK_DEADLINE)
    }

    /// Syncs `repo` unless it is fresh (synced within `fresh_for`). Concurrent callers wait for
    /// one sync and find the mirror fresh.
    pub async fn sync_if_stale(&self, repo: &RepoName) -> Result<SyncReport> {
        let fresh_for = self.shared.config.fresh_for;
        self.lock(repo).await?.sync_if_older(fresh_for).await
    }
}

impl MirrorGuard {
    pub fn repo(&self) -> &RepoName {
        &self.repo.name
    }

    pub fn path(&self) -> &Path {
        &self.repo.path
    }

    /// Syncs unless the last sync is more recent than `age`.
    pub async fn sync_if_older(&mut self, age: Duration) -> Result<SyncReport> {
        if let Some(at) = self.state.synced_at
            && at.elapsed() < age
        {
            return Ok(SyncReport::Fresh);
        }
        self.sync().await
    }

    /// Fetches upstream's branches and tags into the mirror, atomically: every ref moves, or
    /// none. A failed sync leaves the mirror's refs as they were and its partial pack removed,
    /// and marks it stale.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        self.state.synced_at = None;
        let _slot = self
            .shared
            .syncs
            .acquire()
            .await
            .map_err(|_| MirrorError::SyncSlotsClosed)?;
        let fetched = self.fetch().await;
        if fetched.is_err() {
            self.remove_partial_packs();
        }
        let report = fetched?;
        self.state.synced_at = Some(Instant::now());
        self.repack_if_needed().await;
        Ok(report)
    }

    /// Marks the mirror stale: the next fetch or push syncs it first.
    pub fn mark_stale(&mut self) {
        self.state.synced_at = None;
    }
}
