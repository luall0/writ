//! The mirrors: one bare repository per registered repo, `<root>/<name>.git`, created by the
//! daemon in the repo's object format with the reftable ref format, and synced from upstream.
//!
//! One lock per mirror ([`MirrorGuard`]) serializes everything that changes it: a sync, and
//! (from the gateway) a push from its decision until git has moved the refs. At most
//! [`MAX_SYNCS`] syncs run at once, daemon-wide. Every upstream operation is counted while it
//! runs ([`in_flight`]): a daemon stopping waits for them ([`Mirrors::stop`]).
//!
//! - [`open`]: opening the mirrors at startup;
//! - [`access`]: how one operation reaches upstream, and git run through it;
//! - [`sync`]: syncing from upstream; [`push`]: the upstream push; [`notes`]: the daemon's
//!   notes, written and pushed upstream (`ticket_link: notes`);
//! - [`classify`]: what a failure says, and upstream's words made safe to show.

mod access;
mod check;
mod classify;
pub mod in_flight;
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

use crate::known_hosts::PinnedHosts;

use crate::upstream::{HttpsUrl, SshUrl};
use crate::{MirrorError, Result};
pub use check::CheckStep;
pub(crate) use classify::redacted;

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
/// How long a stop waits past an upstream operation's own deadline (`mirrors.timeout`), for
/// its git and ssh to be killed and reaped and its failure said.
pub const STOP_MARGIN: Duration = Duration::from_secs(5);

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
    /// The longest one handshake of a host key scan may take ([`crate::scan`]).
    pub scan_timeout: Duration,
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
    /// The daemon's sync slots: shared by every `Mirrors` a registry change makes, so a
    /// change never adds slots while syncs run.
    syncs: Arc<Semaphore>,
    /// The upstream operations in flight, shared the same way.
    in_flight: Arc<in_flight::InFlight>,
    /// The policy's proxies, each with its password from the keystore: what a host key scan
    /// through one dials with.
    proxies: BTreeMap<writ_core::names::ProxyName, crate::dial::Dialer>,
}

struct Repo {
    name: RepoName,
    /// Its registry entry: a registry change reopens the repo only if it changed.
    entry: writ_core::config::RepoEntry,
    path: PathBuf,
    reach: Reach,
    /// How its upstream's connections are opened: directly, or through its proxy.
    dialer: crate::dial::Dialer,
    format: ObjectFormat,
    state: Arc<Mutex<SyncState>>,
}

/// The operator's CA certificates, as git is given them: the file (`http.sslCAInfo`), and an
/// empty directory as the CA path (`http.sslCAPath`). curl built with a default CA path (Debian's
/// is) keeps trusting it when only the file is set: with the empty one, the operator's CAs are
/// the only ones.
#[derive(Clone)]
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
    /// `https://`, with a token from the keystore: none until an approver adds it
    /// (`writ admin token`), and until then nothing reaches upstream.
    Https {
        url: HttpsUrl,
        credential: KeyId,
        token: Option<Arc<crate::credential::TokenRef>>,
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

    /// How long one handshake of a host key scan may take (`mirrors.scan_timeout`).
    pub fn scan_timeout(&self) -> Duration {
        self.shared.config.scan_timeout
    }

    /// How a host key scan reaches its host: through `proxy` of the policy in force (with its
    /// password), or directly. A proxy the policy doesn't declare is refused, so is one whose
    /// password isn't in the keystore yet.
    pub fn dialer(
        &self,
        proxy: Option<&writ_core::names::ProxyName>,
    ) -> std::result::Result<crate::dial::Dialer, String> {
        let Some(name) = proxy else {
            return Ok(crate::dial::Dialer::Direct);
        };
        let dialer = self
            .shared
            .proxies
            .get(name)
            .ok_or_else(|| format!("proxy {name} is not declared in proxies"))?;
        if let Some(key) = dialer
            .proxy()
            .and_then(crate::dial::ProxyRoute::missing_password)
        {
            return Err(format!(
                "proxy {name}'s password ({key}) isn't in the keystore yet: an approver adds it \
                 with `writ admin token {key}`"
            ));
        }
        Ok(dialer.clone())
    }

    /// The registered repos.
    pub fn repos(&self) -> impl Iterator<Item = &RepoName> {
        self.shared.repos.keys()
    }

    /// Stops reaching upstream, for the daemon's orderly stop: from now on every upstream
    /// operation is refused ([`MirrorError::Stopping`]), with every `Mirrors` a registry
    /// change made, and those in flight are waited for, at most their own deadline
    /// (`mirrors.timeout`) and [`STOP_MARGIN`]. Returns how many still ran then.
    pub async fn stop(&self) -> usize {
        self.shared.in_flight.stop(self.stop_wait()).await
    }

    /// The longest a stop waits for operations in flight: one upstream operation's deadline
    /// (`mirrors.timeout`) and [`STOP_MARGIN`].
    pub fn stop_wait(&self) -> Duration {
        self.shared
            .config
            .timeout
            .checked_add(STOP_MARGIN)
            .unwrap_or(Duration::MAX)
    }

    /// Whether `other` (a registry change's `Mirrors`) holds `repo` under the same lock as
    /// this one, and shares its sync slots (tests only).
    #[cfg(any(test, feature = "testing"))]
    pub fn shares_lock_with(&self, other: &Mirrors, repo: &RepoName) -> bool {
        let (Some(mine), Some(theirs)) =
            (self.shared.repos.get(repo), other.shared.repos.get(repo))
        else {
            return false;
        };
        Arc::ptr_eq(&mine.state, &theirs.state)
            && Arc::ptr_eq(&self.shared.syncs, &other.shared.syncs)
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

    /// How long [`Mirrors::lock`] waits: a holder doing its job keeps a mirror for a wait for a
    /// sync slot (`timeout`), one upstream operation (`timeout`: a sync's gits, a notes push's,
    /// an upstream push, share it) and the local work around it ([`LOCAL_WORK_DEADLINE`], all
    /// of it together: a sync's `HEAD` and repack, a push's reading, a notes batch). `writ
    /// admin repo check` takes the lock for each of its steps apart (the review after M7.6,
    /// M-9: under one lock it held about four times `timeout`).
    pub fn lock_deadline(&self) -> Duration {
        // The holder's wait for a sync slot, its upstream operation, its local work.
        self.shared
            .config
            .timeout
            .saturating_mul(2)
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
        // A slot waited for at most one upstream operation (the others' fetches end by then),
        // counted in what the mirror lock's waiters allow ([`Mirrors::lock_deadline`]).
        let wait = self.shared.config.timeout;
        let _slot = tokio::time::timeout(wait, self.shared.syncs.acquire())
            .await
            .map_err(|_| MirrorError::Busy {
                repo: self.repo.name.clone(),
                seconds: wait.as_secs(),
            })?
            .map_err(|_| MirrorError::SyncSlotsClosed)?;
        // A fetch that fails, or whose sync is dropped (its caller gone), leaves no partial
        // pack (`tmp_*`): removed on the way out, unless the fetch succeeded.
        let mut partial = PartialPacks {
            guard: self,
            done: false,
        };
        let fetched = partial.guard.fetch().await;
        partial.done = fetched.is_ok();
        drop(partial);
        let (report, head) = fetched?;
        self.state.synced_at = Some(Instant::now());
        // The local work after it (HEAD followed, a repack) within one LOCAL_WORK_DEADLINE,
        // all of it together: what `lock_deadline` counts (the review after M7.6, M-9).
        let now = tokio::time::Instant::now();
        let until = now.checked_add(LOCAL_WORK_DEADLINE).unwrap_or(now);
        self.follow_head(&head, until).await;
        self.repack_if_needed(until).await;
        Ok(report)
    }

    /// Marks the mirror stale: the next fetch or push syncs it first.
    pub fn mark_stale(&mut self) {
        self.state.synced_at = None;
    }
}

/// Removes a sync's partial packs when dropped, unless its fetch succeeded.
struct PartialPacks<'a> {
    guard: &'a MirrorGuard,
    done: bool,
}

impl Drop for PartialPacks<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.guard.remove_partial_packs();
        }
    }
}
