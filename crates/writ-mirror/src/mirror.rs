//! The mirrors: one bare repository per registered repo, `<root>/<name>.git`, created by the
//! daemon in the repo's object format with the reftable ref format, and synced from upstream.
//!
//! One lock per mirror ([`MirrorGuard`]) serializes everything that changes it: a sync, and
//! (from the gateway) a push from its decision until git has moved the refs. At most
//! [`MAX_SYNCS`] syncs run at once, daemon-wide.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ssh_key::PublicKey;
use tokio::sync::{Mutex, OwnedMutexGuard, Semaphore};
use tokio::time::Instant;
use writ_core::config::{ObjectFormat, RepoEntry};
use writ_core::names::{KeyId, RepoName};
use writ_signer::Signer;

use crate::agent::AgentSocket;
use crate::git::{self, Hooks};
use crate::known_hosts::PinnedHosts;
use crate::process::{self, RunError};
use crate::quarantine::Quarantine;
use crate::upstream::{SshCommand, SshUrl};
use crate::{MIN_GIT, MirrorError, Result, relay, shown};

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
/// How long a repack may take.
const REPACK_DEADLINE: Duration = Duration::from_secs(600);

/// What the mirrors need.
#[derive(Debug, Clone)]
pub struct MirrorConfig {
    /// The directory holding the mirrors (`<name>.git`).
    pub root: PathBuf,
    /// A private directory for the daemon's upstream files: the pinned host keys as ssh reads
    /// them, the credentials' public keys, the agent sockets.
    pub run_dir: PathBuf,
    /// The relay program (`writd`, run as `writd upstream-ssh …`).
    pub relay: PathBuf,
    /// The system's ssh, by absolute path.
    pub ssh: PathBuf,
    /// The upstream host keys the operator pinned.
    pub pinned: PinnedHosts,
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
    agent_dir: PathBuf,
    known_hosts: PathBuf,
    syncs: Semaphore,
}

struct Repo {
    name: RepoName,
    path: PathBuf,
    upstream: SshUrl,
    credential: KeyId,
    public: PublicKey,
    /// The credential's public key file, which picks it in the agent.
    identity: PathBuf,
    format: ObjectFormat,
    state: Arc<Mutex<SyncState>>,
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
    /// Opens the mirror of every repo in `repos`, creating the ones that don't exist yet.
    /// Refuses (fail closed) an upstream it can't reach as configured: not `ssh://`, a host
    /// without a pinned key, a credential the signer doesn't hold; and a directory in the
    /// mirror's place that isn't one the daemon made (another object or ref format, not bare,
    /// a link).
    pub async fn open(
        config: MirrorConfig,
        repos: &BTreeMap<RepoName, RepoEntry>,
        signer: Arc<dyn Signer>,
    ) -> Result<Self> {
        check_git_version().await?;
        check_program(&config.ssh, "ssh")?;
        check_program(&config.relay, "the relay")?;
        let private = |path: &Path| {
            writ_platform::fs::create_private_dir(path).map_err(|source| MirrorError::Io {
                what: "cannot create the private directory",
                path: path.to_owned(),
                source,
            })
        };
        std::fs::create_dir_all(&config.root).map_err(|source| MirrorError::Io {
            what: "cannot create",
            path: config.root.clone(),
            source,
        })?;
        private(&config.run_dir)?;
        let agent_dir = config.run_dir.join("agent");
        private(&agent_dir)?;
        remove_leftovers(&agent_dir, |name| name.ends_with(".sock"))?;
        let keys_dir = config.run_dir.join("keys");
        private(&keys_dir)?;
        let known_hosts = config.run_dir.join("known_hosts");
        replace_file(&known_hosts, config.pinned.to_file()?.as_bytes())?;

        let mut opened = BTreeMap::new();
        for (name, entry) in repos {
            let repo = open_repo(&config, &keys_dir, &*signer, name, entry).await?;
            opened.insert(name.clone(), Arc::new(repo));
        }
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                signer,
                repos: opened,
                agent_dir,
                known_hosts,
                syncs: Semaphore::new(MAX_SYNCS),
            }),
        })
    }

    /// The mirror's directory, for a registered repo.
    pub fn path(&self, repo: &RepoName) -> Option<&Path> {
        self.shared.repos.get(repo).map(|r| r.path.as_path())
    }

    /// The registered repos.
    pub fn repos(&self) -> impl Iterator<Item = &RepoName> {
        self.shared.repos.keys()
    }

    /// Holds the mirror of `repo` (waits for a sync or a push in progress).
    pub async fn lock(&self, repo: &RepoName) -> Result<MirrorGuard> {
        let found = self
            .shared
            .repos
            .get(repo)
            .ok_or_else(|| MirrorError::UnknownRepo(repo.clone()))?
            .clone();
        let state = found.state.clone().lock_owned().await;
        Ok(MirrorGuard {
            shared: self.shared.clone(),
            repo: found,
            state,
        })
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
            .map_err(|_| MirrorError::Agent("the sync slots are closed".to_owned()))?;
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

    /// Fetches upstream's branches and tags, then points the mirror's `HEAD` at upstream's
    /// default branch, both within the sync's deadline and through one agent socket.
    async fn fetch(&self) -> Result<SyncReport> {
        let shared = &self.shared;
        let repo = &self.repo;
        let started = Instant::now();
        let (agent, ssh) = self.reach_upstream()?;
        let fetched = self
            .upstream_git(
                &ssh,
                &[
                    "fetch",
                    "--porcelain",
                    "--atomic",
                    "--prune",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--no-recurse-submodules",
                    "--no-auto-maintenance",
                    "--no-show-forced-updates",
                    "--",
                    repo.upstream.as_str(),
                    "+refs/heads/*:refs/heads/*",
                    "+refs/tags/*:refs/tags/*",
                ],
                shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await?;
        let left = shared.config.timeout.saturating_sub(started.elapsed());
        let head = self
            .upstream_git(
                &ssh,
                &[
                    "ls-remote",
                    "--symref",
                    "--",
                    repo.upstream.as_str(),
                    "HEAD",
                ],
                left,
                MAX_HEAD_OUTPUT,
            )
            .await?;
        drop(agent);
        self.follow_head(&head).await;
        Ok(parse_moves(&fetched))
    }

    /// An agent socket serving the repo's credential, and the ssh command that uses it (for
    /// one operation: the socket goes when dropped).
    fn reach_upstream(&self) -> Result<(AgentSocket, String)> {
        let shared = &self.shared;
        let agent = AgentSocket::start(
            &shared.agent_dir,
            shared.signer.clone(),
            self.repo.credential.clone(),
            &self.repo.public,
        )?;
        let ssh = SshCommand {
            relay: &shared.config.relay,
            ssh: &shared.config.ssh,
            known_hosts: &shared.known_hosts,
            agent: agent.path(),
            identity: &self.repo.identity,
            max_bytes: shared.config.max_fetch_bytes,
        }
        .to_git_ssh_command()?;
        Ok((agent, ssh))
    }

    /// Pushes the accepted updates upstream from the push's quarantine, before git moves the
    /// mirror's refs: all or none (`--atomic`), each only if upstream still has what the
    /// agent's push started from (`--force-with-lease=<ref>:<old>`, empty for a new ref), so a
    /// ref upstream moved meanwhile is refused with the remote's reason. Within the sync's
    /// deadline, its bytes capped like a sync's.
    pub async fn push_upstream(
        &mut self,
        quarantine: &Quarantine,
        updates: &[UpstreamUpdate],
    ) -> Result<()> {
        let (agent, ssh) = self.reach_upstream()?;
        let mut args: Vec<String> = [
            "push",
            "--atomic",
            "--porcelain",
            "--no-verify",
            "--no-follow-tags",
            "--no-recurse-submodules",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
        for update in updates {
            let old = update.old.as_deref().unwrap_or_default();
            args.push(format!("--force-with-lease={}:{old}", update.name));
        }
        args.push("--".to_owned());
        args.push(self.repo.upstream.as_str().to_owned());
        for update in updates {
            args.push(match &update.new {
                Some(new) => format!("{new}:{}", update.name),
                None => format!(":{}", update.name),
            });
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let pushed = self
            .run_upstream(
                &ssh,
                &args,
                Some(quarantine),
                self.shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await;
        drop(agent);
        let finished = pushed?;
        if finished.status.success() {
            return Ok(());
        }
        let classified = self.classify(&finished.stderr);
        Err(match classified {
            MirrorError::Git { repo, .. } => {
                // What upstream said: the refused refs (porcelain), then its own words.
                let refused: Vec<u8> = String::from_utf8_lossy(&finished.stdout)
                    .lines()
                    .filter(|line| line.starts_with('!'))
                    .flat_map(|line| format!("{line}\n").into_bytes())
                    .chain(finished.stderr.iter().copied())
                    .collect();
                MirrorError::Rejected {
                    repo,
                    reason: shown(&refused),
                }
            }
            other => other,
        })
    }

    /// Runs git against upstream (`GIT_SSH_COMMAND` = `ssh`), within `deadline`, keeping at
    /// most `max_stdout` bytes of its output. A failure is classified from its stderr.
    async fn upstream_git(
        &self,
        ssh: &str,
        args: &[&str],
        deadline: Duration,
        max_stdout: usize,
    ) -> Result<Vec<u8>> {
        let finished = self
            .run_upstream(ssh, args, None, deadline, max_stdout)
            .await?;
        if !finished.status.success() {
            return Err(self.classify(&finished.stderr));
        }
        Ok(finished.stdout)
    }

    /// Runs git against upstream, reading a push's objects when `quarantine` is given.
    async fn run_upstream(
        &self,
        ssh: &str,
        args: &[&str],
        quarantine: Option<&Quarantine>,
        deadline: Duration,
        max_stdout: usize,
    ) -> Result<process::Finished> {
        let mut cmd = git::command(Hooks::None);
        cmd.arg("--git-dir")
            .arg(&self.repo.path)
            .args(args)
            .env("GIT_SSH_COMMAND", ssh)
            .env("GIT_SSH_VARIANT", "ssh");
        if let Some(quarantine) = quarantine {
            quarantine.objects_env(&mut cmd);
        }
        match process::run(cmd, None, deadline, max_stdout).await {
            Ok(finished) => Ok(finished),
            Err(RunError::Timeout) => Err(MirrorError::Timeout {
                repo: self.repo.name.clone(),
                seconds: self.shared.config.timeout.as_secs(),
            }),
            Err(RunError::Spawn(e) | RunError::Wait(e)) => Err(MirrorError::Spawn(e)),
        }
    }

    /// Points the mirror's `HEAD` at upstream's default branch (from `ls-remote --symref`'s
    /// `ref: refs/heads/<name>\tHEAD`), so a clone checks it out. Only a branch the mirror
    /// has; anything else leaves `HEAD` as it is (git refuses an invalid name itself).
    async fn follow_head(&self, ls_remote: &[u8]) {
        let text = String::from_utf8_lossy(ls_remote);
        let Some(target) = text.lines().find_map(|line| {
            line.strip_prefix("ref: ")
                .and_then(|rest| rest.strip_suffix("\tHEAD"))
                .filter(|name| name.starts_with("refs/heads/"))
        }) else {
            return;
        };
        let path = &self.repo.path;
        let git_in = |args: &[&str]| {
            let mut cmd = git::command(Hooks::None);
            cmd.arg("--git-dir").arg(path).args(args);
            cmd
        };
        let current = local(git_in(&["symbolic-ref", "-q", "HEAD"])).await;
        if matches!(&current, Ok(out) if out.stdout.trim_ascii() == target.as_bytes()) {
            return;
        }
        let exists = local(git_in(&["show-ref", "--verify", "--quiet", "--", target])).await;
        if !matches!(&exists, Ok(out) if out.status.success()) {
            return;
        }
        match local(git_in(&["symbolic-ref", "HEAD", target])).await {
            Ok(out) if out.status.success() => {
                tracing::info!(repo = %self.repo.name, head = target, "mirror HEAD follows upstream");
            }
            _ => {
                tracing::warn!(repo = %self.repo.name, "cannot point the mirror's HEAD at upstream's")
            }
        }
    }

    /// The error a failed sync's stderr names. Upstream can print anything there: at worst it
    /// changes which failure is reported, never whether the sync failed.
    fn classify(&self, stderr: &[u8]) -> MirrorError {
        let text = String::from_utf8_lossy(stderr);
        let repo = self.repo.name.clone();
        if text.contains(relay::TOO_LARGE) {
            MirrorError::TooLarge {
                repo,
                max: self.shared.config.max_fetch_bytes,
            }
        } else if text.contains("Host key verification failed") {
            MirrorError::HostKey { repo }
        } else if text.contains("mismatched algorithms") {
            MirrorError::ObjectFormat {
                repo,
                expected: self.repo.format.as_str().to_owned(),
            }
        } else {
            MirrorError::Git {
                repo,
                what: "sync",
                stderr: shown(stderr),
            }
        }
    }

    /// Removes what a failed or killed fetch left in the pack directory (`tmp_*`). Only a
    /// fetch writes there while the mirror is held (a push writes into its own quarantine).
    fn remove_partial_packs(&self) {
        let pack = self.repo.path.join("objects").join("pack");
        if let Err(e) = remove_leftovers(&pack, |name| name.starts_with("tmp_")) {
            tracing::warn!(repo = %self.repo.name, error = %e, "cannot remove a failed sync's pack");
        }
    }

    /// Repacks the mirror once it holds more than [`MAX_PACKS`] packs. A failure only costs
    /// speed: logged, never fatal.
    async fn repack_if_needed(&self) {
        let pack = self.repo.path.join("objects").join("pack");
        let packs = std::fs::read_dir(&pack)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".pack"))
                    .count()
            })
            .unwrap_or(0);
        if packs <= MAX_PACKS {
            return;
        }
        let mut cmd = git::command(Hooks::None);
        cmd.arg("--git-dir")
            .arg(&self.repo.path)
            .args(["repack", "-a", "-d", "-q"]);
        match process::run(cmd, None, REPACK_DEADLINE, 0).await {
            Ok(done) if done.status.success() => {}
            Ok(done) => tracing::warn!(
                repo = %self.repo.name,
                stderr = %shown(&done.stderr),
                "repack failed"
            ),
            Err(e) => tracing::warn!(repo = %self.repo.name, error = ?e, "repack failed"),
        }
    }
}

/// `git fetch --porcelain`'s lines: `<flag> <old> <new> <ref>`. Up to-date refs (`=`) and
/// unreadable lines are left out.
fn parse_moves(stdout: &[u8]) -> SyncReport {
    let mut moved = Vec::new();
    let mut more: usize = 0;
    for line in String::from_utf8_lossy(stdout).lines() {
        let mut chars = line.chars();
        let Some(flag) = chars.next() else { continue };
        let mut parts = chars.as_str().trim_start().split(' ');
        let (Some(old), Some(new), Some(name), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if flag == '=' {
            continue;
        }
        if moved.len() < MAX_MOVES_KEPT {
            moved.push(RefMove {
                flag,
                name: writ_core::text::shown(name, 256),
                old: old.to_owned(),
                new: new.to_owned(),
            });
        } else {
            more = more.saturating_add(1);
        }
    }
    SyncReport::Synced { moved, more }
}

/// A program the daemon runs by path: absolute, a regular file (links resolved), executable.
fn check_program(path: &Path, what: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let refuse = |why: &str| MirrorError::Config(format!("{what} {}: {why}", path.display()));
    if !path.is_absolute() {
        return Err(refuse("must be an absolute path"));
    }
    let meta = std::fs::metadata(path).map_err(|_| refuse("not found"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(refuse("not an executable file"));
    }
    Ok(())
}

/// Runs a short local git command at startup (no network: the version, creating or checking a
/// mirror) to its end.
async fn local(mut cmd: tokio::process::Command) -> Result<std::process::Output> {
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    cmd.output().await.map_err(MirrorError::Spawn)
}

async fn check_git_version() -> Result<()> {
    let mut cmd = git::command(Hooks::None);
    cmd.arg("version");
    let done = local(cmd).await?;
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    match git::parse_version(&text) {
        Some(version) if version >= MIN_GIT => Ok(()),
        _ => Err(MirrorError::GitTooOld {
            found: shown(text.as_bytes()),
        }),
    }
}

/// Checks a repo's upstream, credential and pin, then opens its mirror (creating it if it
/// doesn't exist).
async fn open_repo(
    config: &MirrorConfig,
    keys_dir: &Path,
    signer: &dyn Signer,
    name: &RepoName,
    entry: &RepoEntry,
) -> Result<Repo> {
    let upstream = SshUrl::parse(&entry.upstream).map_err(|why| MirrorError::Upstream {
        repo: name.clone(),
        upstream: entry.upstream.clone(),
        why: why.to_owned(),
    })?;
    let host = upstream.known_hosts_name();
    if !config.pinned.covers(&host) {
        return Err(MirrorError::HostNotPinned {
            repo: name.clone(),
            host,
        });
    }
    let credential = entry.upstream_credential.clone();
    let public = writ_signer::public_key(signer, &credential).map_err(|_| {
        MirrorError::UnknownCredential {
            repo: name.clone(),
            key: credential.clone(),
        }
    })?;
    let identity = keys_dir.join(format!("{credential}.pub"));
    let line = public
        .to_openssh()
        .map_err(|_| MirrorError::Config(format!("key {credential}: unencodable")))?;
    replace_file(&identity, format!("{line}\n").as_bytes())?;

    let path = config.root.join(format!("{name}.git"));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => verify_mirror(name, &path, entry.object_format).await?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_mirror(config, name, &path, entry.object_format).await?;
        }
        Err(source) => {
            return Err(MirrorError::Io {
                what: "cannot read",
                path,
                source,
            });
        }
    }
    Ok(Repo {
        name: name.clone(),
        path,
        upstream,
        credential,
        public,
        identity,
        format: entry.object_format,
        state: Arc::new(Mutex::new(SyncState::default())),
    })
}

/// Creates a bare mirror (reftable, the repo's object format, no template) under a temporary
/// name, then moves it in place: a crash never leaves a half-made mirror at its name.
async fn create_mirror(
    config: &MirrorConfig,
    name: &RepoName,
    path: &Path,
    format: ObjectFormat,
) -> Result<()> {
    let suffix = writ_crypto::keys::random_hex(8)
        .map_err(|_| MirrorError::Config("no randomness".to_owned()))?;
    let temporary = config.root.join(format!(".{name}.git.new-{suffix}"));
    let mut cmd = git::command(Hooks::None);
    cmd.args(["init", "--bare", "--quiet", "--template="])
        .arg(format!("--object-format={}", format.as_str()))
        .arg("--ref-format=reftable")
        .arg("--")
        .arg(&temporary);
    let done = local(cmd).await?;
    if !done.status.success() {
        return Err(MirrorError::Git {
            repo: name.clone(),
            what: "creating the mirror",
            stderr: shown(&done.stderr),
        });
    }
    std::fs::rename(&temporary, path).map_err(|source| MirrorError::Io {
        what: "cannot move the new mirror to",
        path: path.to_owned(),
        source,
    })?;
    tracing::info!(repo = %name, format = format.as_str(), "mirror created");
    Ok(())
}

/// Checks that `path` is a mirror the daemon made: a directory (not a link), a bare
/// repository, in the repo's object format, with reftable refs.
async fn verify_mirror(name: &RepoName, path: &Path, format: ObjectFormat) -> Result<()> {
    let not = |why: String| MirrorError::NotAMirror {
        repo: name.clone(),
        path: path.to_owned(),
        why,
    };
    let meta = std::fs::symlink_metadata(path).map_err(|source| MirrorError::Io {
        what: "cannot read",
        path: path.to_owned(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(not("not a directory (a link or a file)".to_owned()));
    }
    let mut cmd = git::command(Hooks::None);
    cmd.arg("--git-dir").arg(path).args([
        "rev-parse",
        "--is-bare-repository",
        "--show-object-format",
        "--show-ref-format",
    ]);
    let done = local(cmd).await?;
    if !done.status.success() {
        return Err(not(format!("not a repository ({})", shown(&done.stderr))));
    }
    let text = String::from_utf8_lossy(&done.stdout);
    let found: Vec<&str> = text.lines().collect();
    let expected = ["true", format.as_str(), "reftable"];
    if found != expected {
        return Err(not(format!(
            "bare, object format and ref format are {found:?}, not {expected:?}"
        )));
    }
    Ok(())
}

/// Removes the files of `dir` whose name `matches` (never following a link: only the entry
/// itself goes).
fn remove_leftovers(dir: &Path, matches: impl Fn(&str) -> bool) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(MirrorError::Io {
                what: "cannot read",
                path: dir.to_owned(),
                source,
            });
        }
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        if matches(&entry.file_name().to_string_lossy()) {
            let path = entry.path();
            std::fs::remove_file(&path).map_err(|source| MirrorError::Io {
                what: "cannot remove",
                path,
                source,
            })?;
        }
    }
    Ok(())
}

/// Writes `bytes` to a new private file at `path`, replacing what was there (never through a
/// link: the old entry is removed first, then the file is created anew).
fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let io = |what: &'static str| {
        move |source| MirrorError::Io {
            what,
            path: path.to_owned(),
            source,
        }
    };
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io("cannot replace")(e)),
        _ => {}
    }
    let mut file = writ_platform::fs::create_new_private_file(path).map_err(io("cannot create"))?;
    std::io::Write::write_all(&mut file, bytes).map_err(io("cannot write"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_lines_become_ref_moves() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let out = format!(
            "* {z} {a} refs/heads/new\n+ {a} {z} refs/heads/forced\n= {a} {a} refs/heads/same\n\
             - {a} {z} refs/heads/gone\ngarbage\n"
        );
        let SyncReport::Synced { moved, more } = parse_moves(out.as_bytes()) else {
            panic!("synced");
        };
        let names: Vec<(char, &str)> = moved.iter().map(|m| (m.flag, m.name.as_str())).collect();
        assert_eq!(
            names,
            [
                ('*', "refs/heads/new"),
                ('+', "refs/heads/forced"),
                ('-', "refs/heads/gone")
            ]
        );
        assert_eq!(more, 0);
    }

    #[test]
    fn a_report_keeps_a_bounded_number_of_moves() {
        let a = "a".repeat(40);
        let line = |n: usize| format!("* {a} {a} refs/heads/b{n}\n");
        let out: String = (0..MAX_MOVES_KEPT + 3).map(line).collect();
        let SyncReport::Synced { moved, more } = parse_moves(out.as_bytes()) else {
            panic!("synced");
        };
        assert_eq!(moved.len(), MAX_MOVES_KEPT);
        assert_eq!(more, 3);
        let out: String = (0..MAX_MOVES_KEPT).map(line).collect();
        assert_eq!(
            parse_moves(out.as_bytes()),
            SyncReport::Synced {
                moved: (0..MAX_MOVES_KEPT)
                    .map(|n| RefMove {
                        flag: '*',
                        name: format!("refs/heads/b{n}"),
                        old: a.clone(),
                        new: a.clone(),
                    })
                    .collect(),
                more: 0,
            }
        );
    }
}
