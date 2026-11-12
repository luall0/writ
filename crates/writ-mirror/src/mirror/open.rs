//! Opening the mirrors at startup: the programs and git checked, the private directories and
//! the files git and ssh read written (pinned host keys, CA certificates, the credentials'
//! public keys), each repo's way upstream, and each mirror created or checked to be one the
//! daemon made.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use writ_core::config::{ObjectFormat, Proxy, RepoEntry};
use writ_core::names::{KeyId, ProxyName, RepoName};
use writ_signer::Signer;

use super::{CaCerts, MAX_SYNCS, MirrorConfig, Mirrors, Reach, Repo, Shared, SyncState};
use crate::credential::UpstreamToken;
use crate::dial::Dialer;
use crate::git::{self, Hooks};
use crate::known_hosts::PinnedHosts;
use crate::upstream::{SshUrl, Upstream};
use crate::{MIN_GIT, MIN_GIT_HTTPS, MirrorError, Result, shown};

impl Mirrors {
    /// Opens the mirror of every repo in `repos`, creating the ones that don't exist yet.
    /// Refuses (fail closed) an upstream it can't reach as configured: neither `ssh://` nor
    /// `https://`, an ssh host without a pinned key, a credential the signer doesn't hold
    /// (ssh), a git too old for it; and a directory in the mirror's place that isn't one the
    /// daemon made (another object or ref format, not bare, a link). An `https://` repo whose
    /// token `tokens` lacks is opened, and reaches nothing upstream until it is added
    /// ([`MirrorError::NoToken`]); so is a repo behind a proxy of `proxies` whose password
    /// `tokens` lacks ([`MirrorError::NoProxyPassword`]).
    pub async fn open(
        config: MirrorConfig,
        repos: &BTreeMap<RepoName, RepoEntry>,
        proxies: &BTreeMap<ProxyName, Proxy>,
        signer: Arc<dyn Signer>,
        tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
    ) -> Result<Self> {
        check_config(&config, repos).await?;
        let files = RunFiles::write(&config)?;
        remove_unfinished_mirrors(&config.root)?;
        let mut opened = BTreeMap::new();
        for (name, entry) in repos {
            let dialer = dialer(name, entry, proxies, tokens)?;
            let repo = open_repo(
                &config,
                &files.keys_dir,
                &*signer,
                tokens,
                name,
                entry,
                dialer,
            )
            .await?;
            opened.insert(name.clone(), Arc::new(repo));
        }
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                signer,
                repos: opened,
                socket_dir: files.socket_dir,
                known_hosts: files.known_hosts,
                ca_certs: files.ca_certs,
                home: files.home,
                syncs: Arc::new(Semaphore::new(MAX_SYNCS)),
                in_flight: super::in_flight::InFlight::new(),
                proxies: routes(proxies, tokens),
            }),
        })
    }
}

impl Mirrors {
    /// The mirrors of `repos`, a registry replacing this one's (an admin change): a repo whose
    /// entry didn't change keeps its mirror and its lock (an operation in flight on it goes
    /// on), a new or changed one is opened and checked as at start, a removed one is no longer
    /// served. `pinned` are the host keys in force (the file ssh reads is written again with
    /// them, for every operation from now on); `signer` and `tokens` the upstream credentials
    /// in force: an `https://` repo whose token changed (added or replaced: `writ admin
    /// token`) is opened again with it, and so is a repo whose proxy changed in `proxies` (its
    /// entry, or its password).
    pub async fn with_registry(
        &self,
        repos: &BTreeMap<RepoName, RepoEntry>,
        proxies: &BTreeMap<ProxyName, Proxy>,
        pinned: PinnedHosts,
        signer: Arc<dyn Signer>,
        tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
    ) -> Result<Self> {
        let shared = &self.shared;
        let mut config = shared.config.clone();
        config.pinned = pinned;
        check_config(&config, repos).await?;
        let keys_dir = shared.config.run_dir.join("keys");
        let mut opened = BTreeMap::new();
        for (name, entry) in repos {
            let dialer = dialer(name, entry, proxies, tokens)?;
            let kept = shared
                .repos
                .get(name)
                .filter(|repo| {
                    repo.entry == *entry
                        && same_token(&repo.reach, tokens)
                        && repo.dialer.same_as(&dialer)
                })
                .cloned();
            let repo = match kept {
                Some(repo) => repo,
                None => {
                    let mut repo =
                        open_repo(&config, &keys_dir, &*signer, tokens, name, entry, dialer)
                            .await?;
                    // The same mirror on disk keeps its one lock: an operation holding it
                    // from before the change still excludes every one after (the review
                    // after M5.5, S10).
                    if let Some(old) = shared.repos.get(name).filter(|old| old.path == repo.path) {
                        repo.state = old.state.clone();
                    }
                    Arc::new(repo)
                }
            };
            opened.insert(name.clone(), repo);
        }
        // Every repo opened: the pins ssh reads from now on.
        replace_file(&shared.known_hosts, config.pinned.to_file()?.as_bytes())?;
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                signer,
                repos: opened,
                socket_dir: shared.socket_dir.clone(),
                known_hosts: shared.known_hosts.clone(),
                ca_certs: shared.ca_certs.clone(),
                home: shared.home.clone(),
                syncs: shared.syncs.clone(),
                in_flight: shared.in_flight.clone(),
                proxies: routes(proxies, tokens),
            }),
        })
    }
}

/// How `name`'s upstream connections are opened: through the proxy its entry names (with its
/// password from `tokens`), or directly. A proxy `proxies` doesn't declare is refused (the
/// policy never lets one through).
fn dialer(
    name: &RepoName,
    entry: &RepoEntry,
    proxies: &BTreeMap<ProxyName, Proxy>,
    tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
) -> Result<Dialer> {
    let dialer = Dialer::for_repo(entry.proxy.as_ref(), proxies, tokens)
        .map_err(|why| MirrorError::Config(format!("repo {name}: {why}")))?;
    if let Some(key) = dialer.proxy().and_then(|p| p.missing_password()) {
        tracing::warn!(
            repo = %name,
            credential = %key,
            "no proxy password yet: syncs and pushes are refused until `writ admin token` adds it"
        );
    }
    Ok(dialer)
}

/// Each proxy of the policy as a dialer, with its password from `tokens`.
fn routes(
    proxies: &BTreeMap<ProxyName, Proxy>,
    tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
) -> BTreeMap<ProxyName, Dialer> {
    proxies
        .iter()
        .map(|(name, proxy)| {
            let route = crate::dial::ProxyRoute::new(name, proxy, tokens);
            (name.clone(), Dialer::Proxy(Arc::new(route)))
        })
        .collect()
}

/// Whether `reach` holds the token `tokens` has for its credential (an `ssh://` one: always).
fn same_token(reach: &Reach, tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>) -> bool {
    match reach {
        Reach::Ssh { .. } => true,
        Reach::Https {
            credential, token, ..
        } => match (token, tokens.get(credential)) {
            (None, None) => true,
            (Some(held), Some(given)) => Arc::ptr_eq(held, given),
            _ => false,
        },
    }
}

/// What `config` names, checked before anything is written: git an executable file recent
/// enough for these repos, ssh and the relay executable files, all by absolute path, and the
/// directories absolute (git and ssh resolve a relative path from wherever they run).
async fn check_config(config: &MirrorConfig, repos: &BTreeMap<RepoName, RepoEntry>) -> Result<()> {
    let https = repos
        .values()
        .any(|entry| matches!(Upstream::parse(&entry.upstream), Ok(Upstream::Https(_))));
    check_program(&config.git, "git")?;
    check_git_version(&config.git, if https { MIN_GIT_HTTPS } else { MIN_GIT }).await?;
    for (what, path) in [("root", &config.root), ("run_dir", &config.run_dir)] {
        if !path.is_absolute() {
            return Err(MirrorError::Config(format!(
                "{what} {} must be an absolute path",
                path.display()
            )));
        }
    }
    check_program(&config.ssh, "ssh")?;
    check_program(&config.relay, "the relay")
}

/// What the daemon writes in `run_dir` for git and ssh to read, all private: the directory of
/// each operation's sockets (a crash's leftovers removed), the credentials' public keys, an
/// empty `HOME`, the pinned host keys, and the operator's CA certificates.
struct RunFiles {
    socket_dir: PathBuf,
    keys_dir: PathBuf,
    home: PathBuf,
    known_hosts: PathBuf,
    ca_certs: Option<CaCerts>,
}

impl RunFiles {
    fn write(config: &MirrorConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.root).map_err(|source| MirrorError::Io {
            what: "cannot create",
            path: config.root.clone(),
            source,
        })?;
        private_dir(&config.run_dir)?;
        let socket_dir = config.run_dir.join("sockets");
        private_dir(&socket_dir)?;
        remove_leftovers(&socket_dir, |name| {
            [".sock", ".cred", ".proxy"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
        })?;
        let keys_dir = config.run_dir.join("keys");
        private_dir(&keys_dir)?;
        let home = config.run_dir.join("home");
        private_dir(&home)?;
        let known_hosts = config.run_dir.join("known_hosts");
        replace_file(&known_hosts, config.pinned.to_file()?.as_bytes())?;
        Ok(Self {
            socket_dir,
            keys_dir,
            home,
            known_hosts,
            ca_certs: write_ca_certs(config)?,
        })
    }
}

/// The operator's CA certificates as git reads them, with the empty CA directory beside them
/// ([`CaCerts`]); without `ca_certs`, any earlier file removed.
fn write_ca_certs(config: &MirrorConfig) -> Result<Option<CaCerts>> {
    let file = config.run_dir.join("ca_certs.pem");
    let Some(pem) = &config.ca_certs else {
        remove_leftovers(&config.run_dir, |name| name == "ca_certs.pem")?;
        return Ok(None);
    };
    replace_file(&file, pem.as_bytes())?;
    let empty_dir = config.run_dir.join("ca_path");
    private_dir(&empty_dir)?;
    // Empty, or nothing at all: whatever is in it, git would trust.
    remove_leftovers(&empty_dir, |_| true)?;
    Ok(Some(CaCerts { file, empty_dir }))
}

/// Creates `path` (and its parents) as a directory only the daemon can enter.
fn private_dir(path: &Path) -> Result<()> {
    writ_platform::fs::create_private_dir(path).map_err(|source| MirrorError::Io {
        what: "cannot create the private directory",
        path: path.to_owned(),
        source,
    })
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
pub(super) async fn local(mut cmd: tokio::process::Command) -> Result<std::process::Output> {
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    cmd.output().await.map_err(MirrorError::Spawn)
}

/// git must be at least `min`.
async fn check_git_version(program: &Path, min: (u32, u32)) -> Result<()> {
    let mut cmd = git::command(program, Hooks::None);
    cmd.arg("version");
    let done = local(cmd).await?;
    let text = String::from_utf8_lossy(&done.stdout).into_owned();
    match git::parse_version(&text) {
        Some(version) if version >= min => Ok(()),
        _ => Err(MirrorError::GitTooOld {
            found: shown(text.as_bytes()),
            needed: format!("{}.{}", min.0, min.1),
        }),
    }
}

/// Checks a repo's upstream and credential (and the pin of an ssh host), then opens its
/// mirror (creating it if it doesn't exist).
async fn open_repo(
    config: &MirrorConfig,
    keys_dir: &Path,
    signer: &dyn Signer,
    tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
    name: &RepoName,
    entry: &RepoEntry,
    dialer: Dialer,
) -> Result<Repo> {
    let reach = reach(config, keys_dir, signer, tokens, name, entry)?;
    let path = config.root.join(format!("{name}.git"));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => verify_mirror(&config.git, name, &path, entry.object_format).await?,
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
        entry: entry.clone(),
        path,
        reach,
        dialer,
        format: entry.object_format,
        state: Arc::new(Mutex::new(SyncState::default())),
    })
}

/// How `name`'s upstream is reached: neither `ssh://` nor `https://` is refused, and so is a
/// credential the signer doesn't hold (ssh); a token `tokens` lacks (HTTPS) is none yet.
fn reach(
    config: &MirrorConfig,
    keys_dir: &Path,
    signer: &dyn Signer,
    tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
    name: &RepoName,
    entry: &RepoEntry,
) -> Result<Reach> {
    let upstream = Upstream::parse(&entry.upstream).map_err(|why| MirrorError::Upstream {
        repo: name.clone(),
        upstream: entry.upstream.clone(),
        why: why.to_owned(),
    })?;
    let credential = entry.upstream_credential.clone();
    match upstream {
        Upstream::Ssh(url) => ssh_reach(config, keys_dir, signer, name, url, credential),
        Upstream::Https(url) => {
            let token = tokens.get(&credential).cloned();
            if token.is_none() {
                tracing::warn!(
                    repo = %name,
                    credential = %credential,
                    "no token yet: syncs and pushes are refused until `writ admin token` adds it"
                );
            }
            Ok(Reach::Https {
                url,
                credential,
                token,
            })
        }
    }
}

/// An `ssh://` upstream: its host pinned, its credential in the signer, whose public key is
/// written where ssh picks it from (`<keys>/<id>.pub`).
fn ssh_reach(
    config: &MirrorConfig,
    keys_dir: &Path,
    signer: &dyn Signer,
    name: &RepoName,
    url: SshUrl,
    credential: KeyId,
) -> Result<Reach> {
    let host = url.known_hosts_name();
    if !config.pinned.covers(&host) {
        return Err(MirrorError::HostNotPinned {
            repo: name.clone(),
            host,
        });
    }
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
    Ok(Reach::Ssh {
        url,
        credential,
        public,
        identity,
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
    let suffix = writ_crypto::keys::random_hex(8).map_err(|source| MirrorError::NoRandomness {
        what: "a new mirror's name",
        source,
    })?;
    let temporary = config.root.join(format!(".{name}.git.new-{suffix}"));
    let mut cmd = git::command(&config.git, Hooks::None);
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
async fn verify_mirror(
    program: &Path,
    name: &RepoName,
    path: &Path,
    format: ObjectFormat,
) -> Result<()> {
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
    let mut cmd = git::command(program, Hooks::None);
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
/// Removes the mirrors a start cut short left (`.<name>.git.new-<hex>`, made then renamed
/// into place by [`create_mirror`]): nothing else ever uses them (the review after M5.5).
fn remove_unfinished_mirrors(root: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(MirrorError::Io {
                what: "cannot read",
                path: root.to_owned(),
                source,
            });
        }
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && name.contains(".git.new-") {
            let path = entry.path();
            std::fs::remove_dir_all(&path).map_err(|source| MirrorError::Io {
                what: "cannot remove",
                path,
                source,
            })?;
        }
    }
    Ok(())
}

pub(super) fn remove_leftovers(dir: &Path, matches: impl Fn(&str) -> bool) -> Result<()> {
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

/// Writes `bytes` to a new private file at `path`, replacing what was there at once: written
/// whole beside it, then renamed over it (a rename replaces the entry, never follows a link
/// there), so an ssh starting meanwhile reads the old file or the new one, never none.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let io = |what: &'static str, at: &Path| {
        let at = at.to_owned();
        move |source| MirrorError::Io {
            what,
            path: at,
            source,
        }
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let suffix = writ_crypto::keys::random_hex(8).map_err(|source| MirrorError::NoRandomness {
        what: "a temporary file's name",
        source,
    })?;
    let temporary = path.with_file_name(format!(".{name}.new-{suffix}"));
    let written = writ_platform::fs::create_new_private_file(&temporary)
        .map_err(io("cannot create", &temporary))
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, bytes).map_err(io("cannot write", &temporary))
        })
        .and_then(|()| std::fs::rename(&temporary, path).map_err(io("cannot replace", path)));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mirror_a_start_cut_short_is_removed_and_nothing_else() {
        let root = tempfile::tempdir().unwrap();
        for dir in [
            ".demo.git.new-0123abcd/objects",
            "demo.git/objects",
            ".hidden",
        ] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        std::fs::write(root.path().join("demo.git.new-not-hidden"), "x").unwrap();
        remove_unfinished_mirrors(root.path()).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, [".hidden", "demo.git", "demo.git.new-not-hidden"]);
        // No root yet: nothing to do.
        remove_unfinished_mirrors(&root.path().join("absent")).unwrap();
    }
}
