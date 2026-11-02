//! Opening the mirrors at startup: the programs and git checked, the private directories and
//! the files git and ssh read written (pinned host keys, CA certificates, the credentials'
//! public keys), each repo's way upstream, and each mirror created or checked to be one the
//! daemon made.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use writ_core::config::{ObjectFormat, RepoEntry};
use writ_core::names::{KeyId, RepoName};
use writ_signer::Signer;

use super::{CaCerts, MAX_SYNCS, MirrorConfig, Mirrors, Reach, Repo, Shared, SyncState};
use crate::credential::UpstreamToken;
use crate::git::{self, Hooks};
use crate::upstream::{SshUrl, Upstream};
use crate::{MIN_GIT, MIN_GIT_HTTPS, MirrorError, Result, shown};

impl Mirrors {
    /// Opens the mirror of every repo in `repos`, creating the ones that don't exist yet.
    /// Refuses (fail closed) an upstream it can't reach as configured: neither `ssh://` nor
    /// `https://`, an ssh host without a pinned key, a credential the signer (ssh) or `tokens`
    /// (HTTPS) don't hold, a git too old for it; and a directory in the mirror's place that
    /// isn't one the daemon made (another object or ref format, not bare, a link).
    pub async fn open(
        config: MirrorConfig,
        repos: &BTreeMap<RepoName, RepoEntry>,
        signer: Arc<dyn Signer>,
        tokens: &BTreeMap<KeyId, Arc<UpstreamToken>>,
    ) -> Result<Self> {
        check_config(&config, repos).await?;
        let files = RunFiles::write(&config)?;
        let mut opened = BTreeMap::new();
        for (name, entry) in repos {
            let repo = open_repo(&config, &files.keys_dir, &*signer, tokens, name, entry).await?;
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
                syncs: Semaphore::new(MAX_SYNCS),
            }),
        })
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
        path,
        reach,
        format: entry.object_format,
        state: Arc::new(Mutex::new(SyncState::default())),
    })
}

/// How `name`'s upstream is reached: neither `ssh://` nor `https://` is refused, and so is a
/// credential the signer (ssh) or `tokens` (HTTPS) don't hold.
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
            let token = tokens
                .get(&credential)
                .ok_or_else(|| MirrorError::UnknownToken {
                    repo: name.clone(),
                    key: credential.clone(),
                })?
                .clone();
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
