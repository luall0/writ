//! How a repository is wired for Writ (`docs/architecture/clients.md`, repo setup): the git
//! settings that send commits to the daemon to sign and reach it with the session's key,
//! built in one place ([`settings`]) for both modes.
//!
//! - **Wrapper** (the default): nothing in the repository's git config. `writ git …` and
//!   `writ exec -- …` run git (or any program) with the settings passed through the
//!   environment (`GIT_CONFIG_COUNT`, git ≥ 2.31), so the operator's own git, in the same
//!   clone, keeps the operator's keys, email and remotes.
//! - **Whole repo** (`writ init --whole-repo`): the settings written in the repository's
//!   config, for a clone dedicated to an agent; the values they replace are kept, so
//!   `writ init --undo` puts them back.
//!
//! What `writ init` records lives in `<git common dir>/writ/config` (git config format): never
//! in the working tree, so it can't be committed, and it travels with the clone.
//!
//! The settings point at one session ([`choose_session`]): `WRIT_SESSION` when it is set, then
//! the lease the repo is pinned to (`writ init --lease`), then `<home>/sessions/current`. A
//! session named by the first two must be on this host and not ended, or the command is
//! refused: never replaced by `current`. `writ.session` names the session's directory, so
//! `writ-sign` signs with that session only, in its lease's format.
//!
//! The clone's `origin` URL, as it was when wired, is rewritten to the daemon
//! (`url.<daemon>/<repo>.git.insteadOf`), so `git push origin` and `git fetch origin` under the
//! wiring go through the daemon; only that exact URL, never the user's global config.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use writ_core::canonical::Canonical;
use writ_core::names::{RepoName, TicketId};
use writ_core::ticket::Ticket;

use crate::Paths;
use crate::display;

/// How a repository is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wrapper,
    WholeRepo,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Wrapper => "wrapper",
            Mode::WholeRepo => "whole-repo",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "wrapper" => Some(Mode::Wrapper),
            "whole-repo" => Some(Mode::WholeRepo),
            _ => None,
        }
    }
}

/// What `writ init` recorded for a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiring {
    pub mode: Mode,
    /// The daemon's agents listener as git reaches it (`ssh://git@host:port`).
    pub base_url: String,
    pub repo: RepoName,
    /// The committer email asked for (`writ init --email`); otherwise the current lease's.
    pub email: Option<String>,
    /// The repository's shared git directory (`writ.gitdir`): `writ-sign` refuses a commit
    /// made in any other repository with these settings.
    pub common_dir: PathBuf,
    /// The clone's `origin` URL when it was wired (`writ.origin`), rewritten to the daemon.
    pub origin: Option<String>,
    /// The lease the repo is pinned to (`writ init --lease`): its session, not `current`.
    pub lease: Option<TicketId>,
    /// The workspace root it was wired from (`writ.workspace`: `writ init` there, with no
    /// repo named), whose `writ init --undo` takes it back.
    pub workspace: Option<PathBuf>,
}

/// The session a command works under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRef {
    /// `<home>/sessions/current`, whichever lease it points at.
    Current,
    /// `<home>/sessions/<lease>`.
    Lease(TicketId),
}

impl SessionRef {
    /// The session's directory under `home`.
    pub fn dir(&self, home: &Path) -> PathBuf {
        let sessions = home.join("sessions");
        match self {
            Self::Current => sessions.join("current"),
            Self::Lease(id) => sessions.join(id.as_str()),
        }
    }
}

/// The file in a session's directory that says it ended (closed, renewed), with why.
pub const ENDED: &str = "ended";

/// The session a command in a repo wired as `wiring` works under: `WRIT_SESSION`, then the
/// repo's pinned lease, then `current`. One named that is unknown on this host, ended (its
/// `ended` file) or past its end is refused with the reason, never replaced by `current`.
pub fn choose_session(home: &Path, pinned: Option<&TicketId>) -> anyhow::Result<SessionRef> {
    let (id, from) = match std::env::var("WRIT_SESSION") {
        Ok(text) if !text.is_empty() => {
            let id: TicketId = text
                .parse()
                .map_err(|e| anyhow::anyhow!("WRIT_SESSION {}: {e}", display::clean(&text)))?;
            (id, "WRIT_SESSION")
        }
        _ => match pinned {
            Some(id) => (id.clone(), "the lease this repository is pinned to"),
            None => return Ok(SessionRef::Current),
        },
    };
    check_session(home, &id).map_err(|why| anyhow::anyhow!("{from} names lease {id}: {why}"))?;
    Ok(SessionRef::Lease(id))
}

/// Why the session of lease `id` can't be used, if it can't: not on this host, ended, or past
/// its end by this host's clock.
pub fn check_session(home: &Path, id: &TicketId) -> Result<(), String> {
    let dir = SessionRef::Lease(id.clone()).dir(home);
    let Ok(bytes) = std::fs::read(dir.join("lease.json")) else {
        return Err(format!(
            "no granted session for it on this host ({})",
            dir.display()
        ));
    };
    let lease = Ticket::from_canonical(&bytes)
        .map_err(|_| format!("its session's lease.json doesn't read ({})", dir.display()))?;
    if let Ok(ended) = std::fs::read_to_string(dir.join(ENDED)) {
        return Err(format!("it ended ({})", display::clean(ended.trim())));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    let ended = u64::try_from(lease.limits.expires_at.unix()).map_or(true, |end| now >= end);
    if ended {
        return Err(format!("it expired at {}", lease.limits.expires_at));
    }
    Ok(())
}

/// One git setting: its key and value.
pub type Setting = (String, String);

/// Single-quoted for `sh` (git runs `core.sshCommand` through it).
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Where a repository is wired to, for [`settings`].
pub struct Target<'a> {
    /// The daemon's agents listener as git reaches it (`ssh://git@host:port`).
    pub base_url: &'a str,
    pub repo: &'a RepoName,
    pub common_dir: &'a Path,
    /// The clone's `origin` URL, rewritten to the daemon.
    pub origin: Option<&'a str>,
    /// The session the settings point at.
    pub session: &'a SessionRef,
}

/// The settings that wire a repository, in order (`<key> <value>`).
pub fn settings(
    target: &Target<'_>,
    home: &Path,
    known_hosts: &Path,
    writ_sign: &str,
    email: Option<&str>,
) -> Vec<Setting> {
    let Target {
        base_url,
        repo,
        common_dir,
        origin,
        session,
    } = *target;
    let session_ref = session;
    let session = session_ref.dir(home);
    let path = |p: PathBuf| p.display().to_string();
    let mut settings: Vec<(&'static str, String)> = vec![
        ("remote.writ.url", format!("{base_url}/{repo}.git")),
        (
            "remote.writ.fetch",
            "+refs/heads/*:refs/remotes/writ/*".to_owned(),
        ),
        ("writ.url", base_url.to_owned()),
        ("writ.repo", repo.to_string()),
        ("writ.gitdir", path(common_dir.to_path_buf())),
        ("writ.session", path(session.clone())),
    ];
    // The lease's key signs in OpenPGP when its session holds the key's certificate: git
    // then calls `writ-sign` as `gpg`, and names the key by its fingerprint.
    match openpgp_fingerprint(&session) {
        Some(fingerprint) => settings.extend([
            ("gpg.format", "openpgp".to_owned()),
            ("gpg.openpgp.program", writ_sign.to_owned()),
            ("user.signingkey", fingerprint),
        ]),
        None => settings.extend([
            ("gpg.format", "ssh".to_owned()),
            ("gpg.ssh.program", writ_sign.to_owned()),
            ("user.signingkey", path(session.join("signing_key.pub"))),
        ]),
    }
    settings.extend([
        ("commit.gpgSign", "true".to_owned()),
        // Tags are never signed by the daemon (releases stay a human act).
        ("tag.gpgSign", "false".to_owned()),
        ("core.sshCommand", ssh_command(&session, known_hosts)),
    ]);
    if let Some(email) = email {
        settings.push(("user.email", email.to_owned()));
    }
    // The lease's committer_name, when its template sets one: the daemon refuses any other.
    if let Some(name) = lease_name(&session) {
        settings.push(("user.name", name));
    }
    let mut settings: Vec<Setting> = settings
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    let daemon = format!("{base_url}/{repo}.git");
    if let Some(origin) = origin.filter(|o| !o.is_empty() && *o != daemon) {
        settings.push((format!("url.{daemon}.insteadOf"), origin.to_owned()));
    }
    settings
}

/// The fingerprint of the OpenPGP certificate in `session` (`signing_key.asc`, written with
/// the grant when the lease's key signs in OpenPGP), if there is one that reads.
fn openpgp_fingerprint(session: &Path) -> Option<String> {
    let text = std::fs::read_to_string(session.join("signing_key.asc")).ok()?;
    writ_crypto::openpgp::certificate_fingerprint(&text).ok()
}

/// The SSH command to reach the daemon with the session in `session` (its directory): nothing
/// from the user's own SSH setup (no config, no agent, no other key, no prompt), only the
/// daemon's pinned host key.
pub fn ssh_command(session: &Path, known_hosts: &Path) -> String {
    format!(
        "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i {} \
         -o {} -o {} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes",
        quote(&session.join("key").display().to_string()),
        quote(&format!(
            "CertificateFile={}",
            session.join("key-cert.pub").display()
        )),
        quote(&format!("UserKnownHostsFile={}", known_hosts.display())),
    )
}

/// `writ-sign` next to this `writ`, if it is there; otherwise found in `PATH` by git.
pub fn writ_sign_program() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("writ-sign")))
        .filter(|path| path.is_file())
        .map_or_else(|| "writ-sign".to_owned(), |path| path.display().to_string())
}

/// The single committer email of the lease in `session`, if it allows exactly one.
pub fn lease_email(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    let lease = Ticket::from_canonical(&bytes).ok()?;
    match lease.scope.committer_emails.iter().collect::<Vec<_>>()[..] {
        [only] => Some(only.as_str().to_owned()),
        _ => None,
    }
}

/// The name the lease in `session` requires of its commits (its template's
/// `committer_name`), if it requires one.
pub fn lease_name(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    let lease = Ticket::from_canonical(&bytes).ok()?;
    lease.scope.committer_name.map(String::from)
}

/// The id of the lease in `session`, if there is one on this host.
pub fn lease_id(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    Some(Ticket::from_canonical(&bytes).ok()?.lease_id().to_string())
}

/// Runs git in `dir`; its stdout, or why it failed.
pub fn git(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    // PATH: the agent host's own git, the one the repo is used with.
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .context("cannot run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            display::clean_lines(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The repository's shared git directory (the same for every worktree).
pub fn common_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    let out = git(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .map_err(|_| anyhow::anyhow!("not in a git repository ({})", dir.display()))?;
    Ok(PathBuf::from(out.trim_end_matches('\n')))
}

/// `<common dir>/writ/config`, where `writ init` records what it did.
pub fn record_path(dir: &Path) -> anyhow::Result<PathBuf> {
    Ok(common_dir(dir)?.join("writ").join("config"))
}

/// The entries of a git config file (`git config -f <file> --list -z`), in order.
pub fn read_file(dir: &Path, file: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let file = file.display().to_string();
    let out = git(dir, &["config", "-f", &file, "--list", "-z"])?;
    Ok(out
        .split('\0')
        .filter(|e| !e.is_empty())
        .map(|entry| match entry.split_once('\n') {
            Some((key, value)) => (key.to_owned(), value.to_owned()),
            None => (entry.to_owned(), String::new()),
        })
        .collect())
}

/// What `writ init` recorded in the repository at `dir`, if it is wired.
pub fn load(dir: &Path) -> anyhow::Result<Option<Wiring>> {
    load_common(&common_dir(dir)?)
}

/// What `writ init` recorded in the repository whose shared git directory is `common_dir`,
/// if it is wired.
pub fn load_common(common_dir: &Path) -> anyhow::Result<Option<Wiring>> {
    let path = common_dir.join("writ").join("config");
    if !path.exists() {
        return Ok(None);
    }
    let entries = read_file(common_dir, &path)?;
    let get = |key: &str| {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let invalid = || anyhow::anyhow!("{} is not a Writ wiring record", path.display());
    let mode = get("writ.mode")
        .as_deref()
        .and_then(Mode::parse)
        .ok_or_else(invalid)?;
    let base_url = get("writ.url").ok_or_else(invalid)?;
    let repo = get("writ.repo")
        .and_then(|r| r.parse().ok())
        .ok_or_else(invalid)?;
    let lease = match get("writ.lease") {
        Some(text) => Some(text.parse().map_err(|_| invalid())?),
        None => None,
    };
    Ok(Some(Wiring {
        mode,
        base_url,
        repo,
        email: get("writ.email"),
        common_dir: common_dir.to_path_buf(),
        origin: get("writ.origin"),
        lease,
        workspace: get("writ.workspace").map(PathBuf::from),
    }))
}

/// The settings of a wired repository, with this host's paths and the session `session`.
pub fn settings_with(
    paths: &Paths,
    wiring: &Wiring,
    session: &SessionRef,
) -> anyhow::Result<Vec<Setting>> {
    let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
    let known_hosts =
        std::path::absolute(&paths.known_hosts).context("cannot resolve the known_hosts path")?;
    let email = wiring
        .email
        .clone()
        .or_else(|| lease_email(&session.dir(&home)));
    Ok(settings(
        &Target {
            base_url: &wiring.base_url,
            repo: &wiring.repo,
            common_dir: &wiring.common_dir,
            origin: wiring.origin.as_deref(),
            session,
        },
        &home,
        &known_hosts,
        &writ_sign_program(),
        email.as_deref(),
    ))
}

/// The environment that passes `settings` to git, after the `GIT_CONFIG_COUNT` entries the
/// caller already has (`existing`): later entries win, so these override the user's config.
pub fn config_env(
    existing: Option<&str>,
    settings: &[Setting],
) -> anyhow::Result<Vec<(String, OsString)>> {
    let start: usize = match existing {
        None => 0,
        Some(text) => text
            .parse()
            .with_context(|| format!("GIT_CONFIG_COUNT is not a number: {text:?}"))?,
    };
    let mut env = Vec::new();
    let mut index = start;
    for (key, value) in settings {
        env.push((format!("GIT_CONFIG_KEY_{index}"), OsString::from(key)));
        env.push((format!("GIT_CONFIG_VALUE_{index}"), OsString::from(value)));
        index = index.saturating_add(1);
    }
    env.push((
        "GIT_CONFIG_COUNT".to_owned(),
        OsString::from(index.to_string()),
    ));
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_openpgp_lease_is_wired_for_gpg_by_its_fingerprint() {
        use writ_crypto::algorithm::{Hash, KeyAlgorithm};
        use writ_crypto::keypair::KeyPair;
        use writ_crypto::openpgp::{OpenpgpKey, certificate, certification};
        let home = tempfile::tempdir().unwrap();
        let session = home.path().join("sessions/current");
        std::fs::create_dir_all(&session).unwrap();
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let pgp = OpenpgpKey::new(&key.public_key(), 1_762_128_000).unwrap();
        let prepared = certification(&pgp, Hash::Sha512, "<a@b>").unwrap();
        let (data, hash) = prepared.signer_input();
        let packet = prepared.packet(&key.sign(data, hash).unwrap()).unwrap();
        std::fs::write(
            session.join("signing_key.asc"),
            certificate(&pgp, &[("<a@b>", packet)]).unwrap(),
        )
        .unwrap();
        let wired = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: None,
                session: &SessionRef::Current,
            },
            home.path(),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            None,
        );
        let get = |key: &str| {
            wired
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("gpg.format"), Some("openpgp"));
        assert_eq!(get("gpg.openpgp.program"), Some("/usr/local/bin/writ-sign"));
        assert_eq!(get("user.signingkey"), Some(pgp.fingerprint_hex().as_str()));
        assert_eq!(get("gpg.ssh.program"), None);
        // A certificate that doesn't read: wired for SSH, as without one.
        std::fs::write(session.join("signing_key.asc"), "not a certificate").unwrap();
        let wired = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: None,
                session: &SessionRef::Current,
            },
            home.path(),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            None,
        );
        assert!(wired.iter().any(|(k, v)| k == "gpg.format" && v == "ssh"));
    }

    #[test]
    fn writes_exactly_the_documented_config() {
        let settings = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: Some("git@github.com:user/omega-code.git"),
                session: &SessionRef::Current,
            },
            Path::new("/opt/agent/.writ"),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            Some("user+agent@example.org"),
        );
        let expected = [
            ("remote.writ.url", "ssh://git@writ.home:2222/omega-code.git"),
            ("remote.writ.fetch", "+refs/heads/*:refs/remotes/writ/*"),
            ("writ.url", "ssh://git@writ.home:2222"),
            ("writ.repo", "omega-code"),
            ("writ.gitdir", "/opt/agent/omega/.git"),
            ("writ.session", "/opt/agent/.writ/sessions/current"),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", "/usr/local/bin/writ-sign"),
            (
                "user.signingkey",
                "/opt/agent/.writ/sessions/current/signing_key.pub",
            ),
            ("commit.gpgSign", "true"),
            ("tag.gpgSign", "false"),
            (
                "core.sshCommand",
                "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
                 -i '/opt/agent/.writ/sessions/current/key' \
                 -o 'CertificateFile=/opt/agent/.writ/sessions/current/key-cert.pub' \
                 -o 'UserKnownHostsFile=/opt/agent/.writ/known_hosts' \
                 -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes",
            ),
            ("user.email", "user+agent@example.org"),
            (
                "url.ssh://git@writ.home:2222/omega-code.git.insteadOf",
                "git@github.com:user/omega-code.git",
            ),
        ];
        let got: Vec<(&str, &str)> = settings
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn only_a_real_origin_is_rewritten() {
        let repo: RepoName = "demo".parse().unwrap();
        let rewrites = |origin: Option<&str>| {
            settings(
                &Target {
                    base_url: "ssh://git@writ.home:2222",
                    repo: &repo,
                    common_dir: Path::new("/r/.git"),
                    origin,
                    session: &SessionRef::Current,
                },
                Path::new("/h"),
                Path::new("/k"),
                "writ-sign",
                None,
            )
            .into_iter()
            .filter(|(k, _)| k.starts_with("url."))
            .count()
        };
        assert_eq!(rewrites(Some("ssh://git@github.com/u/demo.git")), 1);
        assert_eq!(rewrites(None), 0, "no origin");
        assert_eq!(rewrites(Some("")), 0, "an empty origin");
        assert_eq!(
            rewrites(Some("ssh://git@writ.home:2222/demo.git")),
            0,
            "origin already the daemon: no loop"
        );
    }

    #[test]
    fn paths_are_quoted_for_sh() {
        assert_eq!(quote("/a b/it's"), r"'/a b/it'\''s'");
        let ssh = ssh_command(Path::new("/x y/$(id)/sessions/current"), Path::new("/k"));
        assert!(
            ssh.contains("-i '/x y/$(id)/sessions/current/key'"),
            "{ssh}"
        );
    }

    #[test]
    fn the_environment_comes_after_what_the_caller_has() {
        let settings = vec![
            ("writ.repo".to_owned(), "demo".to_owned()),
            ("commit.gpgSign".to_owned(), "true".to_owned()),
        ];
        let env = config_env(None, &settings).unwrap();
        let text: Vec<(&str, &str)> = env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            text,
            [
                ("GIT_CONFIG_KEY_0", "writ.repo"),
                ("GIT_CONFIG_VALUE_0", "demo"),
                ("GIT_CONFIG_KEY_1", "commit.gpgSign"),
                ("GIT_CONFIG_VALUE_1", "true"),
                ("GIT_CONFIG_COUNT", "2"),
            ]
        );
        // Two entries the caller set: ours follow, so ours win.
        let env = config_env(Some("2"), &settings).unwrap();
        assert_eq!(env[0].0, "GIT_CONFIG_KEY_2");
        assert_eq!(env.last().unwrap().1, "4");
        let error = crate::error_of(config_env(Some("two"), &settings));
        assert!(
            error.starts_with("GIT_CONFIG_COUNT is not a number: \"two\""),
            "{error}"
        );
    }
}
