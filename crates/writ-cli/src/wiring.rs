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
//! in the working tree, so it can't be committed, and it travels with the clone. Paths in the
//! settings point at `<home>/sessions/current`, so a wired repo follows the current lease.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use writ_core::canonical::Canonical;
use writ_core::names::RepoName;
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
}

/// Single-quoted for `sh` (git runs `core.sshCommand` through it).
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The settings that wire a repository, in order (`<key> <value>`).
pub fn settings(
    base_url: &str,
    repo: &RepoName,
    home: &Path,
    known_hosts: &Path,
    writ_sign: &str,
    email: Option<&str>,
) -> Vec<(&'static str, String)> {
    let session = home.join("sessions").join("current");
    let path = |p: PathBuf| p.display().to_string();
    let mut settings = vec![
        ("remote.writ.url", format!("{base_url}/{repo}.git")),
        (
            "remote.writ.fetch",
            "+refs/heads/*:refs/remotes/writ/*".to_owned(),
        ),
        ("writ.url", base_url.to_owned()),
        ("writ.repo", repo.to_string()),
        ("gpg.format", "ssh".to_owned()),
        ("gpg.ssh.program", writ_sign.to_owned()),
        ("user.signingkey", path(session.join("signing_key.pub"))),
        ("commit.gpgSign", "true".to_owned()),
        // Tags are never signed by the daemon (releases stay a human act).
        ("tag.gpgSign", "false".to_owned()),
        ("core.sshCommand", ssh_command(home, known_hosts)),
    ];
    if let Some(email) = email {
        settings.push(("user.email", email.to_owned()));
    }
    settings
}

/// The SSH command to reach the daemon with the current session: nothing from the user's own
/// SSH setup (no config, no agent, no other key, no prompt), only the daemon's pinned host key.
pub fn ssh_command(home: &Path, known_hosts: &Path) -> String {
    let session = home.join("sessions").join("current");
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

/// The current lease's single committer email, if it allows exactly one.
pub fn lease_email(home: &Path) -> Option<String> {
    let bytes = std::fs::read(home.join("sessions/current/lease.json")).ok()?;
    let lease = Ticket::from_canonical(&bytes).ok()?;
    match lease.scope.committer_emails.iter().collect::<Vec<_>>()[..] {
        [only] => Some(only.as_str().to_owned()),
        _ => None,
    }
}

/// The current lease's id, if there is one on this host.
pub fn lease_id(home: &Path) -> Option<String> {
    let bytes = std::fs::read(home.join("sessions/current/lease.json")).ok()?;
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
    let path = record_path(dir)?;
    if !path.exists() {
        return Ok(None);
    }
    let entries = read_file(dir, &path)?;
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
    Ok(Some(Wiring {
        mode,
        base_url,
        repo,
        email: get("writ.email"),
    }))
}

/// The settings of a wired repository, with this host's paths and the current lease.
pub fn settings_for(paths: &Paths, wiring: &Wiring) -> anyhow::Result<Vec<(&'static str, String)>> {
    let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
    let known_hosts =
        std::path::absolute(&paths.known_hosts).context("cannot resolve the known_hosts path")?;
    let email = wiring.email.clone().or_else(|| lease_email(&home));
    Ok(settings(
        &wiring.base_url,
        &wiring.repo,
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
    settings: &[(&'static str, String)],
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
    fn writes_exactly_the_documented_config() {
        let settings = settings(
            "ssh://git@writ.home:2222",
            &"omega-code".parse().unwrap(),
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
        ];
        let got: Vec<(&str, &str)> = settings.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn paths_are_quoted_for_sh() {
        assert_eq!(quote("/a b/it's"), r"'/a b/it'\''s'");
        let ssh = ssh_command(Path::new("/x y/$(id)"), Path::new("/k"));
        assert!(
            ssh.contains("-i '/x y/$(id)/sessions/current/key'"),
            "{ssh}"
        );
    }

    #[test]
    fn the_environment_comes_after_what_the_caller_has() {
        let settings = vec![
            ("writ.repo", "demo".to_owned()),
            ("commit.gpgSign", "true".to_owned()),
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
