//! `writ init <repo>`: wires the git repository in the current directory for Writ
//! ([`wiring`](crate::wiring)), and `writ init --undo`, which takes it back exactly.
//!
//! - Wrapper mode (the default) writes only `<git common dir>/writ/config`: the repo's git
//!   config, and so the operator's own git, stay as they are; the agent runs git through
//!   `writ git`.
//! - `--whole-repo` writes the settings in the repo's config (a clone dedicated to an agent),
//!   after recording the values they replace (`previous.<key>.value`, or
//!   `previous.<key>.absent`) for `--undo`.

use std::path::Path;

use anyhow::{Context, bail};
use writ_core::names::{Email, RepoName};

use crate::client::Endpoint;
use crate::wiring::{self, Mode, Wiring};
use crate::{Exit, Paths};

/// What to wire.
pub struct Init<'a> {
    /// The daemon's agents listener (`WRIT_URL`).
    pub url: &'a str,
    pub repo: &'a RepoName,
    pub mode: Mode,
    /// The committer email; by default the current lease's, when it allows exactly one.
    pub email: Option<&'a Email>,
}

/// `ssh://git@host:port`, the daemon as git reaches it.
fn base_url(url: &str) -> anyhow::Result<String> {
    let Endpoint::Tcp { host, port } = Endpoint::parse(url)? else {
        bail!(
            "writ init wires an ssh://host:port endpoint, not {url} (a Unix socket comes with \
             local mode)"
        );
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(format!("ssh://git@{host}:{port}"))
}

/// `git config -f <record> <key> <value>` (`--add` keeps several values of one key).
fn record(dir: &Path, file: &Path, key: &str, value: &str) -> anyhow::Result<()> {
    let file = file.display().to_string();
    wiring::git(dir, &["config", "-f", &file, "--add", key, value]).map(|_| ())
}

/// The repo's own values of `key` (`git config --local --get-all`); none is an empty list.
fn local_values(dir: &Path, key: &str) -> anyhow::Result<Vec<String>> {
    // PATH: the agent host's own git.
    let out = std::process::Command::new("git")
        .args(["config", "--local", "--get-all", key])
        .current_dir(dir)
        .output()
        .context("cannot run git")?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect()),
        // Exit 1: the key isn't set.
        Some(1) => Ok(Vec::new()),
        _ => bail!("git config --get-all {key} failed"),
    }
}

pub fn init(paths: &Paths, request: &Init<'_>) -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let base_url = base_url(request.url)?;
    let record_path = wiring::record_path(&dir)?;
    if let Some(wired) = wiring::load(&dir)? {
        bail!(
            "this repo is already wired for Writ ({} mode, repo {}): `writ init --undo` first",
            wired.mode.as_str(),
            wired.repo
        );
    }
    let record_dir = record_path
        .parent()
        .context("the record has no directory")?;
    std::fs::create_dir_all(record_dir)
        .with_context(|| format!("cannot create {}", record_dir.display()))?;
    let origin = local_values(&dir, "remote.origin.url")?.into_iter().next();
    let wiring = Wiring {
        mode: request.mode,
        base_url: base_url.clone(),
        repo: request.repo.clone(),
        email: request.email.map(|e| e.as_str().to_owned()),
        common_dir: wiring::common_dir(&dir)?,
        origin,
    };
    if request.mode == Mode::WholeRepo {
        // The values replaced, first: `--undo` puts them back.
        for (key, _) in wiring::settings_for(paths, &wiring)? {
            let before = local_values(&dir, &key)?;
            if before.is_empty() {
                record(
                    &dir,
                    &record_path,
                    &format!("previous.{key}.absent"),
                    "true",
                )?;
            }
            for value in before {
                record(&dir, &record_path, &format!("previous.{key}.value"), &value)?;
            }
        }
    }
    record(&dir, &record_path, "writ.mode", request.mode.as_str())?;
    record(&dir, &record_path, "writ.url", &base_url)?;
    record(&dir, &record_path, "writ.repo", request.repo.as_str())?;
    if let Some(email) = &wiring.email {
        record(&dir, &record_path, "writ.email", email)?;
    }
    if let Some(origin) = &wiring.origin {
        record(&dir, &record_path, "writ.origin", origin)?;
    }
    if request.mode == Mode::WholeRepo {
        for (key, value) in wiring::settings_for(paths, &wiring)? {
            wiring::git(&dir, &["config", "--local", "--replace-all", &key, &value])?;
        }
    }
    print_summary(paths, &wiring)?;
    Ok(Exit::Ok)
}

fn print_summary(paths: &Paths, wiring: &Wiring) -> anyhow::Result<()> {
    let settings = wiring::settings_for(paths, wiring)?;
    let email = settings.iter().find(|(k, _)| k == "user.email");
    match wiring.mode {
        Mode::Wrapper => println!(
            "Wired for Writ (wrapper mode): run git through `writ git …` (any command) to work \
             under the lease; plain git keeps your own config."
        ),
        Mode::WholeRepo => println!(
            "Wired for Writ (whole repo): this clone's git config now sends commits to the \
             daemon and reaches it with the session's key."
        ),
    }
    println!("Remote `writ`: {}/{}.git.", wiring.base_url, wiring.repo);
    match (&wiring.origin, wiring.mode) {
        (Some(origin), Mode::Wrapper) => println!(
            "Remote `origin` ({}): `writ git push origin` and `writ git fetch origin` go through \
             the daemon; plain git still reaches it directly.",
            crate::display::clean(origin)
        ),
        (Some(origin), Mode::WholeRepo) => println!(
            "Remote `origin` ({}): in this clone every push and fetch to it goes through the \
             daemon, plain git too (`writ init --undo` takes that back).",
            crate::display::clean(origin)
        ),
        (None, _) => println!("No `origin` remote: push to the `writ` remote."),
    }
    match email {
        Some((_, email)) => println!("Committer email: {email}."),
        None => {
            println!("No committer email: the current lease allows none or several; use --email.")
        }
    }
    if let Some(lease) = wiring::lease_id(&std::path::absolute(&paths.home)?) {
        println!(
            "Current lease {lease}: when the repo's ticket_link is `trailer`, each commit needs \
             `Writ: {lease}` (git commit --trailer \"Writ: {lease}\")."
        );
    }
    Ok(())
}

/// Takes the repository back to before `writ init`.
pub fn undo() -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let Some(wired) = wiring::load(&dir)? else {
        bail!("this repo isn't wired for Writ: nothing to undo");
    };
    let record_path = wiring::record_path(&dir)?;
    if wired.mode == Mode::WholeRepo {
        // The keys `writ init` set: the ones it recorded a previous state for.
        let entries = wiring::read_file(&dir, &record_path)?;
        let mut keys: Vec<&str> = Vec::new();
        for (entry, _) in &entries {
            let key = entry.strip_prefix("previous.").and_then(|k| {
                k.strip_suffix(".value")
                    .or_else(|| k.strip_suffix(".absent"))
            });
            if let Some(key) = key.filter(|k| !keys.contains(k)) {
                keys.push(key);
            }
        }
        for key in keys {
            // PATH: the agent host's own git.
            let unset = std::process::Command::new("git")
                .args(["config", "--local", "--unset-all", key])
                .current_dir(&dir)
                .output()
                .context("cannot run git")?;
            // Exit 5: the key wasn't there any more. Anything else (a locked config) stops
            // here, before the previous values are added on top of the current ones.
            if !matches!(unset.status.code(), Some(0 | 5)) {
                bail!(
                    "git config --unset-all {key} failed: {}",
                    crate::display::clean_lines(String::from_utf8_lossy(&unset.stderr).trim())
                );
            }
            let previous = format!("previous.{key}.value");
            for (_, value) in entries.iter().filter(|(k, _)| *k == previous) {
                wiring::git(&dir, &["config", "--local", "--add", key, value])?;
            }
            remove_section_if_empty(&dir, key)?;
        }
    }
    let record_dir = record_path
        .parent()
        .context("the record has no directory")?;
    std::fs::remove_dir_all(record_dir)
        .with_context(|| format!("cannot remove {}", record_dir.display()))?;
    println!(
        "Writ wiring removed ({} mode): the repo's git config is as it was before writ init.",
        wired.mode.as_str()
    );
    Ok(Exit::Ok)
}

/// Removes the section of `key` (`remote.writ` of `remote.writ.url`) when nothing is left in
/// it, so an emptied `[remote "writ"]` doesn't stay behind.
fn remove_section_if_empty(dir: &Path, key: &str) -> anyhow::Result<()> {
    let Some((section, _)) = key.rsplit_once('.') else {
        return Ok(());
    };
    let prefix = format!("{}.", section.to_lowercase());
    let left = wiring::git(dir, &["config", "--local", "--list"])?
        .lines()
        .any(|line| line.to_lowercase().starts_with(&prefix));
    if !left {
        // PATH: the agent host's own git. Fails when the section is already gone: nothing
        // to remove.
        let _ = std::process::Command::new("git")
            .args(["config", "--local", "--remove-section", section])
            .current_dir(dir)
            .output();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_becomes_git_s_url() {
        assert_eq!(
            base_url("ssh://writ.home:2222").unwrap(),
            "ssh://git@writ.home:2222"
        );
        assert_eq!(
            base_url("ssh://[::1]:2222").unwrap(),
            "ssh://git@[::1]:2222"
        );
        let error = crate::error_of(base_url("unix:/tmp/writd.sock"));
        assert!(
            error.starts_with("writ init wires an ssh://host:port endpoint"),
            "{error}"
        );
    }
}
