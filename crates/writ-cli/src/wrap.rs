//! `writ git <args>` and `writ exec [-C <dir>] -- <program> <args>`: any git command (commit,
//! rebase, cherry-pick, fetch, push, log…), or any program that runs git, with the
//! repository's Writ settings passed through the environment (`GIT_CONFIG_COUNT`,
//! `GIT_SSH_COMMAND`). Nothing is written anywhere: the settings last as long as the process,
//! and git hands them to what it runs (`writ-sign`, `ssh`, hooks).
//!
//! `writ git` finds the repository as git will: its global options read in order
//! ([`gitopts`](crate::gitopts)), then git resolves the repository from the ones that say
//! which (`-C`, `--git-dir`, `--work-tree`, `--bare`) and the environment. `writ exec -C
//! <dir>` runs the program in `<dir>`, under that repository's wiring: one repository per
//! process. At a workspace root that isn't a wired repository, both list the workspace's
//! repositories.
//!
//! In a repository wired with `--whole-repo` the settings are in its config already, and the
//! program runs as it is (`writ-sign` checks `WRIT_SESSION` against them).

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use crate::gitopts::{self, Parsed};
use crate::wiring::{self, Mode, Wiring};
use crate::{Exit, Paths, workspace};

/// Why there is no wiring for a command in `dir` (`reason`: git's, when it found no
/// repository): at a workspace root, its repositories listed.
fn not_wired(dir: &Path, reason: Option<&str>) -> anyhow::Error {
    if let Ok(Some(found)) = workspace::load(dir) {
        return anyhow::anyhow!(
            "{} is a Writ workspace, not a repository wired for Writ: run git in one of its \
             repositories (`writ git -C <dir> …`, `writ exec -C <dir> -- …`):\n{}",
            dir.display(),
            found.listing()
        );
    }
    match reason {
        Some(reason) => anyhow::anyhow!("not in a git repository ({}): {reason}", dir.display()),
        None => {
            anyhow::anyhow!("this repo isn't wired for Writ: run `writ init <repo>` in it first")
        }
    }
}

/// Runs `command` (in place of this process) under the wiring `wired`.
fn run(paths: &Paths, wired: &Wiring, mut command: Command) -> anyhow::Result<Exit> {
    if wired.mode == Mode::Wrapper {
        // One session for the whole command: chosen once, `current` resolved to its lease, so
        // every setting names that session however `current` moves while the command runs.
        let session =
            wiring::choose_session(&paths.home, wired.lease.as_ref())?.resolved(&paths.home)?;
        let settings = wiring::settings_with(paths, wired, &session)?;
        let existing = std::env::var("GIT_CONFIG_COUNT").ok();
        command.envs(wiring::config_env(existing.as_deref(), &settings)?);
        // Over the caller's own GIT_SSH_COMMAND, which git (and writ-sign) would take first.
        let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
        let known_hosts = std::path::absolute(&paths.known_hosts)
            .context("cannot resolve the known_hosts path")?;
        command.env(
            "GIT_SSH_COMMAND",
            wiring::ssh_command(&session.dir(&home), &known_hosts, wired.socket.as_deref()),
        );
    }
    let error = command.exec();
    bail!(
        "cannot run {}: {error}",
        PathBuf::from(command.get_program()).display()
    )
}

/// `writ git <args>`.
pub async fn git(paths: &Paths, args: &[OsString]) -> anyhow::Result<Exit> {
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    // PATH: the agent host's own git, as the agent would run it.
    let mut command = Command::new("git");
    command.args(args);
    let (dir, locate, git_command) =
        match gitopts::parse(&cwd, args).map_err(|e| anyhow::anyhow!(e))? {
            Parsed::Command {
                dir,
                locate,
                command,
            } => (dir, locate, command),
            // `--version`, `--help`…: no repository, nothing signed or pushed.
            Parsed::Informational => {
                let error = command.exec();
                bail!("cannot run git: {error}");
            }
        };
    let common = gitopts::common_dir(&locate).map_err(|why| not_wired(&dir, Some(&why)))?;
    let wired = wiring::load_common(&common)?.ok_or_else(|| not_wired(&dir, None))?;
    // A fetch with no lease (M7.9.7): under one granted with no signature, when the policy
    // has a template for it; git's exit is the command's.
    if crate::unsigned::applies(&paths.home, &wired, git_command.as_deref())? {
        // PATH: the agent host's own git, as the agent would run it.
        let mut fetching = Command::new("git");
        fetching.args(args);
        if let Some(code) = crate::unsigned::fetch(paths, &wired, fetching).await? {
            std::process::exit(code);
        }
    }
    run(paths, &wired, command)
}

/// `writ exec [-C <dir>] -- <program> <args>`.
pub fn exec(paths: &Paths, dir: Option<&Path>, command: &[OsString]) -> anyhow::Result<Exit> {
    let [program, args @ ..] = command else {
        bail!("writ exec needs a program to run: writ exec -- <program> [args]");
    };
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    let dir = match dir {
        Some(dir) => cwd.join(dir),
        None => cwd,
    };
    if !dir.is_dir() {
        bail!("-C {}: not a directory", dir.display());
    }
    let wired = match wiring::load(&dir) {
        Ok(Some(wired)) => wired,
        Ok(None) => return Err(not_wired(&dir, None)),
        Err(e) => return Err(not_wired(&dir, Some(&format!("{e:#}")))),
    };
    // PATH: the agent host's own tools, as the agent would run them.
    let mut command = Command::new(program);
    command.args(args).current_dir(&dir);
    run(paths, &wired, command)
}
