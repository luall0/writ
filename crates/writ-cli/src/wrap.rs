//! `writ git <args>` and `writ exec -- <program> <args>`: any git command (commit, rebase,
//! cherry-pick, fetch, push, log…), or any program that runs git, with the repository's Writ
//! settings passed through the environment (`GIT_CONFIG_COUNT`, `GIT_SSH_COMMAND`). Nothing is
//! written anywhere: the settings last as long as the process, and git hands them to what it
//! runs (`writ-sign`, `ssh`, hooks).
//!
//! In a repository wired with `--whole-repo` the settings are in its config already, and the
//! program runs as it is.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, bail};

use crate::wiring::{self, Mode};
use crate::{Exit, Paths};

/// The directory git would work in: `-C <dir>` options at the front of git's arguments, from
/// the current directory.
fn git_dir(args: &[OsString]) -> anyhow::Result<PathBuf> {
    let mut dir = std::env::current_dir().context("cannot read the current directory")?;
    let mut rest = args;
    while let [flag, value, more @ ..] = rest {
        if flag != "-C" {
            break;
        }
        dir = dir.join(value);
        rest = more;
    }
    Ok(dir)
}

/// Runs `program` with `args` (in place of this process) under the wiring of the repository
/// at `dir`.
fn run(
    paths: &Paths,
    dir: &std::path::Path,
    program: &OsString,
    args: &[OsString],
) -> anyhow::Result<Exit> {
    let Some(wired) = wiring::load(dir)? else {
        bail!("this repo isn't wired for Writ: run `writ init <repo>` in it first");
    };
    // PATH: the agent host's own git and tools, as the agent would run them.
    let mut command = Command::new(program);
    command.args(args);
    if wired.mode == Mode::Wrapper {
        let settings = wiring::settings_for(paths, &wired)?;
        let existing = std::env::var("GIT_CONFIG_COUNT").ok();
        command.envs(wiring::config_env(existing.as_deref(), &settings)?);
        // Over the caller's own GIT_SSH_COMMAND, which git (and writ-sign) would take first.
        let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
        let known_hosts = std::path::absolute(&paths.known_hosts)
            .context("cannot resolve the known_hosts path")?;
        command.env("GIT_SSH_COMMAND", wiring::ssh_command(&home, &known_hosts));
    }
    let error = command.exec();
    bail!("cannot run {}: {error}", PathBuf::from(program).display())
}

/// `writ git <args>`.
pub fn git(paths: &Paths, args: &[OsString]) -> anyhow::Result<Exit> {
    run(paths, &git_dir(args)?, &OsString::from("git"), args)
}

/// `writ exec -- <program> <args>`.
pub fn exec(paths: &Paths, command: &[OsString]) -> anyhow::Result<Exit> {
    let [program, args @ ..] = command else {
        bail!("writ exec needs a program to run: writ exec -- <program> [args]");
    };
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    run(paths, &dir, program, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn leading_dash_c_options_pick_the_repository() {
        let here = std::env::current_dir().unwrap();
        assert_eq!(git_dir(&os(&["status"])).unwrap(), here);
        assert_eq!(
            git_dir(&os(&["-C", "/r", "log"])).unwrap(),
            PathBuf::from("/r")
        );
        assert_eq!(
            git_dir(&os(&["-C", "/r", "-C", "sub", "log"])).unwrap(),
            PathBuf::from("/r/sub")
        );
        // Only at the front: a later -C belongs to the subcommand.
        assert_eq!(git_dir(&os(&["log", "-C", "/r"])).unwrap(), here);
    }
}
