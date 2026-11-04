//! `writ init <repo>`: wires the git repository in the current directory for Writ
//! ([`wiring`](crate::wiring)) and installs the agent skill ([`skill`](crate::skill)); `writ
//! init --undo` takes both back exactly (the timings file aside: what the agent learned).
//!
//! - Wrapper mode (the default) writes only `<git common dir>/writ/config`: the repo's git
//!   config, and so the operator's own git, stay as they are; the agent runs git through
//!   `writ git`.
//! - `--whole-repo` writes the settings in the repo's config (a clone dedicated to an agent),
//!   after recording the values they replace (`previous.<key>.value`, or
//!   `previous.<key>.absent`) for `--undo`.
//! - `--lease <id>` pins the repo to a lease: its session, never `current`.
//!
//! Which agents get the skill is asked on a terminal (the ones detected in the repo and the
//! home pre-selected), or given by `--agents` / `--skill-dir`. Without a terminal and without
//! them, nothing is wired: the command fails and names the flags.

use std::collections::BTreeSet;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::names::{Email, RepoName, TicketId};

use crate::client::Endpoint;
use crate::skill::{self, Agent};
use crate::wiring::{self, Mode, SessionRef, Setting, Wiring};
use crate::{Exit, Paths};

/// Where the skill goes.
pub struct SkillChoice {
    /// `--agents`: the agents, or none (`None`: not given).
    pub agents: Option<BTreeSet<Agent>>,
    /// `--skill-dir`: one more skills folder, anywhere.
    pub skill_dir: Option<PathBuf>,
    /// `--global`: the user's folders instead of the repository's.
    pub global: bool,
    /// `--agents-md`: a pointer line in `AGENTS.md` / `CLAUDE.md`.
    pub agents_md: bool,
}

/// What to wire.
pub struct Init<'a> {
    /// The daemon's agents listener (`WRIT_URL`).
    pub url: &'a str,
    pub repo: &'a RepoName,
    pub mode: Mode,
    /// The committer email; by default the lease's, when it allows exactly one.
    pub email: Option<&'a Email>,
    /// The lease the repo is pinned to (`--lease`).
    pub lease: Option<&'a TicketId>,
    pub skill: SkillChoice,
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

/// The repo's own values of `key` (`git config --local --get-all -z`: a value over several
/// lines kept whole); none is an empty list.
fn local_values(dir: &Path, key: &str) -> anyhow::Result<Vec<String>> {
    // PATH: the agent host's own git.
    let out = std::process::Command::new("git")
        .args(["config", "--local", "--get-all", "-z", key])
        .current_dir(dir)
        .output()
        .context("cannot run git")?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect()),
        // Exit 1: the key isn't set.
        Some(1) => Ok(Vec::new()),
        _ => bail!("git config --get-all {key} failed"),
    }
}

/// The agents the skill goes to, and one more folder: from the flags, or asked on a terminal.
fn choose_agents(
    choice: &SkillChoice,
    root: &Path,
    home: Option<&Path>,
) -> anyhow::Result<BTreeSet<Agent>> {
    if let Some(agents) = &choice.agents {
        return Ok(agents.clone());
    }
    if choice.skill_dir.is_some() {
        return Ok(BTreeSet::new());
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "no terminal to ask which agents get the Writ skill: pass --agents \
             <claude,agents,opencode,cursor|none> or --skill-dir <path> (nothing was wired)"
        );
    }
    ask_agents(&skill::detect(root, home))
}

/// The prompt: the agents, the detected ones marked; Enter takes them, 0 none.
fn ask_agents(detected: &BTreeSet<Agent>) -> anyhow::Result<BTreeSet<Agent>> {
    println!("Install the Writ skill for which agents? (* detected here)");
    for (i, agent) in Agent::ALL.iter().enumerate() {
        let mark = if detected.contains(agent) { " *" } else { "" };
        println!("  {}. {}{mark}", i + 1, agent.label());
    }
    print!("Numbers separated by commas; Enter: the detected ones; 0: none: ");
    std::io::Write::flush(&mut std::io::stdout()).context("cannot write to the terminal")?;
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
        .context("cannot read the answer")?;
    picked(&line, detected).map_err(|e| anyhow::anyhow!(e))
}

/// The agents an answer to the prompt picks.
fn picked(answer: &str, detected: &BTreeSet<Agent>) -> Result<BTreeSet<Agent>, String> {
    let answer = answer.trim();
    match answer {
        "" => return Ok(detected.clone()),
        "0" => return Ok(BTreeSet::new()),
        _ => {}
    }
    answer
        .split(',')
        .map(str::trim)
        .map(|n| {
            n.parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| Agent::ALL.get(i).copied())
                .ok_or_else(|| format!("{n:?}: answer with numbers from 1 to {}", Agent::ALL.len()))
        })
        .collect()
}

/// The repository's top directory.
fn top_level(dir: &Path) -> anyhow::Result<PathBuf> {
    let out = wiring::git(dir, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(out.trim_end_matches('\n')))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
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
    let root = top_level(&dir)?;
    let home = home_dir();
    // Everything that can refuse comes first: nothing is wired when it can't all be done.
    let agents = choose_agents(&request.skill, &root, home.as_deref())?;
    let session = match request.lease {
        Some(id) => {
            wiring::check_session(&paths.home, id)
                .map_err(|why| anyhow::anyhow!("--lease {id}: {why}"))?;
            SessionRef::Lease(id.clone())
        }
        None => SessionRef::Current,
    };
    let base = if request.skill.global {
        home.clone().context("--global needs HOME")?
    } else {
        root.clone()
    };
    let mut folders: Vec<PathBuf> = skill::folders(&agents, request.skill.global)
        .into_iter()
        .map(|f| base.join(f))
        .collect();
    if let Some(extra) = &request.skill.skill_dir {
        folders.push(std::path::absolute(extra).context("cannot resolve --skill-dir")?);
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
        lease: request.lease.cloned(),
    };
    // Once: the record for `--undo`, the config and the summary all come from these.
    let settings = wiring::settings_with(paths, &wiring, &session)?;
    if request.mode == Mode::WholeRepo {
        // The values replaced, first: `--undo` puts them back.
        for (key, _) in &settings {
            let before = local_values(&dir, key)?;
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
    if let Some(lease) = &wiring.lease {
        record(&dir, &record_path, "writ.lease", lease.as_str())?;
    }
    if request.mode == Mode::WholeRepo {
        for (key, value) in &settings {
            wiring::git(&dir, &["config", "--local", "--replace-all", key, value])?;
        }
    }
    let exclude = wiring.common_dir.join("info").join("exclude");
    let installed = skill::install(
        &skill::Plan {
            folders,
            root: root.clone(),
        },
        &exclude,
    )?;
    for (path, new) in &installed.skills {
        if *new {
            record(
                &dir,
                &record_path,
                "skill.created",
                &path.display().to_string(),
            )?;
        }
    }
    for line in &installed.excluded {
        record(&dir, &record_path, "skill.exclude", line)?;
    }
    if let Some((timings, _)) = &installed.timings {
        record(
            &dir,
            &record_path,
            "skill.timings",
            &timings.display().to_string(),
        )?;
    }
    let pointed = if request.skill.agents_md {
        agents_md(&dir, &record_path, &root)?
    } else {
        Vec::new()
    };
    print_summary(
        &wiring,
        &settings,
        &session,
        &installed,
        &pointed,
        request.skill.agents_md,
    );
    Ok(Exit::Ok)
}

/// `--agents-md`: the pointer line in each of `AGENTS.md` and `CLAUDE.md` the repository has
/// (a new `AGENTS.md` when it has neither), recorded for `--undo`.
fn agents_md(dir: &Path, record_path: &Path, root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = ["AGENTS.md", "CLAUDE.md"]
        .iter()
        .map(|f| root.join(f))
        .filter(|f| f.exists())
        .collect();
    let mut created = false;
    if files.is_empty() {
        files.push(root.join("AGENTS.md"));
        created = true;
    }
    for file in &files {
        if skill::add_line(file, skill::POINTER)? {
            let key = if created {
                "skill.agentsmdcreated"
            } else {
                "skill.agentsmd"
            };
            record(dir, record_path, key, &file.display().to_string())?;
        }
    }
    Ok(files)
}

fn print_summary(
    wiring: &Wiring,
    settings: &[Setting],
    session: &SessionRef,
    installed: &skill::Installed,
    pointed: &[PathBuf],
    agents_md: bool,
) {
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
        Some((_, email)) => println!("Committer email: {}.", crate::display::clean(email)),
        None => {
            println!("No committer email: the lease allows none or several; use --email.")
        }
    }
    match session {
        SessionRef::Lease(id) => println!(
            "Pinned to lease {id}: commands here use its session, never `current` \
             (WRIT_SESSION still comes first)."
        ),
        SessionRef::Current => println!(
            "Session: WRIT_SESSION when it is set, otherwise the current lease \
             (<home>/sessions/current)."
        ),
    }
    let settings_session = settings
        .iter()
        .find(|(k, _)| k == "writ.session")
        .map(|(_, v)| PathBuf::from(v));
    if let Some(lease) = settings_session.as_deref().and_then(wiring::lease_id) {
        println!(
            "Lease {lease}: when the repo's ticket_link is `trailer`, each commit needs \
             `Writ: {lease}` (git commit --trailer \"Writ: {lease}\")."
        );
    }
    if installed.skills.is_empty() {
        println!("No skill installed (--agents none).");
    }
    for (path, new) in &installed.skills {
        let how = if *new { "installed" } else { "refreshed" };
        println!("Skill {how}: {}.", path.display());
    }
    if let Some((timings, new)) = &installed.timings {
        let how = if *new { "new" } else { "kept" };
        println!(
            "Timings ({how}): {} (`writ close` records each run).",
            timings.display()
        );
    }
    if !installed.excluded.is_empty() {
        println!(
            "Excluded from git (.git/info/exclude): {}.",
            installed.excluded.join(", ")
        );
    }
    if agents_md {
        for file in pointed {
            println!("Pointer added to {}.", file.display());
        }
    } else if !installed.skills.is_empty() {
        println!(
            "To point every agent at the skill, add this line to AGENTS.md or CLAUDE.md (or run \
             writ init with --agents-md):\n  {}",
            skill::POINTER
        );
    }
}

/// Takes the repository back to before `writ init`.
pub fn undo() -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let Some(wired) = wiring::load(&dir)? else {
        bail!("this repo isn't wired for Writ: nothing to undo");
    };
    let record_path = wiring::record_path(&dir)?;
    let entries = wiring::read_file(&dir, &record_path)?;
    if wired.mode == Mode::WholeRepo {
        // The keys `writ init` set: the ones it recorded a previous state for.
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
    let values = |key: &'static str| {
        entries
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v)
    };
    for path in values("skill.created") {
        skill::remove_skill(Path::new(path))?;
    }
    let exclude = wired.common_dir.join("info").join("exclude");
    for line in values("skill.exclude") {
        skill::remove_line(&exclude, line, false)?;
    }
    for file in values("skill.agentsmd") {
        skill::remove_line(Path::new(file), skill::POINTER, false)?;
    }
    for file in values("skill.agentsmdcreated") {
        skill::remove_line(Path::new(file), skill::POINTER, true)?;
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
    for timings in values("skill.timings").filter(|t| Path::new(t).exists()) {
        println!(
            "Kept {timings}: what the agent learned (a new writ init uses it again; delete it if \
             you don't need it)."
        );
    }
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

    #[test]
    fn the_prompt_s_answer_picks_the_agents() {
        let detected: BTreeSet<Agent> = [Agent::Claude].into();
        assert_eq!(picked("\n", &detected), Ok(detected.clone()));
        assert_eq!(picked("0", &detected), Ok(BTreeSet::new()));
        assert_eq!(
            picked(" 2, 4 ", &detected),
            Ok([Agent::Agents, Agent::Cursor].into())
        );
        for (bad, word) in [("5", "5"), ("x", "x"), ("1,,2", ""), ("-1", "-1")] {
            assert_eq!(
                picked(bad, &detected),
                Err(format!("{word:?}: answer with numbers from 1 to 4")),
                "{bad}"
            );
        }
    }
}
