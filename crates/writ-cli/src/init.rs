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
//! With no repo named, at a folder of repositories ([`workspace`](crate::workspace)): each
//! repository one level down is wired the same way under its registry name (`--repo
//! <dir>=<name>`, or confirmed on a terminal), the folder's own repository too when named,
//! with the `writ-workspace` skill at the root instead of one per repository; the workspace's
//! record lets `writ init --undo` there take every repository back.
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
use crate::skill::{self, Agent, Kind};
use crate::wiring::{self, Mode, SessionRef, Setting, Wiring};
use crate::workspace::{self, Member, Workspace};
use crate::{Exit, Paths, display, repos};

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

/// The daemon as git reaches it: `ssh://git@host:port`, or for a local daemon
/// `ssh://git@writ-local` and its socket (an absolute path).
fn base_url(url: &str) -> anyhow::Result<(String, Option<PathBuf>)> {
    match Endpoint::parse(url)? {
        Endpoint::Tcp { host, port } => {
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host
            };
            Ok((format!("ssh://git@{host}:{port}"), None))
        }
        Endpoint::Unix { path } => {
            if !path.is_absolute() {
                bail!("writ init wires a Unix socket by its absolute path, not {url}");
            }
            Ok((
                format!("ssh://git@{}", crate::client::UNIX_HOST_ALIAS),
                Some(path),
            ))
        }
        Endpoint::Https { .. } => bail!(
            "writ init wires the agents' listener (ssh://host:port or unix:<path>), not {url}"
        ),
    }
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
    if crate::prompt::widgets() {
        // The detected ones ticked; space ticks, Enter takes what is ticked (none: none).
        let choices: Vec<crate::prompt::Choice> = Agent::ALL
            .iter()
            .map(|agent| {
                let mark = if detected.contains(agent) {
                    " (detected here)"
                } else {
                    ""
                };
                crate::prompt::Choice::new(agent.label(), format!("{}{mark}", agent.label()))
            })
            .collect();
        let chosen: Vec<usize> = Agent::ALL
            .iter()
            .enumerate()
            .filter(|(_, agent)| detected.contains(agent))
            .map(|(i, _)| i)
            .collect();
        let help = "the agents that get the Writ skill";
        return match crate::prompt::multi("Install the Writ skill for", help, &choices, &chosen)? {
            crate::prompt::Answer::Given(picked) => Ok(Agent::ALL
                .iter()
                .filter(|agent| picked.iter().any(|p| p == agent.label()))
                .copied()
                .collect()),
            crate::prompt::Answer::Cancelled => bail!("stopped: nothing was wired"),
        };
    }
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

/// One repository to wire.
struct RepoWiring<'a> {
    dir: &'a Path,
    repo: &'a RepoName,
    mode: Mode,
    email: Option<&'a Email>,
    lease: Option<&'a TicketId>,
    /// `ssh://git@host:port`.
    base_url: &'a str,
    /// The daemon's Unix socket, for a local endpoint.
    socket: Option<&'a Path>,
    /// The workspace root it is wired from (`writ.workspace`).
    workspace: Option<&'a Path>,
    /// Its `origin` URL, checked ([`check_remotes`]).
    origin: Option<&'a str>,
}

/// Where the session a wiring points at comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFrom {
    /// `--lease`: the repo is pinned to it.
    Pinned,
    /// `WRIT_SESSION`, as every command of the session order takes it.
    Env,
    /// `<home>/sessions/current`.
    Current,
}

/// The session the settings point at, in the order every command takes it: `WRIT_SESSION`,
/// the lease named (`--lease`), `current`. A lease named must be on this host and running.
/// `--lease` and `WRIT_SESSION` naming two leases are refused: one wiring, one session.
fn session_for(
    paths: &Paths,
    lease: Option<&TicketId>,
) -> anyhow::Result<(SessionRef, SessionFrom)> {
    let env = match std::env::var("WRIT_SESSION") {
        Ok(text) if !text.is_empty() => Some(
            text.parse::<TicketId>()
                .map_err(|e| anyhow::anyhow!("WRIT_SESSION {}: {e}", display::clean(&text)))?,
        ),
        _ => None,
    };
    let (id, from, why) = match (env, lease) {
        (Some(env), Some(pinned)) if &env != pinned => bail!(
            "--lease {pinned}, but WRIT_SESSION names lease {env}: one wiring works under one \
             session (unset WRIT_SESSION, or pin that lease) (nothing was wired)"
        ),
        (Some(id), pinned) => {
            let from = if pinned.is_some() {
                SessionFrom::Pinned
            } else {
                SessionFrom::Env
            };
            let why = format!("WRIT_SESSION names lease {id}");
            (id, from, why)
        }
        (None, Some(id)) => (id.clone(), SessionFrom::Pinned, format!("--lease {id}")),
        (None, None) => return Ok((SessionRef::Current, SessionFrom::Current)),
    };
    wiring::check_session(&paths.home, &id)
        .map_err(|e| anyhow::anyhow!("{why}: {e} (nothing was wired)"))?;
    Ok((SessionRef::Lease(id), from))
}

/// Every value of `key` git reads in `dir`, from every scope (the system's, the user's, the
/// repository's, the environment's), in order; none is an empty list.
fn all_values(dir: &Path, key: &str) -> anyhow::Result<Vec<String>> {
    // PATH: the agent host's own git.
    let out = std::process::Command::new("git")
        .args(["config", "--get-all", "-z", key])
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

/// The repository at `dir`'s `origin` URL, once checked to be one `writ init` can send
/// through the daemon whole: one URL, no push URL of its own, no credential in it; and, in
/// wrapper mode, no `writ` remote of the user's (git would add the daemon's URL to it). In
/// whole-repo mode the repo's own `writ` remote is replaced and put back by `--undo`, so only
/// one set elsewhere, or with a push URL, is refused. Each refusal names the command that fixes
/// it.
fn check_remotes(dir: &Path, mode: Mode) -> anyhow::Result<Option<String>> {
    let urls = all_values(dir, "remote.origin.url")?;
    if urls.len() > 1 {
        let shown: Vec<String> = urls.iter().map(|u| wiring::shown_url(u)).collect();
        bail!(
            "`origin` has {} URLs ({}): git pushes to each, and only one would go through the \
             daemon. Keep one: `git remote set-url --delete origin <url>` (nothing was wired)",
            urls.len(),
            shown.join(", ")
        );
    }
    if let Some(push) = all_values(dir, "remote.origin.pushurl")?.first() {
        bail!(
            "`origin` has a push URL of its own ({}): git pushes there, past the daemon. \
             Remove it: `git config --unset-all remote.origin.pushurl` (nothing was wired)",
            wiring::shown_url(push)
        );
    }
    let origin = urls.into_iter().next();
    if let Some(url) = origin.as_deref().filter(|u| wiring::has_credential(u)) {
        bail!(
            "`origin`'s URL holds a credential ({}): writ init would copy it into its settings \
             and print it, and plain git would use it past the daemon. Keep it out of the URL \
             (a credential helper holds it): `git remote set-url origin {}` (nothing was wired)",
            wiring::shown_url(url),
            wiring::without_credential(url)
        );
    }
    let writ_urls = all_values(dir, "remote.writ.url")?;
    let writ_push = all_values(dir, "remote.writ.pushurl")?;
    let theirs = match mode {
        Mode::Wrapper => !writ_urls.is_empty() || !writ_push.is_empty(),
        Mode::WholeRepo => {
            !writ_push.is_empty() || writ_urls.len() > local_values(dir, "remote.writ.url")?.len()
        }
    };
    if theirs {
        let shown = writ_urls
            .iter()
            .chain(&writ_push)
            .next()
            .map_or_else(String::new, |u| wiring::shown_url(u));
        bail!(
            "a `writ` remote is already set ({shown}): writ init adds its own, and git would push \
             to both. Rename or remove yours (`git remote rename writ <name>`) (nothing was \
             wired)"
        );
    }
    Ok(origin)
}

/// `--whole-repo` writes the repository's config: in a linked worktree, that is the config
/// every worktree of the repository reads, the operator's own checkout included. Refused.
fn check_worktree(dir: &Path, mode: Mode) -> anyhow::Result<()> {
    if mode == Mode::WholeRepo && wiring::is_linked_worktree(dir)? {
        bail!(
            "this is a linked worktree (git worktree add): its git config is the one every \
             worktree of the repository reads, your own checkout's included, so --whole-repo \
             would wire them all. Wire it in wrapper mode (writ init without --whole-repo), or \
             give the agent a clone of its own (git clone) (nothing was wired)"
        );
    }
    Ok(())
}

/// `--agents-md` adds a line to `AGENTS.md` and `CLAUDE.md` where they are: each must be a
/// regular file (a folder or a FIFO there is refused before anything is written).
fn check_agents_md(root: &Path) -> anyhow::Result<()> {
    for name in skill::AGENTS_MD {
        let file = root.join(name);
        match std::fs::metadata(&file) {
            Ok(meta) if !meta.is_file() => bail!(
                "{} is there and isn't a regular file: --agents-md adds a line to it (nothing \
                 was wired)",
                file.display()
            ),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", file.display())),
        }
    }
    Ok(())
}

/// What a stop part way through says: the record exists, so `--undo` takes it back.
const PART_WAY: &str =
    "writ init stopped part way (`writ init --undo` here takes back what it did)";

/// The skills folders (absolute) for `agents`, in the root or the user's folders, and
/// `--skill-dir`.
fn skill_folders(
    choice: &SkillChoice,
    agents: &BTreeSet<Agent>,
    root: &Path,
    home: Option<&Path>,
) -> anyhow::Result<Vec<PathBuf>> {
    let base = if choice.global {
        home.context("--global needs HOME")?.to_path_buf()
    } else {
        root.to_path_buf()
    };
    let mut folders: Vec<PathBuf> = skill::folders(agents, choice.global)
        .into_iter()
        .map(|f| base.join(f))
        .collect();
    if let Some(extra) = &choice.skill_dir {
        folders.push(std::path::absolute(extra).context("cannot resolve --skill-dir")?);
    }
    Ok(folders)
}

/// Starts the wiring of the repository at `plan.dir`: its record (`<git common dir>/writ/
/// config`) written with what says what it is, whole (to a file beside it, then renamed), so
/// from here on `writ init --undo` can read it and take back whatever follows, however far
/// that goes.
fn start_record(plan: &RepoWiring<'_>) -> anyhow::Result<Wiring> {
    let dir = plan.dir;
    let final_path = wiring::record_path(dir)?;
    let record_dir = final_path.parent().context("the record has no directory")?;
    std::fs::create_dir_all(record_dir)
        .with_context(|| format!("cannot create {}", record_dir.display()))?;
    let record_path = record_dir.join("config.new");
    match std::fs::remove_file(&record_path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("cannot remove {}", record_path.display()));
        }
        _ => {}
    }
    let wiring = Wiring {
        mode: plan.mode,
        base_url: plan.base_url.to_owned(),
        socket: plan.socket.map(Path::to_path_buf),
        repo: plan.repo.clone(),
        email: plan.email.map(|e| e.as_str().to_owned()),
        common_dir: wiring::common_dir(dir)?,
        origin: plan.origin.map(str::to_owned),
        lease: plan.lease.cloned(),
        workspace: plan.workspace.map(Path::to_path_buf),
    };
    record(dir, &record_path, "writ.mode", plan.mode.as_str())?;
    record(dir, &record_path, "writ.url", plan.base_url)?;
    if let Some(socket) = plan.socket {
        record(
            dir,
            &record_path,
            "writ.socket",
            &socket.display().to_string(),
        )?;
    }
    record(dir, &record_path, "writ.repo", plan.repo.as_str())?;
    if let Some(email) = &wiring.email {
        record(dir, &record_path, "writ.email", email)?;
    }
    if let Some(origin) = &wiring.origin {
        record(dir, &record_path, "writ.origin", origin)?;
    }
    if let Some(lease) = &wiring.lease {
        record(dir, &record_path, "writ.lease", lease.as_str())?;
    }
    if let Some(root) = &wiring.workspace {
        record(
            dir,
            &record_path,
            "writ.workspace",
            &root.display().to_string(),
        )?;
    }
    std::fs::rename(&record_path, &final_path)
        .with_context(|| format!("cannot write {}", final_path.display()))?;
    Ok(wiring)
}

/// The settings of the repository whose record [`start_record`] wrote, computed once (the
/// config and the summary come from them); in whole-repo mode, each written in its config
/// after the values it replaces are recorded (`--undo` puts them back).
fn apply_settings(
    paths: &Paths,
    dir: &Path,
    wiring: &Wiring,
    session: &SessionRef,
) -> anyhow::Result<Vec<Setting>> {
    let settings = wiring::settings_with(paths, wiring, session)?;
    if wiring.mode == Mode::WholeRepo {
        let record_path = wiring.common_dir.join("writ").join("config");
        for (key, value) in &settings {
            let before = local_values(dir, key)?;
            if before.is_empty() {
                record(dir, &record_path, &format!("previous.{key}.absent"), "true")?;
            }
            for value in before {
                record(dir, &record_path, &format!("previous.{key}.value"), &value)?;
            }
            wiring::git(dir, &["config", "--local", "--replace-all", key, value])?;
        }
    }
    Ok(settings)
}

/// Records a line [`skill::add_line`] added to an `exclude` file, and how, for `--undo`.
fn record_excluded(
    dir: &Path,
    record_path: &Path,
    line: &str,
    added: skill::Added,
) -> anyhow::Result<()> {
    if added.created {
        record(dir, record_path, "skill.excludecreated", "true")?;
    }
    if added.joined {
        record(dir, record_path, "skill.excludejoined", line)?;
    }
    record(dir, record_path, "skill.exclude", line)
}

/// Records one step of a skill installation, in the record at `record_path`, as it is done.
fn record_step(dir: &Path, record_path: &Path, step: skill::Step<'_>) -> anyhow::Result<()> {
    let path = |p: &Path| p.display().to_string();
    match step {
        skill::Step::CreatedDir(created) => {
            record(dir, record_path, "skill.createddir", &path(created))
        }
        // Created: `--undo` removes it. Written over (Writ's already, a global skill another
        // repository's `writ init` made): `--undo` leaves it in the repository, and outside
        // it removes it once no other wired repository's record names it.
        skill::Step::Skill(skill, new) => {
            let key = if new {
                "skill.created"
            } else {
                "skill.written"
            };
            record(dir, record_path, key, &path(skill))
        }
        skill::Step::Excluded(line, added) => record_excluded(dir, record_path, line, added),
        skill::Step::Timings(timings) => record(dir, record_path, "skill.timings", &path(timings)),
    }
}

pub fn init(paths: &Paths, request: &Init<'_>) -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let (base_url, socket) = base_url(request.url)?;
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
    check_worktree(&dir, request.mode)?;
    let origin = check_remotes(&dir, request.mode)?;
    let agents = choose_agents(&request.skill, &root, home.as_deref())?;
    let (session, from) = session_for(paths, request.lease)?;
    let folders = skill_folders(&request.skill, &agents, &root, home.as_deref())?;
    let plan = skill::Plan {
        folders,
        root: root.clone(),
        kind: Kind::Repo,
        repos: String::new(),
    };
    skill::check(&plan)?;
    if request.skill.agents_md {
        check_agents_md(&root)?;
    }

    let wiring = start_record(&RepoWiring {
        dir: &dir,
        repo: request.repo,
        mode: request.mode,
        email: request.email,
        lease: request.lease,
        base_url: &base_url,
        socket: socket.as_deref(),
        workspace: None,
        origin: origin.as_deref(),
    })?;
    // Listed as soon as there is a record, so the uninstall's `--undo --all` finds it.
    repos::add(&paths.home, repos::Kind::Repo, &root).context(PART_WAY)?;
    let settings = apply_settings(paths, &dir, &wiring, &session).context(PART_WAY)?;
    let exclude = wiring.common_dir.join("info").join("exclude");
    let installed = skill::install(&plan, Some(&exclude), &mut |step| {
        record_step(&dir, &record_path, step)
    })
    .context(PART_WAY)?;
    let pointed = if request.skill.agents_md {
        agents_md(&dir, &record_path, &root, Kind::Repo).context(PART_WAY)?
    } else {
        Vec::new()
    };
    print_summary(
        &wiring,
        &settings,
        (&session, from),
        &installed,
        &pointed,
        request.skill.agents_md,
    );
    Ok(Exit::Ok)
}

/// `--agents-md`: the pointer line in each of `AGENTS.md` and `CLAUDE.md` in `root` (a new
/// `AGENTS.md` when it has neither), recorded for `--undo` as each is added.
fn agents_md(
    dir: &Path,
    record_path: &Path,
    root: &Path,
    kind: Kind,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = skill::AGENTS_MD
        .iter()
        .map(|f| root.join(f))
        .filter(|f| f.exists())
        .collect();
    if files.is_empty() {
        files.push(root.join("AGENTS.md"));
    }
    for file in &files {
        // A line an earlier version added: today's in its place, its record standing.
        for former in kind.former_pointers() {
            skill::replace_line(file, former, kind.pointer())?;
        }
        if let Some(added) = skill::add_line(file, kind.pointer())? {
            let shown = file.display().to_string();
            if added.joined {
                record(dir, record_path, "skill.agentsmdjoined", &shown)?;
            }
            let key = if added.created {
                "skill.agentsmdcreated"
            } else {
                "skill.agentsmd"
            };
            record(dir, record_path, key, &shown)?;
        }
    }
    Ok(files)
}

/// What `writ init` at a workspace root is asked.
pub struct WorkspaceInit<'a> {
    /// The daemon's agents listener (`WRIT_URL`).
    pub url: &'a str,
    pub mode: Mode,
    pub email: Option<&'a Email>,
    pub lease: Option<&'a TicketId>,
    pub skill: SkillChoice,
    /// `--repo <dir>=<name>` (`None`: left out).
    pub answers: &'a [(String, Option<RepoName>)],
}

/// A repository found in a workspace, before its name is settled.
struct Found {
    dir: String,
    /// The name it gets when nobody says otherwise (none for the root's own repository: it
    /// is left out unless named).
    default: Option<RepoName>,
    /// Where the default comes from, for the prompt.
    origin: Option<String>,
}

/// The repositories of the workspace at `root`, named: from `--repo`, else asked on a
/// terminal (Enter takes the default, `-` leaves one out). Without a terminal, a child
/// repository no `--repo` answers for is refused, naming each.
fn names(found: &[Found], answers: &[(String, Option<RepoName>)]) -> anyhow::Result<Vec<Member>> {
    for (dir, _) in answers {
        if !found.iter().any(|f| &f.dir == dir) {
            bail!(
                "--repo {}: not a repository right under this folder (found: {})",
                display::clean(dir),
                found
                    .iter()
                    .map(|f| f.dir.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if answers.iter().filter(|(d, _)| d == dir).count() > 1 {
            bail!("--repo {} is given twice", display::clean(dir));
        }
    }
    let unanswered: Vec<&Found> = found
        .iter()
        .filter(|f| !answers.iter().any(|(d, _)| *d == f.dir))
        .collect();
    let terminal = std::io::stdin().is_terminal();
    let must_ask: Vec<&&Found> = unanswered.iter().filter(|f| f.dir != ".").collect();
    if !terminal && !must_ask.is_empty() {
        let listed: Vec<String> = must_ask
            .iter()
            .map(|f| match &f.default {
                Some(name) => format!("{} (by default {name})", display::clean(&f.dir)),
                None => format!("{} (no default)", display::clean(&f.dir)),
            })
            .collect();
        bail!(
            "no terminal to confirm the registry names: pass --repo <dir>=<name> (or <dir>=- \
             to leave it out) for each of: {} (nothing was wired)",
            listed.join(", ")
        );
    }
    let mut asked: Vec<(String, Option<RepoName>)> = Vec::new();
    if terminal && !unanswered.is_empty() {
        println!(
            "Registry names for this workspace's repositories (Enter: the name in brackets; \
             -: leave it out):"
        );
        for f in &unanswered {
            asked.push((f.dir.clone(), ask_name(f)?));
        }
    }
    let mut members: Vec<Member> = Vec::new();
    for f in found {
        let name = answers
            .iter()
            .chain(&asked)
            .find(|(d, _)| *d == f.dir)
            .map_or_else(
                || f.default.clone().filter(|_| f.dir != "."),
                |(_, n)| n.clone(),
            );
        if let Some(repo) = name {
            if let Some(other) = members.iter().find(|m| m.repo == repo) {
                bail!(
                    "{} and {} are both named {repo}: one registry name per repository",
                    display::clean(&other.dir),
                    display::clean(&f.dir)
                );
            }
            members.push(Member {
                dir: f.dir.clone(),
                repo,
            });
        }
    }
    if members.is_empty() {
        bail!("every repository was left out: nothing to wire");
    }
    Ok(members)
}

/// One repository's name, asked on the terminal.
fn ask_name(found: &Found) -> anyhow::Result<Option<RepoName>> {
    let what = shown_dir(&found.dir);
    let default = match &found.default {
        Some(name) if found.dir != "." => name.to_string(),
        _ => "-".to_owned(),
    };
    let from = found.origin.as_deref().map_or_else(String::new, |o| {
        format!(" (origin {})", wiring::shown_url(o))
    });
    let line = if crate::prompt::widgets() {
        let check = |typed: &str| match typed.trim() {
            "" | "-" => Ok(()),
            name => name
                .parse::<RepoName>()
                .map(|_| ())
                .map_err(|e| e.to_string()),
        };
        let help = format!("its registry name; Enter: {default}; -: leave it out");
        match crate::prompt::text(&format!("{what}{from}"), &help, Some(&default), check)? {
            crate::prompt::Answer::Given(typed) => typed,
            crate::prompt::Answer::Cancelled => bail!("stopped: nothing was wired"),
        }
    } else {
        print!("  {what}{from} [{default}]: ");
        std::io::Write::flush(&mut std::io::stdout()).context("cannot write to the terminal")?;
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
            .context("cannot read the answer")?;
        line
    };
    let answer = line.trim();
    let answer = if answer.is_empty() {
        default.as_str()
    } else {
        answer
    };
    if answer == "-" {
        return Ok(None);
    }
    answer
        .parse()
        .map(Some)
        .map_err(|e: writ_core::names::NameError| anyhow::anyhow!(display::clean(&e.to_string())))
}

/// The repositories right under the workspace at `root` that are wired on their own, and the
/// ones set aside with why: a submodule of the root's repository, or a worktree of a
/// repository already found (its git directory, and so its record, is the other's).
fn workspace_dirs(
    root: &Path,
    root_common: Option<&Path>,
) -> anyhow::Result<(Vec<String>, Vec<workspace::Aside>)> {
    let (children, mut aside) = workspace::children(root)?;
    let mut seen: Vec<PathBuf> = root_common
        .and_then(|c| std::fs::canonicalize(c).ok())
        .into_iter()
        .collect();
    let root_common = seen.first().cloned();
    let mut found: Vec<(String, PathBuf, bool)> = Vec::new();
    for child in children {
        let path = root.join(&child);
        let common = wiring::common_dir(&path)?;
        let common = std::fs::canonicalize(&common)
            .with_context(|| format!("cannot resolve {}", common.display()))?;
        found.push((child, common, wiring::is_linked_worktree(&path)?));
    }
    // The repository's own checkout before its linked worktrees, then by name.
    found.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    let mut dirs: Vec<String> = Vec::new();
    for (child, common, _) in found {
        if seen.contains(&common) {
            aside.push((
                display::clean(&child),
                "a worktree of a repository already here (one git directory, one wiring)",
            ));
        } else if root_common
            .as_ref()
            .is_some_and(|rc| common.starts_with(rc))
        {
            // A submodule of the root's repository: left to the backlog.
            aside.push((
                display::clean(&child),
                "a submodule of this folder's repository: submodules aren't wired yet",
            ));
        } else {
            seen.push(common);
            dirs.push(child);
        }
    }
    dirs.sort();
    aside.sort();
    Ok((dirs, aside))
}

/// `writ init` with no repo named, at a folder of repositories: every child repository one
/// level down wired (and the folder's own, when named), the `writ-workspace` skill installed
/// at the root, the workspace recorded in `<root>/.writ-workspace`.
pub fn init_workspace(paths: &Paths, request: &WorkspaceInit<'_>) -> anyhow::Result<Exit> {
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    let root = std::path::absolute(&cwd).context("cannot resolve the current directory")?;
    let (base_url, socket) = base_url(request.url)?;
    if let Some(existing) = workspace::load(&root)? {
        bail!(
            "this folder is already a Writ workspace ({} repositories): `writ init --undo` first",
            existing.members.len()
        );
    }
    if request.skill.global {
        bail!(
            "--global at a workspace: its skill lists this folder's repositories, and one skill \
             in your home can't list two workspaces'. Install it here (writ init without \
             --global) (nothing was wired)"
        );
    }
    let root_is_repo = workspace::is_top_level(&root);
    let root_common = if root_is_repo {
        Some(wiring::common_dir(&root)?)
    } else {
        None
    };
    let (mut dirs, aside) = workspace_dirs(&root, root_common.as_deref())?;
    if dirs.is_empty() {
        bail!(
            "writ init needs the repo's registry name (`writ init <repo>`), or a folder whose \
             repositories are one level down (none in {})",
            root.display()
        );
    }
    if root_is_repo {
        dirs.insert(0, ".".to_owned());
    }
    let mut found = Vec::new();
    for dir in &dirs {
        let path = if dir == "." {
            root.clone()
        } else {
            root.join(dir)
        };
        if let Some(wired) = wiring::load(&path)? {
            bail!(
                "{} is already wired for Writ ({} mode, repo {}): `writ init --undo` in it first \
                 (nothing was wired)",
                display::clean(dir),
                wired.mode.as_str(),
                wired.repo
            );
        }
        let origin = all_values(&path, "remote.origin.url")?.into_iter().next();
        let folder = if dir == "." {
            root.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            dir.clone()
        };
        found.push(Found {
            dir: dir.clone(),
            default: workspace::default_name(origin.as_deref(), &folder),
            origin,
        });
    }
    // Everything that can refuse comes first: nothing is wired when it can't all be done.
    let members = names(&found, request.answers)?;
    let workspace = Workspace {
        root: root.clone(),
        members: members.clone(),
        lease: request.lease.cloned(),
        entries: Vec::new(),
    };
    let mut origins: Vec<Option<String>> = Vec::new();
    for member in &members {
        let path = workspace.path(member);
        let checked = check_worktree(&path, request.mode)
            .and_then(|()| check_remotes(&path, request.mode))
            .with_context(|| shown_dir(&member.dir))?;
        origins.push(checked);
    }
    let home = home_dir();
    let agents = choose_agents(&request.skill, &root, home.as_deref())?;
    let (session, from) = session_for(paths, request.lease)?;
    let folders = skill_folders(&request.skill, &agents, &root, home.as_deref())?;
    let plan = skill::Plan {
        folders,
        root: root.clone(),
        kind: Kind::Workspace,
        repos: skill_repos(&members),
    };
    skill::check(&plan)?;
    if request.skill.agents_md {
        check_agents_md(&root)?;
    }

    let record_path = workspace::record_path(&root);
    // The record first, then each repository named in it before it is wired: a run stopped
    // half way is taken back by `writ init --undo` here.
    record(&root, &record_path, "writ.mode", request.mode.as_str())?;
    // Listed as soon as there is a record, so the uninstall's `--undo --all` finds it.
    repos::add(&paths.home, repos::Kind::Workspace, &root).context(PART_WAY)?;
    let exclude = root_common
        .as_ref()
        .map(|common| common.join("info").join("exclude"));
    let wired = wire_members(
        paths,
        &workspace,
        &origins,
        &MemberWiring {
            request,
            base_url: &base_url,
            socket: socket.as_deref(),
            exclude: exclude.as_deref(),
            session: &session,
        },
    )
    .context(PART_WAY)?;
    let installed = skill::install(&plan, exclude.as_deref(), &mut |step| {
        record_step(&root, &record_path, step)
    })
    .context(PART_WAY)?;
    let pointed = if request.skill.agents_md {
        agents_md(&root, &record_path, &root, Kind::Workspace).context(PART_WAY)?
    } else {
        Vec::new()
    };
    print_workspace_summary(&WorkspaceSummary {
        request,
        root: &root,
        found: &found,
        members: &members,
        aside: &aside,
        wired: &wired,
        session: (&session, from),
        installed: &installed,
        pointed: &pointed,
    });
    Ok(Exit::Ok)
}

/// What every repository of a workspace is wired with.
struct MemberWiring<'a> {
    request: &'a WorkspaceInit<'a>,
    base_url: &'a str,
    socket: Option<&'a Path>,
    /// The root repository's `.git/info/exclude`, when the root is one.
    exclude: Option<&'a Path>,
    session: &'a SessionRef,
}

/// Wires each repository of `workspace` (its `origins` checked), each named in the
/// workspace's record before it is wired; the record itself excluded from the root's git
/// first.
fn wire_members(
    paths: &Paths,
    workspace: &Workspace,
    origins: &[Option<String>],
    with: &MemberWiring<'_>,
) -> anyhow::Result<Vec<(Wiring, Vec<Setting>)>> {
    let root = &workspace.root;
    let record_path = workspace::record_path(root);
    if let Some(lease) = with.request.lease {
        record(root, &record_path, "writ.lease", lease.as_str())?;
    }
    if let Some(exclude) = with.exclude {
        let line = format!("/{}", workspace::RECORD);
        if let Some(added) = skill::add_line(exclude, &line)? {
            record_excluded(root, &record_path, &line, added)?;
        }
    }
    let mut wired = Vec::new();
    for (member, origin) in workspace.members.iter().zip(origins) {
        record(
            root,
            &record_path,
            &format!("member.{}.repo", member.dir),
            member.repo.as_str(),
        )?;
        let dir = workspace.path(member);
        let wiring = start_record(&RepoWiring {
            dir: &dir,
            repo: &member.repo,
            mode: with.request.mode,
            email: with.request.email,
            lease: with.request.lease,
            base_url: with.base_url,
            socket: with.socket,
            workspace: Some(root),
            origin: origin.as_deref(),
        })
        .and_then(|wiring| {
            let settings = apply_settings(paths, &dir, &wiring, with.session)?;
            Ok((wiring, settings))
        })
        .with_context(|| format!("wiring {}", display::clean(&member.dir)))?;
        wired.push(wiring);
    }
    Ok(wired)
}

/// What the summary of a workspace's wiring shows.
struct WorkspaceSummary<'a> {
    request: &'a WorkspaceInit<'a>,
    root: &'a Path,
    found: &'a [Found],
    members: &'a [Member],
    aside: &'a [workspace::Aside],
    wired: &'a [(Wiring, Vec<Setting>)],
    session: (&'a SessionRef, SessionFrom),
    installed: &'a skill::Installed,
    pointed: &'a [PathBuf],
}

fn print_workspace_summary(summary: &WorkspaceSummary<'_>) {
    let WorkspaceSummary {
        request,
        root,
        found,
        members,
        aside,
        wired,
        session,
        installed,
        pointed,
    } = *summary;
    let mode = match request.mode {
        Mode::Wrapper => "wrapper mode: `writ git -C <dir> …`; plain git keeps your own config",
        Mode::WholeRepo => "whole repo: plain git in each is the agent's",
    };
    println!(
        "Workspace wired for Writ at {} ({mode}). One agent at this folder works on:",
        root.display()
    );
    for (member, (wiring, _)) in members.iter().zip(wired) {
        let origin = match &wiring.origin {
            Some(origin) => format!(", origin {} through the daemon", wiring::shown_url(origin)),
            None => ", no origin: push to the `writ` remote".to_owned(),
        };
        println!("  {}  repo {}{origin}", shown_dir(&member.dir), member.repo);
    }
    for f in found {
        if !members.iter().any(|m| m.dir == f.dir) {
            println!("Left out: {}.", shown_dir(&f.dir));
        }
    }
    for (dir, why) in aside {
        println!("Not wired: {dir} ({why}).");
    }
    let email = wired
        .first()
        .and_then(|(_, settings)| settings.iter().find(|(k, _)| k == "user.email"));
    match (request.email, email) {
        (Some(email), _) => println!(
            "Committer email: {} (--email; the lease must allow it).",
            display::clean(email.as_str())
        ),
        (None, Some((_, email))) => {
            println!("Committer email: {} (the lease's).", display::clean(email))
        }
        (None, None) => println!(
            "Committer email: the lease's, once one is granted (`writ policy <repo>` lists the \
             emails a ticket may ask for)."
        ),
    }
    print_session(session, request.mode);
    println!("One ticket names every repository a task touches.");
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
            "Timings ({how}): {} (`writ close` here records each run).",
            timings.display()
        );
    }
    if !installed.excluded.is_empty() {
        println!(
            "Excluded from this folder's git (.git/info/exclude): {}.",
            installed.excluded.join(", ")
        );
    }
    for file in pointed {
        println!("Pointer added to {}.", file.display());
    }
    if !request.skill.agents_md && !installed.skills.is_empty() {
        println!(
            "To point every agent at the skill, add this line to AGENTS.md or CLAUDE.md (or run \
             writ init with --agents-md):\n  {}",
            skill::WORKSPACE_POINTER
        );
    }
    println!(
        "Recorded in {}: `writ init --undo` here takes every repository back.",
        workspace::record_path(root).display()
    );
}

/// The summary's line on the session the wiring works under.
fn print_session(session: (&SessionRef, SessionFrom), mode: Mode) {
    match (session, mode) {
        ((SessionRef::Lease(id), SessionFrom::Pinned), _) => println!(
            "Pinned to lease {id}: commands here use its session, never `current` \
             (WRIT_SESSION still comes first)."
        ),
        ((SessionRef::Lease(id), _), Mode::WholeRepo) => println!(
            "Session: lease {id}, from WRIT_SESSION: this clone's git config names its session, \
             never `current`."
        ),
        ((SessionRef::Lease(id), _), Mode::Wrapper) => println!(
            "Session: WRIT_SESSION when it is set (now lease {id}), otherwise the current lease \
             (<home>/sessions/current)."
        ),
        ((SessionRef::Current, _), Mode::WholeRepo) => println!(
            "Session: the current lease (<home>/sessions/current), whichever it is when git \
             runs: this clone's git config names `current` (WRIT_SESSION set later is checked \
             against it by writ-sign)."
        ),
        ((SessionRef::Current, _), Mode::Wrapper) => println!(
            "Session: WRIT_SESSION when it is set, otherwise the current lease \
             (<home>/sessions/current)."
        ),
    }
}

/// A workspace repository's folder, for the terminal.
fn shown_dir(dir: &str) -> String {
    if dir == "." {
        ". (this folder's own repository)".to_owned()
    } else {
        display::clean(dir)
    }
}

/// The workspace's repositories as the skill lists them.
fn skill_repos(members: &[Member]) -> String {
    members
        .iter()
        .map(|m| {
            if m.dir == "." {
                format!("- `.` (this folder's own repository): repo `{}`", m.repo)
            } else {
                format!("- `{}`: repo `{}`", m.dir.replace('`', "'"), m.repo)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_summary(
    wiring: &Wiring,
    settings: &[Setting],
    session: (&SessionRef, SessionFrom),
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
            wiring::shown_url(origin)
        ),
        (Some(origin), Mode::WholeRepo) => println!(
            "Remote `origin` ({}): in this clone every push and fetch to it goes through the \
             daemon, plain git too (`writ init --undo` takes that back).",
            wiring::shown_url(origin)
        ),
        (None, _) => println!("No `origin` remote: push to the `writ` remote."),
    }
    let has_lease = settings
        .iter()
        .find(|(k, _)| k == "writ.session")
        .and_then(|(_, v)| wiring::lease_id(std::path::Path::new(v)))
        .is_some();
    match (email, &wiring.email, has_lease) {
        (Some((_, email)), Some(_), _) => println!(
            "Committer email: {} (--email; the lease must allow it).",
            crate::display::clean(email)
        ),
        (Some((_, email)), None, _) => {
            println!(
                "Committer email: {} (the lease's).",
                crate::display::clean(email)
            )
        }
        // Before any lease, the email comes from the lease once it is granted: an --email
        // here would override it with one the lease may not allow.
        (None, _, false) => println!(
            "Committer email: the lease's, once one is granted (`writ policy` lists the emails \
             a ticket may ask for)."
        ),
        (None, _, true) => {
            println!("No committer email: the lease allows none or several; use --email.")
        }
    }
    if let Some((_, name)) = settings.iter().find(|(k, _)| k == "user.name") {
        println!(
            "Committer name: {} (the lease's).",
            crate::display::clean(name)
        );
    }
    print_session(session, wiring.mode);
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

/// What undoing a record left alone, to say so.
#[derive(Debug, Default)]
struct Undone {
    /// The timings files kept (what the agent learned).
    timings: Vec<String>,
    /// What the record named that was left as it is, with why.
    left: Vec<String>,
}

/// Why a skill file outside the root being taken back stays: another entry of the host's
/// list of wired repositories (`<home>/repos`) whose record names it (a global skill is
/// shared), or the list can't be read; none when nothing else uses it.
fn used_elsewhere(paths: &Paths, own: &Own<'_>, skill: &str) -> Option<String> {
    let listing = match repos::read(&paths.home) {
        Ok(listing) => listing,
        Err(e) => {
            return Some(format!(
                "the list of wired repositories can't be read ({})",
                display::clean_lines(&format!("{e:#}"))
            ));
        }
    };
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    let own_root = canonical(own.root);
    let own_common = own.common_dir.and_then(canonical);
    for entry in &listing.entries {
        let entries = match entry.kind {
            repos::Kind::Repo => {
                let Ok(common) = wiring::common_dir(&entry.path) else {
                    continue;
                };
                // The same record, reached from another worktree of the repository.
                if own_common.is_some() && canonical(&common) == own_common {
                    continue;
                }
                wiring::record_entries(&common).ok().flatten()
            }
            repos::Kind::Workspace => {
                if canonical(&entry.path) == own_root {
                    continue;
                }
                workspace::load(&entry.path)
                    .ok()
                    .flatten()
                    .map(|w| w.entries)
            }
        };
        let names = entries.is_some_and(|entries| {
            entries
                .iter()
                .any(|(k, v)| (k == "skill.created" || k == "skill.written") && v == skill)
        });
        if names {
            return Some(format!(
                "another wired repository uses it ({})",
                display::clean(&entry.path.display().to_string())
            ));
        }
    }
    None
}

/// The record an undo takes back: its root, and a repository's git directory (a workspace
/// has none of its own).
struct Own<'a> {
    root: &'a Path,
    common_dir: Option<&'a Path>,
}

/// Takes back what the record's `skill.*` entries say `writ init` installed in or for `root`:
/// the skill files (Writ's only: in the root those it created, outside it, a global skill,
/// those it created or wrote once no other wired repository's record names them), the
/// folders made for them (when empty), the lines added to `exclude` (the repository's own
/// `.git/info/exclude`, never a file the record names) and the pointer lines (in `AGENTS.md`
/// and `CLAUDE.md` only), each line's bytes taken out as they were put in.
fn undo_skill(
    paths: &Paths,
    own: &Own<'_>,
    entries: &[(String, String)],
    exclude: Option<&Path>,
    kind: Kind,
) -> anyhow::Result<Undone> {
    let mut undone = Undone::default();
    let values = |key: &'static str| -> Vec<&str> {
        entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    };
    let inside = |path: &str| Path::new(path).starts_with(own.root);
    let mut removable: Vec<&str> = values("skill.created");
    removable.retain(|path| {
        if inside(path) {
            return true;
        }
        match used_elsewhere(paths, own, path) {
            Some(why) => {
                undone.left.push(format!("{}: {why}", display::clean(path)));
                false
            }
            None => true,
        }
    });
    for path in values("skill.written") {
        if !inside(path) && !removable.contains(&path) && used_elsewhere(paths, own, path).is_none()
        {
            removable.push(path);
        }
    }
    for path in &removable {
        match skill::remove_skill(Path::new(path))? {
            None => {}
            Some(skill::Kept::NotASkillPath) => undone.left.push(format!(
                "{}: not a Writ skill file's path, left as it is",
                display::clean(path)
            )),
            Some(skill::Kept::NotWrits) => undone.left.push(format!(
                "{}: no longer Writ's skill, left as it is",
                display::clean(path)
            )),
        }
    }
    skill::remove_created_dirs(&values("skill.createddir"), &removable);
    if let Some(exclude) = exclude {
        let created = values("skill.excludecreated").contains(&"true");
        let joined = values("skill.excludejoined");
        // The last added first: a line break added before the first comes off last.
        for line in values("skill.exclude").into_iter().rev() {
            let added = skill::Added {
                created,
                joined: joined.contains(&line),
            };
            skill::remove_line(exclude, line, added)?;
        }
    }
    let pointer_file = |file: &str| {
        Path::new(file)
            .file_name()
            .is_some_and(|n| skill::AGENTS_MD.iter().any(|a| n == *a))
    };
    let joined = values("skill.agentsmdjoined");
    for (key, created) in [("skill.agentsmd", false), ("skill.agentsmdcreated", true)] {
        for file in values(key) {
            if pointer_file(file) {
                let added = skill::Added {
                    created,
                    joined: joined.contains(&file),
                };
                // Today's line, or one an earlier version added (M7.9.7).
                for line in
                    std::iter::once(kind.pointer()).chain(kind.former_pointers().iter().copied())
                {
                    skill::remove_line(Path::new(file), line, added)?;
                }
            } else {
                undone.left.push(format!(
                    "{}: not an AGENTS.md or CLAUDE.md, left as it is",
                    display::clean(file)
                ));
            }
        }
    }
    undone.timings = values("skill.timings")
        .into_iter()
        .filter(|t| Path::new(t).exists())
        .map(str::to_owned)
        .collect();
    Ok(undone)
}

/// Takes the repository at `dir`, wired as `wired`, back to before `writ init`.
fn undo_repo(paths: &Paths, dir: &Path, wired: &Wiring) -> anyhow::Result<Undone> {
    let record_path = wired.common_dir.join("writ").join("config");
    let entries = wiring::record_entries(&wired.common_dir)?.unwrap_or_default();
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
                .current_dir(dir)
                .output()
                .context("cannot run git")?;
            // Exit 5: the key wasn't there any more. Anything else (a locked config) stops
            // here, before the previous values are added on top of the current ones.
            if !matches!(unset.status.code(), Some(0 | 5)) {
                bail!(
                    "git config --unset-all {key} failed: {}",
                    display::clean_lines(String::from_utf8_lossy(&unset.stderr).trim())
                );
            }
            let previous = format!("previous.{key}.value");
            for (_, value) in entries.iter().filter(|(k, _)| *k == previous) {
                wiring::git(dir, &["config", "--local", "--add", key, value])?;
            }
            remove_section_if_empty(dir, key)?;
        }
    }
    let exclude = wired.common_dir.join("info").join("exclude");
    let own = Own {
        root: dir,
        common_dir: Some(&wired.common_dir),
    };
    let undone = undo_skill(paths, &own, &entries, Some(&exclude), Kind::Repo)?;
    let record_dir = record_path
        .parent()
        .context("the record has no directory")?;
    std::fs::remove_dir_all(record_dir)
        .with_context(|| format!("cannot remove {}", record_dir.display()))?;
    Ok(undone)
}

/// `writ skill update`: every skill file the record here names (the workspace's at its root,
/// the repository's in it) rewritten from the skill built into this `writ`, its timings file
/// and a workspace's repositories filled in again; a file that isn't Writ's skill any more, or
/// isn't at a skill's path, left as it is and said.
pub fn update_skills() -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    update_skills_in(&dir)
}

/// `writ skill update --all`: the skill rewritten in each repository and workspace on the
/// list, as `writ skill update` there would; one that can't be is named with why.
pub fn update_skills_all(paths: &Paths) -> anyhow::Result<Exit> {
    let listing = repos::read(&paths.home)?;
    let mut exit = Exit::Ok;
    for entry in &listing.entries {
        let shown = display::clean(&entry.path.display().to_string());
        println!("{} {shown}:", entry.kind.as_str());
        if let Err(e) = update_skills_in(&entry.path) {
            println!("  not updated: {}", display::clean_lines(&format!("{e:#}")));
            exit = Exit::Error;
        }
    }
    print_skipped(&listing);
    if listing.entries.is_empty() {
        println!("Nothing wired by writ init on this host's list.");
    }
    Ok(exit)
}

fn update_skills_in(dir: &Path) -> anyhow::Result<Exit> {
    let dir = dir.to_path_buf();
    let (root, entries, kind, repos) = if let Some(workspace) = workspace::load(&dir)? {
        let repos = skill_repos(&workspace.members);
        (workspace.root, workspace.entries, Kind::Workspace, repos)
    } else {
        let Some(wired) = wiring::load(&dir)? else {
            bail!("this repo isn't wired for Writ: `writ init` wires it and installs the skill");
        };
        if let Some(found) = workspace::find(&dir) {
            bail!(
                "this repository was wired with the workspace at {}: run `writ skill update` \
                 there (the skill is the workspace's)",
                found.root.display()
            );
        }
        let entries = wiring::record_entries(&wired.common_dir)?.unwrap_or_default();
        (top_level(&dir)?, entries, Kind::Repo, String::new())
    };
    let mut skills: Vec<&str> = Vec::new();
    for (key, value) in &entries {
        if (key == "skill.created" || key == "skill.written") && !skills.contains(&value.as_str()) {
            skills.push(value);
        }
    }
    let timings = entries.iter().find(|(k, _)| k == "skill.timings");
    let (Some((_, timings)), false) = (timings, skills.is_empty()) else {
        println!("No skill installed here (writ init --agents none): nothing to update.");
        return Ok(Exit::Ok);
    };
    let text = skill::text(kind, &root, Path::new(timings), &repos);
    println!("The {} skill, from this writ:", kind.name());
    for path in skills {
        let shown = Path::new(path)
            .strip_prefix(&root)
            .map_or_else(|_| path.to_owned(), |p| p.display().to_string());
        let shown = display::clean(&shown);
        match skill::update(Path::new(path), kind, &text)? {
            skill::Updated::Written => println!("  {shown}: updated"),
            skill::Updated::Current => println!("  {shown}: up to date"),
            skill::Updated::Gone => {
                println!("  {shown}: not there any more (writ init puts it back after --undo)")
            }
            skill::Updated::Kept(skill::Kept::NotASkillPath) => {
                println!("  {shown}: not a Writ skill file's path, left as it is");
            }
            skill::Updated::Kept(skill::Kept::NotWrits) => {
                println!("  {shown}: no longer Writ's skill, left as it is");
            }
        }
    }
    Ok(Exit::Ok)
}

/// Prints what an undo kept.
fn print_kept(undone: &Undone) {
    for left in &undone.left {
        println!("Kept {left}.");
    }
    for timings in &undone.timings {
        println!(
            "Kept {timings}: what the agent learned (a new writ init uses it again; delete it if \
             you don't need it)."
        );
    }
}

/// Whether the repository wired as `wired` was wired from the workspace at `root`.
fn from_workspace(wired: &Wiring, root: &Path) -> bool {
    match (&wired.workspace, std::fs::canonicalize(root)) {
        (Some(from), Ok(root)) => std::fs::canonicalize(from).is_ok_and(|f| f == root),
        _ => false,
    }
}

/// `writ init --undo`: the workspace recorded here (every repository, then the root), or the
/// repository here.
pub fn undo(paths: &Paths) -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    undo_in(paths, &dir)
}

/// `writ init --undo` in `dir`: its line taken off the list of wired repositories once done.
fn undo_in(paths: &Paths, dir: &Path) -> anyhow::Result<Exit> {
    if let Some(workspace) = workspace::load(dir)? {
        let exit = undo_workspace(paths, &workspace)?;
        repos::remove(&paths.home, &workspace.root)?;
        return Ok(exit);
    }
    let dir = &top_level(dir)?;
    let Some(wired) = wiring::load(dir)? else {
        bail!("this repo isn't wired for Writ: nothing to undo");
    };
    if let Some(found) = workspace::find(dir) {
        bail!(
            "this repository was wired with the workspace at {}: run `writ init --undo` there (it \
             takes every repository back)",
            found.root.display()
        );
    }
    let undone = undo_repo(paths, dir, &wired)?;
    println!(
        "Writ wiring removed ({} mode): the repo's git config is as it was before writ init.",
        wired.mode.as_str()
    );
    print_kept(&undone);
    repos::remove(&paths.home, dir)?;
    Ok(Exit::Ok)
}

/// `writ init --list`: the repositories and workspaces `writ init` wired on this host, each
/// checked, and the lines skipped with why.
pub fn list(paths: &Paths) -> anyhow::Result<Exit> {
    let listing = repos::read(&paths.home)?;
    for entry in &listing.entries {
        let shown = display::clean(&entry.path.display().to_string());
        let what = match entry.kind {
            repos::Kind::Repo => wiring::load(&entry.path)
                .ok()
                .flatten()
                .map(|w| format!("{} mode", w.mode.as_str())),
            repos::Kind::Workspace => workspace::load(&entry.path)
                .ok()
                .flatten()
                .map(|w| format!("{} repositories", w.members.len())),
        };
        println!(
            "{} {shown} ({})",
            entry.kind.as_str(),
            what.unwrap_or_default()
        );
    }
    print_skipped(&listing);
    Ok(Exit::Ok)
}

fn print_skipped(listing: &repos::Listing) {
    for (line, why) in &listing.skipped {
        println!("skipped: {line}: {why}");
    }
}

/// `writ init --undo --all`: each repository and workspace on the list taken back, as
/// `writ init --undo` there would; one that can't be is named with why, and the others
/// still done (exit 1 then).
pub fn undo_all(paths: &Paths) -> anyhow::Result<Exit> {
    let listing = repos::read(&paths.home)?;
    let mut exit = Exit::Ok;
    for entry in &listing.entries {
        let shown = display::clean(&entry.path.display().to_string());
        println!("{} {shown}:", entry.kind.as_str());
        if let Err(e) = undo_in(paths, &entry.path) {
            println!(
                "  not taken back: {}",
                display::clean_lines(&format!("{e:#}"))
            );
            exit = Exit::Error;
        }
    }
    print_skipped(&listing);
    if listing.entries.is_empty() {
        println!("Nothing wired by writ init on this host's list.");
    }
    Ok(exit)
}

/// Takes a workspace back: each repository it lists that was wired from it, then what was
/// installed at the root, then its record. Stopped by an error, the record stays: running it
/// again takes back the rest.
fn undo_workspace(paths: &Paths, workspace: &Workspace) -> anyhow::Result<Exit> {
    let root = &workspace.root;
    println!("Taking the workspace at {} back:", root.display());
    for member in &workspace.members {
        let path = workspace.path(member);
        let shown = shown_dir(&member.dir);
        match wiring::load(&path) {
            Ok(Some(wired)) if from_workspace(&wired, root) => {
                undo_repo(paths, &path, &wired).with_context(|| format!("undoing {shown}"))?;
                println!("  {shown}: wiring removed ({} mode).", wired.mode.as_str());
            }
            Ok(Some(_)) => println!(
                "  {shown}: wired, but not from this workspace: left as it is (`writ init \
                 --undo` in it)."
            ),
            Ok(None) | Err(_) => println!("  {shown}: not wired (any more): nothing to undo."),
        }
    }
    let exclude = if workspace::is_top_level(root) {
        Some(wiring::common_dir(root)?.join("info").join("exclude"))
    } else {
        None
    };
    let own = Own {
        root,
        common_dir: None,
    };
    let undone = undo_skill(
        paths,
        &own,
        &workspace.entries,
        exclude.as_deref(),
        Kind::Workspace,
    )?;
    let record_path = workspace::record_path(root);
    std::fs::remove_file(&record_path)
        .with_context(|| format!("cannot remove {}", record_path.display()))?;
    println!(
        "Writ workspace removed: every repository's git config is as it was before writ init."
    );
    print_kept(&undone);
    Ok(Exit::Ok)
}

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
            ("ssh://git@writ.home:2222".to_owned(), None)
        );
        assert_eq!(
            base_url("ssh://[::1]:2222").unwrap(),
            ("ssh://git@[::1]:2222".to_owned(), None)
        );
        // A local daemon: git reaches it by the alias its host key is pinned under.
        let socket = "/Library/Application Support/Writ/run/agents.sock";
        assert_eq!(
            base_url(&format!("unix:{socket}")).unwrap(),
            (
                "ssh://git@writ-local".to_owned(),
                Some(PathBuf::from(socket))
            )
        );
        let error = crate::error_of(base_url("unix:run/agents.sock"));
        assert_eq!(
            error,
            "writ init wires a Unix socket by its absolute path, not unix:run/agents.sock"
        );
        let error = crate::error_of(base_url("https://writ.home:8443"));
        assert!(
            error.starts_with(
                "writ init wires the agents' listener (ssh://host:port or unix:<path>)"
            ),
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
