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
}

/// The session the settings point at: the lease named (on this host and running), or
/// `current`.
fn session_for(paths: &Paths, lease: Option<&TicketId>) -> anyhow::Result<SessionRef> {
    match lease {
        Some(id) => {
            wiring::check_session(&paths.home, id)
                .map_err(|why| anyhow::anyhow!("--lease {id}: {why}"))?;
            Ok(SessionRef::Lease(id.clone()))
        }
        None => Ok(SessionRef::Current),
    }
}

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

/// Wires the repository at `plan.dir`: what is done recorded in its `<git common dir>/writ/
/// config` first, then, in whole-repo mode, the settings written in its config. The settings
/// are computed once: the record, the config and the summary come from them.
fn wire(
    paths: &Paths,
    plan: &RepoWiring<'_>,
    session: &SessionRef,
) -> anyhow::Result<(Wiring, Vec<Setting>)> {
    let dir = plan.dir;
    let record_path = wiring::record_path(dir)?;
    let record_dir = record_path
        .parent()
        .context("the record has no directory")?;
    std::fs::create_dir_all(record_dir)
        .with_context(|| format!("cannot create {}", record_dir.display()))?;
    let origin = local_values(dir, "remote.origin.url")?.into_iter().next();
    let wiring = Wiring {
        mode: plan.mode,
        base_url: plan.base_url.to_owned(),
        socket: plan.socket.map(Path::to_path_buf),
        repo: plan.repo.clone(),
        email: plan.email.map(|e| e.as_str().to_owned()),
        common_dir: wiring::common_dir(dir)?,
        origin,
        lease: plan.lease.cloned(),
        workspace: plan.workspace.map(Path::to_path_buf),
    };
    let settings = wiring::settings_with(paths, &wiring, session)?;
    if plan.mode == Mode::WholeRepo {
        // The values replaced, first: `--undo` puts them back.
        for (key, _) in &settings {
            let before = local_values(dir, key)?;
            if before.is_empty() {
                record(dir, &record_path, &format!("previous.{key}.absent"), "true")?;
            }
            for value in before {
                record(dir, &record_path, &format!("previous.{key}.value"), &value)?;
            }
        }
    }
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
    if plan.mode == Mode::WholeRepo {
        for (key, value) in &settings {
            wiring::git(dir, &["config", "--local", "--replace-all", key, value])?;
        }
    }
    Ok((wiring, settings))
}

/// Records what a skill installation made, in the record at `record_path`.
fn record_skill(
    dir: &Path,
    record_path: &Path,
    installed: &skill::Installed,
) -> anyhow::Result<()> {
    for (path, new) in &installed.skills {
        // Created: `--undo` removes it. Written over (Writ's already, a global skill another
        // repository's `writ init` made): only `writ skill update` rewrites it.
        let key = if *new {
            "skill.created"
        } else {
            "skill.written"
        };
        record(dir, record_path, key, &path.display().to_string())?;
    }
    for created in &installed.created_dirs {
        record(
            dir,
            record_path,
            "skill.createddir",
            &created.display().to_string(),
        )?;
    }
    for line in &installed.excluded {
        record(dir, record_path, "skill.exclude", line)?;
    }
    if let Some((timings, _)) = &installed.timings {
        record(
            dir,
            record_path,
            "skill.timings",
            &timings.display().to_string(),
        )?;
    }
    Ok(())
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
    let agents = choose_agents(&request.skill, &root, home.as_deref())?;
    let session = session_for(paths, request.lease)?;
    let folders = skill_folders(&request.skill, &agents, &root, home.as_deref())?;

    let (wiring, settings) = wire(
        paths,
        &RepoWiring {
            dir: &dir,
            repo: request.repo,
            mode: request.mode,
            email: request.email,
            lease: request.lease,
            base_url: &base_url,
            socket: socket.as_deref(),
            workspace: None,
        },
        &session,
    )?;
    let exclude = wiring.common_dir.join("info").join("exclude");
    let installed = skill::install(
        &skill::Plan {
            folders,
            root: root.clone(),
            kind: Kind::Repo,
            repos: String::new(),
        },
        Some(&exclude),
    )?;
    record_skill(&dir, &record_path, &installed)?;
    let pointed = if request.skill.agents_md {
        agents_md(&dir, &record_path, &root, Kind::Repo)?
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
    repos::add(&paths.home, repos::Kind::Repo, &root)?;
    Ok(Exit::Ok)
}

/// `--agents-md`: the pointer line in each of `AGENTS.md` and `CLAUDE.md` in `root` (a new
/// `AGENTS.md` when it has neither), recorded for `--undo`.
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
    let mut created = false;
    if files.is_empty() {
        files.push(root.join("AGENTS.md"));
        created = true;
    }
    for file in &files {
        if skill::add_line(file, kind.pointer())? {
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
    let from = found
        .origin
        .as_deref()
        .map_or_else(String::new, |o| format!(" (origin {})", display::clean(o)));
    print!("  {what}{from} [{default}]: ");
    std::io::Write::flush(&mut std::io::stdout()).context("cannot write to the terminal")?;
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
        .context("cannot read the answer")?;
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
    let root_is_repo = workspace::is_top_level(&root);
    let root_common = if root_is_repo {
        Some(wiring::common_dir(&root)?)
    } else {
        None
    };
    let (children, mut aside) = workspace::children(&root)?;
    let mut dirs: Vec<String> = Vec::new();
    for child in children {
        // A submodule of the root's repository: left to the backlog.
        let common = wiring::common_dir(&root.join(&child))?;
        let inside = match (&root_common, std::fs::canonicalize(&common)) {
            (Some(rc), Ok(c)) => std::fs::canonicalize(rc).is_ok_and(|rc| c.starts_with(rc)),
            _ => false,
        };
        if inside {
            aside.push((
                display::clean(&child),
                "a submodule of this folder's repository: submodules aren't wired yet",
            ));
        } else {
            dirs.push(child);
        }
    }
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
        let origin = local_values(&path, "remote.origin.url")?.into_iter().next();
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
    let home = home_dir();
    let agents = choose_agents(&request.skill, &root, home.as_deref())?;
    let session = session_for(paths, request.lease)?;
    let folders = skill_folders(&request.skill, &agents, &root, home.as_deref())?;

    let record_path = workspace::record_path(&root);
    // The record first, then each repository named in it before it is wired: a run stopped
    // half way is taken back by `writ init --undo` here.
    record(&root, &record_path, "writ.mode", request.mode.as_str())?;
    if let Some(lease) = request.lease {
        record(&root, &record_path, "writ.lease", lease.as_str())?;
    }
    let exclude = root_common
        .as_ref()
        .map(|common| common.join("info").join("exclude"));
    if let Some(exclude) = &exclude {
        let line = format!("/{}", workspace::RECORD);
        if skill::add_line(exclude, &line)? {
            record(&root, &record_path, "skill.exclude", &line)?;
        }
    }
    let workspace = Workspace {
        root: root.clone(),
        members: members.clone(),
        lease: request.lease.cloned(),
        entries: Vec::new(),
    };
    let mut wired = Vec::new();
    for member in &members {
        record(
            &root,
            &record_path,
            &format!("member.{}.repo", member.dir),
            member.repo.as_str(),
        )?;
        let (wiring, settings) = wire(
            paths,
            &RepoWiring {
                dir: &workspace.path(member),
                repo: &member.repo,
                mode: request.mode,
                email: request.email,
                lease: request.lease,
                base_url: &base_url,
                socket: socket.as_deref(),
                workspace: Some(&root),
            },
            &session,
        )
        .with_context(|| format!("wiring {}", display::clean(&member.dir)))?;
        wired.push((member, wiring, settings));
    }
    let installed = skill::install(
        &skill::Plan {
            folders,
            root: root.clone(),
            kind: Kind::Workspace,
            repos: skill_repos(&members),
        },
        exclude.as_deref(),
    )?;
    record_skill(&root, &record_path, &installed)?;
    let pointed = if request.skill.agents_md {
        agents_md(&root, &record_path, &root, Kind::Workspace)?
    } else {
        Vec::new()
    };

    let mode = match request.mode {
        Mode::Wrapper => "wrapper mode: `writ git -C <dir> …`; plain git keeps your own config",
        Mode::WholeRepo => "whole repo: plain git in each is the agent's",
    };
    println!(
        "Workspace wired for Writ at {} ({mode}). One agent at this folder works on:",
        root.display()
    );
    for (member, wiring, _) in &wired {
        let origin = match &wiring.origin {
            Some(origin) => format!(", origin {} through the daemon", display::clean(origin)),
            None => ", no origin: push to the `writ` remote".to_owned(),
        };
        println!("  {}  repo {}{origin}", shown_dir(&member.dir), member.repo);
    }
    for f in &found {
        if !members.iter().any(|m| m.dir == f.dir) {
            println!("Left out: {}.", shown_dir(&f.dir));
        }
    }
    for (dir, why) in &aside {
        println!("Not wired: {dir} ({why}).");
    }
    let email = wired
        .first()
        .and_then(|(_, _, settings)| settings.iter().find(|(k, _)| k == "user.email"));
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
    match &session {
        SessionRef::Lease(id) => println!(
            "Pinned to lease {id}: commands here use its session, never `current` \
             (WRIT_SESSION still comes first)."
        ),
        SessionRef::Current => println!(
            "Session: WRIT_SESSION when it is set, otherwise the current lease \
             (<home>/sessions/current). One ticket names every repository a task touches."
        ),
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
    for file in &pointed {
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
        record_path.display()
    );
    repos::add(&paths.home, repos::Kind::Workspace, &root)?;
    Ok(Exit::Ok)
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
/// What undoing a record left alone, to say so.
#[derive(Debug, Default)]
struct Undone {
    /// The timings files kept (what the agent learned).
    timings: Vec<String>,
    /// What the record named that was left as it is, with why.
    left: Vec<String>,
}

/// Takes back what the record's `skill.*` entries say `writ init` installed: the skill files
/// (Writ's only), the folders made for them (when empty), the lines added to `exclude` (the
/// repository's own `.git/info/exclude`, never a file the record names) and the pointer
/// lines (in `AGENTS.md` and `CLAUDE.md` only).
fn undo_skill(
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
    let created = values("skill.created");
    for path in &created {
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
    skill::remove_created_dirs(&values("skill.createddir"), &created);
    if let Some(exclude) = exclude {
        for line in values("skill.exclude") {
            skill::remove_line(exclude, line, false)?;
        }
    }
    let pointer_file = |file: &str| {
        Path::new(file)
            .file_name()
            .is_some_and(|n| skill::AGENTS_MD.iter().any(|a| n == *a))
    };
    for (key, created) in [("skill.agentsmd", false), ("skill.agentsmdcreated", true)] {
        for file in values(key) {
            if pointer_file(file) {
                skill::remove_line(Path::new(file), kind.pointer(), created)?;
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
fn undo_repo(dir: &Path, wired: &Wiring) -> anyhow::Result<Undone> {
    let record_path = wired.common_dir.join("writ").join("config");
    let entries = wiring::read_file(dir, &record_path)?;
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
    let undone = undo_skill(&entries, Some(&exclude), Kind::Repo)?;
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
        let record_path = wired.common_dir.join("writ").join("config");
        let entries = wiring::read_file(&dir, &record_path)?;
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
        let exit = undo_workspace(&workspace)?;
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
    let undone = undo_repo(dir, &wired)?;
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
fn undo_workspace(workspace: &Workspace) -> anyhow::Result<Exit> {
    let root = &workspace.root;
    println!("Taking the workspace at {} back:", root.display());
    for member in &workspace.members {
        let path = workspace.path(member);
        let shown = shown_dir(&member.dir);
        match wiring::load(&path) {
            Ok(Some(wired)) if from_workspace(&wired, root) => {
                undo_repo(&path, &wired).with_context(|| format!("undoing {shown}"))?;
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
    let undone = undo_skill(&workspace.entries, exclude.as_deref(), Kind::Workspace)?;
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
