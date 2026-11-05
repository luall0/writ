//! The agent skill `writ init` installs (`skill/writ/SKILL.md`, built into `writ` so it
//! always matches the CLI), where each agent looks for it: Claude Code (`.claude/skills`),
//! `.agents/skills` (Codex, Gemini CLI, GitHub Copilot, Amp…), OpenCode (`.opencode/skills`,
//! only without the other two, which it reads too: it wants a skill once) and Cursor
//! (`.cursor/skills`); in the repository, or the user's folders with `--global`, or any folder
//! with `--skill-dir`. Beside the first one, `timings.md` holds what the agent learns.
//!
//! In the repository, every path installed goes in `.git/info/exclude` (never committed,
//! never against `expected_paths`). What is created is recorded, so `writ init --undo`
//! removes exactly it; `timings.md` stays (what the agent learned).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// The skill, as built into this `writ`.
pub const SKILL: &str = include_str!("../../../skill/writ/SKILL.md");

/// The workspace skill (`writ init` at a folder of repositories), as built into this `writ`.
pub const WORKSPACE_SKILL: &str = include_str!("../../../skill/writ-workspace/SKILL.md");

/// Where the skill names its timings file.
const TIMINGS_MARK: &str = "{{TIMINGS}}";

/// Where the workspace skill lists the workspace's repositories.
const REPOS_MARK: &str = "{{REPOS}}";

/// What says a `SKILL.md` is Writ's (`writ init` replaces, and `--undo` removes, only such a
/// file).
const OWNED: &str = "<!-- Written by `writ init`";

/// The line `--agents-md` appends to `AGENTS.md` / `CLAUDE.md`.
pub const POINTER: &str = "Git goes through `writ git …` here (Writ leases): read the `writ` skill before you start any task that changes files.";

/// The same line at a workspace root.
pub const WORKSPACE_POINTER: &str = "Git goes through `writ git -C <repository> …` here (Writ leases): read the `writ-workspace` skill before you start any task that changes files.";

/// The files `--agents-md` adds its line to.
pub const AGENTS_MD: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// Which skill: one repository's, or a workspace's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Repo,
    Workspace,
}

impl Kind {
    /// Its folder in a skills folder, and its `name:`.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Repo => "writ",
            Kind::Workspace => "writ-workspace",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Kind::Repo => SKILL,
            Kind::Workspace => WORKSPACE_SKILL,
        }
    }

    /// The line `--agents-md` adds.
    pub fn pointer(self) -> &'static str {
        match self {
            Kind::Repo => POINTER,
            Kind::Workspace => WORKSPACE_POINTER,
        }
    }
}

/// An agent the skill can be installed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Agent {
    Claude,
    Agents,
    Opencode,
    Cursor,
}

impl Agent {
    pub const ALL: [Agent; 4] = [Agent::Claude, Agent::Agents, Agent::Opencode, Agent::Cursor];

    /// Its name for `--agents`.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Agents => "agents",
            Agent::Opencode => "opencode",
            Agent::Cursor => "cursor",
        }
    }

    /// What the prompt shows.
    pub fn label(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code (.claude/skills)",
            Agent::Agents => "Codex, Gemini CLI, GitHub Copilot, Amp… (.agents/skills)",
            Agent::Opencode => "OpenCode (.opencode/skills)",
            Agent::Cursor => "Cursor (.cursor/skills)",
        }
    }

    /// Its skills folder in a repository.
    fn repo_folder(self) -> &'static str {
        match self {
            Agent::Claude => ".claude/skills",
            Agent::Agents => ".agents/skills",
            Agent::Opencode => ".opencode/skills",
            Agent::Cursor => ".cursor/skills",
        }
    }

    /// Its skills folder in the user's home.
    fn home_folder(self) -> &'static str {
        match self {
            Agent::Claude => ".claude/skills",
            Agent::Agents => ".agents/skills",
            Agent::Opencode => ".config/opencode/skills",
            Agent::Cursor => ".cursor/skills",
        }
    }

    /// What shows it is used: in the repository, then in the home.
    fn signs(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Agent::Claude => (&[".claude", "CLAUDE.md"], &[".claude"]),
            Agent::Agents => (&[".agents", ".codex", "AGENTS.md"], &[".codex", ".agents"]),
            Agent::Opencode => (&[".opencode", "opencode.json"], &[".config/opencode"]),
            Agent::Cursor => (&[".cursor"], &[".cursor"]),
        }
    }
}

/// `--agents`: names separated by commas, or `none`.
pub fn parse_agents(text: &str) -> Result<BTreeSet<Agent>, String> {
    if text.trim() == "none" {
        return Ok(BTreeSet::new());
    }
    text.split(',')
        .map(str::trim)
        .map(|name| {
            Agent::ALL
                .into_iter()
                .find(|a| a.name() == name)
                .ok_or_else(|| {
                    format!("unknown agent {name:?} (claude, agents, opencode, cursor, or none)")
                })
        })
        .collect()
}

/// The agents whose signs are in `root` or `home`.
pub fn detect(root: &Path, home: Option<&Path>) -> BTreeSet<Agent> {
    Agent::ALL
        .into_iter()
        .filter(|agent| {
            let (in_repo, in_home) = agent.signs();
            in_repo.iter().any(|sign| root.join(sign).exists())
                || home.is_some_and(|home| in_home.iter().any(|sign| home.join(sign).exists()))
        })
        .collect()
}

/// The skills folders for `agents`, as few as possible: OpenCode reads `.claude/skills` and
/// `.agents/skills` too, so its own folder only when neither is there.
pub fn folders(agents: &BTreeSet<Agent>, global: bool) -> Vec<&'static str> {
    let has = |a| agents.contains(&a);
    Agent::ALL
        .into_iter()
        .filter(|a| has(*a))
        .filter(|a| *a != Agent::Opencode || !(has(Agent::Claude) || has(Agent::Agents)))
        .map(|a| {
            if global {
                a.home_folder()
            } else {
                a.repo_folder()
            }
        })
        .collect()
}

/// Where to install: the skills folders (absolute), the root of the repository or workspace
/// (paths in it are shown relative to it, and excluded from git when it is a repository),
/// which skill, and for a workspace the list of its repositories the skill shows.
pub struct Plan {
    pub folders: Vec<PathBuf>,
    pub root: PathBuf,
    pub kind: Kind,
    /// The workspace's repositories, as the skill lists them (Markdown lines).
    pub repos: String,
}

/// What an installation did.
#[derive(Debug, Default)]
pub struct Installed {
    /// The `SKILL.md` files written, and whether each was new.
    pub skills: Vec<(PathBuf, bool)>,
    /// The folders made for them (the deepest first), which `--undo` removes when empty.
    pub created_dirs: Vec<PathBuf>,
    /// The timings file, and whether it was new.
    pub timings: Option<(PathBuf, bool)>,
    /// The lines added to `.git/info/exclude`.
    pub excluded: Vec<String>,
}

/// The skill with its timings file named (relative to the root when it is in it), and the
/// workspace's repositories listed.
fn skill_text(plan: &Plan, timings: &Path) -> String {
    let shown = timings.strip_prefix(&plan.root).unwrap_or(timings);
    plan.kind
        .text()
        .replace(TIMINGS_MARK, &shown.display().to_string())
        .replace(REPOS_MARK, &plan.repos)
}

/// The folders `dir` needs made, from the deepest up to the first that exists.
fn missing_dirs(dir: &Path) -> Vec<PathBuf> {
    dir.ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && std::fs::symlink_metadata(d).is_err())
        .map(Path::to_path_buf)
        .collect()
}

/// Installs the skill in every folder of `plan` (`<folder>/<kind>/SKILL.md`), the timings
/// file beside the first; a `SKILL.md` that isn't Writ's is never written over. In the root,
/// each new skill folder is excluded from git when the root is a repository (`exclude`: its
/// `.git/info/exclude`).
pub fn install(plan: &Plan, exclude: Option<&Path>) -> anyhow::Result<Installed> {
    let mut installed = Installed::default();
    let Some(first) = plan.folders.first() else {
        return Ok(installed);
    };
    let timings = first.join(plan.kind.name()).join("timings.md");
    for folder in &plan.folders {
        let dir = folder.join(plan.kind.name());
        let path = dir.join("SKILL.md");
        let existed = match std::fs::read_to_string(&path) {
            Ok(text) if text.contains(OWNED) => true,
            Ok(_) => bail!(
                "{} exists and isn't Writ's: not writing over it (move it, or use --skill-dir)",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let missing = missing_dirs(&dir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        installed.created_dirs.extend(missing);
        std::fs::write(&path, skill_text(plan, &timings))
            .with_context(|| format!("cannot write {}", path.display()))?;
        installed.skills.push((path, !existed));
        if let (Some(exclude), Ok(relative)) = (exclude, dir.strip_prefix(&plan.root)) {
            let line = format!("/{}/", relative.display());
            if add_line(exclude, &line)? {
                installed.excluded.push(line);
            }
        }
    }
    let new = !timings.exists();
    if new {
        crate::timings::write(&timings, &crate::timings::Timings::default())?;
    }
    installed.timings = Some((timings, new));
    Ok(installed)
}

/// Appends `line` to the file at `path` (created if it isn't there) unless a line of it is
/// already exactly that; whether it was added.
pub fn add_line(path: &Path, line: &str) -> anyhow::Result<bool> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if text.lines().any(|l| l == line) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut new = text;
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push_str(line);
    new.push('\n');
    std::fs::write(path, new).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(true)
}

/// Removes the lines exactly `line` from the file at `path`; the file too when it is left
/// empty and `created` says `writ init` made it.
pub fn remove_line(path: &Path, line: &str, created: bool) -> anyhow::Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let kept: Vec<&str> = text.lines().filter(|l| *l != line).collect();
    if kept.is_empty() && created {
        return std::fs::remove_file(path)
            .with_context(|| format!("cannot remove {}", path.display()));
    }
    let mut new = kept.join("\n");
    if !new.is_empty() {
        new.push('\n');
    }
    std::fs::write(path, new).with_context(|| format!("cannot write {}", path.display()))
}

/// Why `--undo` leaves a recorded skill file alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// Not `<folder>/writ/SKILL.md` or `<folder>/writ-workspace/SKILL.md`, or a link.
    NotASkillPath,
    /// No `Written by writ init` mark: someone else's.
    NotWrits,
}

/// Removes a `SKILL.md` `writ init` created, and its skill folder when nothing else is in it
/// (the timings file keeps the first one). The record names it, and the record is the
/// agent's to write too: only a regular file named `SKILL.md` in a `writ/` or
/// `writ-workspace/` folder, with Writ's mark, is removed; anything else is kept, with why.
pub fn remove_skill(path: &Path) -> anyhow::Result<Option<Kept>> {
    let shaped = path.file_name().is_some_and(|n| n == "SKILL.md")
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == Kind::Repo.name() || n == Kind::Workspace.name());
    let regular = std::fs::symlink_metadata(path).map(|m| m.file_type().is_file());
    match regular {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        Ok(false) => return Ok(Some(Kept::NotASkillPath)),
        Ok(true) if !shaped => return Ok(Some(Kept::NotASkillPath)),
        Ok(true) => {}
    }
    let text = read_bounded(path, 1024 * 1024)?;
    if !text.contains(OWNED) {
        return Ok(Some(Kept::NotWrits));
    }
    std::fs::remove_file(path).with_context(|| format!("cannot remove {}", path.display()))?;
    if let Some(dir) = path.parent() {
        // Not empty (the timings file, another file): kept.
        let _ = std::fs::remove_dir(dir);
    }
    Ok(None)
}

/// Removes the folders `writ init` made for its skills, when they are empty and on the way to
/// one of `skills` (the record's own `SKILL.md` paths): never any other folder.
pub fn remove_created_dirs(dirs: &[&str], skills: &[&str]) {
    for dir in dirs {
        let dir = Path::new(dir);
        if skills.iter().any(|s| Path::new(s).starts_with(dir)) {
            // Not empty (the timings file, the user's own files): kept.
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// At most `max` bytes of the file at `path`, as text (what isn't UTF-8 replaced).
fn read_bounded(path: &Path, max: u64) -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(max).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[Agent]) -> BTreeSet<Agent> {
        names.iter().copied().collect()
    }

    #[test]
    fn opencode_gets_its_own_folder_only_without_the_folders_it_reads() {
        use Agent::*;
        assert_eq!(folders(&set(&[Opencode]), false), [".opencode/skills"]);
        assert_eq!(
            folders(&set(&[Claude, Opencode]), false),
            [".claude/skills"]
        );
        assert_eq!(
            folders(&set(&[Agents, Opencode]), false),
            [".agents/skills"]
        );
        assert_eq!(
            folders(&set(&[Claude, Agents, Opencode, Cursor]), false),
            [".claude/skills", ".agents/skills", ".cursor/skills"]
        );
        assert_eq!(
            folders(&set(&[Opencode, Cursor]), true),
            [".config/opencode/skills", ".cursor/skills"]
        );
        assert!(folders(&BTreeSet::new(), false).is_empty());
    }

    #[test]
    fn agents_are_named_and_detected() {
        assert_eq!(
            parse_agents("claude, cursor").unwrap(),
            set(&[Agent::Claude, Agent::Cursor])
        );
        assert!(parse_agents("none").unwrap().is_empty());
        assert!(
            parse_agents("codex")
                .unwrap_err()
                .contains("unknown agent \"codex\"")
        );
        assert_eq!(
            parse_agents(""),
            Err("unknown agent \"\" (claude, agents, opencode, cursor, or none)".to_owned())
        );
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(detect(root.path(), Some(home.path())).is_empty());
        std::fs::write(root.path().join("AGENTS.md"), "").unwrap();
        std::fs::create_dir_all(home.path().join(".config/opencode")).unwrap();
        assert_eq!(
            detect(root.path(), Some(home.path())),
            set(&[Agent::Agents, Agent::Opencode])
        );
    }

    #[test]
    fn the_skill_is_installed_once_excluded_and_never_over_someone_else_s() {
        let root = tempfile::tempdir().unwrap();
        let exclude = root.path().join(".git/info/exclude");
        std::fs::create_dir_all(exclude.parent().unwrap()).unwrap();
        std::fs::write(&exclude, "# git's own\n").unwrap();
        let plan = Plan {
            folders: vec![
                root.path().join(".claude/skills"),
                root.path().join(".cursor/skills"),
            ],
            root: root.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        let installed = install(&plan, Some(&exclude)).unwrap();
        assert_eq!(installed.skills.len(), 2);
        assert!(installed.skills.iter().all(|(_, new)| *new));
        assert_eq!(
            installed.excluded,
            ["/.claude/skills/writ/", "/.cursor/skills/writ/"]
        );
        let skill =
            std::fs::read_to_string(root.path().join(".cursor/skills/writ/SKILL.md")).unwrap();
        assert!(
            skill.contains("`.claude/skills/writ/timings.md`"),
            "{skill}"
        );
        // Every mention filled, the checks among them.
        assert!(!skill.contains(TIMINGS_MARK), "{skill}");
        assert!(
            skill.contains("writ check .claude/skills/writ/timings.md"),
            "{skill}"
        );
        assert!(skill.contains("writ check ticket.yaml"), "{skill}");
        assert!(skill.starts_with("---\nname: writ\n"));
        assert!(root.path().join(".claude/skills/writ/timings.md").exists());
        assert!(!root.path().join(".cursor/skills/writ/timings.md").exists());
        // Again: refreshed, nothing added twice.
        let again = install(&plan, Some(&exclude)).unwrap();
        assert!(again.skills.iter().all(|(_, new)| !*new));
        assert!(again.excluded.is_empty());
        assert_eq!(again.timings.as_ref().map(|(_, new)| *new), Some(false));
        // Someone else's SKILL.md: refused, untouched.
        let theirs = root.path().join(".agents/skills/writ/SKILL.md");
        std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
        std::fs::write(&theirs, "my own skill").unwrap();
        let plan = Plan {
            folders: vec![root.path().join(".agents/skills")],
            root: root.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        let error = install(&plan, Some(&exclude)).unwrap_err().to_string();
        assert!(error.contains("isn't Writ's"), "{error}");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "my own skill");
        // Lines come back out exactly.
        remove_line(&exclude, "/.claude/skills/writ/", false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&exclude).unwrap(),
            "# git's own\n/.cursor/skills/writ/\n"
        );
    }

    #[test]
    fn undo_removes_only_writ_s_own_skill_files_and_the_empty_folders_it_made() {
        let root = tempfile::tempdir().unwrap();
        let plan = Plan {
            folders: vec![root.path().join(".claude/skills")],
            root: root.path().to_owned(),
            kind: Kind::Workspace,
            repos: "- `api`: repo `api`".to_owned(),
        };
        let installed = install(&plan, None).unwrap();
        let skill = root.path().join(".claude/skills/writ-workspace/SKILL.md");
        assert_eq!(installed.skills, [(skill.clone(), true)]);
        assert_eq!(
            installed.created_dirs,
            [
                root.path().join(".claude/skills/writ-workspace"),
                root.path().join(".claude/skills"),
                root.path().join(".claude"),
            ]
        );
        assert!(
            installed.excluded.is_empty(),
            "no repository: nothing excluded"
        );
        let text = std::fs::read_to_string(&skill).unwrap();
        assert!(text.starts_with("---\nname: writ-workspace\n"), "{text}");
        assert!(text.contains("- `api`: repo `api`"), "{text}");
        assert!(
            !text.contains(REPOS_MARK) && !text.contains(TIMINGS_MARK),
            "{text}"
        );

        // A record naming something else: never removed.
        let mine = root.path().join("notes.md");
        std::fs::write(&mine, "mine").unwrap();
        assert_eq!(remove_skill(&mine).unwrap(), Some(Kept::NotASkillPath));
        let theirs = root.path().join("other/writ/SKILL.md");
        std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
        std::fs::write(&theirs, "their own skill").unwrap();
        assert_eq!(remove_skill(&theirs).unwrap(), Some(Kept::NotWrits));
        let link = root.path().join("linked/writ/SKILL.md");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&skill, &link).unwrap();
        assert_eq!(remove_skill(&link).unwrap(), Some(Kept::NotASkillPath));
        assert!(mine.exists() && theirs.exists() && skill.exists());
        assert_eq!(
            remove_skill(&root.path().join("gone/writ/SKILL.md")).unwrap(),
            None
        );

        // Writ's own: removed, then the folders it made once empty, never another one.
        assert_eq!(remove_skill(&skill).unwrap(), None);
        assert!(!skill.exists());
        let timings = root.path().join(".claude/skills/writ-workspace/timings.md");
        assert!(timings.exists(), "the timings file stays");
        let dirs: Vec<String> = installed
            .created_dirs
            .iter()
            .map(|d| d.display().to_string())
            .chain([root.path().join("other").display().to_string()])
            .collect();
        let dirs: Vec<&str> = dirs.iter().map(String::as_str).collect();
        let skills = skill.display().to_string();
        remove_created_dirs(&dirs, &[skills.as_str()]);
        assert!(timings.exists(), "a folder holding the timings file stays");
        std::fs::remove_file(&timings).unwrap();
        std::fs::create_dir_all(root.path().join("empty")).unwrap();
        let empty = root.path().join("empty").display().to_string();
        let mut with_empty = dirs.clone();
        with_empty.push(empty.as_str());
        remove_created_dirs(&with_empty, &[skills.as_str()]);
        assert!(
            !root.path().join(".claude").exists(),
            "every folder it made, once empty"
        );
        assert!(
            root.path().join("empty").exists(),
            "not on the way to a skill: kept"
        );
        assert!(root.path().join("other").exists());
    }

    /// Every ticket example in both skills is one `writ check` takes (the agent copies them):
    /// the ticket file's shape, in the current layout.
    #[test]
    fn the_skills_ticket_examples_are_well_formed_tickets() {
        for (kind, text) in [("writ", SKILL), ("writ-workspace", WORKSPACE_SKILL)] {
            let examples: Vec<&str> = text
                .split("```yaml\n")
                .skip(1)
                .filter_map(|rest| rest.split_once("```").map(|(yaml, _)| yaml))
                .collect();
            assert!(!examples.is_empty(), "{kind}: no ticket example");
            for yaml in examples {
                let request = writ_core::ticket::TicketRequest::from_yaml(yaml)
                    .unwrap_or_else(|e| panic!("{kind}: {e}\n{yaml}"));
                let problems = writ_core::fit::check_request(&request);
                assert!(problems.is_empty(), "{kind}: {problems:?}\n{yaml}");
                assert!(!request.repos.is_empty(), "{kind}: a repos block");
            }
        }
        // The workspace skill's example names several repositories, each with its own terms.
        let workspace = WORKSPACE_SKILL
            .split("```yaml\n")
            .nth(1)
            .and_then(|rest| rest.split_once("```"))
            .map(|(yaml, _)| writ_core::ticket::TicketRequest::from_yaml(yaml).unwrap())
            .unwrap();
        assert!(workspace.repos.len() > 1);
    }
}
