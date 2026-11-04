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

/// Where the skill names its timings file.
const TIMINGS_MARK: &str = "{{TIMINGS}}";

/// What says a `SKILL.md` is Writ's (`writ init` replaces only such a file).
const OWNED: &str = "<!-- Written by `writ init`";

/// The line `--agents-md` appends to `AGENTS.md` / `CLAUDE.md`.
pub const POINTER: &str = "Git goes through `writ git …` here (Writ leases): read the `writ` skill before you start any task that changes files.";

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

/// Where to install: the skills folders (absolute), and the repository's root when they are
/// in it (their paths then go in `.git/info/exclude`).
pub struct Plan {
    pub folders: Vec<PathBuf>,
    pub root: PathBuf,
}

/// What an installation did.
#[derive(Debug, Default)]
pub struct Installed {
    /// The `SKILL.md` files written, and whether each was new.
    pub skills: Vec<(PathBuf, bool)>,
    /// The timings file, and whether it was new.
    pub timings: Option<(PathBuf, bool)>,
    /// The lines added to `.git/info/exclude`.
    pub excluded: Vec<String>,
}

/// The skill with its timings file named (relative to the repository when it is in it).
fn skill_text(timings: &Path, root: &Path) -> String {
    let shown = timings.strip_prefix(root).unwrap_or(timings);
    SKILL.replace(TIMINGS_MARK, &shown.display().to_string())
}

/// Installs the skill in every folder of `plan` (`<folder>/writ/SKILL.md`), the timings file
/// beside the first; a `SKILL.md` that isn't Writ's is never written over. In the
/// repository, each new `writ/` folder is excluded from git (`exclude` is
/// `.git/info/exclude`).
pub fn install(plan: &Plan, exclude: &Path) -> anyhow::Result<Installed> {
    let mut installed = Installed::default();
    let Some(first) = plan.folders.first() else {
        return Ok(installed);
    };
    let timings = first.join("writ").join("timings.md");
    for folder in &plan.folders {
        let dir = folder.join("writ");
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
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        std::fs::write(&path, skill_text(&timings, &plan.root))
            .with_context(|| format!("cannot write {}", path.display()))?;
        installed.skills.push((path, !existed));
        if let Ok(relative) = dir.strip_prefix(&plan.root) {
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

/// Removes a `SKILL.md` `writ init` created, and its `writ/` folder when nothing else is in
/// it (the timings file keeps the first one).
pub fn remove_skill(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot remove {}", path.display())),
    }
    if let Some(dir) = path.parent() {
        // Not empty (the timings file, another file): kept.
        let _ = std::fs::remove_dir(dir);
    }
    Ok(())
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
        };
        let installed = install(&plan, &exclude).unwrap();
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
        let again = install(&plan, &exclude).unwrap();
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
        };
        let error = install(&plan, &exclude).unwrap_err().to_string();
        assert!(error.contains("isn't Writ's"), "{error}");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "my own skill");
        // Lines come back out exactly.
        remove_line(&exclude, "/.claude/skills/writ/", false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&exclude).unwrap(),
            "# git's own\n/.cursor/skills/writ/\n"
        );
    }
}
