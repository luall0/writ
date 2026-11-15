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

/// The line `--agents-md` appends to `AGENTS.md` / `CLAUDE.md`. Fetch and pull are named:
/// agents fetched with plain git before planning, outside the skill (M7.9.7).
pub const POINTER: &str = "Git goes through `writ git …` here (Writ leases), fetch and pull included, even before a task: read the `writ` skill before you run git or start any task that changes files.";

/// The same line at a workspace root.
pub const WORKSPACE_POINTER: &str = "Git goes through `writ git -C <repository> …` here (Writ leases), fetch and pull included, even before a task: read the `writ-workspace` skill before you run git or start any task that changes files.";

/// The lines earlier versions added, replaced in place by `writ init` and taken back by
/// `--undo` like today's (M7.9.7): a repository wired before keeps one line, never two.
const FORMER_POINTERS: [&str; 1] = [
    "Git goes through `writ git …` here (Writ leases): read the `writ` skill before you start any task that changes files.",
];

/// The same at a workspace root.
const FORMER_WORKSPACE_POINTERS: [&str; 1] = [
    "Git goes through `writ git -C <repository> …` here (Writ leases): read the `writ-workspace` skill before you start any task that changes files.",
];

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

    /// The lines earlier versions of `--agents-md` added in its place.
    pub fn former_pointers(self) -> &'static [&'static str] {
        match self {
            Kind::Repo => &FORMER_POINTERS,
            Kind::Workspace => &FORMER_WORKSPACE_POINTERS,
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
    text(plan.kind, &plan.root, timings, &plan.repos)
}

/// The `kind` skill as built into this `writ`, for the repository or workspace at `root`: its
/// timings file named (relative to `root` when it is in it), `repos` listed (a workspace's).
pub fn text(kind: Kind, root: &Path, timings: &Path, repos: &str) -> String {
    let shown = timings.strip_prefix(root).unwrap_or(timings);
    kind.text()
        .replace(TIMINGS_MARK, &shown.display().to_string())
        .replace(REPOS_MARK, repos)
}

/// What `writ skill update` did with one skill file the record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Updated {
    /// Rewritten from this `writ`'s skill.
    Written,
    /// Already this `writ`'s skill.
    Current,
    /// Not there any more.
    Gone,
    /// Left as it is, with why.
    Kept(Kept),
}

/// Rewrites a skill file `writ init` wrote with `text` (this `writ`'s skill). The record names
/// it, and the record is the agent's to write too: only a regular file named `SKILL.md` in a
/// `<kind>/` folder (`writ/` or `writ-workspace/`), with Writ's mark, is written; anything
/// else is kept, with why.
pub fn update(path: &Path, kind: Kind, text: &str) -> anyhow::Result<Updated> {
    let shaped = path.file_name().is_some_and(|n| n == "SKILL.md")
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == kind.name());
    match std::fs::symlink_metadata(path).map(|m| m.file_type().is_file()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Updated::Gone),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        Ok(false) => return Ok(Updated::Kept(Kept::NotASkillPath)),
        Ok(true) if !shaped => return Ok(Updated::Kept(Kept::NotASkillPath)),
        Ok(true) => {}
    }
    let current = read_bounded(path, MAX_SKILL)?;
    if !current.contains(OWNED) {
        return Ok(Updated::Kept(Kept::NotWrits));
    }
    if current == text {
        return Ok(Updated::Current);
    }
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(Updated::Written)
}

/// The folders `dir` needs made, from the deepest up to the first that exists.
fn missing_dirs(dir: &Path) -> Vec<PathBuf> {
    dir.ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && std::fs::symlink_metadata(d).is_err())
        .map(Path::to_path_buf)
        .collect()
}

/// Whether the `SKILL.md` at `path` is Writ's already (`false`: there is none), or why it
/// can't be written.
fn existing(path: &Path) -> anyhow::Result<bool> {
    use std::io::Read as _;
    // A FIFO or a device in its place is refused, never waited on.
    let Some(file) = crate::timings::open_regular(path)? else {
        return Ok(false);
    };
    let mut bytes = Vec::new();
    file.take(MAX_SKILL)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if !String::from_utf8_lossy(&bytes).contains(OWNED) {
        bail!(
            "{} exists and isn't Writ's: not writing over it (move it, or use --skill-dir)",
            path.display()
        );
    }
    Ok(true)
}

/// The most of a `SKILL.md` read to find Writ's mark.
const MAX_SKILL: u64 = 1024 * 1024;

/// The timings file the skills of `plan` name: beside the first.
fn timings_path(plan: &Plan) -> Option<PathBuf> {
    let first = plan.folders.first()?;
    Some(first.join(plan.kind.name()).join("timings.md"))
}

/// What [`install`] would refuse, refused before anything is written: a `SKILL.md` in any of
/// the folders that isn't Writ's or can't be read, a timings path that is there but isn't a
/// regular file.
pub fn check(plan: &Plan) -> anyhow::Result<()> {
    for folder in &plan.folders {
        existing(&folder.join(plan.kind.name()).join("SKILL.md"))?;
    }
    if let Some(timings) = timings_path(plan) {
        match std::fs::metadata(&timings) {
            Ok(meta) if !meta.is_file() => bail!(
                "{} is there and isn't a timings file (not a regular file): move it, or use \
                 --skill-dir",
                timings.display()
            ),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read {}", timings.display()));
            }
        }
    }
    Ok(())
}

/// One thing [`install`] does, handed to its caller to record before or as it is done, so
/// `--undo` after a failure part way still takes back everything done.
pub enum Step<'a> {
    /// A folder about to be made (recorded first: `--undo` removes it only when empty).
    CreatedDir(&'a Path),
    /// A `SKILL.md` about to be written, and whether it is new (recorded first: `--undo`
    /// removes it only when it carries Writ's mark).
    Skill(&'a Path, bool),
    /// A line just added to `.git/info/exclude`, and how.
    Excluded(&'a str, Added),
    /// The timings file, and whether it is new.
    Timings(&'a Path),
}

/// Installs the skill in every folder of `plan` (`<folder>/<kind>/SKILL.md`), the timings
/// file beside the first; a `SKILL.md` that isn't Writ's is never written over ([`check`],
/// which the caller runs before anything is written). In the root, each new skill folder is
/// excluded from git when the root is a repository (`exclude`: its `.git/info/exclude`).
/// Each step goes to `record` as it is done.
pub fn install(
    plan: &Plan,
    exclude: Option<&Path>,
    record: &mut dyn FnMut(Step<'_>) -> anyhow::Result<()>,
) -> anyhow::Result<Installed> {
    let mut installed = Installed::default();
    let Some(timings) = timings_path(plan) else {
        return Ok(installed);
    };
    for folder in &plan.folders {
        let dir = folder.join(plan.kind.name());
        let path = dir.join("SKILL.md");
        let existed = existing(&path)?;
        let missing = missing_dirs(&dir);
        for created in &missing {
            record(Step::CreatedDir(created))?;
        }
        installed.created_dirs.extend(missing);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        record(Step::Skill(&path, !existed))?;
        std::fs::write(&path, skill_text(plan, &timings))
            .with_context(|| format!("cannot write {}", path.display()))?;
        installed.skills.push((path, !existed));
        if let (Some(exclude), Ok(relative)) = (exclude, dir.strip_prefix(&plan.root)) {
            let line = format!("/{}/", relative.display());
            if let Some(added) = add_line(exclude, &line)? {
                record(Step::Excluded(&line, added))?;
                installed.excluded.push(line);
            }
        }
    }
    let new = !timings.exists();
    if new {
        crate::timings::write(&timings, &crate::timings::Timings::default())?;
    }
    record(Step::Timings(&timings))?;
    installed.timings = Some((timings, new));
    Ok(installed)
}

/// How [`add_line`] added its line, for [`remove_line`] to take exactly that back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Added {
    /// The file wasn't there: made for the line.
    pub created: bool,
    /// The file didn't end with a line break: one was added before the line.
    pub joined: bool,
}

/// The file's lines, each with its own line break (`\n`, `\r\n`, or none for the last).
fn lines_of(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split_inclusive(|b| *b == b'\n')
}

/// A line without its line break.
fn content(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Appends `line` to the file at `path` (created if it isn't there) unless a line of it is
/// already exactly that, with the file's own line break (`\r\n` when its lines end so, `\n`
/// otherwise); how it was added, or none.
pub fn add_line(path: &Path, line: &str) -> anyhow::Result<Option<Added>> {
    let (bytes, created) = match std::fs::read(path) {
        Ok(bytes) => (bytes, false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), true),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if lines_of(&bytes).any(|l| content(l) == line.as_bytes()) {
        return Ok(None);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let crlf = lines_of(&bytes)
        .next()
        .is_some_and(|l| l.ends_with(b"\r\n"));
    let eol: &[u8] = if crlf { b"\r\n" } else { b"\n" };
    let joined = !bytes.is_empty() && !bytes.ends_with(b"\n");
    let mut new = bytes;
    if joined {
        new.extend_from_slice(eol);
    }
    new.extend_from_slice(line.as_bytes());
    new.extend_from_slice(eol);
    std::fs::write(path, new).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(Some(Added { created, joined }))
}

/// Replaces each line exactly `old` in `path` with `new`, its line break kept, nothing else
/// of the file touched; whether one was. A file that isn't there has none.
pub fn replace_line(path: &Path, old: &str, new: &str) -> anyhow::Result<bool> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut replaced = false;
    for piece in lines_of(&bytes) {
        if content(piece) == old.as_bytes() {
            out.extend_from_slice(new.as_bytes());
            out.extend_from_slice(piece.get(old.len()..).unwrap_or_default());
            replaced = true;
        } else {
            out.extend_from_slice(piece);
        }
    }
    if replaced {
        std::fs::write(path, out).with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(replaced)
}

/// Takes back what [`add_line`] added: the lines exactly `line`, each with its own line break
/// and nothing else of the file, so it comes back byte for byte; the line break added before
/// it too (`added.joined`) when it is still the last line; the file when it is left empty and
/// `added.created` says `writ init` made it.
pub fn remove_line(path: &Path, line: &str, added: Added) -> anyhow::Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut new: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut last_removed = false;
    for piece in lines_of(&bytes) {
        last_removed = content(piece) == line.as_bytes();
        if !last_removed {
            new.extend_from_slice(piece);
        }
    }
    if new.len() == bytes.len() {
        return Ok(());
    }
    if added.joined && last_removed {
        if new.ends_with(b"\r\n") {
            new.truncate(new.len().saturating_sub(2));
        } else if new.ends_with(b"\n") {
            new.truncate(new.len().saturating_sub(1));
        }
    }
    if new.is_empty() && added.created {
        return std::fs::remove_file(path)
            .with_context(|| format!("cannot remove {}", path.display()));
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
    let text = read_bounded(path, MAX_SKILL)?;
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
        let installed = install(&plan, Some(&exclude), &mut |_| Ok(())).unwrap();
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
        let again = install(&plan, Some(&exclude), &mut |_| Ok(())).unwrap();
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
        let error = install(&plan, Some(&exclude), &mut |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("isn't Writ's"), "{error}");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "my own skill");
        // Lines come back out exactly.
        remove_line(&exclude, "/.claude/skills/writ/", Added::default()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&exclude).unwrap(),
            "# git's own\n/.cursor/skills/writ/\n"
        );
    }

    #[test]
    fn every_target_is_checked_before_anything_is_written() {
        let root = tempfile::tempdir().unwrap();
        let plan = |folders: &[&str]| Plan {
            folders: folders.iter().map(|f| root.path().join(f)).collect(),
            root: root.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        let both = plan(&[".claude/skills", ".cursor/skills"]);
        check(&both).unwrap();
        // The second folder's SKILL.md is someone else's: refused by the check, nothing made.
        let theirs = root.path().join(".cursor/skills/writ/SKILL.md");
        std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
        std::fs::write(&theirs, "my own skill").unwrap();
        let error = crate::error_of(check(&both));
        assert!(
            error.ends_with(".cursor/skills/writ/SKILL.md exists and isn't Writ's: not writing over it (move it, or use --skill-dir)"),
            "{error}"
        );
        assert!(!root.path().join(".claude").exists());
        std::fs::remove_file(&theirs).unwrap();
        // A FIFO in its place: refused at once, never waited on.
        let made = std::process::Command::new("mkfifo")
            .arg(&theirs)
            .status()
            .unwrap();
        assert!(made.success());
        let error = crate::error_of(check(&both));
        assert!(
            error.ends_with("SKILL.md is not a regular file: not read"),
            "{error}"
        );
        std::fs::remove_file(&theirs).unwrap();
        // A file where its folder should be: can't be read, refused.
        std::fs::remove_dir_all(root.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(root.path().join(".cursor")).unwrap();
        std::fs::write(root.path().join(".cursor/skills"), "").unwrap();
        let error = crate::error_of(check(&both));
        assert!(error.starts_with("cannot read "), "{error}");
        std::fs::remove_dir_all(root.path().join(".cursor")).unwrap();
        // The timings path taken by a folder: refused; a timings file there already: kept.
        let timings = root.path().join(".claude/skills/writ/timings.md");
        std::fs::create_dir_all(&timings).unwrap();
        let error = crate::error_of(check(&both));
        assert!(
            error.ends_with("timings.md is there and isn't a timings file (not a regular file): move it, or use --skill-dir"),
            "{error}"
        );
        std::fs::remove_dir(&timings).unwrap();
        std::fs::write(&timings, "").unwrap();
        check(&both).unwrap();
        check(&plan(&[])).unwrap();
    }

    #[test]
    fn each_step_is_handed_over_as_it_is_done() {
        let root = tempfile::tempdir().unwrap();
        let exclude = root.path().join(".git/info/exclude");
        let plan = Plan {
            folders: vec![root.path().join(".claude/skills")],
            root: root.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        let mut steps: Vec<String> = Vec::new();
        install(&plan, Some(&exclude), &mut |step| {
            // Each thing recorded before it is made (a folder, a skill) is not there yet.
            steps.push(match step {
                Step::CreatedDir(dir) => {
                    assert!(!dir.exists(), "{}", dir.display());
                    format!("dir {}", dir.strip_prefix(root.path()).unwrap().display())
                }
                Step::Skill(path, new) => {
                    assert!(!path.exists());
                    format!("skill {new}")
                }
                Step::Excluded(line, added) => {
                    format!("exclude {line} {} {}", added.created, added.joined)
                }
                Step::Timings(path) => {
                    assert!(path.is_file());
                    "timings".to_owned()
                }
            });
            Ok(())
        })
        .unwrap();
        assert_eq!(
            steps,
            [
                "dir .claude/skills/writ",
                "dir .claude/skills",
                "dir .claude",
                "skill true",
                "exclude /.claude/skills/writ/ true false",
                "timings",
            ]
        );
        // A recorder that fails stops the installation there.
        let other = tempfile::tempdir().unwrap();
        let plan = Plan {
            folders: vec![other.path().join("a"), other.path().join("b")],
            root: other.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        let mut seen = 0;
        let error = install(&plan, None, &mut |step| {
            seen += 1;
            match step {
                Step::Skill(..) => anyhow::bail!("the record can't be written"),
                _ => Ok(()),
            }
        });
        assert_eq!(crate::error_of(error), "the record can't be written");
        assert_eq!(seen, 3, "a/writ, a, then the skill");
        assert!(!other.path().join("a/writ/SKILL.md").exists());
    }

    /// M7.9.7: a pointer line an earlier version added is replaced in place by today's, its
    /// line break and the rest of the file kept, and taken back by the undo as it came.
    #[test]
    fn a_former_pointer_line_is_replaced_in_place_and_taken_back() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("AGENTS.md");
        let [former] = Kind::Repo.former_pointers() else {
            panic!("one former line");
        };
        let before = b"# Agents\r\nBe kind.".to_vec();
        std::fs::write(&file, &before).unwrap();
        let added = add_line(&file, former).unwrap().unwrap();
        std::fs::write(
            &file,
            [&std::fs::read(&file).unwrap()[..], b"mine\r\n"].concat(),
        )
        .unwrap();
        assert!(replace_line(&file, former, POINTER).unwrap());
        assert_eq!(
            std::fs::read(&file).unwrap(),
            [&before[..], b"\r\n", POINTER.as_bytes(), b"\r\nmine\r\n"].concat()
        );
        // Once only: today's line is there, nothing to replace or add.
        assert!(!replace_line(&file, former, POINTER).unwrap());
        assert_eq!(add_line(&file, POINTER).unwrap(), None);
        // Neither line there, or no file: nothing changes.
        assert!(!replace_line(&dir.path().join("none.md"), former, POINTER).unwrap());
        // The undo takes either line back, the user's own kept.
        remove_line(&file, POINTER, added).unwrap();
        remove_line(&file, former, added).unwrap();
        assert_eq!(
            std::fs::read(&file).unwrap(),
            [&before[..], b"\r\nmine\r\n"].concat()
        );
        // A workspace has its own, never today's repository line.
        assert_ne!(
            Kind::Workspace.former_pointers(),
            Kind::Repo.former_pointers()
        );
        assert!(!Kind::Repo.former_pointers().contains(&POINTER));
    }

    #[test]
    fn lines_come_back_out_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("AGENTS.md");
        // CRLF, no final line break: the line follows in CRLF, and goes with the break added.
        let before = b"# Agents\r\nBe kind.".to_vec();
        std::fs::write(&file, &before).unwrap();
        let added = add_line(&file, POINTER).unwrap().unwrap();
        assert_eq!(
            added,
            Added {
                created: false,
                joined: true
            }
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            [&before[..], b"\r\n", POINTER.as_bytes(), b"\r\n"].concat()
        );
        assert_eq!(add_line(&file, POINTER).unwrap(), None, "once");
        remove_line(&file, POINTER, added).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), before);
        // LF, ending with its break: nothing joined, the rest untouched.
        let before = b"one\n\ntwo\n".to_vec();
        std::fs::write(&file, &before).unwrap();
        let added = add_line(&file, POINTER).unwrap().unwrap();
        assert_eq!(added, Added::default());
        remove_line(&file, POINTER, added).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), before);
        // Lines added after it since: only the line goes.
        let added = add_line(&file, POINTER).unwrap().unwrap();
        let mut edited = std::fs::read(&file).unwrap();
        edited.extend_from_slice(b"mine\n");
        std::fs::write(&file, &edited).unwrap();
        remove_line(&file, POINTER, added).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"one\n\ntwo\nmine\n");
        // A file it made: gone once its lines are; one with the user's lines too: kept.
        let made = dir.path().join("info/exclude");
        let added = add_line(&made, "/a/").unwrap().unwrap();
        assert_eq!(
            added,
            Added {
                created: true,
                joined: false
            }
        );
        let second = add_line(&made, "/b/").unwrap().unwrap();
        assert_eq!(second, Added::default());
        remove_line(&made, "/a/", added).unwrap();
        remove_line(&made, "/b/", added).unwrap();
        assert!(!made.exists());
        add_line(&made, "/a/").unwrap().unwrap();
        std::fs::write(&made, "/a/\n# mine\n").unwrap();
        remove_line(&made, "/a/", added).unwrap();
        assert_eq!(std::fs::read(&made).unwrap(), b"# mine\n");
        // Not UTF-8: read and kept as bytes.
        let bytes = b"\xff\xfe\n".to_vec();
        std::fs::write(&file, &bytes).unwrap();
        let added = add_line(&file, POINTER).unwrap().unwrap();
        remove_line(&file, POINTER, added).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
    }

    #[test]
    fn update_rewrites_only_writ_s_own_skill_files_from_this_writ() {
        let root = tempfile::tempdir().unwrap();
        let plan = Plan {
            folders: vec![
                root.path().join(".claude/skills"),
                root.path().join(".agents/skills"),
            ],
            root: root.path().to_owned(),
            kind: Kind::Repo,
            repos: String::new(),
        };
        install(&plan, None, &mut |_| Ok(())).unwrap();
        let claude = root.path().join(".claude/skills/writ/SKILL.md");
        let agents = root.path().join(".agents/skills/writ/SKILL.md");
        let timings = root.path().join(".claude/skills/writ/timings.md");
        let current = text(Kind::Repo, root.path(), &timings, "");
        assert_eq!(std::fs::read_to_string(&claude).unwrap(), current);
        // Already this writ's: left alone, said so.
        assert_eq!(
            update(&claude, Kind::Repo, &current).unwrap(),
            Updated::Current
        );
        // An older writ's (its mark kept, another text): rewritten, the timings file named.
        let older = current.replace("writ git", "writ old-git");
        assert_ne!(older, current);
        std::fs::write(&agents, &older).unwrap();
        assert_eq!(
            update(&agents, Kind::Repo, &current).unwrap(),
            Updated::Written
        );
        assert_eq!(std::fs::read_to_string(&agents).unwrap(), current);
        assert!(
            current.contains(".claude/skills/writ/timings.md"),
            "{current}"
        );

        // What the record may name that isn't Writ's skill file here: never written.
        let theirs = root.path().join("other/writ/SKILL.md");
        std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
        std::fs::write(&theirs, "their own skill").unwrap();
        assert_eq!(
            update(&theirs, Kind::Repo, &current).unwrap(),
            Updated::Kept(Kept::NotWrits)
        );
        let link = root.path().join("linked/writ/SKILL.md");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&agents, &link).unwrap();
        assert_eq!(
            update(&link, Kind::Repo, "replaced").unwrap(),
            Updated::Kept(Kept::NotASkillPath)
        );
        // Writ's mark, but in the other kind's folder, or not named SKILL.md.
        let workspace = root.path().join("ws/writ-workspace/SKILL.md");
        std::fs::create_dir_all(workspace.parent().unwrap()).unwrap();
        std::fs::write(&workspace, &older).unwrap();
        assert_eq!(
            update(&workspace, Kind::Repo, &current).unwrap(),
            Updated::Kept(Kept::NotASkillPath)
        );
        let named = root.path().join(".claude/skills/writ/notes.md");
        std::fs::write(&named, &older).unwrap();
        assert_eq!(
            update(&named, Kind::Repo, &current).unwrap(),
            Updated::Kept(Kept::NotASkillPath)
        );
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "their own skill");
        assert_eq!(std::fs::read_to_string(&workspace).unwrap(), older);
        assert_eq!(std::fs::read_to_string(&named).unwrap(), older);
        assert_eq!(std::fs::read_to_string(&agents).unwrap(), current);
        assert_eq!(
            update(
                &root.path().join("gone/writ/SKILL.md"),
                Kind::Repo,
                &current
            )
            .unwrap(),
            Updated::Gone
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
        let installed = install(&plan, None, &mut |_| Ok(())).unwrap();
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
