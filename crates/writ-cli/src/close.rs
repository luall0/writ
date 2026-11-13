//! The end of a lease and what the agent learns from it: `writ close` (the lease ended with a
//! summary, its activity report printed and recorded in the timings file), `writ mark` (the
//! end of a phase the daemon can't see), `writ timings` (the timings file's limits) and
//! `writ check` (a ticket file or the timings file checked as written, nothing sent).
//!
//! Marks are the agent's own words about its time: kept in its session's `marks` file, shown
//! as the agent's in the report, never sent to the daemon.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use writ_core::names::TicketId;
use writ_proto::{CLIENT_USER, CloseRequest, Command, Report};

use crate::client::{Endpoint, Session};
use crate::session::{load_key, session_dir, write_file};
use crate::timings::{self, Phase};
use crate::wiring::{self, SessionRef};
use crate::{Exit, Paths, display, workspace};

/// The lease a command is about when none is named: `WRIT_SESSION`, then the one `current`
/// points at.
fn lease_of_session(paths: &Paths) -> anyhow::Result<TicketId> {
    if let Ok(text) = std::env::var("WRIT_SESSION")
        && !text.is_empty()
    {
        return text
            .parse()
            .map_err(|e| anyhow::anyhow!("WRIT_SESSION {}: {e}", display::clean(&text)));
    }
    let link = std::fs::read_link(paths.home.join("sessions").join("current"))
        .context("no lease named, no WRIT_SESSION and no current session on this host")?;
    link.to_string_lossy()
        .parse()
        .map_err(|_| anyhow::anyhow!("sessions/current doesn't point at a lease"))
}

/// The timings file runs are recorded in from the current directory, and the name of the
/// section: a wired repository's own (its registry name), or, in a workspace (its root, or one
/// of its repositories), the workspace's, the section then named by the lease's repositories
/// (`None`).
fn timings_here() -> Option<(PathBuf, Option<String>)> {
    let dir = std::env::current_dir().ok()?;
    if let Ok(Some(wired)) = wiring::load(&dir) {
        let own = wiring::record_entries(&wired.common_dir)
            .ok()??
            .into_iter()
            .find(|(k, _)| k == "skill.timings")
            .map(|(_, v)| PathBuf::from(v));
        if let Some(path) = own {
            return Some((path, Some(wired.repo.to_string())));
        }
    }
    let found = workspace::find(&dir)?;
    Some((found.timings()?, None))
}

/// The section a workspace run goes in: the lease's repositories, sorted, joined with ` + `
/// (`api + web`); one repository's is its own.
fn section_of(report: &Report) -> String {
    let mut repos: Vec<&str> = report.repos.iter().map(|r| r.as_str()).collect();
    repos.sort_unstable();
    repos.dedup();
    repos.join(" + ")
}

/// The lease the repository here, or the workspace here, is pinned to (`writ init --lease`).
fn pinned_here(dir: &Path) -> Option<TicketId> {
    match wiring::load(dir) {
        Ok(Some(wired)) => wired.lease,
        _ => workspace::find(dir).and_then(|w| w.lease),
    }
}

/// The most of a session's `marks` file read: `writ mark` writes about 20 bytes a mark.
const MAX_MARKS_BYTES: u64 = 256 * 1024;

/// The most marks read from one session.
const MAX_MARKS: usize = 10_000;

/// A session's `marks` file, as text: at most [`MAX_MARKS_BYTES`] of it; none when it isn't
/// there, isn't a regular file (a FIFO never holds `writ close` up) or doesn't read.
fn marks_text(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let file = timings::open_regular(path).ok()??;
    let mut text = String::new();
    file.take(MAX_MARKS_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

/// The agent's marks in the sessions of `leases` (`marks`: one `<unix time> <phase>` a line;
/// a line that doesn't read is skipped).
fn read_marks(paths: &Paths, leases: &[TicketId]) -> Vec<(i64, Phase)> {
    let mut marks = Vec::new();
    for lease in leases {
        let Some(text) = marks_text(&session_dir(paths, lease).join("marks")) else {
            continue;
        };
        for line in text.lines().take(MAX_MARKS) {
            if let Some((at, phase)) = line.split_once(' ')
                && let (Ok(at), Ok(phase)) = (at.parse::<i64>(), phase.parse::<Phase>())
            {
                marks.push((at, phase));
            }
        }
    }
    marks
}

/// `writ close [<lease>] --summary <text> [--full]` (`full`: every line of the report's agent
/// text and warnings).
pub async fn close(
    paths: &Paths,
    url: &str,
    lease: Option<&TicketId>,
    summary: &str,
    full: bool,
) -> anyhow::Result<Exit> {
    let id = match lease {
        Some(id) => id.clone(),
        None => lease_of_session(paths)?,
    };
    let dir = session_dir(paths, &id);
    let key = load_key(&dir.join("key"))
        .with_context(|| format!("no session for lease {id} on this host ({})", dir.display()))?;
    let endpoint = Endpoint::parse(url)?;
    let body = writ_proto::encode_body(&CloseRequest {
        summary: summary.to_owned(),
    })?;
    let report: Report = Session::connect(&endpoint, &paths.known_hosts, CLIENT_USER, key)
        .await?
        .run(async |session| {
            Ok(session
                .call(&Command::Close { id: id.clone() }, &body)
                .await??)
        })
        .await?;
    if !dir.join(wiring::ENDED).exists() {
        write_file(&dir.join(wiring::ENDED), format!("{}\n", report.state))?;
    }
    let leases: Vec<TicketId> = report.chain.iter().map(|l| l.id.clone()).collect();
    let start = report.chain.first().map_or(0, |l| l.created_at.unix());
    let marks = timings::marked(start, &read_marks(paths, &leases));
    // A lease is closed once: what the report cuts, the approver's `writ report` shows (the
    // review after M7.6, U-5).
    let command = format!("writ report {id} --full");
    print!(
        "{}",
        display::report(&report, &marks, display::Rows::new(full, &command))
    );
    match timings_here() {
        Some((path, repo)) => {
            let repo = repo.unwrap_or_else(|| section_of(&report));
            let mut file = timings::read(&path)?;
            let end = report
                .chain
                .last()
                .and_then(|l| l.ended_at)
                .map_or_else(String::new, |t| t.to_string());
            let date = end.get(..10).unwrap_or("");
            file.record(&repo, &report, timings::run_line(&report, &marks, date));
            timings::write(&path, &file)?;
            println!(
                "\nRecorded in {}: add a note under `{}` if something explains these figures.",
                path.display(),
                display::clean(&repo)
            );
        }
        None => println!(
            "\nNo timings file here: run writ close in a repository (or at a workspace root) \
             writ init wired with the skill to record the run."
        ),
    }
    Ok(Exit::Ok)
}

/// `writ mark <phase>`: the end of a phase, in the session the repo here works under.
pub fn mark(paths: &Paths, phase: Phase) -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let pinned = pinned_here(&dir);
    let session = wiring::choose_session(&paths.home, pinned.as_ref())?;
    let session_dir = session.dir(&paths.home);
    let Some(lease) = wiring::lease_id(&session_dir) else {
        bail!("no granted session to mark ({})", session_dir.display());
    };
    if let SessionRef::Current = session
        && let Ok(id) = lease.parse::<TicketId>()
    {
        wiring::check_session(&paths.home, &id)
            .map_err(|why| anyhow::anyhow!("the current lease {id}: {why}"))?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    append(
        &session_dir.join("marks"),
        &format!("{now} {}\n", phase.as_str()),
    )?;
    println!(
        "Marked the end of {} under lease {lease} (shown as yours in the report).",
        phase.as_str()
    );
    Ok(Exit::Ok)
}

fn append(path: &Path, line: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))
}

/// `writ timings`: the limits of the timings file of the repository here, changed as asked,
/// then the file compacted to them; prints them and its size.
pub fn timings(set: &[(&str, Option<usize>)]) -> anyhow::Result<Exit> {
    let Some((path, _)) = timings_here() else {
        bail!("no timings file here: writ init installs one with the skill");
    };
    let mut file = timings::read(&path)?;
    for (name, value) in set {
        if let Some(value) = value {
            file.limits
                .set(name, *value)
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }
    file.compact();
    timings::write(&path, &file)?;
    let text = file.render();
    println!("{}", path.display());
    let limits = file.limits;
    println!(
        "  max_lines {}, max_bytes {}, keep_runs {}, max_notes {}",
        limits.max_lines, limits.max_bytes, limits.keep_runs, limits.max_notes
    );
    println!(
        "  {} lines, {} bytes, {} repositories",
        text.lines().count(),
        text.len(),
        file.sections.len()
    );
    Ok(Exit::Ok)
}

/// Whether `file` is the timings file the wiring here records (whatever its text says).
fn is_timings_here(file: &Path) -> bool {
    let Some((recorded, _)) = timings_here() else {
        return false;
    };
    match (std::fs::canonicalize(file), std::fs::canonicalize(recorded)) {
        (Ok(file), Ok(recorded)) => file == recorded,
        _ => false,
    }
}

/// The largest file `writ check` reads: a ticket's bound on the wire ([`writ_proto::MAX_BODY`]).
const MAX_CHECKED: u64 = writ_proto::MAX_BODY as u64;

/// `writ check <file>`: a ticket file checked as far as it can be without the daemon, or a
/// timings file (its front matter names a limit, or it is the one the wiring here records)
/// checked for what `writ close` would drop or rewrite. A ticket may start with YAML's `---`
/// too: that alone doesn't make a timings file. Sends nothing, changes nothing; exit 3 with
/// every problem when there are some.
pub fn check(file: &Path) -> anyhow::Result<Exit> {
    check_with(file, is_timings_here)
}

/// [`check`], `here` saying whether a file is the timings file the wiring here records.
fn check_with(file: &Path, here: impl Fn(&Path) -> bool) -> anyhow::Result<Exit> {
    use std::io::Read as _;
    let mut text = String::new();
    let reader: Box<dyn std::io::Read> = if file == Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(
            std::fs::File::open(file).with_context(|| format!("cannot read {}", file.display()))?,
        )
    };
    reader
        .take(MAX_CHECKED.saturating_add(1))
        .read_to_string(&mut text)
        .with_context(|| format!("cannot read {} (UTF-8 text)", file.display()))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_CHECKED) {
        println!(
            "{}: larger than {MAX_CHECKED} bytes, the most a ticket may be",
            file.display()
        );
        return Ok(Exit::Rejected);
    }
    let timings_file = timings::looks_like_one(&text) || here(file);
    let (what, problems) = if timings_file {
        ("timings file", timings::problems(&text))
    } else {
        let problems = match writ_core::ticket::TicketRequest::from_yaml(&text) {
            Ok(request) => writ_core::fit::check_request(&request),
            Err(e) => vec![e.to_string()],
        };
        ("ticket file", problems)
    };
    let shown = display::clean(&file.display().to_string());
    if problems.is_empty() {
        println!("{shown}: a well-formed {what}.");
        if !timings_file {
            println!(
                "The daemon also checks what only it knows: the templates (which one it fits), \
                 the leases it amends, renews or revises, its min_ttl and its limits."
            );
        }
        return Ok(Exit::Ok);
    }
    println!("{shown}: {} problems in this {what}:", problems.len());
    for problem in &problems {
        println!("  - {}", display::clean(problem));
    }
    Ok(Exit::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ticket as the skill shows one, after YAML's document marker.
    const TICKET: &str = "---\nrepos:\n  demo:\n    operations: [fetch, commit_sign, push]\n    \
                          branches: [\"agent/x\"]\nticket:\n  title: A title\n  task: A task\n\
                          limits:\n  ttl: 1h\n";

    #[test]
    fn a_ticket_starting_with_yaml_s_marker_is_checked_as_a_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let ticket = dir.path().join("ticket.yaml");
        std::fs::write(&ticket, TICKET).unwrap();
        assert!(!timings::looks_like_one(TICKET));
        assert_eq!(check_with(&ticket, |_| false).unwrap(), Exit::Ok);
        // The same with a problem: named as a ticket's, exit 3.
        std::fs::write(&ticket, TICKET.replace("ttl: 1h", "ttl: soon")).unwrap();
        assert_eq!(check_with(&ticket, |_| false).unwrap(), Exit::Rejected);
        // A timings file is still one.
        let file = dir.path().join("timings.md");
        std::fs::write(&file, timings::Timings::default().render()).unwrap();
        assert_eq!(check_with(&file, |_| false).unwrap(), Exit::Ok);
    }

    #[test]
    fn marks_are_read_bounded_and_never_from_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let marks = dir.path().join("marks");
        assert_eq!(marks_text(&marks), None);
        std::fs::write(&marks, "1800000000 coding\n").unwrap();
        assert_eq!(marks_text(&marks).as_deref(), Some("1800000000 coding\n"));
        // Past the bound: only the bound read.
        let line = "1800000000 checks\n";
        let many = line.repeat(usize::try_from(MAX_MARKS_BYTES).unwrap() / line.len() + 10);
        std::fs::write(&marks, &many).unwrap();
        let read = marks_text(&marks).unwrap();
        assert_eq!(read.len() as u64, MAX_MARKS_BYTES);
        std::fs::remove_file(&marks).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&marks)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(marks_text(&marks), None, "a FIFO: not waited on");
    }
}
