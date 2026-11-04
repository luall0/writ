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
use crate::{Exit, Paths, display};

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

/// The timings file the repository in the current directory records runs in, and the name of
/// its section (the repo's registry name).
fn timings_here() -> Option<(PathBuf, String)> {
    let dir = std::env::current_dir().ok()?;
    let wired = wiring::load(&dir).ok()??;
    let record = wiring::record_path(&dir).ok()?;
    let entries = wiring::read_file(&dir, &record).ok()?;
    let path = entries
        .iter()
        .find(|(k, _)| k == "skill.timings")
        .map(|(_, v)| PathBuf::from(v))?;
    Some((path, wired.repo.to_string()))
}

/// The agent's marks in the sessions of `leases` (`marks`: one `<unix time> <phase>` a line;
/// a line that doesn't read is skipped).
fn read_marks(paths: &Paths, leases: &[TicketId]) -> Vec<(i64, Phase)> {
    let mut marks = Vec::new();
    for lease in leases {
        let Ok(text) = std::fs::read_to_string(session_dir(paths, lease).join("marks")) else {
            continue;
        };
        for line in text.lines().take(10_000) {
            if let Some((at, phase)) = line.split_once(' ')
                && let (Ok(at), Ok(phase)) = (at.parse::<i64>(), phase.parse::<Phase>())
            {
                marks.push((at, phase));
            }
        }
    }
    marks
}

/// `writ close [<lease>] --summary <text>`.
pub async fn close(
    paths: &Paths,
    url: &str,
    lease: Option<&TicketId>,
    summary: &str,
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
    print!("{}", display::report(&report, &marks, false));
    match timings_here() {
        Some((path, repo)) => {
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
            "\nNo timings file here: run writ close in a repository writ init wired with the \
             skill to record the run."
        ),
    }
    Ok(Exit::Ok)
}

/// `writ mark <phase>`: the end of a phase, in the session the repo here works under.
pub fn mark(paths: &Paths, phase: Phase) -> anyhow::Result<Exit> {
    let dir = std::env::current_dir().context("cannot read the current directory")?;
    let pinned = wiring::load(&dir).ok().flatten().and_then(|w| w.lease);
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

/// The largest file `writ check` reads: a ticket's bound on the wire ([`writ_proto::MAX_BODY`]).
const MAX_CHECKED: u64 = writ_proto::MAX_BODY as u64;

/// `writ check <file>`: a ticket file checked as far as it can be without the daemon, or a
/// timings file (it starts with front matter) checked for what `writ close` would drop or
/// rewrite. Sends nothing, changes nothing; exit 3 with every problem when there are some.
pub fn check(file: &Path) -> anyhow::Result<Exit> {
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
    let timings_file = text.lines().next().map(str::trim) == Some("---");
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
