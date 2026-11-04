//! The timings file beside the installed skill (`timings.md`): what the agent learns about
//! sizing its tickets, repository by repository. `writ close` appends each run's figures from
//! the activity report (the daemon's numbers, never the agent's sense of time) and compacts
//! the file with fixed rules; the agent adds short notes. The limits live in the file's front
//! matter, and `writ timings` changes them.
//!
//! The file is the agent's to read and partly to write, so it is untrusted: only what this
//! module can parse back is kept (the front matter, each repository's `summary:`, `runs:` and
//! `notes:`), the rest is rewritten, and every bound holds whatever the file said.
//!
//! ```text
//! ---
//! max_lines: 80
//! max_bytes: 6144
//! keep_runs: 5
//! max_notes: 5
//! ---
//! # Writ timings
//! (a few lines on how to read it)
//!
//! ## omega-code
//! summary: runs=3 used_min=150 used_max_min=70 granted_min=360 …
//! averages: 50m used of 2h granted; 4 signatures, 2 pushes; …
//! runs:
//! - 2026-11-04 wrt_…: used 52m of 2h (closed); estimate 55m (…); …
//! notes:
//! - remote CI takes about 25 minutes a round
//! ```

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, bail};
use writ_proto::Report;

use crate::display::duration;

/// A phase the agent can mark the end of (`writ mark <phase>`), as in `ticket.estimate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Coding,
    Checks,
    Ci,
}

impl Phase {
    pub const ALL: [Phase; 3] = [Phase::Coding, Phase::Checks, Phase::Ci];

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Coding => "coding",
            Phase::Checks => "checks",
            Phase::Ci => "ci",
        }
    }
}

impl std::str::FromStr for Phase {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        Phase::ALL
            .into_iter()
            .find(|p| p.as_str() == text)
            .ok_or_else(|| format!("unknown phase {text:?} (coding, checks, ci)"))
    }
}

/// The limits of a timings file (its front matter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_lines: usize,
    pub max_bytes: usize,
    pub keep_runs: usize,
    pub max_notes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_lines: 80,
            max_bytes: 6 * 1024,
            keep_runs: 5,
            max_notes: 5,
        }
    }
}

/// Each limit's name and bounds: a value outside them is refused by `writ timings`, and read
/// as the default from a file.
pub const BOUNDS: [(&str, usize, usize); 4] = [
    ("max_lines", 20, 1_000),
    ("max_bytes", 1_024, 64 * 1024),
    ("keep_runs", 1, 50),
    ("max_notes", 0, 50),
];

impl Limits {
    fn get(&self, name: &str) -> Option<usize> {
        match name {
            "max_lines" => Some(self.max_lines),
            "max_bytes" => Some(self.max_bytes),
            "keep_runs" => Some(self.keep_runs),
            "max_notes" => Some(self.max_notes),
            _ => None,
        }
    }

    /// Sets `name` to `value`, within its bounds.
    pub fn set(&mut self, name: &str, value: usize) -> Result<(), String> {
        let Some((_, low, high)) = BOUNDS.iter().find(|(n, _, _)| *n == name) else {
            return Err(format!("unknown limit {name}"));
        };
        if value < *low || value > *high {
            return Err(format!("{name}: {value}, must be from {low} to {high}"));
        }
        match name {
            "max_lines" => self.max_lines = value,
            "max_bytes" => self.max_bytes = value,
            "keep_runs" => self.keep_runs = value,
            _ => self.max_notes = value,
        }
        Ok(())
    }
}

/// Every run recorded for a repository, added up: what the summary line holds. Times in
/// minutes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub runs: u64,
    pub used_min: u64,
    pub used_max_min: u64,
    pub granted_min: u64,
    pub signatures: u64,
    pub signatures_max: u64,
    pub pushes: u64,
    pub pushes_max: u64,
    pub renewals: u64,
    pub ci_rounds: u64,
    pub ci_min: u64,
    /// The runs whose ticket had an estimate, the minutes estimated, and the minutes they
    /// really took.
    pub estimate_runs: u64,
    pub estimated_min: u64,
    pub estimate_real_min: u64,
}

const SUMMARY_KEYS: [&str; 14] = [
    "runs",
    "used_min",
    "used_max_min",
    "granted_min",
    "signatures",
    "signatures_max",
    "pushes",
    "pushes_max",
    "renewals",
    "ci_rounds",
    "ci_min",
    "estimate_runs",
    "estimated_min",
    "estimate_real_min",
];

impl Summary {
    fn fields(&mut self) -> [&mut u64; 14] {
        [
            &mut self.runs,
            &mut self.used_min,
            &mut self.used_max_min,
            &mut self.granted_min,
            &mut self.signatures,
            &mut self.signatures_max,
            &mut self.pushes,
            &mut self.pushes_max,
            &mut self.renewals,
            &mut self.ci_rounds,
            &mut self.ci_min,
            &mut self.estimate_runs,
            &mut self.estimated_min,
            &mut self.estimate_real_min,
        ]
    }

    fn parse(line: &str) -> Self {
        let mut summary = Self::default();
        for token in line.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            if let Some(at) = SUMMARY_KEYS.iter().position(|k| *k == key)
                && let Some(field) = summary.fields().into_iter().nth(at)
            {
                *field = value;
            }
        }
        summary
    }

    fn line(&self) -> String {
        let mut copy = *self;
        let values: Vec<String> = SUMMARY_KEYS
            .iter()
            .zip(copy.fields())
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        format!("summary: {}", values.join(" "))
    }

    /// The averages, for a reader: regenerated from the summary, never parsed.
    fn averages(&self) -> String {
        let Some(runs) = std::num::NonZeroU64::new(self.runs) else {
            return "averages: no run yet".to_owned();
        };
        let avg = |total: u64| total / runs;
        let minutes = |m: u64| duration(i64::try_from(m.saturating_mul(60)).unwrap_or(i64::MAX));
        let mut text = format!(
            "averages: {} used of {} granted (longest {}); {} signatures, {} pushes; {} renewals in all",
            minutes(avg(self.used_min)),
            minutes(avg(self.granted_min)),
            minutes(self.used_max_min),
            avg(self.signatures),
            avg(self.pushes),
            self.renewals
        );
        if let Some(rounds) = std::num::NonZeroU64::new(self.ci_rounds) {
            let _ = write!(text, "; a CI round {}", minutes(self.ci_min / rounds));
        }
        if self.estimate_runs > 0 && self.estimated_min > 0 {
            let ratio = self.estimate_real_min.saturating_mul(100) / self.estimated_min;
            let _ = write!(text, "; the real time was {ratio}% of the estimates");
        }
        text
    }

    /// Adds one run (a closed lease's report).
    pub fn add(&mut self, report: &Report) {
        let used = report.used_seconds / 60;
        let signatures = u64::from(report.chain.iter().map(|l| l.signatures).sum::<u32>());
        let pushes = u64::from(report.chain.iter().map(|l| l.pushes).sum::<u32>());
        self.runs = self.runs.saturating_add(1);
        self.used_min = self.used_min.saturating_add(used);
        self.used_max_min = self.used_max_min.max(used);
        self.granted_min = self.granted_min.saturating_add(report.granted_seconds / 60);
        self.signatures = self.signatures.saturating_add(signatures);
        self.signatures_max = self.signatures_max.max(signatures);
        self.pushes = self.pushes.saturating_add(pushes);
        self.pushes_max = self.pushes_max.max(pushes);
        let renewals = u64::try_from(report.chain.len().saturating_sub(1)).unwrap_or(u64::MAX);
        self.renewals = self.renewals.saturating_add(renewals);
        let rounds = &report.phases.ci_rounds_seconds;
        self.ci_rounds = self
            .ci_rounds
            .saturating_add(u64::try_from(rounds.len()).unwrap_or(u64::MAX));
        self.ci_min = self
            .ci_min
            .saturating_add(rounds.iter().fold(0u64, |s, r| s.saturating_add(*r)) / 60);
        if let Some(total) = report.estimate.as_ref().and_then(|e| e.total()) {
            self.estimate_runs = self.estimate_runs.saturating_add(1);
            self.estimated_min = self.estimated_min.saturating_add(total.seconds() / 60);
            self.estimate_real_min = self.estimate_real_min.saturating_add(used);
        }
    }
}

/// One repository's section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub summary: Summary,
    pub runs: Vec<String>,
    pub notes: Vec<String>,
}

/// A timings file, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timings {
    pub limits: Limits,
    /// The least recently updated first.
    pub sections: Vec<Section>,
}

/// The longest timings file read: past it, it isn't one `writ close` wrote.
const MAX_READ: u64 = 1024 * 1024;

/// The longest line kept from the file (a run, a note): longer ones are cut.
const MAX_LINE_CHARS: usize = 400;

const INTRO: &str = "# Writ timings

Written by `writ close` from each lease's activity report: the figures are the daemon's.
Read it before writing a ticket, to size `limits.ttl`, the counts and `ticket.estimate`.
Add a note under a repository's `notes:` (one line, starting with `- `) when something
explains the figures; `writ close` keeps the latest ones and rewrites the rest.
";

impl Timings {
    /// Parses a timings file (tolerant: what it can't read is dropped).
    pub fn parse(text: &str) -> Self {
        let mut timings = Timings::default();
        let mut lines = text.lines().peekable();
        if lines.peek().map(|l| l.trim()) == Some("---") {
            lines.next();
            for line in lines.by_ref() {
                if line.trim() == "---" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && let Ok(value) = value.trim().parse::<usize>()
                    && timings.limits.get(key.trim()).is_some()
                {
                    // Out of bounds: the default stays.
                    let _ = timings.limits.set(key.trim(), value);
                }
            }
        }
        #[derive(PartialEq)]
        enum In {
            Nothing,
            Runs,
            Notes,
        }
        let mut list = In::Nothing;
        for line in lines {
            let line = line.trim_end();
            if let Some(name) = line.strip_prefix("## ") {
                timings.sections.push(Section {
                    name: cut(name.trim()),
                    ..Section::default()
                });
                list = In::Nothing;
                continue;
            }
            let Some(section) = timings.sections.last_mut() else {
                continue;
            };
            if let Some(rest) = line.strip_prefix("summary:") {
                section.summary = Summary::parse(rest);
                list = In::Nothing;
            } else if line == "runs:" {
                list = In::Runs;
            } else if line == "notes:" {
                list = In::Notes;
            } else if let Some(item) = line.strip_prefix("- ") {
                match list {
                    In::Runs => section.runs.push(cut(item)),
                    In::Notes => section.notes.push(cut(item)),
                    In::Nothing => {}
                }
            } else if !line.trim().is_empty() {
                list = In::Nothing;
            }
        }
        timings
    }

    /// The file's text.
    pub fn render(&self) -> String {
        let mut out = String::from("---\n");
        for (name, _, _) in BOUNDS {
            let _ = writeln!(out, "{name}: {}", self.limits.get(name).unwrap_or(0));
        }
        out.push_str("---\n");
        out.push_str(INTRO);
        for section in &self.sections {
            let _ = write!(out, "\n## {}\n", section.name);
            let _ = writeln!(out, "{}", section.summary.line());
            let _ = writeln!(out, "{}", section.summary.averages());
            out.push_str("runs:\n");
            for run in &section.runs {
                let _ = writeln!(out, "- {run}");
            }
            out.push_str("notes:\n");
            for note in &section.notes {
                let _ = writeln!(out, "- {note}");
            }
        }
        out
    }

    /// Records a run of `repo` (moved last: the most recently updated), then compacts.
    pub fn record(&mut self, repo: &str, report: &Report, line: String) {
        let at = self.sections.iter().position(|s| s.name == repo);
        let mut section = match at {
            Some(at) => self.sections.remove(at),
            None => Section {
                name: repo.to_owned(),
                ..Section::default()
            },
        };
        section.summary.add(report);
        section.runs.push(cut(&line));
        self.sections.push(section);
        self.compact();
    }

    /// Brings the file within its limits, with fixed rules: each repository keeps its last
    /// `keep_runs` runs and its last `max_notes` notes (the same note once); then, while the
    /// text is over `max_lines` or `max_bytes`, the oldest run of the repository with the
    /// most runs goes, then the oldest note of the one with the most notes, then the least
    /// recently updated repository. Summaries are never cut: they hold every run.
    pub fn compact(&mut self) {
        let limits = self.limits;
        for section in &mut self.sections {
            let extra = section.runs.len().saturating_sub(limits.keep_runs);
            section.runs.drain(..extra);
            let mut seen = Vec::new();
            for note in section.notes.iter().rev() {
                if !seen.contains(note) {
                    seen.push(note.clone());
                }
            }
            seen.reverse();
            let extra = seen.len().saturating_sub(limits.max_notes);
            seen.drain(..extra);
            section.notes = seen;
        }
        loop {
            let text = self.render();
            if text.lines().count() <= limits.max_lines && text.len() <= limits.max_bytes {
                return;
            }
            if let Some(section) = most(&mut self.sections, |s| s.runs.len()) {
                section.runs.remove(0);
            } else if let Some(section) = most(&mut self.sections, |s| s.notes.len()) {
                section.notes.remove(0);
            } else if self.sections.len() > 1 {
                self.sections.remove(0);
            } else {
                return;
            }
        }
    }
}

/// The section with the most of `count` (more than zero), the first of equals.
fn most(sections: &mut [Section], count: impl Fn(&Section) -> usize) -> Option<&mut Section> {
    let best = sections
        .iter()
        .enumerate()
        .filter(|(_, s)| count(s) > 0)
        .max_by(|(i, a), (j, b)| count(a).cmp(&count(b)).then(j.cmp(i)))
        .map(|(i, _)| i)?;
    sections.get_mut(best)
}

/// A line kept from the file: one line, at most [`MAX_LINE_CHARS`] (`…` ending a cut one).
fn cut(text: &str) -> String {
    let one: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    writ_core::text::shown(&one, MAX_LINE_CHARS.saturating_sub(1))
}

/// What `writ close` would change in a timings file, for `writ check`: every line it would
/// drop or rewrite (a line edited outside a repository's `notes:`, a note that isn't one line
/// starting with `- `, a limit out of its bounds), then what compacting would drop. Empty
/// when the file is as `writ close` would leave it.
pub fn problems(text: &str) -> Vec<String> {
    let timings = Timings::parse(text);
    let rendered = timings.render();
    let kept: std::collections::BTreeSet<&str> = rendered.lines().collect();
    let mut problems: Vec<String> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !kept.contains(line.trim_end()))
        .map(|(n, line)| {
            format!(
                "line {}: writ close would drop or rewrite it: {}",
                n.saturating_add(1),
                writ_core::text::shown(&writ_core::text::escaped(line), 120)
            )
        })
        .collect();
    let mut compacted = timings.clone();
    compacted.compact();
    for (before, after) in timings.sections.iter().zip(&compacted.sections) {
        let runs = before.runs.len().saturating_sub(after.runs.len());
        let notes = before.notes.len().saturating_sub(after.notes.len());
        if runs > 0 || notes > 0 {
            problems.push(format!(
                "{}: writ close would drop the {runs} oldest runs and {notes} oldest or repeated \
                 notes (keep_runs {}, max_notes {}, max_lines {}, max_bytes {})",
                writ_core::text::escaped(&before.name),
                timings.limits.keep_runs,
                timings.limits.max_notes,
                timings.limits.max_lines,
                timings.limits.max_bytes
            ));
        }
    }
    let dropped = timings
        .sections
        .len()
        .saturating_sub(compacted.sections.len());
    if dropped > 0 {
        problems.push(format!(
            "writ close would drop the {dropped} least recently updated repositories to fit the limits"
        ));
    }
    problems
}

/// Reads the timings file at `path` (none yet: an empty one).
pub fn read(path: &Path) -> anyhow::Result<Timings> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Timings::default()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut text = String::new();
    file.take(MAX_READ.saturating_add(1))
        .read_to_string(&mut text)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_READ) {
        bail!(
            "{} is larger than {MAX_READ} bytes: not a timings file",
            path.display()
        );
    }
    Ok(Timings::parse(&text))
}

/// Writes the timings file: to a temporary file beside it, then renamed into place.
pub fn write(path: &Path, timings: &Timings) -> anyhow::Result<()> {
    let temporary = path.with_extension("md.tmp");
    std::fs::write(&temporary, timings.render())
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("cannot write {}", path.display()))
}

/// One run, as the timings file records it: the date, the lease, the time used against the
/// time granted, the estimate against the real phases, the counts, and the agent's marks.
pub fn run_line(report: &Report, marks: &[(Phase, u64)], date: &str) -> String {
    let secs = |s: u64| duration(i64::try_from(s).unwrap_or(i64::MAX));
    let mut line = format!(
        "{date} {}: used {} of {} ({})",
        report.lease,
        secs(report.used_seconds),
        secs(report.granted_seconds),
        report.state
    );
    match report
        .estimate
        .as_ref()
        .and_then(|e| e.total().map(|t| (e, t)))
    {
        Some((e, total)) => {
            let phase = |d: Option<writ_core::units::Duration>| {
                d.map_or("—".to_owned(), |d| d.to_string())
            };
            let _ = write!(
                line,
                "; estimate {} (coding {}, checks {}, ci {})",
                secs(total.seconds()),
                phase(e.coding),
                phase(e.checks),
                phase(e.ci)
            );
        }
        None => line.push_str("; no estimate"),
    }
    let phases = &report.phases;
    if let Some(coding) = phases.coding_seconds {
        let _ = write!(line, "; coding {}", secs(coding));
    }
    if !phases.ci_rounds_seconds.is_empty() {
        let rounds: Vec<String> = phases.ci_rounds_seconds.iter().map(|r| secs(*r)).collect();
        let _ = write!(line, "; ci rounds {}", rounds.join(" "));
    }
    if let Some(after) = phases.after_last_push_seconds {
        let _ = write!(line, "; after the last push {}", secs(after));
    }
    let signatures: u32 = report.chain.iter().map(|l| l.signatures).sum();
    let pushes: u32 = report.chain.iter().map(|l| l.pushes).sum();
    let _ = write!(
        line,
        "; {signatures} signatures, {pushes} pushes, {} renewals",
        report.chain.len().saturating_sub(1)
    );
    if !marks.is_empty() {
        let marked: Vec<String> = marks
            .iter()
            .map(|(phase, seconds)| format!("{} {}", phase.as_str(), secs(*seconds)))
            .collect();
        let _ = write!(line, "; marked {}", marked.join(", "));
    }
    line
}

/// The time between the agent's marks (`(unix time, phase)`, in any order), added up per
/// phase: each mark ends a phase that began at the previous mark, or at `start`.
pub fn marked(start: i64, marks: &[(i64, Phase)]) -> Vec<(Phase, u64)> {
    let mut sorted = marks.to_vec();
    sorted.sort();
    let mut totals: Vec<(Phase, u64)> = Vec::new();
    let mut from = start;
    for (at, phase) in sorted {
        let seconds = u64::try_from(at.saturating_sub(from)).unwrap_or(0);
        from = at.max(from);
        match totals.iter_mut().find(|(p, _)| *p == phase) {
            Some((_, total)) => *total = total.saturating_add(seconds),
            None => totals.push((phase, seconds)),
        }
    }
    totals.sort();
    totals
}

#[cfg(test)]
mod tests {
    use super::*;
    use writ_proto::{ChainLink, Count, Phases};

    fn report(used: u64, signatures: u32) -> Report {
        let id: writ_core::names::TicketId = "wrt_01JD8X0000000000000000000A".parse().unwrap();
        let at = writ_core::units::Timestamp::from_unix(1_800_000_000).unwrap();
        Report {
            lease: id.clone(),
            state: writ_core::lease::State::Closed,
            title: "t".to_owned(),
            template: "feature".parse().unwrap(),
            repos: vec!["demo".parse().unwrap()],
            expected_paths: Vec::new(),
            summary: None,
            estimate: Some(writ_core::ticket::Estimate {
                coding: Some(writ_core::units::Duration::from_seconds(1800)),
                checks: None,
                ci: Some(writ_core::units::Duration::from_seconds(600)),
            }),
            chain: vec![ChainLink {
                id,
                state: writ_core::lease::State::Closed,
                created_at: at,
                expires_at: at,
                ended_at: Some(at),
                signatures,
                pushes: 2,
            }],
            granted_seconds: 7200,
            used_seconds: used,
            signatures: Count {
                used: signatures,
                max: 10,
            },
            pushes: Count { used: 2, max: 5 },
            fetches: 0,
            commits: Vec::new(),
            pushed: Vec::new(),
            branches: Vec::new(),
            denials: Vec::new(),
            warnings: Vec::new(),
            phases: Phases {
                approval_wait_seconds: Some(30),
                coding_seconds: Some(1500),
                ci_rounds_seconds: vec![900, 300],
                after_last_push_seconds: Some(60),
            },
            truncated: false,
        }
    }

    #[test]
    fn a_run_is_recorded_and_read_back() {
        let mut timings = Timings::default();
        let r = report(3_000, 4);
        timings.record(
            "demo",
            &r,
            run_line(&r, &[(Phase::Checks, 600)], "2026-11-04"),
        );
        let text = timings.render();
        assert!(
            text.contains(
                "summary: runs=1 used_min=50 used_max_min=50 granted_min=120 signatures=4"
            ),
            "{text}"
        );
        assert!(text.contains("ci rounds 15m00s 5m00s"), "{text}");
        assert!(text.contains("marked checks 10m00s"), "{text}");
        assert!(
            text.contains("the real time was 125% of the estimates"),
            "{text}"
        );
        assert_eq!(Timings::parse(&text), timings);
    }

    #[test]
    fn the_file_stays_within_its_limits_whatever_the_number_of_runs() {
        let mut timings = Timings::default();
        timings.limits.set("max_lines", 100).unwrap();
        timings.limits.set("max_bytes", 16 * 1024).unwrap();
        timings.limits.set("keep_runs", 3).unwrap();
        timings.limits.set("max_notes", 2).unwrap();
        for n in 0..500u64 {
            let r = report(60 * n, 1);
            let repo = format!("repo-{}", n % 7);
            timings.record(&repo, &r, run_line(&r, &[], "2026-11-04"));
            if let Some(section) = timings.sections.last_mut() {
                section.notes.push(format!("note {n}"));
                section.notes.push(format!("note {n}"));
            }
            timings.compact();
            let text = timings.render();
            assert!(text.lines().count() <= 100, "{n}: {}", text.lines().count());
            assert!(text.len() <= timings.limits.max_bytes, "{n}");
            assert!(
                timings
                    .sections
                    .iter()
                    .all(|s| s.runs.len() <= 3 && s.notes.len() <= 2)
            );
        }
        // A summary holds every run of its repository, even the ones no longer listed.
        let last = timings.sections.last().unwrap();
        assert_eq!(last.name, "repo-2");
        assert_eq!(last.summary.runs, 72);
        assert_eq!(timings.sections.len(), 7);
        // The same note once.
        assert!(timings.sections.iter().all(|s| {
            let mut notes = s.notes.clone();
            notes.dedup();
            notes.len() == s.notes.len()
        }));
        // Tighter limits: runs, then notes, then the least recently updated repositories go.
        timings.limits.set("max_lines", 20).unwrap();
        timings.compact();
        let text = timings.render();
        assert!(text.lines().count() <= 20, "{text}");
        assert_eq!(
            timings.sections.last().unwrap().name,
            "repo-2",
            "the latest kept"
        );
        assert!(
            timings
                .sections
                .iter()
                .all(|s| s.runs.is_empty() && s.notes.is_empty())
        );
    }

    #[test]
    fn hostile_or_broken_files_are_read_within_bounds() {
        let text = format!(
            "---\nmax_lines: 5\nkeep_runs: 999999\nmax_notes: x\n---\n## demo\nsummary: runs=2 used_min=abc granted_min=10\nruns:\n- {}\nnotes:\n- a\u{1b}[2Jb\nstray text\n- not a note\n",
            "r".repeat(10_000)
        );
        let timings = Timings::parse(&text);
        // Out of bounds or unreadable: the defaults.
        assert_eq!(timings.limits, Limits::default());
        let section = &timings.sections[0];
        assert_eq!(section.summary.runs, 2);
        assert_eq!(section.summary.used_min, 0);
        assert_eq!(section.summary.granted_min, 10);
        assert!(section.runs[0].chars().count() <= MAX_LINE_CHARS);
        assert_eq!(section.notes, ["a [2Jb"]);
    }

    #[test]
    fn a_file_as_writ_close_leaves_it_has_no_problem_and_edits_are_named() {
        let mut timings = Timings::default();
        let r = report(3_000, 4);
        timings.record("demo", &r, run_line(&r, &[], "2026-11-04"));
        let clean = timings.render();
        assert!(problems(&clean).is_empty(), "{:?}", problems(&clean));
        // A good note: kept.
        let noted = format!("{clean}- CI takes 25 minutes a round\n");
        assert!(problems(&noted).is_empty(), "{:?}", problems(&noted));
        // A note without its dash, a summary edited, a limit out of bounds.
        let edited = noted
            .replace("- CI takes", "CI takes")
            .replace("runs=1 ", "runs=9 x ")
            .replace("keep_runs: 5", "keep_runs: 0");
        let found = problems(&edited);
        // The averages line follows the summary: rewritten with it.
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(
            found[0].starts_with("line 4: writ close would drop or rewrite it: keep_runs: 0"),
            "{found:?}"
        );
        assert!(
            found.iter().any(|p| p.contains("CI takes 25 minutes")),
            "{found:?}"
        );
        // More notes than kept.
        let many = format!("{clean}- a\n- b\n- c\n- d\n- e\n- f\n");
        let found = problems(&many);
        assert_eq!(
            found,
            [
                "demo: writ close would drop the 0 oldest runs and 1 oldest or repeated notes (keep_runs 5, max_notes 5, max_lines 80, max_bytes 6144)"
            ]
        );
    }

    #[test]
    fn limits_are_set_within_their_bounds_only() {
        let mut limits = Limits::default();
        for (name, low, high) in BOUNDS {
            assert!(limits.set(name, low).is_ok());
            assert!(limits.set(name, high).is_ok());
            assert_eq!(
                limits.set(name, high + 1),
                Err(format!(
                    "{name}: {}, must be from {low} to {high}",
                    high + 1
                ))
            );
            if low > 0 {
                assert_eq!(
                    limits.set(name, low - 1),
                    Err(format!("{name}: {}, must be from {low} to {high}", low - 1))
                );
            }
        }
        assert_eq!(
            limits.set("depth", 1),
            Err("unknown limit depth".to_owned())
        );
    }

    #[test]
    fn marks_split_the_time_into_phases() {
        let marks = [
            (1_300, Phase::Ci),
            (1_000, Phase::Checks),
            (1_900, Phase::Ci),
        ];
        assert_eq!(
            marked(400, &marks),
            [(Phase::Checks, 600), (Phase::Ci, 900)]
        );
        assert!(marked(0, &[]).is_empty());
        assert_eq!("checks".parse::<Phase>(), Ok(Phase::Checks));
        assert_eq!(
            "lunch".parse::<Phase>(),
            Err("unknown phase \"lunch\" (coding, checks, ci)".to_owned())
        );
    }
}
