//! The trusted display: how `writ sign` shows a ticket before it is signed.
//!
//! Everything the agent wrote (title, task, plan, expected paths, origin hint, the caller's
//! executable) is untrusted. Before it reaches the terminal, [`clean`] turns every character
//! that could move the cursor, recolor, hide or reorder text into a visible `\u{…}` escape,
//! and multi-line text is printed behind a gutter (`│`) on every line, so agent text can
//! never pass for a line `writ sign` wrote itself. Warnings come from `writ sign`, never from
//! the ticket.
//!
//! The display is bounded in both directions. Every row it prints fits [`WIDTH`] columns (a
//! non-ASCII character counted as two), so a terminal of 80 columns never wraps one: a long
//! line is cut into rows here, each continuation behind the gutter, and a row the terminal
//! wrapped can't start with agent text that reads like a line of `writ sign`'s (the review
//! after M5.5, S2). Each agent field shows at most [`MAX_BLOCK_LINES`] rows (runs of blank
//! lines collapsed) unless `--full` is asked, then how many more and the command that shows
//! them ([`Rows`]); an enforced term is never cut, the expected paths included (the review
//! after M7.6, U-1: the agent chose which paths fell past row 40). The enforced terms are
//! repeated in a summary of one row each right before the prompt ([`summary`]), so no
//! amount of agent text can push what gets signed off the screen.
//!
//! Every field of a ticket is displayed: [`ticket`] and [`summary`] destructure its types
//! with no `..` and [`Field`]'s matches have no catch-all arm, so a field added to the ticket
//! doesn't compile until it is placed, and a test changes every leaf of a ticket's canonical
//! JSON and checks the display changes (the review after M7.6, U-4).

use std::fmt::Write as _;

pub mod doc;

pub use doc::{Doc, Out, SectionKind, Tag};

use writ_core::lease::State;
use writ_core::ticket::{
    Common, Limits, OnViolation, RepoLimits, RepoTerms, Subject, Ticket, TicketText,
};
use writ_core::units::Timestamp;

/// The gutter in front of every line of agent-written text.
pub const GUTTER: &str = "│ ";

/// The most rows one agent field shows without `--full`.
pub const MAX_BLOCK_LINES: usize = 40;

/// The widest row the display prints, in columns: an 80-column terminal never wraps it.
pub const WIDTH: usize = 78;

/// The columns `c` takes on a terminal, counted high: 1 for ASCII, 2 for anything else (a
/// wide character takes 2, and the rest no more).
fn columns(c: char) -> usize {
    if c.is_ascii() { 1 } else { 2 }
}

/// The columns `text` takes.
pub fn width(text: &str) -> usize {
    text.chars().map(columns).sum()
}

/// One line of text (already [`clean`]ed) cut into rows of at most `width` columns (at least
/// one row, possibly empty), between words: a row ends at its last space (the space itself
/// not shown), and only a word longer than a row is cut inside, so a name or an id is never
/// shown as two (`ABCDE123` then `45`).
pub(crate) fn cut(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = vec![String::new()];
    let mut used = 0;
    for c in text.chars() {
        let w = columns(c);
        if used > 0 && used + w > width {
            let carried = match rows.last_mut() {
                // The break falls on a space: it ends the row.
                _ if c == ' ' => String::new(),
                // The word being written moves down whole, after the row's last space.
                Some(row) => match row.rfind(' ') {
                    Some(at) if at > 0 => {
                        let word = row.split_off(at + 1);
                        row.pop();
                        word
                    }
                    _ => String::new(),
                },
                None => String::new(),
            };
            used = self::width(&carried);
            rows.push(carried);
            if c == ' ' {
                continue;
            }
        }
        if let Some(row) = rows.last_mut() {
            row.push(c);
        }
        used += w;
    }
    rows
}

/// `text` (already [`clean`]ed) as one row of at most `width` columns: cut, with `…` and
/// `more` when it doesn't fit.
pub(crate) fn one_row(text: &str, width: usize, more: &str) -> String {
    if self::width(text) <= width {
        return text.to_owned();
    }
    let tail = format!("… {more}");
    let room = width.saturating_sub(self::width(&tail));
    let mut out = cut(text, room).into_iter().next().unwrap_or_default();
    out.push_str(&tail);
    out
}

/// A labelled row (`  label              value`), the value cut into rows that fit [`WIDTH`]:
/// each continuation indented under the value, behind the gutter.
fn labelled(out: &mut String, label: &str, value: &str) {
    rows_after(out, &format!("  {label:<18} "), value);
}

/// `value` after `head`, cut into rows that fit [`WIDTH`]: each continuation indented under
/// the value, behind the gutter.
pub(crate) fn rows_after(out: &mut String, head: &str, value: &str) {
    // A value that fits after the head is one row as it is.
    if width(head) + width(value) <= WIDTH {
        let _ = writeln!(out, "{head}{value}");
        return;
    }
    let rest = format!("{}{GUTTER}", " ".repeat(width(head)));
    let mut rows = cut(value, WIDTH.saturating_sub(width(&rest))).into_iter();
    let _ = writeln!(out, "{head}{}", rows.next().unwrap_or_default());
    for row in rows {
        let _ = writeln!(out, "{rest}{row}");
    }
}

/// Agent text made safe for one line of the terminal: every hidden character as `\u{…}`
/// (newlines included), and `\` as `\\`, so a typed `\u{1b}` can't pass for an escaped one.
pub fn clean(text: &str) -> String {
    writ_core::text::escaped(text)
}

/// Text from outside the program (a daemon's error, a tool's stderr) for the terminal: each
/// line [`clean`]ed, the line breaks kept. Nothing from elsewhere reaches the terminal raw.
pub fn clean_lines(text: &str) -> String {
    text.lines().map(clean).collect::<Vec<_>>().join("\n")
}

/// How many rows of agent text a field shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rows<'a> {
    /// Every row (`--full`).
    All,
    /// At most [`MAX_BLOCK_LINES`], then how many more and `full`, the command that shows
    /// them all (`writ sign wrt_… --full`): never a command that can't.
    Cut { full: &'a str },
}

impl<'a> Rows<'a> {
    /// Every row when `full`, else cut, `command` showing the rest.
    pub fn new(full: bool, command: &'a str) -> Self {
        if full {
            Self::All
        } else {
            Self::Cut { full: command }
        }
    }

    /// How many of `rows` rows are shown.
    fn limit(self, rows: usize) -> usize {
        match self {
            Self::All => rows,
            Self::Cut { .. } => rows.min(MAX_BLOCK_LINES),
        }
    }

    /// After a field cut at `shown` of `rows` rows: how many more, and the command that shows
    /// them, each on a row of its own within [`WIDTH`] (the command takes a row of its own:
    /// with a ticket id, it doesn't fit beside the count).
    fn more(self, out: &mut String, indent: &str, shown: usize, rows: usize) {
        if let Self::Cut { full } = self
            && shown < rows
        {
            let _ = writeln!(
                out,
                "{indent}… {} more lines not shown",
                rows.saturating_sub(shown)
            );
            let _ = writeln!(
                out,
                "{}",
                one_row(&format!("{indent}  ({full} shows them)"), WIDTH, "")
            );
        }
    }
}

/// Agent text over several lines, each behind the gutter and indented, cut into rows that
/// fit [`WIDTH`] (each row behind the gutter too): runs of blank lines shown as one, and,
/// unless every row is asked, at most [`MAX_BLOCK_LINES`] rows, then how many more.
pub fn block(text: &str, indent: &str, shown: Rows) -> String {
    let room = WIDTH.saturating_sub(width(indent) + width(GUTTER));
    let rows: Vec<String> = block_lines(text)
        .iter()
        .flat_map(|line| cut(line, room))
        .collect();
    gutter_rows(&rows, indent, shown)
}

/// The lines of agent text as [`block`] shows them, before they are cut into rows: each
/// [`clean`]ed, runs of blank lines as one.
fn block_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let blank = line.trim().is_empty();
        if blank && lines.last().is_some_and(|l| l.trim().is_empty()) {
            continue;
        }
        lines.push(line);
    }
    lines.iter().map(|line| clean(line)).collect()
}

/// [`block`]'s text in `out`, and the same lines as one row of the structure.
fn agent_block(out: &mut Out, label: &str, text: &str, indent: &str, shown: Rows, tag: Tag) {
    out.text.push_str(&block(text, indent, shown));
    out.row(Some(label), &block_lines(text).join("\n"), tag);
}

/// A labelled row in the text ([`labelled`]) and the structure.
fn labelled_row(out: &mut Out, label: &str, value: &str, tag: Tag) {
    labelled(&mut out.text, label, value);
    out.row(Some(label), value, tag);
}

/// `rows` behind `indent` and the gutter, as many as `shown` says, then how many more.
fn gutter_rows(rows: &[String], indent: &str, shown: Rows) -> String {
    let limit = shown.limit(rows.len());
    let mut out = String::new();
    for row in rows.iter().take(limit) {
        let _ = writeln!(out, "{indent}{GUTTER}{row}");
    }
    shown.more(&mut out, indent, limit, rows.len());
    out
}

/// Agent-chosen items, each quoted: `"a", "b"`. A quote inside an item is escaped (`\"`),
/// and [`clean`] already doubled every backslash, so two different lists never read the same.
pub fn quoted(items: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    let items: Vec<String> = items
        .into_iter()
        .map(|i| format!("\"{}\"", clean(i.as_ref()).replace('"', "\\\"")))
        .collect();
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
}

/// Items joined by `, `, or `(none)`. Each item is [`clean`]ed: names validated by
/// `writ-core` can still hold characters a terminal would act on (an email's bidi control).
pub fn list(items: impl IntoIterator<Item = impl ToString>) -> String {
    let items: Vec<String> = items.into_iter().map(|i| clean(&i.to_string())).collect();
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
}

/// `writ ls`: per ticket, a row with its id, state, revision, template and time left; a row
/// with its repos (and the lease it amends); then its title behind the gutter. Every row fits
/// [`WIDTH`].
pub fn listing(listing: &writ_proto::Listing, now: Timestamp) -> String {
    let mut out = String::new();
    for t in &listing.tickets {
        let left = match t.state {
            State::Pending | State::Active => {
                format!("{} left", duration(now.seconds_until(t.expires_at)))
            }
            _ => String::new(),
        };
        let lease = if t.lease != t.id {
            format!(" (amends {})", t.lease)
        } else {
            String::new()
        };
        // `as_str`: `State`'s `Display` doesn't pad.
        let head = format!("{}  {:<9} r{}  ", t.id, t.state.as_str(), t.revision);
        let templates = clean(
            &t.templates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        // Every template shown, the rows past the first behind the gutter: nothing cut, so
        // no hint names a command (the review after M7.6, U-5: it named `writ show`, which
        // isn't one).
        rows_after(
            &mut out,
            &head,
            format!("{templates:<14} {left}").trim_end(),
        );
        let repos = t
            .repos
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        rows_after(&mut out, "    repos ", &clean(&format!("{repos}{lease}")));
        out.push_str(&block(&t.title, "    ", Rows::All));
    }
    out
}

/// `2h05m`, `45s`.
pub fn duration(seconds: i64) -> String {
    if seconds <= 0 {
        return "0s".to_owned();
    }
    let (h, m, s) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m{s:02}s"),
        _ => format!("{h}h{m:02}m"),
    }
}

/// A field of a ticket, as `writ sign` shows it and diffs compare it: the lease's, or one
/// repository's ([`RepoField`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ExpiresAt,
    SessionKey,
    OriginHint,
    Caller,
    Repos,
    CommitterEmails,
    CommitterName,
    SigningKey,
    MaxOpsPerMinute,
    OnViolation,
    Title,
    Task,
    Plan,
    Estimate,
    /// One repository's term, over every repository.
    Repo(RepoField),
}

/// A field of one repository's terms (`repos.<repo>.…`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoField {
    Template,
    Operations,
    Branches,
    ForcePush,
    ExpectedPaths,
    MaxSignatures,
    MaxPushes,
    MaxPushSize,
}

impl RepoField {
    /// Every one, in the order a repository's block shows them.
    pub const ALL: [Self; 8] = [
        Self::Template,
        Self::Operations,
        Self::Branches,
        Self::ForcePush,
        Self::MaxSignatures,
        Self::MaxPushes,
        Self::MaxPushSize,
        Self::ExpectedPaths,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::Operations => "operations",
            Self::Branches => "branches",
            Self::ForcePush => "force push",
            Self::ExpectedPaths => "expected paths",
            Self::MaxSignatures => "max signatures",
            Self::MaxPushes => "max pushes",
            Self::MaxPushSize => "max push size",
        }
    }
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Self::ExpiresAt => "expires at",
            Self::SessionKey => "session key",
            Self::OriginHint => "origin hint",
            Self::Caller => "caller",
            Self::Repos => "repos",
            Self::CommitterEmails => "committer emails",
            Self::CommitterName => "committer name",
            Self::SigningKey => "signing key",
            Self::MaxOpsPerMinute => "max ops per minute",
            Self::OnViolation => "on violation",
            Self::Title => "title",
            Self::Task => "task",
            Self::Plan => "plan",
            Self::Estimate => "estimate",
            Self::Repo(field) => field.label(),
        }
    }

    /// Whether the field is the agent's words (its prose, its claims), which the display
    /// bounds in rows; every other field is an enforced term, never cut.
    pub fn agent_written(self) -> bool {
        match self {
            Self::OriginHint | Self::Title | Self::Task | Self::Plan | Self::Estimate => true,
            Self::ExpiresAt
            | Self::SessionKey
            | Self::Caller
            | Self::Repos
            | Self::CommitterEmails
            | Self::CommitterName
            | Self::SigningKey
            | Self::MaxOpsPerMinute
            | Self::OnViolation
            | Self::Repo(_) => false,
        }
    }
}

/// One repository's value of a field, already [`clean`]ed (one line).
pub fn repo_field(terms: &RepoTerms, field: RepoField) -> String {
    let RepoTerms {
        template,
        operations,
        branches,
        force_push,
        expected_paths,
        limits:
            RepoLimits {
                max_signatures,
                max_pushes,
                max_push_size,
            },
    } = terms;
    match field {
        RepoField::Template => clean(template.as_str()),
        RepoField::Operations => list(operations),
        RepoField::Branches => list(branches),
        RepoField::ForcePush => if *force_push { "yes" } else { "no" }.to_owned(),
        RepoField::ExpectedPaths => quoted(expected_paths.iter().map(|p| p.as_str())),
        RepoField::MaxSignatures => max_signatures.to_string(),
        RepoField::MaxPushes => max_pushes.to_string(),
        RepoField::MaxPushSize => max_push_size.to_string(),
    }
}

/// A per-repository field over the whole ticket, in one line: the value alone for one
/// repository, `api: …; web: …` for several.
fn every_repo(ticket: &Ticket, field: RepoField) -> String {
    if ticket.repos.len() == 1 {
        return ticket
            .repos
            .values()
            .map(|terms| repo_field(terms, field))
            .collect();
    }
    ticket
        .repos
        .iter()
        .map(|(repo, terms)| format!("{repo}: {}", repo_field(terms, field)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A list-valued term's items, for the structure (the popup shows each on its own), each
/// [`clean`]ed as the value shows it: none for a term that isn't a list, or for a
/// per-repository term over several repositories (its value names each repository).
fn items(ticket: &Ticket, field: Field) -> Vec<String> {
    match field {
        Field::Repos => ticket.repos.keys().map(|r| clean(r.as_str())).collect(),
        Field::CommitterEmails => ticket
            .common
            .committer_emails
            .iter()
            .map(|e| clean(e.as_ref()))
            .collect(),
        Field::Repo(f) if ticket.repos.len() == 1 => ticket
            .repos
            .values()
            .next()
            .map(|terms| repo_items(terms, f))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// One repository's list-valued term, item by item ([`items`]).
fn repo_items(terms: &RepoTerms, field: RepoField) -> Vec<String> {
    match field {
        RepoField::Operations => terms
            .operations
            .iter()
            .map(|o| clean(&o.to_string()))
            .collect(),
        RepoField::Branches => terms
            .branches
            .iter()
            .map(|b| clean(&b.to_string()))
            .collect(),
        RepoField::ExpectedPaths => terms
            .expected_paths
            .iter()
            .map(|p| clean(p.as_str()))
            .collect(),
        RepoField::Template
        | RepoField::ForcePush
        | RepoField::MaxSignatures
        | RepoField::MaxPushes
        | RepoField::MaxPushSize => Vec::new(),
    }
}

/// The templates a ticket fits, in a sentence: `template t`, or `templates a, b`.
pub fn templates(ticket: &Ticket) -> String {
    let names: Vec<String> = ticket
        .templates()
        .iter()
        .map(|t| clean(t.as_str()))
        .collect();
    match names.as_slice() {
        [one] => format!("template {one}"),
        _ => format!("templates {}", names.join(", ")),
    }
}

/// Each repository's template, operations and branches in one line, for the agent (the
/// template the daemon chose when the ticket named none):
/// `api (template backend): fetch, push on agent/x; web (template read-only): fetch`.
pub fn repo_terms(ticket: &Ticket) -> String {
    ticket
        .repos
        .iter()
        .map(|(repo, terms)| {
            let branches = if terms.branches.is_empty() {
                String::new()
            } else {
                format!(" on {}", list(&terms.branches))
            };
            format!(
                "{} (template {}): {}{branches}",
                clean(repo.as_str()),
                clean(terms.template.as_str()),
                list(&terms.operations)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// One field's value, already [`clean`]ed (one line).
pub fn field(ticket: &Ticket, field: Field) -> String {
    let common = &ticket.common;
    let limits = &ticket.limits;
    let text = &ticket.text;
    match field {
        Field::ExpiresAt => limits.expires_at.to_string(),
        Field::SessionKey => clean(ticket.subject.session_key.as_str()),
        Field::OriginHint => clean(ticket.subject.origin_hint.as_deref().unwrap_or("(none)")),
        Field::Caller => match &ticket.subject.caller {
            None => "(none)".to_owned(),
            Some(c) => {
                let p = &c.descends_from;
                let identity = p.code_identity.as_ref().map_or(String::new(), |i| {
                    format!(
                        ", signed {} team {}",
                        clean(&i.signing_id),
                        clean(i.team_id.as_deref().unwrap_or("(none)"))
                    )
                });
                // The executable quoted, as the lists are (the review after M7.6, U-9): a path
                // holding ` (pid …, signed …)` can't pass for the row's own words.
                format!(
                    "descends from {} (pid {}, generation {}{identity}), started by writ",
                    quoted([&p.executable]),
                    p.pid,
                    p.generation
                )
            }
        },
        Field::Repos => list(ticket.repos.keys()),
        Field::CommitterEmails => list(&common.committer_emails),
        Field::CommitterName => common
            .committer_name
            .as_ref()
            .map_or("(none: not checked)".to_owned(), |n| clean(n.as_str())),
        Field::SigningKey => common
            .signing_key
            .as_ref()
            .map_or("(none)".to_owned(), |k| clean(k.as_str())),
        Field::MaxOpsPerMinute => limits.max_ops_per_minute.to_string(),
        Field::OnViolation => match ticket.on_violation {
            OnViolation::DenyAndNotify => "deny and notify",
            OnViolation::RevokeLease => "revoke the lease",
        }
        .to_owned(),
        Field::Title => clean(&text.title),
        Field::Task => clean(&text.task),
        Field::Plan => quoted(&text.plan),
        Field::Estimate => estimate(text.estimate.as_ref()),
        Field::Repo(field) => every_repo(ticket, field),
    }
}

/// The agent's estimate in one row (made of durations only: nothing to clean): each phase,
/// and the total.
pub fn estimate(estimate: Option<&writ_core::ticket::Estimate>) -> String {
    let Some(e) = estimate else {
        return "(none)".to_owned();
    };
    let writ_core::ticket::Estimate { coding, checks, ci } = e;
    let phase =
        |d: &Option<writ_core::units::Duration>| d.map_or("—".to_owned(), |d| d.to_string());
    let total = e.total().map_or("—".to_owned(), |d| {
        duration(i64::try_from(d.seconds()).unwrap_or(i64::MAX))
    });
    format!(
        "{total} in all (coding {}, checks {}, ci {})",
        phase(coding),
        phase(checks),
        phase(ci)
    )
}

/// Every field, in the order a diff lists them (the agent's words then printed first, the
/// enforced terms last: [`changes`]).
pub const FIELDS: [Field; 22] = [
    Field::Repo(RepoField::Template),
    Field::ExpiresAt,
    Field::SessionKey,
    Field::OriginHint,
    Field::Caller,
    Field::Repos,
    Field::Repo(RepoField::Operations),
    Field::Repo(RepoField::Branches),
    Field::Repo(RepoField::ForcePush),
    Field::CommitterEmails,
    Field::CommitterName,
    Field::SigningKey,
    Field::Repo(RepoField::MaxSignatures),
    Field::Repo(RepoField::MaxPushes),
    Field::MaxOpsPerMinute,
    Field::Repo(RepoField::MaxPushSize),
    Field::OnViolation,
    Field::Title,
    Field::Task,
    Field::Plan,
    Field::Estimate,
    Field::Repo(RepoField::ExpectedPaths),
];

/// A field that differs between two tickets, each side as [`field`] shows it. For a term
/// that is a set (repos, committer emails, operations, branches, expected paths), the items
/// removed and added too, each as the value shows it: the change is shown as those alone,
/// never as both whole lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub field: Field,
    pub before: String,
    pub after: String,
    /// The set's items in `before` only (empty for a term that isn't a set).
    pub removed: Vec<String>,
    /// The set's items in `after` only.
    pub added: Vec<String>,
    /// How many of the set's items both sides hold.
    pub kept: usize,
    /// Each side's time, for a time (the expiry).
    pub times: Option<(Timestamp, Timestamp)>,
}

impl Changed {
    /// Whether the change is shown item by item: a set's.
    pub fn by_items(&self) -> bool {
        !self.removed.is_empty() || !self.added.is_empty()
    }
}

/// The fields that differ between two tickets.
pub fn diff(before: &Ticket, after: &Ticket) -> Vec<Changed> {
    // A per-repository term over several repositories, or over a repository renamed: each
    // item says its repository (`web: push`), so the sets compare item for item.
    let qualify = before.repos.len() > 1
        || after.repos.len() > 1
        || !before.repos.keys().eq(after.repos.keys());
    FIELDS
        .into_iter()
        .filter_map(|f| {
            let (a, b) = (field(before, f), field(after, f));
            if a == b {
                return None;
            }
            let (removed, added, kept) = match (set(before, f, qualify), set(after, f, qualify)) {
                (Some(old), Some(new)) => (
                    old.difference(&new).cloned().collect(),
                    new.difference(&old).cloned().collect(),
                    old.intersection(&new).count(),
                ),
                _ => (Vec::new(), Vec::new(), 0),
            };
            let times = (f == Field::ExpiresAt)
                .then_some((before.limits.expires_at, after.limits.expires_at));
            Some(Changed {
                field: f,
                before: a,
                after: b,
                removed,
                added,
                kept,
                times,
            })
        })
        .collect()
}

/// A term's items as a set, each as the value shows it (an expected path quoted); with
/// `qualify`, a per-repository term's items each after its repository's name. None for a
/// term that isn't a set. The ticket's lists are sets ([`writ_core::ticket`]): neither the
/// order nor a repetition is a term, so a set difference is the whole change.
fn set(ticket: &Ticket, field: Field, qualify: bool) -> Option<std::collections::BTreeSet<String>> {
    let shown = |f: RepoField, terms: &RepoTerms| -> Vec<String> {
        match f {
            RepoField::ExpectedPaths => terms
                .expected_paths
                .iter()
                .map(|p| quoted([p.as_str()]))
                .collect(),
            _ => repo_items(terms, f),
        }
    };
    match field {
        Field::Repos => Some(ticket.repos.keys().map(|r| clean(r.as_str())).collect()),
        Field::CommitterEmails => Some(
            ticket
                .common
                .committer_emails
                .iter()
                .map(|e| clean(e.as_ref()))
                .collect(),
        ),
        Field::Repo(
            f @ (RepoField::Operations | RepoField::Branches | RepoField::ExpectedPaths),
        ) => Some(
            ticket
                .repos
                .iter()
                .flat_map(|(repo, terms)| {
                    shown(f, terms).into_iter().map(move |item| match qualify {
                        true => format!("{}: {item}", clean(repo.as_str())),
                        false => item,
                    })
                })
                .collect(),
        ),
        _ => None,
    }
}

/// The full display of a ticket waiting for a signature, its agent text as `shown` says.
#[cfg(test)]
pub fn ticket(ticket: &Ticket, state: State, now: Timestamp, shown: Rows) -> String {
    let mut out = Out::default();
    ticket_into(&mut out, ticket, state, now, shown);
    out.text
}

/// [`ticket`] into `out`: its text and its structure, written by the same calls.
pub fn ticket_into(out: &mut Out, ticket: &Ticket, state: State, now: Timestamp, shown: Rows) {
    // Every field placed (the review after M7.6, U-4): one added to the ticket doesn't compile
    // until it is shown. The ones bound to `_` are shown through [`field`].
    let Ticket {
        // One kind, `writ-ticket/3`: nothing to show.
        kind: _,
        id,
        created_at,
        subject:
            Subject {
                session_key: _,
                origin_hint,
                caller: _,
            },
        common:
            Common {
                committer_emails: _,
                committer_name: _,
                signing_key: _,
            },
        repos,
        text:
            TicketText {
                title,
                task,
                plan,
                estimate: _,
                amends,
                renews,
                revises,
                revision,
                previous_feedback,
            },
        limits: Limits {
            expires_at,
            max_ops_per_minute: _,
        },
        on_violation: _,
    } = ticket;
    let kind = if amends.is_some() {
        "Amendment"
    } else if renews.is_some() {
        "Renewal"
    } else {
        "Ticket"
    };
    let _ = writeln!(out.text, "{kind} {id}");
    out.section(SectionKind::Ticket, &format!("{kind} {id}"));
    let _ = writeln!(out.text, "  revision {revision} · {state}");
    out.row(
        Some("revision"),
        &format!("{revision} · {state}"),
        Tag::Context,
    );
    let left = duration(now.seconds_until(*expires_at));
    let _ = writeln!(
        out.text,
        "  created {created_at}, expires {expires_at} (in {left})"
    );
    out.row(Some("created"), &created_at.to_string(), Tag::Context);
    out.at(*created_at);
    out.row(
        Some("expires"),
        &format!("{expires_at} (in {left})"),
        Tag::Enforced,
    );
    out.at(*expires_at);
    if let Some(lease) = amends {
        let _ = writeln!(out.text, "  amends lease {lease}");
        out.row(Some("amends lease"), lease.as_ref(), Tag::Enforced);
    }
    if let Some(lease) = renews {
        let _ = writeln!(out.text, "  renews lease {lease}");
        out.row(Some("renews lease"), lease.as_ref(), Tag::Enforced);
    }
    if let Some(revised) = revises {
        let _ = writeln!(out.text, "  revises ticket {revised}");
        out.row(Some("revises ticket"), revised.as_ref(), Tag::Context);
    }
    let row = |out: &mut Out, f: Field| {
        labelled_row(out, f.label(), &field(ticket, f), Tag::Enforced);
        out.items(items(ticket, f));
    };
    out.text.push_str("\nWho\n");
    out.section(SectionKind::Who, "Who");
    for f in [Field::SessionKey, Field::Caller] {
        row(out, f);
    }
    let _ = writeln!(out.text, "  origin hint (the agent's claim, not checked):");
    agent_block(
        out,
        "origin hint (the agent's claim, not checked)",
        origin_hint.as_deref().unwrap_or("(none)"),
        "    ",
        shown,
        Tag::Agent,
    );
    out.text
        .push_str("\nThe lease (enforced, for every repository)\n");
    out.section(
        SectionKind::Lease,
        "The lease (enforced, for every repository)",
    );
    for f in [
        Field::Repos,
        Field::CommitterEmails,
        Field::CommitterName,
        Field::SigningKey,
        Field::MaxOpsPerMinute,
        Field::OnViolation,
    ] {
        row(out, f);
    }
    for (repo, terms) in repos {
        // A registry name: up to 100 characters, cut like any value.
        let title = format!("Repository {repo} (enforced)");
        let _ = writeln!(out.text, "\n{}", one_row(&clean(&title), WIDTH, "…"));
        out.section(SectionKind::Repository, &clean(&title));
        for f in RepoField::ALL {
            if f != RepoField::ExpectedPaths {
                labelled_row(out, f.label(), &repo_field(terms, f), Tag::Enforced);
                out.items(repo_items(terms, f));
            }
        }
        // Chosen by the agent but enforced by the path check: one quoted item per line, and
        // never cut (the review after M7.6, U-1: the agent chose which paths fell past row
        // 40). The ticket's bounds keep it displayable: 100 paths, 16 KiB, per repository.
        let _ = writeln!(out.text, "  {}", RepoField::ExpectedPaths.label());
        if terms.expected_paths.is_empty() {
            let _ = writeln!(out.text, "    (none: not checked)");
        }
        let paths: Vec<String> = terms
            .expected_paths
            .iter()
            .map(|path| quoted([path.as_str()]))
            .collect();
        let paths = match paths.is_empty() {
            true => "(none: not checked)".to_owned(),
            false => paths.join("\n"),
        };
        out.row(
            Some(RepoField::ExpectedPaths.label()),
            &paths,
            Tag::Enforced,
        );
        out.items(repo_items(terms, RepoField::ExpectedPaths));
        out.tree();
        let room = WIDTH.saturating_sub(4 + width(GUTTER));
        let rows: Vec<String> = terms
            .expected_paths
            .iter()
            .flat_map(|path| cut(&quoted([path.as_str()]), room))
            .collect();
        out.text.push_str(&gutter_rows(&rows, "    ", Rows::All));
    }
    out.text
        .push_str("\nWritten by the agent (untrusted, shown as written)\n");
    out.section(
        SectionKind::Agent,
        "Written by the agent (untrusted, shown as written)",
    );
    out.text.push_str("  title\n");
    agent_block(out, "title", title, "    ", shown, Tag::Agent);
    out.text.push_str("  task\n");
    agent_block(out, "task", task, "    ", shown, Tag::Agent);
    out.text.push_str("  plan\n");
    if plan.is_empty() {
        agent_block(out, "plan", "(none)", "    ", shown, Tag::Agent);
    }
    let plan = plan
        .iter()
        .enumerate()
        .map(|(i, step)| format!("{}. {step}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    if !plan.is_empty() {
        agent_block(out, "plan", &plan, "    ", shown, Tag::Agent);
    }
    let asked = created_at.seconds_until(*expires_at);
    labelled_row(
        out,
        "estimate",
        &format!(
            "{}; the lease asks {}",
            field(ticket, Field::Estimate),
            duration(asked)
        ),
        Tag::Agent,
    );
    if let Some(feedback) = previous_feedback {
        let title = format!(
            "Feedback on revision {} (as recorded by the daemon)",
            revision.saturating_sub(1)
        );
        let _ = writeln!(out.text, "\n{title}");
        out.section(SectionKind::Feedback, &title);
        agent_block(out, "feedback", feedback, "    ", shown, Tag::Context);
    }
}

/// The enforced terms in a few lines, shown last, right before the prompt: whatever the agent
/// wrote above, this is what gets signed.
#[cfg(test)]
pub fn summary(ticket: &Ticket, narrowed: bool) -> String {
    let mut out = Out::default();
    summary_into(&mut out, ticket, narrowed);
    out.text
}

/// [`summary`] into `out`: each term whole in the structure (the app wraps it), cut to one
/// row in the text.
pub fn summary_into(out: &mut Out, ticket: &Ticket, narrowed: bool) {
    // Every field placed (the review after M7.6, U-4): a term added to the ticket doesn't
    // compile until it is in the summary, or said here why not. The ones bound to `_` are
    // repeated through [`field`], or only in the full display above.
    let Ticket {
        kind: _,
        id,
        // Who may use the lease, and the agent's own words: above only.
        created_at: _,
        subject:
            Subject {
                session_key: _,
                origin_hint: _,
                caller: _,
            },
        common:
            Common {
                committer_emails: _,
                committer_name: _,
                // One key for the lease, from its templates: above only.
                signing_key: _,
            },
        repos,
        text:
            TicketText {
                title: _,
                task: _,
                plan: _,
                estimate: _,
                amends: _,
                renews: _,
                revises: _,
                revision: _,
                previous_feedback: _,
            },
        limits: Limits {
            expires_at,
            max_ops_per_minute,
        },
        on_violation: _,
    } = ticket;
    out.text.push_str("\nYou are signing (enforced):\n");
    out.section(SectionKind::Signing, "You are signing (enforced)");
    let _ = writeln!(out.text, "  {id}");
    out.row(Some("ticket"), id.as_ref(), Tag::Enforced);
    // One row each: what doesn't fit says so, and is shown whole above (every enforced term
    // is: none is cut there).
    let room = WIDTH.saturating_sub(21);
    let templates = field(ticket, Field::Repo(RepoField::Template));
    let _ = writeln!(
        out.text,
        "  {:<18} {}",
        "templates",
        one_row(&templates, room, "(see above)")
    );
    out.row(Some("templates"), &templates, Tag::Enforced);
    let _ = writeln!(out.text, "  {:<18} {expires_at}", Field::ExpiresAt.label());
    out.row(
        Some(Field::ExpiresAt.label()),
        &expires_at.to_string(),
        Tag::Enforced,
    );
    out.at(*expires_at);
    for f in [
        Field::Repos,
        Field::Repo(RepoField::Operations),
        Field::Repo(RepoField::Branches),
        Field::Repo(RepoField::ForcePush),
        Field::CommitterEmails,
        Field::CommitterName,
    ] {
        let value = field(ticket, f);
        let _ = writeln!(
            out.text,
            "  {:<18} {}",
            f.label(),
            one_row(&value, room, "(see above)")
        );
        out.row(Some(f.label()), &value, Tag::Enforced);
        out.items(items(ticket, f));
    }
    let paths: usize = repos.values().map(|t| t.expected_paths.len()).sum();
    let whole = if paths == 0 {
        "(none: not checked)".to_owned()
    } else {
        format!(
            "{paths}: {}",
            field(ticket, Field::Repo(RepoField::ExpectedPaths))
        )
    };
    let shown = match paths {
        0 => whole.clone(),
        _ => one_row(&whole, room, "(see above)"),
    };
    let _ = writeln!(
        out.text,
        "  {:<18} {shown}",
        RepoField::ExpectedPaths.label()
    );
    out.row(
        Some(RepoField::ExpectedPaths.label()),
        &whole,
        Tag::Enforced,
    );
    out.items(items(ticket, Field::Repo(RepoField::ExpectedPaths)));
    out.tree();
    // Rows within [`WIDTH`] whatever the numbers: the totals over every repository (`u32`
    // sums, saturating), each repository's counts above.
    let limits = format!(
        "{} signatures, {} pushes, {max_ops_per_minute}/min",
        ticket.max_signatures(),
        ticket.max_pushes(),
    );
    let _ = writeln!(out.text, "  {:<18} {limits}", "limits");
    out.row(Some("limits"), &limits, Tag::Enforced);
    let size = field(ticket, Field::Repo(RepoField::MaxPushSize));
    let _ = writeln!(
        out.text,
        "  {:<18} {}",
        RepoField::MaxPushSize.label(),
        one_row(&size, room, "(see above)")
    );
    out.row(Some(RepoField::MaxPushSize.label()), &size, Tag::Enforced);
    let violation = field(ticket, Field::OnViolation);
    let _ = writeln!(out.text, "  {:<18} {violation}", Field::OnViolation.label());
    out.row(Some(Field::OnViolation.label()), &violation, Tag::Enforced);
    if narrowed {
        out.text.push_str("  (narrowed by you: see above)\n");
        out.row(None, "narrowed by you", Tag::Warning);
    }
}

/// The chain a renewal continues: the original ticket (the task as first signed: agent text,
/// behind the gutter), which renewal this is, the time used so far, and what the renewed
/// lease used.
#[cfg(test)]
pub fn renewal_section(view: &writ_proto::Renewal, original: &Ticket, shown: Rows) -> String {
    let mut out = Out::default();
    renewal_into(&mut out, view, original, shown);
    out.text
}

/// [`renewal_section`] into `out`.
pub fn renewal_into(out: &mut Out, view: &writ_proto::Renewal, original: &Ticket, shown: Rows) {
    let title = format!(
        "Renewal {} of the work started as lease {}",
        view.number, original.id
    );
    let _ = writeln!(out.text, "\n{title}");
    out.section(SectionKind::Renewal, &title);
    labelled_row(
        out,
        "time used so far",
        &format!(
            "{} (every lease of the work together)",
            duration(i64::try_from(view.used_seconds).unwrap_or(i64::MAX))
        ),
        Tag::Context,
    );
    labelled_row(
        out,
        "renewed lease",
        &format!(
            "{}: {}/{} signatures, {}/{} pushes used",
            view.state,
            view.signatures.used,
            view.signatures.max,
            view.pushes.used,
            view.pushes.max
        ),
        Tag::Context,
    );
    out.text
        .push_str("  The original ticket, as you signed it (written by the agent):\n");
    out.text.push_str("  title\n");
    agent_block(
        out,
        "original title",
        &original.text.title,
        "    ",
        shown,
        Tag::Agent,
    );
    out.text.push_str("  task\n");
    agent_block(
        out,
        "original task",
        &original.text.task,
        "    ",
        shown,
        Tag::Agent,
    );
    if !original.text.plan.is_empty() {
        let plan = original
            .text
            .plan
            .iter()
            .enumerate()
            .map(|(i, step)| format!("{}. {step}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        out.text.push_str("  plan\n");
        agent_block(out, "original plan", &plan, "    ", shown, Tag::Agent);
    }
    labelled_row(out, "repos", &field(original, Field::Repos), Tag::Context);
    labelled_row(
        out,
        "branches",
        &field(original, Field::Repo(RepoField::Branches)),
        Tag::Context,
    );
    labelled_row(
        out,
        "expires at",
        &original.limits.expires_at.to_string(),
        Tag::Context,
    );
    out.at(original.limits.expires_at);
}

/// The other active leases from the ticket's source (the daemon's record of where tickets
/// come from): one row each with its id, time left and an overlap flag, then its scope.
#[cfg(test)]
pub fn others(others: &writ_proto::Others, now: Timestamp) -> String {
    let mut out = Out::default();
    others_into(&mut out, others, now);
    out.text
}

/// [`others`] into `out`: a lease that overlaps is a warning row.
pub fn others_into(out: &mut Out, others: &writ_proto::Others, now: Timestamp) {
    if others.shown.is_empty() {
        out.text
            .push_str("\nOther active leases from this source: none\n");
        out.section(
            SectionKind::Others,
            "Other active leases from this source: none",
        );
        return;
    }
    let total = others
        .shown
        .len()
        .saturating_add(usize::try_from(others.more).unwrap_or(usize::MAX));
    let title = format!("Other active leases from this source ({total})");
    let _ = writeln!(out.text, "\n{title}");
    out.section(SectionKind::Others, &title);
    // The flag's meaning once, on a row of its own: every row stays within [`WIDTH`].
    if others.shown.iter().any(|l| l.overlap) {
        out.text
            .push_str("  OVERLAP: a repo in common with this ticket, and branches that meet\n");
    }
    for lease in &others.shown {
        let flag = if lease.overlap { "  OVERLAP" } else { "" };
        let left = duration(now.seconds_until(lease.expires_at));
        let _ = writeln!(out.text, "  {}  {left} left{flag}", lease.id);
        let scope = format!(
            "repos {} · branches {} · {}",
            list(&lease.repos),
            list(&lease.branches),
            list(&lease.operations)
        );
        rows_after(&mut out.text, "    ", &scope);
        let tag = match lease.overlap {
            true => Tag::Warning,
            false => Tag::Context,
        };
        let overlap = match lease.overlap {
            true => " · OVERLAP: a repo in common with this ticket, and branches that meet",
            false => "",
        };
        out.row(
            Some(lease.id.as_ref()),
            &format!("{left} left · {scope}{overlap}"),
            tag,
        );
        out.at(lease.expires_at);
    }
    if others.more > 0 {
        let _ = writeln!(out.text, "  … and {} more (writ ls)", others.more);
        out.row(
            None,
            &format!("… and {} more (writ ls)", others.more),
            Tag::Context,
        );
    }
}

/// An activity report (`writ close`, `writ report`): what the lease and the leases it renews
/// did, from the daemon. The title, the summary and the paths in warnings are the agent's:
/// behind the gutter, escaped. `marks`: the agent's own phase marks (client-side), if any.
pub fn report(
    report: &writ_proto::Report,
    marks: &[(crate::timings::Phase, u64)],
    shown: Rows,
) -> String {
    let secs = |s: u64| duration(i64::try_from(s).unwrap_or(i64::MAX));
    let mut out = format!(
        "Activity report of lease {} ({})\n",
        report.lease, report.state
    );
    out.push_str("  title\n");
    out.push_str(&block(&report.title, "    ", shown));
    labelled(
        &mut out,
        "templates",
        &clean(
            &report
                .templates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
    );
    labelled(&mut out, "repos", &list(&report.repos));
    if report.chain.len() > 1 {
        let ids: Vec<String> = report.chain.iter().map(|l| l.id.to_string()).collect();
        labelled(&mut out, "renewal chain", &ids.join(" → "));
    }
    out.push_str("\nTime\n");
    labelled(
        &mut out,
        "used",
        &format!(
            "{} of {} granted",
            secs(report.used_seconds),
            secs(report.granted_seconds)
        ),
    );
    labelled(&mut out, "estimate", &estimate(report.estimate.as_ref()));
    let phases = &report.phases;
    let opt = |v: Option<u64>| v.map_or("—".to_owned(), secs);
    labelled(
        &mut out,
        "approval wait",
        &opt(phases.approval_wait_seconds),
    );
    labelled(
        &mut out,
        "coding",
        &format!("{} (to the first commit)", opt(phases.coding_seconds)),
    );
    let rounds = if phases.ci_rounds_seconds.is_empty() {
        "none".to_owned()
    } else {
        phases
            .ci_rounds_seconds
            .iter()
            .map(|r| secs(*r))
            .collect::<Vec<_>>()
            .join(", ")
    };
    labelled(
        &mut out,
        "ci rounds",
        &format!("{rounds} (a push to the next commit)"),
    );
    labelled(
        &mut out,
        "after last push",
        &opt(phases.after_last_push_seconds),
    );
    if !marks.is_empty() {
        let marked: Vec<String> = marks
            .iter()
            .map(|(phase, s)| format!("{} {}", phase.as_str(), secs(*s)))
            .collect();
        labelled(&mut out, "agent's marks", &marked.join(", "));
    }
    out.push_str("  (approximate: derived from when commits were signed and pushes went out)\n");
    out.push_str("\nActivity\n");
    labelled(
        &mut out,
        "signatures",
        &format!("{} of {}", report.signatures.used, report.signatures.max),
    );
    labelled(
        &mut out,
        "pushes",
        &format!("{} of {}", report.pushes.used, report.pushes.max),
    );
    labelled(&mut out, "fetches", &report.fetches.to_string());
    labelled(&mut out, "branches", &list(&report.branches));
    let denials: Vec<String> = report
        .denials
        .iter()
        .map(|d| format!("{} ×{}", clean(&d.code), d.count))
        .collect();
    labelled(
        &mut out,
        "denials",
        &if denials.is_empty() {
            "none".to_owned()
        } else {
            denials.join(", ")
        },
    );
    for commit in &report.commits {
        labelled(
            &mut out,
            "commit",
            &format!(
                "{} {} ({})",
                commit.id,
                clean(commit.repo.as_str()),
                commit.signed_at
            ),
        );
    }
    out.push_str("  expected paths\n");
    out.push_str(&block(
        &if report.expected_paths.is_empty() {
            "(none: not checked)".to_owned()
        } else {
            report.expected_paths.join("\n")
        },
        "    ",
        shown,
    ));
    if !report.warnings.is_empty() {
        out.push_str("  warnings (files outside expected_paths)\n");
        out.push_str(&block(&report.warnings.join("\n"), "    ", shown));
    }
    if let Some(summary) = &report.summary {
        out.push_str("\nSummary (written by the agent, untrusted)\n");
        out.push_str(&block(summary, "    ", shown));
    }
    if report.truncated {
        out.push_str("\n(the audit log held more lines for this lease than a report reads)\n");
    }
    out
}

/// A diff section: `title`, then each changed field's label, its value before (`-`) and after
/// (`+`). The agent's words come first, each side bounded in rows as `shown` says (like a
/// [`block`]); the enforced terms come last, nearest the prompt, and are never cut (the review
/// after M7.6, U-2: an amendment's flood of task and plan pushed what it widened far above).
pub fn changes(title: &str, changes: &[Changed], shown: Rows) -> String {
    let mut out = Out::default();
    changes_into(&mut out, title, changes, shown);
    out.text
}

/// [`changes`] into `out`: each side a row, the agent's words tagged as the agent's.
pub fn changes_into(out: &mut Out, title: &str, changes: &[Changed], shown: Rows) {
    out.text.push('\n');
    // Writ's own words, ids in them: cut to fit like any row.
    for row in cut(title, WIDTH) {
        let _ = writeln!(out.text, "{row}");
    }
    out.section(SectionKind::Changes, title);
    if changes.is_empty() {
        out.text.push_str("  (no change)\n");
        out.row(None, "(no change)", Tag::Context);
    }
    // `    - ` or `    │ ` in front: 7 columns at most (`│` counted two).
    let room = WIDTH.saturating_sub(4 + width("│ "));
    let agent = changes.iter().filter(|c| c.field.agent_written());
    let enforced = changes.iter().filter(|c| !c.field.agent_written());
    for change in agent.chain(enforced) {
        let _ = writeln!(out.text, "  {}", change.field.label());
        if change.by_items() {
            // A set: the items removed, then added, each whole (an enforced term is never
            // cut), then how many stay.
            for (sign, items, tag) in [
                ("-", &change.removed, Tag::Removed),
                ("+", &change.added, Tag::Added),
            ] {
                for item in items {
                    for (i, row) in cut(item, room).iter().enumerate() {
                        let mark = if i == 0 { sign } else { "│" };
                        let _ = writeln!(out.text, "    {mark} {row}");
                    }
                    out.row(Some(change.field.label()), item, tag);
                }
            }
            if change.kept > 0 {
                let kept = format!("{} kept", change.kept);
                let _ = writeln!(out.text, "      ({kept})");
                out.row(Some(change.field.label()), &kept, Tag::Context);
            }
            continue;
        }
        let side = match change.field.agent_written() {
            true => shown,
            false => Rows::All,
        };
        let (removed, added) = match change.field.agent_written() {
            true => (Tag::AgentRemoved, Tag::AgentAdded),
            false => (Tag::Removed, Tag::Added),
        };
        for (sign, value, tag) in [("-", &change.before, removed), ("+", &change.after, added)] {
            let rows = cut(value, room);
            let limit = side.limit(rows.len());
            for (i, row) in rows.iter().take(limit).enumerate() {
                let mark = if i == 0 { sign } else { "│" };
                let _ = writeln!(out.text, "    {mark} {row}");
            }
            side.more(&mut out.text, "    ", limit, rows.len());
            out.row(Some(change.field.label()), value, tag);
            if let Some((was, is)) = change.times {
                out.at(if sign == "-" { was } else { is });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use writ_core::text::is_hidden_char;

    #[test]
    fn hidden_characters_are_shown_escaped() {
        assert_eq!(clean("plain text, é ü 日本"), "plain text, é ü 日本");
        assert_eq!(clean("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(clean("x\ry\nz\t"), "x\\u{d}y\\u{a}z\\u{9}");
        assert_eq!(clean("\u{202E}evil\u{2066}"), "\\u{202e}evil\\u{2066}");
        assert_eq!(
            clean("zero\u{200B}width\u{FEFF}"),
            "zero\\u{200b}width\\u{feff}"
        );
        assert_eq!(clean("\u{9b}31m"), "\\u{9b}31m");
        assert_eq!(clean("del\u{7f}"), "del\\u{7f}");
        // A typed escape is not an escape.
        assert_eq!(clean("\\u{1b}"), "\\\\u{1b}");
        assert_ne!(clean("\\u{1b}"), clean("\u{1b}"));
    }

    #[test]
    fn a_hostile_ticket_shows_nothing_a_terminal_would_act_on() {
        use writ_core::canonical::Canonical;
        const FULL: &[u8] = include_bytes!("../../writ-core/tests/fixtures/ticket-full.json");
        let mut t = Ticket::from_canonical(FULL).unwrap();
        let hostile = "x\u{1b}[2J\u{202e}y\u{200b}\r\nScope (enforced)\n  repos  everything\u{9b}";
        t.text.title = hostile.to_owned();
        t.text.task = hostile.to_owned();
        t.text.plan = vec![hostile.to_owned(), hostile.to_owned()];
        t.text.previous_feedback = Some(hostile.to_owned());
        t.subject.origin_hint = Some(hostile.to_owned());
        if let Some(caller) = &mut t.subject.caller {
            caller.descends_from.executable = hostile.to_owned();
        }
        let now = t.created_at;
        let mut shown = ticket(&t, State::Pending, now, Rows::All);
        shown.push_str(&summary(&t, false));
        shown.push_str(&changes(
            "diff",
            &diff(&Ticket::from_canonical(FULL).unwrap(), &t),
            Rows::All,
        ));
        for c in shown.chars() {
            assert!(
                c == '\n' || !is_hidden_char(c),
                "{c:?} reached the terminal"
            );
        }
        // Agent text never starts a line of its own: a forged section header is behind the
        // gutter or inside a field, never at the start of a line.
        for line in shown.lines() {
            assert!(
                !line.starts_with("Scope (enforced)") || !line.contains("everything"),
                "{line:?}"
            );
            assert!(
                !line.trim_start().starts_with("repos  everything"),
                "{line:?}"
            );
        }
        assert!(shown.contains("\\u{1b}[2J"), "escaped, still visible");
    }

    /// `text` with the gutters gone and every run of whitespace one space: how a value cut
    /// into rows reads again as the value.
    fn flat(text: &str) -> String {
        text.replace(GUTTER, " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Everything `writ sign` shows for `t` (its changes from `before` too), text and
    /// structure written together.
    fn shown_both(t: &Ticket, before: &Ticket) -> Out {
        let mut out = Out::default();
        ticket_into(&mut out, t, State::Pending, t.created_at, Rows::All);
        changes_into(&mut out, "Changes", &diff(before, t), Rows::All);
        summary_into(&mut out, t, false);
        out
    }

    /// M7.8: the approval popup shows the structure, the terminal the text; written by the
    /// same calls, they say the same. Every value of the structure is in the text (cut into
    /// rows there; in the summary, the terms the text cuts to one row are whole above), and
    /// every section of the text is a section of the structure.
    #[test]
    fn the_structure_says_what_the_text_says() {
        let before = full_ticket();
        let mut t = full_ticket();
        t.text.task = "A task\n\nover two paragraphs".to_owned();
        omega(&mut t).branches.insert("agent/also".parse().unwrap());
        let out = shown_both(&t, &before);
        let text = flat(&out.text);
        let kinds: Vec<SectionKind> = out.doc.sections.iter().map(|s| s.kind).collect();
        for kind in [
            SectionKind::Ticket,
            SectionKind::Who,
            SectionKind::Lease,
            SectionKind::Repository,
            SectionKind::Agent,
            SectionKind::Changes,
            SectionKind::Signing,
        ] {
            assert!(kinds.contains(&kind), "{kind:?} not in {kinds:?}");
        }
        for section in &out.doc.sections {
            assert!(text.contains(&flat(&section.title)), "{:?}", section.title);
            for row in &section.rows {
                assert!(
                    text.contains(&flat(&row.value)),
                    "{:?} {:?}: {:?} not in the text",
                    section.kind,
                    row.label,
                    row.value
                );
                for item in &row.items {
                    assert!(
                        row.value.contains(item.as_str()),
                        "{item:?} not in {:?}",
                        row.value
                    );
                    assert!(text.contains(item.as_str()), "{item:?} not in the text");
                }
                if let Some(label) = &row.label {
                    // A label of the structure is one of the text's, or the name of a line
                    // the text writes as a sentence (`created …, expires …`).
                    let named = ["revision", "created", "expires", "ticket", "feedback"];
                    assert!(
                        text.contains(label.as_str()) || named.contains(&label.as_str()),
                        "{label:?}"
                    );
                }
            }
        }
        // The agent's lines one by one, blank runs as one, as the text shows them.
        let agent = &out.doc.sections[kinds.iter().position(|k| *k == SectionKind::Agent).unwrap()];
        let task = agent
            .rows
            .iter()
            .find(|r| r.label.as_deref() == Some("task"))
            .unwrap();
        assert_eq!(task.value, "A task\n\nover two paragraphs");
        assert_eq!(task.tag, Tag::Agent);
        // A change: each side a row, after the agent's words; a set's, its items (M7.9.5).
        let changes = &out.doc.sections[kinds
            .iter()
            .position(|k| *k == SectionKind::Changes)
            .unwrap()];
        let tags: Vec<(Option<&str>, Tag)> = changes
            .rows
            .iter()
            .map(|r| (r.label.as_deref(), r.tag))
            .collect();
        assert_eq!(
            tags,
            [
                (Some("task"), Tag::AgentRemoved),
                (Some("task"), Tag::AgentAdded),
                (Some("branches"), Tag::Added),
                (Some("branches"), Tag::Context),
            ]
        );
    }

    /// M7.8: the popup styles rows by their tag, so agent text must never land in a row of
    /// Writ's words: a hostile ticket's text is only in rows tagged as the agent's, or in a
    /// value where it is quoted (the caller's executable) or recorded as said (the feedback).
    #[test]
    fn agent_text_is_only_ever_in_the_agent_s_rows() {
        let before = full_ticket();
        let mut t = full_ticket();
        let hostile = "x\u{1b}[2J\nYou are signing (enforced)\n  repos  everything";
        t.text.title = hostile.to_owned();
        t.text.task = hostile.to_owned();
        t.text.plan = vec![hostile.to_owned()];
        t.text.previous_feedback = Some(hostile.to_owned());
        t.subject.origin_hint = Some(hostile.to_owned());
        if let Some(caller) = &mut t.subject.caller {
            caller.descends_from.executable = hostile.to_owned();
        }
        let out = shown_both(&t, &before);
        let mut seen = 0;
        for section in &out.doc.sections {
            // A title is Writ's words: never the agent's.
            assert!(!section.title.contains("everything"), "{:?}", section.title);
            for row in &section.rows {
                if !row.value.contains("everything") {
                    continue;
                }
                seen += 1;
                let quoted = row.label.as_deref() == Some("caller") && row.value.contains("\"x");
                let said = row.label.as_deref() == Some("feedback");
                assert!(
                    row.tag.is_agent() || quoted || said,
                    "{:?} {:?} {:?}",
                    section.kind,
                    row.label,
                    row.tag
                );
                // Escaped, like the text: nothing a renderer would act on.
                assert!(!row.value.contains('\u{1b}'), "{:?}", row.value);
            }
        }
        // title, task, plan, origin hint, feedback, caller, and the changes' sides.
        assert!(seen >= 6, "{seen}");
    }

    /// The review after M7.6 (U-9): the caller's executable was shown unquoted, so a path
    /// holding the row's own words read as a signed harness.
    #[test]
    fn the_caller_s_executable_is_quoted_and_can_t_pass_for_the_row_s_words() {
        let mut t = full_ticket();
        let forged = "/tmp/claude (pid 811, generation 3, signed com.vendor.app team ABCDE12345)/x";
        let caller = t.subject.caller.as_mut().unwrap();
        caller.descends_from.executable = forged.to_owned();
        caller.descends_from.code_identity = None;
        let (pid, generation) = (caller.descends_from.pid, caller.descends_from.generation);
        assert_eq!(
            field(&t, Field::Caller),
            format!(
                "descends from \"{forged}\" (pid {pid}, generation {generation}), started by writ"
            )
        );
        caller_with_quote(&mut t);
        assert!(field(&t, Field::Caller).starts_with("descends from \"/opt/a\\\" b\" (pid "));
    }

    fn caller_with_quote(t: &mut Ticket) {
        t.subject.caller.as_mut().unwrap().descends_from.executable = "/opt/a\" b".to_owned();
    }

    fn om(t: &Ticket) -> &writ_core::ticket::RepoTerms {
        t.terms(&"omega-code".parse().unwrap()).unwrap()
    }

    fn omega(t: &mut Ticket) -> &mut writ_core::ticket::RepoTerms {
        t.repos.get_mut(&"omega-code".parse().unwrap()).unwrap()
    }

    fn full_ticket() -> Ticket {
        use writ_core::canonical::Canonical;
        const FULL: &[u8] = include_bytes!("../../writ-core/tests/fixtures/ticket-full.json");
        Ticket::from_canonical(FULL).unwrap()
    }

    /// The review after M5.5 (S2): lines longer than the terminal wrapped there, and the rows
    /// the terminal made started at column 0, without the gutter: 100 expected paths of 1 KiB
    /// padded with spaces read as forged scope rows, and the summary's single line of every
    /// path pushed the real terms hundreds of rows up. Every row now fits an 80-column
    /// terminal, agent text is behind the gutter on each of them, and the summary is a few
    /// rows of one line each.
    #[test]
    fn a_row_breaks_between_words_and_cuts_only_a_word_longer_than_a_row() {
        // Between words: the space at the break is not shown, no word is split.
        assert_eq!(
            cut("signed com.example team ABCDE12345)", 28),
            ["signed com.example team", "ABCDE12345)"]
        );
        assert_eq!(cut("aaaa bbbb", 4), ["aaaa", "bbbb"]);
        assert_eq!(cut("aaa bbbb", 4), ["aaa", "bbbb"]);
        // A word longer than a row: cut inside, where it must be.
        assert_eq!(cut("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(cut("x abcdefghij", 4), ["x", "abcd", "efgh", "ij"]);
        // A leading space is no break; wide characters count 2.
        assert_eq!(cut(" abcde", 4), [" abc", "de"]);
        assert_eq!(cut("日本 日本", 4), ["日本", "日本"]);
        assert_eq!(cut("", 4), [""]);
        // Whatever the text and the width, no row is wider, and nothing but the spaces at the
        // breaks is lost.
        let text = "a bb ccc dddd eeeee 日本語 ffffffffffff  g   h";
        // (A row holds at least one character: 2 columns for a wide one.)
        for room in 2..=20 {
            let rows = cut(text, room);
            assert!(rows.iter().all(|r| width(r) <= room), "{room}: {rows:?}");
            let kept: String = rows.concat().chars().filter(|c| *c != ' ').collect();
            let all: String = text.chars().filter(|c| *c != ' ').collect();
            assert_eq!(kept, all, "{room}: {rows:?}");
        }
    }

    #[test]
    fn a_listing_row_never_hides_the_repos_or_the_lease_amended() {
        use writ_core::names::{RepoName, TicketId};
        let id: TicketId = "wrt_01M6J0KMVRMFR7DNP0ZXD6DYPP".parse().unwrap();
        let lease: TicketId = "wrt_01M6J0KMVRMFR7DNP0ZXD6DYPQ".parse().unwrap();
        let now = Timestamp::from_unix(1_000_000).unwrap();
        let summary = |repos: Vec<RepoName>, lease: TicketId| writ_proto::Summary {
            id: id.clone(),
            lease,
            state: State::Pending,
            templates: vec!["feature".parse().unwrap()],
            revision: 2,
            repos,
            created_at: now,
            expires_at: Timestamp::from_unix(1_003_599).unwrap(),
            title: "First".into(),
        };
        let one = writ_proto::Listing {
            tickets: vec![summary(vec!["lifecycle".parse().unwrap()], lease.clone())],
        };
        assert_eq!(
            listing(&one, now),
            format!(
                "{id}  pending   r2  feature        59m59s left\n    \
                 repos lifecycle (amends {lease})\n    │ First\n"
            )
        );
        // Many long repos: every row fits, continuations behind the gutter, none lost.
        let many: Vec<RepoName> = (0..12)
            .map(|i| {
                format!("repository-{i:02}-{}", "x".repeat(20))
                    .parse()
                    .unwrap()
            })
            .collect();
        let shown = listing(
            &writ_proto::Listing {
                tickets: vec![summary(many.clone(), id.clone())],
            },
            now,
        );
        for line in shown.lines() {
            assert!(width(line) <= WIDTH, "{} columns: {line:?}", width(line));
        }
        for repo in &many {
            assert!(shown.contains(repo.as_str()), "{repo}: {shown}");
        }
        assert!(
            shown
                .lines()
                .nth(1)
                .unwrap()
                .starts_with("    repos repository-00-")
        );
        assert!(
            shown
                .lines()
                .nth(2)
                .unwrap()
                .starts_with("          │ repository-")
        );
    }

    #[test]
    fn no_row_is_wider_than_the_terminal_and_long_agent_text_cannot_forge_a_row() {
        let mut t = full_ticket();
        let forged = format!("{}  repos              docs-site", " ".repeat(57));
        let long = forged.repeat(14);
        let terms = omega(&mut t);
        terms.expected_paths = (0..100)
            .map(|i| {
                format!("p{i:02}/{}", long.chars().take(1019).collect::<String>())
                    .parse()
                    .unwrap()
            })
            .collect();
        terms.expected_paths.insert("**".parse().unwrap());
        terms.branches = (0..50)
            .map(|i| format!("agent/{}{i}", "x".repeat(200)).parse().unwrap())
            .collect();
        terms.template = "t".repeat(64).parse().unwrap();
        // The largest limits a ticket can hold (the e2e pipeline found the limits row 80
        // columns wide with ordinary ones).
        terms.limits.max_signatures = u32::MAX;
        terms.limits.max_pushes = u32::MAX;
        terms.limits.max_push_size = writ_core::units::ByteSize::from_bytes(u64::MAX);
        t.text.task = forged.repeat(60);
        t.text.plan = vec![forged.repeat(8); 50];
        t.text.title = "日本".repeat(50);
        // The longest committer name, one word wide and full-width characters.
        t.common.committer_name = Some("名".repeat(100).parse().unwrap());
        t.limits.max_ops_per_minute = u32::MAX;
        // The sections M6 added, at their widest: the renewal's chain, the source's other
        // leases (each flagged), the activity report (the e2e pipeline found an OVERLAP row
        // 92 columns wide).
        let id: writ_core::names::TicketId = "wrt_01M6KRSS6EEJK15XNDVRTNRQ6X".parse().unwrap();
        let far = writ_core::units::Timestamp::from_unix(253_402_300_799).unwrap();
        let count = writ_proto::Count {
            used: u32::MAX,
            max: u32::MAX,
        };
        let renewal = writ_proto::Renewal {
            original: String::new(),
            number: u32::MAX,
            used_seconds: u64::MAX,
            signatures: count,
            pushes: count,
            state: State::Exhausted,
        };
        let others = writ_proto::Others {
            shown: (0..10)
                .map(|_| writ_proto::OtherLease {
                    id: id.clone(),
                    repos: t.repos.keys().cloned().collect(),
                    branches: om(&t).branches.iter().map(ToString::to_string).collect(),
                    operations: om(&t).operations.iter().copied().collect(),
                    expires_at: far,
                    overlap: true,
                })
                .collect(),
            more: u32::MAX,
        };
        let report = writ_proto::Report {
            lease: id.clone(),
            state: State::Exhausted,
            title: t.text.title.clone(),
            templates: vec![om(&t).template.clone()],
            repos: t.repos.keys().cloned().collect(),
            expected_paths: om(&t)
                .expected_paths
                .iter()
                .map(ToString::to_string)
                .collect(),
            summary: Some(forged.repeat(60)),
            estimate: Some(writ_core::ticket::Estimate {
                coding: Some(writ_core::units::Duration::from_seconds(30 * 86_400)),
                checks: Some(writ_core::units::Duration::from_seconds(30 * 86_400)),
                ci: Some(writ_core::units::Duration::from_seconds(30 * 86_400)),
            }),
            chain: vec![
                writ_proto::ChainLink {
                    id: id.clone(),
                    state: State::Renewed,
                    created_at: far,
                    expires_at: far,
                    ended_at: Some(far),
                    signatures: u32::MAX,
                    pushes: u32::MAX,
                };
                3
            ],
            granted_seconds: u64::MAX,
            used_seconds: u64::MAX,
            signatures: count,
            pushes: count,
            fetches: u64::MAX,
            commits: vec![
                writ_proto::ReportCommit {
                    id: "f".repeat(64).parse().unwrap(),
                    repo: t.repos.keys().next().unwrap().clone(),
                    lease: id.clone(),
                    signed_at: far,
                };
                3
            ],
            pushed: Vec::new(),
            branches: om(&t)
                .branches
                .iter()
                .map(|b| format!("refs/heads/{b}"))
                .collect(),
            denials: vec![writ_proto::DenialCount {
                code: "paths_changed".to_owned(),
                count: u64::MAX,
            }],
            warnings: vec![forged.repeat(20)],
            phases: writ_proto::Phases {
                approval_wait_seconds: Some(u64::MAX),
                coding_seconds: Some(u64::MAX),
                ci_rounds_seconds: vec![u64::MAX; 20],
                after_last_push_seconds: Some(u64::MAX),
            },
            truncated: true,
        };
        let marks = [
            (crate::timings::Phase::Checks, u64::MAX),
            (crate::timings::Phase::Ci, u64::MAX),
        ];
        let command = format!("writ sign {} --full", t.id);
        for full in [false, true] {
            let rows = Rows::new(full, &command);
            let mut shown = ticket(&t, State::Pending, t.created_at, rows);
            shown.push_str(&renewal_section(&renewal, &t, rows));
            shown.push_str(&self::others(&others, t.created_at));
            shown.push_str(&self::report(&report, &marks, rows));
            shown.push_str(&summary(&t, true));
            shown.push_str(&changes("Changed", &diff(&full_ticket(), &t), rows));
            for line in shown.lines() {
                assert!(width(line) <= WIDTH, "{} columns: {line:?}", width(line));
                // No row of agent text reads like a row of the display's own.
                if line.contains("docs-site") {
                    assert!(
                        !line.starts_with("  repos"),
                        "a forged row at column 0: {line:?}"
                    );
                }
            }
            // The summary, right above the prompt: one row per term, the real ones.
            let lines: Vec<&str> = shown.lines().collect();
            let start = lines
                .iter()
                .rposition(|l| *l == "You are signing (enforced):")
                .unwrap();
            let summary: Vec<&str> = lines[start..]
                .iter()
                .take_while(|l| !l.is_empty())
                .copied()
                .collect();
            // The heading, the id, twelve rows of terms (the limits on two), the narrowing
            // note: no term ever takes a second row.
            assert_eq!(summary.len(), 15, "{summary:#?}");
            assert!(
                summary.contains(&"  max push size      18446744073709551615 bytes"),
                "{summary:#?}"
            );
            assert!(
                summary
                    .iter()
                    .any(|l| l.starts_with("  expected paths     101: ")
                        && l.ends_with("… (see above)")),
                "{summary:#?}"
            );
            assert!(
                summary
                    .iter()
                    .any(|l| l.starts_with("  branches           ")),
                "{summary:#?}"
            );
        }
        // Without --full, the agent's words are cut and say how to see the rest, but the
        // expected paths, enforced, are shown whole (the review after M7.6, U-1).
        let shown = ticket(&t, State::Pending, t.created_at, Rows::new(false, &command));
        assert!(shown.contains(&format!(
            " more lines not shown\n      ({command} shows them)\n"
        )));
        assert_eq!(paths_shown(&shown, "omega-code"), paths_of(om(&t)));
    }

    /// The expected paths of `repo` as `display` shows them: the gutter rows under its
    /// `expected paths`, joined, the spaces taken out (a row breaks at a space it drops).
    fn paths_shown(display: &str, repo: &str) -> String {
        let block = display
            .split(&format!("Repository {repo} (enforced)\n"))
            .nth(1)
            .unwrap();
        let rows = block.split("  expected paths\n").nth(1).unwrap();
        rows.lines()
            .take_while(|l| l.starts_with(&format!("    {GUTTER}")))
            .map(|l| l.trim_start_matches(&format!("    {GUTTER}")))
            .collect::<String>()
            .replace(' ', "")
    }

    /// What [`paths_shown`] must read: every path of `terms`, quoted, the spaces taken out.
    fn paths_of(terms: &RepoTerms) -> String {
        terms
            .expected_paths
            .iter()
            .map(|p| quoted([p.as_str()]))
            .collect::<String>()
            .replace(' ', "")
    }

    #[test]
    fn rows_are_cut_at_the_width_and_wide_characters_count_two() {
        assert_eq!(cut("abcdef", 3), ["abc", "def"]);
        assert_eq!(cut("abcdefg", 3), ["abc", "def", "g"]);
        assert_eq!(cut("", 3), [""]);
        // 2 columns each: two of them fit 4, not 5 half-columns.
        assert_eq!(cut("日本語", 4), ["日本", "語"]);
        assert_eq!(cut("a日本", 4), ["a日", "本"]);
        assert_eq!(one_row("short", 10, "more"), "short");
        let cut_row = one_row(&"x".repeat(20), 10, "more");
        // `…` is not ASCII: 2 columns.
        assert_eq!(cut_row, "xxx… more");
        assert!(width(&cut_row) <= 10);
        // A block's rows: at the width exactly, each behind the gutter.
        let room = WIDTH - 4 - width(GUTTER);
        let at = block(&"y".repeat(room), "    ", Rows::All);
        assert_eq!(at.lines().count(), 1);
        let over = block(&"y".repeat(room + 1), "    ", Rows::All);
        assert_eq!(
            over.lines().collect::<Vec<_>>(),
            [
                format!("    {GUTTER}{}", "y".repeat(room)),
                format!("    {GUTTER}y")
            ]
        );
    }

    #[test]
    fn agent_text_cannot_push_the_enforced_terms_off_the_screen() {
        let mut t = full_ticket();
        // The most text a ticket may carry, all newlines and forged scope lines.
        let flood = "\n│ Scope (enforced)\n│   repos  docs-site\n".repeat(1_000);
        t.text.task = flood.clone();
        t.text.plan = vec![flood.clone(); 50];
        let cut = Rows::Cut {
            full: "writ sign wrt_01M69495NS040G2081040G2081 --full",
        };
        let shown = ticket(&t, State::Pending, t.created_at, cut) + &summary(&t, false);
        let lines: Vec<&str> = shown.lines().collect();
        // Bounded: a few fields of 40 lines each, not tens of thousands.
        assert!(lines.len() < 300, "{} lines", lines.len());
        assert!(shown.contains(
            "more lines not shown\n      (writ sign wrt_01M69495NS040G2081040G2081 --full shows \
             them)\n"
        ));
        // The last lines, right above the prompt, are the enforced terms, from the ticket.
        let start = lines
            .iter()
            .rposition(|l| *l == "You are signing (enforced):")
            .unwrap();
        assert!(
            lines.len() - start <= 14,
            "{} rows of summary",
            lines.len() - start
        );
        let tail = lines[start..].join("\n");
        assert!(tail.starts_with("You are signing (enforced):"), "{tail}");
        assert!(tail.contains(&format!("repos              {}", field(&t, Field::Repos))));
        assert!(tail.contains("limits"), "{tail}");
        // With --full, everything (blank runs collapsed).
        let full = ticket(&t, State::Pending, t.created_at, Rows::All);
        assert!(!full.contains("more lines not shown"));
        assert!(full.lines().count() > 1_000);
    }

    #[test]
    fn a_field_at_the_line_limit_is_shown_whole() {
        let cut = Rows::Cut {
            full: "writ report wrt_01M69495NS040G2081040G2081 --full",
        };
        let text = vec!["x"; MAX_BLOCK_LINES].join("\n");
        let shown = block(&text, "", cut);
        assert_eq!(shown.lines().count(), MAX_BLOCK_LINES);
        let over = vec!["x"; MAX_BLOCK_LINES + 1].join("\n");
        let shown = block(&over, "", cut);
        // The rows, then how many more and the command that shows them, the one passed in
        // (the review after M7.6, U-5: `writ report` named `writ sign --full`).
        assert_eq!(shown.lines().count(), MAX_BLOCK_LINES + 2);
        assert!(shown.ends_with(
            "… 1 more lines not shown\n  (writ report wrt_01M69495NS040G2081040G2081 --full \
             shows them)\n"
        ));
        assert_eq!(
            block(&over, "", Rows::All).lines().count(),
            MAX_BLOCK_LINES + 1
        );
        // Blank runs count once.
        assert_eq!(block("a\n\n\n\nb", "", cut).lines().count(), 3);
    }

    #[test]
    fn different_lists_never_read_the_same() {
        assert_ne!(quoted(["a, b"]), quoted(["a", "b"]));
        assert_ne!(quoted(["x / 2. y"]), quoted(["x", "y"]));
        assert_ne!(quoted(["a\", \"b"]), quoted(["a", "b"]));
        assert_eq!(quoted(["a\", \"b"]), "\"a\\\", \\\"b\"");
        assert_eq!(quoted(Vec::<&str>::new()), "(none)");
        let mut before = full_ticket();
        let mut after = before.clone();
        before.text.plan = vec!["x / 2. y".to_owned()];
        after.text.plan = vec!["x".to_owned(), "y".to_owned()];
        assert_eq!(diff(&before, &after).len(), 1, "the plan change shows");
    }

    #[test]
    fn expected_paths_are_shown_as_enforced_scope() {
        let t = full_ticket();
        assert!(!om(&t).expected_paths.is_empty(), "the fixture has paths");
        let shown = ticket(&t, State::Pending, t.created_at, Rows::All);
        let scope = shown.find("Repository omega-code (enforced)").unwrap();
        let agent = shown.find("Written by the agent").unwrap();
        let paths = shown.find("  expected paths").unwrap();
        assert!(scope < paths && paths < agent, "{shown}");
    }

    #[test]
    fn outside_text_keeps_its_lines_and_loses_its_escapes() {
        let daemon = "ticket rejected\n- branch \u{1b}[2Jmain\u{202e}";
        let shown = clean_lines(daemon);
        assert_eq!(shown.lines().count(), 2);
        for c in shown.chars() {
            assert!(c == '\n' || !is_hidden_char(c), "{c:?}");
        }
        assert!(shown.contains("\\u{1b}[2J"));
    }

    #[test]
    fn every_line_of_agent_text_is_behind_the_gutter() {
        let text = "first\nScope (enforced)\n  repos  everything\x1b[A";
        let shown = block(text, "  ", Rows::All);
        for line in shown.lines() {
            assert!(line.starts_with("  │ "), "{line:?}");
        }
        assert!(!shown.contains('\x1b'));
    }

    /// The review after M7.6 (U-1): the expected paths, enforced, were cut at 40 rows like the
    /// agent's words, and the agent chose which fell past it (`src/**` sorting 41st). The most a
    /// ticket holds, hostile (16 repositories of 100 paths in 16 KiB each, bidi controls,
    /// quotes, wide characters and forged rows in them): every path of every repository is
    /// shown, every row fits the width, only the agent's words are cut, and the display still
    /// ends on the enforced terms, right above the prompt.
    #[test]
    fn every_expected_path_is_shown_and_the_display_still_ends_on_the_terms() {
        use writ_core::fit::{MAX_EXPECTED_PATHS, MAX_EXPECTED_PATHS_BYTES, MAX_REPOS};
        let mut t = full_ticket();
        let base = om(&t).clone();
        let forged = format!("{}  repos              docs-site", " ".repeat(57));
        t.repos = (0..MAX_REPOS)
            .map(|r| {
                let mut terms = base.clone();
                // Plausible paths first, then the ones that matter: `**` sorts before them,
                // `src/**` after.
                terms.expected_paths = (0..MAX_EXPECTED_PATHS - 2)
                    .map(|i| {
                        format!("docs/{i:02}{forged}\u{202e}\"\\日本.md")
                            .parse()
                            .unwrap()
                    })
                    .collect();
                terms.expected_paths.insert("**".parse().unwrap());
                terms.expected_paths.insert("src/**".parse().unwrap());
                let bytes: usize = terms.expected_paths.iter().map(|p| p.as_str().len()).sum();
                assert!(bytes <= MAX_EXPECTED_PATHS_BYTES, "{bytes} bytes");
                assert_eq!(terms.expected_paths.len(), MAX_EXPECTED_PATHS);
                (
                    format!("repo-{r:02}-{}", "r".repeat(40)).parse().unwrap(),
                    terms,
                )
            })
            .collect();
        t.text.task = forged.repeat(46);
        t.text.plan = vec![forged.repeat(5); 50];
        let command = format!("writ sign {} --full", t.id);
        let shown = ticket(&t, State::Pending, t.created_at, Rows::new(false, &command))
            + &summary(&t, false);
        for (repo, terms) in &t.repos {
            assert_eq!(
                paths_shown(&shown, repo.as_str()),
                paths_of(terms),
                "{repo}"
            );
        }
        // Cut: the task and the plan only, each saying how to see the rest.
        assert_eq!(
            shown.matches(" more lines not shown\n").count(),
            2,
            "{shown}"
        );
        assert_eq!(
            shown
                .matches(&format!("\n      ({command} shows them)\n"))
                .count(),
            2
        );
        for line in shown.lines() {
            assert!(width(line) <= WIDTH, "{} columns: {line:?}", width(line));
            assert!(
                !(line.starts_with("  repos") && line.contains("docs-site")),
                "a forged row at column 0: {line:?}"
            );
            assert!(!line.chars().any(is_hidden_char), "{line:?}");
        }
        // The last rows, right above the prompt: the summary, the paths counted.
        let lines: Vec<&str> = shown.lines().collect();
        let start = lines
            .iter()
            .rposition(|l| *l == "You are signing (enforced):")
            .unwrap();
        assert_eq!(lines.len() - start, 14, "{:#?}", &lines[start..]);
        assert!(
            lines[start..]
                .iter()
                .any(|l| l.starts_with("  expected paths     1600:") && l.ends_with("(see above)")),
            "{:#?}",
            &lines[start..]
        );
    }

    /// The review after M7.6 (U-4): nothing tied "every field is shown" to the ticket's type.
    /// Each leaf of a ticket's canonical JSON, and each repository's name, changed in turn to a
    /// value that still decodes: what `writ sign` shows changes each time. A field added to the
    /// ticket and not shown fails here (or doesn't compile: [`ticket`] and [`summary`]
    /// destructure every type, [`Field`] has no catch-all arm).
    #[test]
    fn every_leaf_of_a_ticket_changes_what_writ_sign_shows() {
        use serde_json::Value;
        const FULL: &[u8] = include_bytes!("../../writ-core/tests/fixtures/ticket-full.json");
        let root: Value = serde_json::from_slice(FULL).unwrap();
        let fixture = full_ticket();
        let now = fixture.created_at;
        let show = |t: &Ticket| ticket(t, State::Pending, now, Rows::All) + &summary(t, false);
        let original = show(&fixture);

        /// Every leaf under `value`, as a JSON pointer.
        fn leaves(value: &Value, at: String, out: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    for (key, value) in map {
                        leaves(value, format!("{at}/{key}"), out);
                    }
                }
                Value::Array(items) => {
                    for (i, value) in items.iter().enumerate() {
                        leaves(value, format!("{at}/{i}"), out);
                    }
                }
                _ => out.push(at),
            }
        }
        /// Other values a leaf may take, some of which decode where it is.
        fn alternatives(value: &Value) -> Vec<Value> {
            const NAMES: [&str; 5] = [
                "fetch",
                "commit_sign",
                "push",
                "deny_and_notify",
                "revoke_lease",
            ];
            match value {
                Value::Bool(b) => vec![Value::Bool(!b)],
                Value::Number(n) => {
                    let n = n.as_u64().unwrap();
                    vec![Value::from(n + 1), Value::from(n.saturating_sub(1))]
                }
                Value::Null => vec![
                    Value::from("10m"),
                    Value::from("x"),
                    Value::from("wrt_01M69495P21850M2GA1850M2GB"),
                ],
                Value::String(s) => {
                    let mut out = vec![format!("x{s}"), format!("{s}x")];
                    // The last digit one more (a timestamp, an id, a duration).
                    if let Some(at) = s.rfind(|c: char| c.is_ascii_digit()) {
                        let mut bumped = s.clone();
                        let d = s.as_bytes()[at] - b'0';
                        bumped.replace_range(at..=at, &((d + 1) % 10).to_string());
                        out.push(bumped);
                    }
                    // The last character another letter (a fingerprint).
                    let mut other = s.clone();
                    if let Some(last) = other.pop() {
                        other.push(if last == 'T' { 'U' } else { 'T' });
                        out.push(other);
                    }
                    out.extend(NAMES.iter().map(|n| (*n).to_owned()));
                    out.into_iter().map(Value::from).collect()
                }
                Value::Array(_) | Value::Object(_) => Vec::new(),
            }
        }

        let mut found = Vec::new();
        leaves(&root, String::new(), &mut found);
        assert!(found.len() > 35, "{found:?}");
        for leaf in &found {
            let decoded: Vec<Ticket> = alternatives(root.pointer(leaf).unwrap())
                .into_iter()
                .filter_map(|value| {
                    let mut changed = root.clone();
                    *changed.pointer_mut(leaf).unwrap() = value;
                    serde_json::from_value::<Ticket>(changed).ok()
                })
                .filter(|t| *t != fixture)
                .collect();
            if leaf == "/kind" {
                assert!(decoded.is_empty(), "one kind of ticket: {decoded:?}");
                continue;
            }
            assert!(
                !decoded.is_empty(),
                "no other value of {leaf} decodes: give the test one"
            );
            for t in &decoded {
                assert_ne!(show(t), original, "{leaf} changed, what is shown didn't");
            }
        }
        // A repository's name, a key of `repos`.
        let mut renamed = root.clone();
        let repos = renamed["repos"].as_object_mut().unwrap();
        let terms = repos.remove("omega-code").unwrap();
        repos.insert("omega-code-x".to_owned(), terms);
        let t = serde_json::from_value::<Ticket>(renamed).unwrap();
        assert_ne!(show(&t), original, "the repository's name changed");
    }

    /// The review after M7.6 (U-5): each command's hint names the command that shows the rest
    /// (`writ report` said `writ sign --full`), and `writ ls` cuts nothing (it named `writ
    /// show`, which isn't a command).
    #[test]
    fn a_cut_says_which_command_shows_the_rest_and_a_listing_cuts_nothing() {
        let t = full_ticket();
        let warnings: Vec<String> = (0..50).map(|i| format!("src/file-{i}.rs")).collect();
        let report = writ_proto::Report {
            lease: t.id.clone(),
            state: State::Closed,
            title: "t".to_owned(),
            templates: vec![om(&t).template.clone()],
            repos: t.repos.keys().cloned().collect(),
            expected_paths: Vec::new(),
            summary: None,
            estimate: None,
            chain: Vec::new(),
            granted_seconds: 60,
            used_seconds: 60,
            signatures: writ_proto::Count { used: 0, max: 1 },
            pushes: writ_proto::Count { used: 0, max: 1 },
            fetches: 0,
            commits: Vec::new(),
            pushed: Vec::new(),
            branches: Vec::new(),
            denials: Vec::new(),
            warnings: warnings.clone(),
            phases: writ_proto::Phases {
                approval_wait_seconds: None,
                coding_seconds: None,
                ci_rounds_seconds: Vec::new(),
                after_last_push_seconds: None,
            },
            truncated: false,
        };
        let command = format!("writ report {} --full", t.id);
        let cut = self::report(&report, &[], Rows::new(false, &command));
        assert!(
            cut.contains(&format!(
                "    … 10 more lines not shown\n      ({command} shows them)\n"
            )),
            "{cut}"
        );
        assert!(cut.contains("src/file-39.rs") && !cut.contains("src/file-40.rs"));
        let all = self::report(&report, &[], Rows::new(true, &command));
        assert!(warnings.iter().all(|w| all.contains(&format!("│ {w}\n"))));
        assert!(!all.contains("more lines not shown"));

        // Sixteen long templates: every one shown, every row within the width.
        let templates: Vec<writ_core::names::TemplateName> = (0..16)
            .map(|i| {
                format!("template-{i:02}-{}", "t".repeat(50))
                    .parse()
                    .unwrap()
            })
            .collect();
        let listing = writ_proto::Listing {
            tickets: vec![writ_proto::Summary {
                id: t.id.clone(),
                lease: t.id.clone(),
                state: State::Pending,
                templates: templates.clone(),
                revision: 1,
                repos: t.repos.keys().cloned().collect(),
                created_at: t.created_at,
                expires_at: t.limits.expires_at,
                title: "First".into(),
            }],
        };
        let shown = self::listing(&listing, t.created_at);
        assert!(!shown.contains("writ show"), "{shown}");
        let joined: String = shown.lines().collect::<String>().replace([' ', '│'], "");
        for template in &templates {
            assert!(joined.contains(template.as_str()), "{template}: {shown}");
        }
        for line in shown.lines() {
            assert!(width(line) <= WIDTH, "{line:?}");
        }
    }

    /// M7.9.5: an amendment adding one path to many showed both whole lists; a set's change
    /// is now the items removed and added, each whole, and how many stay.
    #[test]
    fn a_set_change_shows_only_the_items_it_removes_and_adds() {
        let mut before = full_ticket();
        for i in 0..40 {
            omega(&mut before)
                .expected_paths
                .insert(format!("src/m{i:02}.rs").parse().unwrap());
        }
        let mut after = before.clone();
        omega(&mut after)
            .expected_paths
            .insert("src/new.rs".parse().unwrap());
        omega(&mut after)
            .expected_paths
            .retain(|p| p.as_str() != "src/m07.rs");
        omega(&mut after)
            .operations
            .retain(|o| o.to_string() != "push");
        omega(&mut after)
            .branches
            .insert("release/*".parse().unwrap());
        let changes = diff(&before, &after);
        let paths = changes
            .iter()
            .find(|c| c.field == Field::Repo(RepoField::ExpectedPaths))
            .unwrap();
        assert_eq!(paths.removed, ["\"src/m07.rs\""]);
        assert_eq!(paths.added, ["\"src/new.rs\""]);
        assert_eq!(paths.kept, 41);
        let shown = self::changes("Changes", &changes, Rows::All);
        assert!(
            shown.contains(
                "  expected paths\n    - \"src/m07.rs\"\n    + \"src/new.rs\"\n      (41 kept)\n"
            ),
            "{shown}"
        );
        assert!(
            !shown.contains("src/m08.rs"),
            "a kept path is not listed: {shown}"
        );
        assert!(
            shown.contains("  operations\n    - push\n      (2 kept)\n"),
            "{shown}"
        );
        assert!(
            shown.contains("  branches\n    + release/*\n      (1 kept)\n"),
            "{shown}"
        );
        // The structure: one row per item, tagged as removed or added, and the count.
        let mut out = Out::default();
        changes_into(&mut out, "Changes", &changes, Rows::All);
        let rows: Vec<(&str, Tag)> = out.doc.sections[0]
            .rows
            .iter()
            .filter(|r| r.label.as_deref() == Some("expected paths"))
            .map(|r| (r.value.as_str(), r.tag))
            .collect();
        assert_eq!(
            rows,
            [
                ("\"src/m07.rs\"", Tag::Removed),
                ("\"src/new.rs\"", Tag::Added),
                ("41 kept", Tag::Context),
            ]
        );
        // A scalar still shows both sides; the agent's words too.
        let mut longer = before.clone();
        omega(&mut longer).limits.max_pushes = 9;
        longer.text.plan = vec!["x, y".to_owned()];
        let shown = self::changes("Changes", &diff(&before, &longer), Rows::All);
        assert!(
            shown.contains("  max pushes\n    - 2\n    + 9\n"),
            "{shown}"
        );
        // Items are never merged or split: "a, b" is not "a" and "b".
        let mut one = before.clone();
        omega(&mut one).expected_paths = ["a, b".parse().unwrap()].into();
        let mut two = before.clone();
        omega(&mut two).expected_paths = ["a".parse().unwrap(), "b".parse().unwrap()].into();
        let c = diff(&one, &two);
        let c = c
            .iter()
            .find(|c| c.field == Field::Repo(RepoField::ExpectedPaths))
            .unwrap();
        assert_eq!(c.removed, ["\"a, b\""]);
        assert_eq!(c.added, ["\"a\"", "\"b\""]);
        assert_eq!(c.kept, 0);
    }

    /// Over several repositories, or a repository swapped for another, each item names its
    /// repository: the same operation in two repositories is two items.
    #[test]
    fn over_several_repositories_each_item_names_its_repository() {
        let mut before = full_ticket();
        let terms = om(&before).clone();
        before.repos.insert("web".parse().unwrap(), terms);
        let mut after = before.clone();
        after
            .repos
            .get_mut(&"web".parse().unwrap())
            .unwrap()
            .operations
            .retain(|o| o.to_string() != "push");
        let changes = diff(&before, &after);
        let ops = changes
            .iter()
            .find(|c| c.field == Field::Repo(RepoField::Operations))
            .unwrap();
        assert_eq!(ops.removed, ["web: push"]);
        assert!(ops.added.is_empty());
        assert_eq!(ops.kept, 5);
        let shown = self::changes("Changes", &changes, Rows::All);
        assert!(
            shown.contains("  operations\n    - web: push\n      (5 kept)\n"),
            "{shown}"
        );

        // One of the two swapped for another: everything it held moves from one name to the
        // other, item by item.
        let mut swapped = before.clone();
        let terms = swapped.repos.remove(&"web".parse().unwrap()).unwrap();
        swapped.repos.insert("www".parse().unwrap(), terms);
        let changes = diff(&before, &swapped);
        let repos = changes.iter().find(|c| c.field == Field::Repos).unwrap();
        assert_eq!(repos.removed, ["web"]);
        assert_eq!(repos.added, ["www"]);
        let paths = changes
            .iter()
            .find(|c| c.field == Field::Repo(RepoField::ExpectedPaths))
            .unwrap();
        assert_eq!(
            paths.removed,
            ["web: \"src/auth/**\"", "web: \"tests/auth/**\""]
        );
        assert_eq!(
            paths.added,
            ["www: \"src/auth/**\"", "www: \"tests/auth/**\""]
        );
        assert_eq!(paths.kept, 2, "omega-code's, unchanged");

        // A lone repository renamed, its terms the same: the name is the change.
        let mut renamed = full_ticket();
        let terms = renamed
            .repos
            .remove(&"omega-code".parse().unwrap())
            .unwrap();
        renamed.repos.insert("omega-next".parse().unwrap(), terms);
        let changes = diff(&full_ticket(), &renamed);
        let fields: Vec<Field> = changes.iter().map(|c| c.field).collect();
        assert_eq!(fields, [Field::Repos], "{changes:?}");
        assert_eq!(changes[0].removed, ["omega-code"]);
        assert_eq!(changes[0].added, ["omega-next"]);
    }

    /// The paths' tree (M7.9.5) gives back every path exactly, hostile ones too: nothing
    /// added, dropped or reordered within a path; a folder merged only when it holds one
    /// folder and nothing else; each folder's count its paths.
    #[test]
    fn the_path_tree_gives_back_every_path_exactly() {
        fn check(items: &[String]) -> Vec<doc::Node> {
            let tree = doc::path_tree(items);
            let mut back = doc::leaves(&tree);
            back.sort();
            let mut want = items.to_vec();
            want.sort();
            want.dedup();
            assert_eq!(back, want, "{tree:#?}");
            fn walk(nodes: &[doc::Node]) -> usize {
                let mut total = 0;
                for node in nodes {
                    match node.kind {
                        doc::NodeKind::Folder => {
                            assert!(node.name.ends_with('/'), "{node:?}");
                            assert!(!node.children.is_empty(), "an empty folder: {node:?}");
                            assert!(
                                !(node.children.len() == 1
                                    && node.children[0].kind == doc::NodeKind::Folder),
                                "a folder holding one folder alone, not merged: {node:?}"
                            );
                            assert_eq!(node.paths, walk(&node.children), "{node:?}");
                        }
                        _ => {
                            assert!(node.children.is_empty());
                            assert_eq!(node.paths, 1);
                        }
                    }
                    total += node.paths;
                }
                total
            }
            assert_eq!(walk(&tree), back.len());
            tree
        }
        let hostile = [
            "src/auth/**",
            "src/auth/login.rs",
            "src/a.rs",
            "docs/*.md",
            "docs/[ab]?.txt",
            "a//b",
            "/abs",
            "trail/",
            "x",
            "x/y",
            "deep/one/two/three.rs",
            "deep/one/two/four.rs",
            ".hidden/f",
            "../up",
            "esc\u{1b}[2J/\u{202e}evil",
            "\\u{1b}/typed",
            "",
            "/",
        ];
        let items: Vec<String> = hostile.iter().map(|p| clean(p)).collect();
        let tree = check(&items);
        let names: Vec<&str> = tree.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"deep/one/two/"), "{names:?}");
        assert!(names.contains(&"x/") && names.contains(&"x"), "{names:?}");
        let kind = |path: &str| -> doc::NodeKind {
            fn find(nodes: &[doc::Node], prefix: &str, path: &str) -> Option<doc::NodeKind> {
                nodes.iter().find_map(|n| {
                    let name = format!("{prefix}{}", n.name);
                    match n.kind {
                        doc::NodeKind::Folder => find(&n.children, &name, path),
                        k => (name == path).then_some(k),
                    }
                })
            }
            find(&tree, "", path).unwrap()
        };
        assert_eq!(kind("src/auth/**"), doc::NodeKind::Everything);
        assert_eq!(kind("docs/*.md"), doc::NodeKind::Pattern);
        assert_eq!(kind("docs/[ab]?.txt"), doc::NodeKind::Pattern);
        assert_eq!(kind("src/a.rs"), doc::NodeKind::File);
        assert!(
            doc::leaves(&tree)
                .iter()
                .all(|p| !p.chars().any(is_hidden_char)),
            "built from the cleaned items"
        );

        // Many sets from a seeded generator: the same holds for each.
        let mut seed: u64 = 0x5eed_7a3e;
        let mut next = |n: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        const PARTS: [&str; 9] = ["a", "b", "src", "*", "**", "", ".", "é", "{x}"];
        for _ in 0..500 {
            let count = next(30);
            let items: Vec<String> = (0..count)
                .map(|_| {
                    let depth = next(5) + 1;
                    (0..depth)
                        .map(|_| PARTS[usize::try_from(next(PARTS.len() as u64)).unwrap()])
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .collect();
            check(&items);
        }
    }

    /// Times and the paths' tree ride with their rows (M7.9.5): the app shows a time as how
    /// far it is and the paths as a tree, never parsing a value for either.
    #[test]
    fn times_and_path_trees_ride_with_their_rows() {
        let t = full_ticket();
        let out = shown_both(&t, &t);
        let rows: Vec<&doc::Row> = out.doc.sections.iter().flat_map(|s| &s.rows).collect();
        let timed: Vec<(Option<&str>, &str)> = rows
            .iter()
            .filter_map(|r| r.at.as_deref().map(|at| (r.label.as_deref(), at)))
            .collect();
        let expires = t.limits.expires_at.to_string();
        let created = t.created_at.to_string();
        assert_eq!(
            timed,
            [
                (Some("created"), created.as_str()),
                (Some("expires"), expires.as_str()),
                (Some("expires at"), expires.as_str()),
            ]
        );
        let trees: Vec<&&doc::Row> = rows.iter().filter(|r| !r.tree.is_empty()).collect();
        assert_eq!(trees.len(), 2, "the repository's paths and the summary's");
        for row in trees {
            assert_eq!(row.label.as_deref(), Some("expected paths"));
            let mut leaves = doc::leaves(&row.tree);
            leaves.sort();
            let mut items = row.items.clone();
            items.sort();
            assert_eq!(leaves, items);
        }
        // An expiry changed: each side's row carries its own time.
        let mut later = t.clone();
        later.limits.expires_at = Timestamp::from_unix(t.limits.expires_at.unix() + 3600).unwrap();
        let mut out = Out::default();
        changes_into(&mut out, "Changes", &diff(&t, &later), Rows::All);
        let ats: Vec<Option<String>> = out.doc.sections[0]
            .rows
            .iter()
            .filter(|r| r.label.as_deref() == Some("expires at"))
            .map(|r| r.at.clone())
            .collect();
        assert_eq!(
            ats,
            [
                Some(expires.clone()),
                Some(later.limits.expires_at.to_string())
            ]
        );
    }

    #[test]
    fn durations() {
        assert_eq!(duration(-5), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m05s");
        assert_eq!(duration(7500), "2h05m");
    }
}
