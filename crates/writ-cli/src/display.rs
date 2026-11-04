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
//! lines collapsed) unless `--full` is asked, the expected paths too, and the enforced terms
//! are repeated in a summary of one row each right before the prompt ([`summary`]), so no
//! amount of agent text can push what gets signed off the screen.

use std::fmt::Write as _;

use writ_core::lease::State;
use writ_core::ticket::{OnViolation, Ticket};
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
fn cut(text: &str, width: usize) -> Vec<String> {
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
fn one_row(text: &str, width: usize, more: &str) -> String {
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
fn rows_after(out: &mut String, head: &str, value: &str) {
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

/// Agent text over several lines, each behind the gutter and indented, cut into rows that
/// fit [`WIDTH`] (each row behind the gutter too): runs of blank lines shown as one, and,
/// unless `full`, at most [`MAX_BLOCK_LINES`] rows, then how many more.
pub fn block(text: &str, indent: &str, full: bool) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let blank = line.trim().is_empty();
        if blank && lines.last().is_some_and(|l| l.trim().is_empty()) {
            continue;
        }
        lines.push(line);
    }
    let room = WIDTH.saturating_sub(width(indent) + width(GUTTER));
    let rows: Vec<String> = lines
        .iter()
        .flat_map(|line| cut(&clean(line), room))
        .collect();
    gutter_rows(&rows, indent, full)
}

/// `rows` behind `indent` and the gutter: at most [`MAX_BLOCK_LINES`] unless `full`, then
/// how many more.
fn gutter_rows(rows: &[String], indent: &str, full: bool) -> String {
    let shown = if full {
        rows.len()
    } else {
        rows.len().min(MAX_BLOCK_LINES)
    };
    let mut out = String::new();
    for row in rows.iter().take(shown) {
        let _ = writeln!(out, "{indent}{GUTTER}{row}");
    }
    if shown < rows.len() {
        let _ = writeln!(
            out,
            "{indent}… {} more lines not shown (writ sign --full shows them)",
            rows.len() - shown
        );
    }
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
        let line = format!(
            "{}  {:<9} r{}  {:<14} {left}",
            t.id,
            // `as_str`: `State`'s `Display` doesn't pad.
            t.state.as_str(),
            t.revision,
            clean(t.template.as_str()),
        );
        let _ = writeln!(out, "{}", one_row(line.trim_end(), WIDTH, "(writ show)"));
        let repos = t
            .repos
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        rows_after(&mut out, "    repos ", &clean(&format!("{repos}{lease}")));
        out.push_str(&block(&t.title, "    ", true));
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

/// A field of a ticket, as `writ sign` shows it and diffs compare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Template,
    ExpiresAt,
    SessionKey,
    OriginHint,
    Caller,
    Repos,
    Operations,
    Branches,
    ForcePush,
    CommitterEmails,
    SigningKey,
    MaxSignatures,
    MaxPushes,
    MaxOpsPerMinute,
    MaxPushSize,
    OnViolation,
    Title,
    Task,
    Plan,
    ExpectedPaths,
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::ExpiresAt => "expires at",
            Self::SessionKey => "session key",
            Self::OriginHint => "origin hint",
            Self::Caller => "caller",
            Self::Repos => "repos",
            Self::Operations => "operations",
            Self::Branches => "branches",
            Self::ForcePush => "force push",
            Self::CommitterEmails => "committer emails",
            Self::SigningKey => "signing key",
            Self::MaxSignatures => "max signatures",
            Self::MaxPushes => "max pushes",
            Self::MaxOpsPerMinute => "max ops per minute",
            Self::MaxPushSize => "max push size",
            Self::OnViolation => "on violation",
            Self::Title => "title",
            Self::Task => "task",
            Self::Plan => "plan",
            Self::ExpectedPaths => "expected paths",
        }
    }
}

/// One field's value, already [`clean`]ed (one line).
pub fn field(ticket: &Ticket, field: Field) -> String {
    let scope = &ticket.scope;
    let limits = &ticket.limits;
    let text = &ticket.text;
    match field {
        Field::Template => clean(ticket.template.as_str()),
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
                format!(
                    "descends from {} (pid {}, generation {}{identity})",
                    clean(&p.executable),
                    p.pid,
                    p.generation
                )
            }
        },
        Field::Repos => list(&scope.repos),
        Field::Operations => list(&scope.operations),
        Field::Branches => list(&scope.branches),
        Field::ForcePush => if scope.force_push { "yes" } else { "no" }.to_owned(),
        Field::CommitterEmails => list(&scope.committer_emails),
        Field::SigningKey => scope
            .signing_key
            .as_ref()
            .map_or("(none)".to_owned(), |k| clean(k.as_str())),
        Field::MaxSignatures => limits.max_signatures.to_string(),
        Field::MaxPushes => limits.max_pushes.to_string(),
        Field::MaxOpsPerMinute => limits.max_ops_per_minute.to_string(),
        Field::MaxPushSize => limits.max_push_size.to_string(),
        Field::OnViolation => match ticket.on_violation {
            OnViolation::DenyAndNotify => "deny and notify",
            OnViolation::RevokeLease => "revoke the lease",
        }
        .to_owned(),
        Field::Title => clean(&text.title),
        Field::Task => clean(&text.task),
        Field::Plan => quoted(&text.plan),
        Field::ExpectedPaths => quoted(text.expected_paths.iter().map(|p| p.as_str())),
    }
}

/// Every field, in display order.
pub const FIELDS: [Field; 20] = [
    Field::Template,
    Field::ExpiresAt,
    Field::SessionKey,
    Field::OriginHint,
    Field::Caller,
    Field::Repos,
    Field::Operations,
    Field::Branches,
    Field::ForcePush,
    Field::CommitterEmails,
    Field::SigningKey,
    Field::MaxSignatures,
    Field::MaxPushes,
    Field::MaxOpsPerMinute,
    Field::MaxPushSize,
    Field::OnViolation,
    Field::Title,
    Field::Task,
    Field::Plan,
    Field::ExpectedPaths,
];

/// The fields that differ between two tickets: `(label, before, after)`.
pub fn diff(before: &Ticket, after: &Ticket) -> Vec<(&'static str, String, String)> {
    FIELDS
        .into_iter()
        .filter_map(|f| {
            let (a, b) = (field(before, f), field(after, f));
            (a != b).then(|| (f.label(), a, b))
        })
        .collect()
}

/// The full display of a ticket waiting for a signature (`full`: every line of agent text).
pub fn ticket(ticket: &Ticket, state: State, now: Timestamp, full: bool) -> String {
    let mut out = String::new();
    let t = &ticket.text;
    let kind = if t.amends.is_some() {
        "Amendment"
    } else {
        "Ticket"
    };
    let _ = writeln!(out, "{kind} {}", ticket.id);
    let _ = writeln!(out, "  revision {} · {state}", t.revision);
    // A name of up to 64 characters: a row of its own, cut like any value.
    labelled(
        &mut out,
        Field::Template.label(),
        &field(ticket, Field::Template),
    );
    let _ = writeln!(
        out,
        "  created {}, expires {} (in {})",
        ticket.created_at,
        ticket.limits.expires_at,
        duration(now.seconds_until(ticket.limits.expires_at))
    );
    if let Some(lease) = &t.amends {
        let _ = writeln!(out, "  amends lease {lease}");
    }
    if let Some(revised) = &t.revises {
        let _ = writeln!(out, "  revises ticket {revised}");
    }
    let row = |out: &mut String, f: Field| labelled(out, f.label(), &field(ticket, f));
    out.push_str("\nWho\n");
    for f in [Field::SessionKey, Field::Caller] {
        row(&mut out, f);
    }
    let _ = writeln!(out, "  origin hint (the agent's claim, not checked):");
    out.push_str(&block(
        ticket.subject.origin_hint.as_deref().unwrap_or("(none)"),
        "    ",
        full,
    ));
    out.push_str("\nScope (enforced)\n");
    for f in [
        Field::Repos,
        Field::Operations,
        Field::Branches,
        Field::ForcePush,
        Field::CommitterEmails,
        Field::SigningKey,
    ] {
        row(&mut out, f);
    }
    // Chosen by the agent but enforced by the path check: one quoted item per line.
    let _ = writeln!(out, "  {}", Field::ExpectedPaths.label());
    if t.expected_paths.is_empty() {
        let _ = writeln!(out, "    (none: not checked)");
    }
    let room = WIDTH.saturating_sub(4 + width(GUTTER));
    let rows: Vec<String> = t
        .expected_paths
        .iter()
        .flat_map(|path| cut(&quoted([path.as_str()]), room))
        .collect();
    out.push_str(&gutter_rows(&rows, "    ", full));
    out.push_str("\nLimits (enforced)\n");
    for f in [
        Field::MaxSignatures,
        Field::MaxPushes,
        Field::MaxOpsPerMinute,
        Field::MaxPushSize,
        Field::OnViolation,
    ] {
        row(&mut out, f);
    }
    out.push_str("\nWritten by the agent (untrusted, shown as written)\n");
    out.push_str("  title\n");
    out.push_str(&block(&t.title, "    ", full));
    out.push_str("  task\n");
    out.push_str(&block(&t.task, "    ", full));
    out.push_str("  plan\n");
    if t.plan.is_empty() {
        out.push_str(&block("(none)", "    ", full));
    }
    let plan = t
        .plan
        .iter()
        .enumerate()
        .map(|(i, step)| format!("{}. {step}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    if !plan.is_empty() {
        out.push_str(&block(&plan, "    ", full));
    }
    if let Some(feedback) = &t.previous_feedback {
        let _ = writeln!(
            out,
            "\nFeedback on revision {} (as recorded by the daemon)",
            t.revision.saturating_sub(1)
        );
        out.push_str(&block(feedback, "    ", full));
    }
    out
}

/// The enforced terms in a few lines, shown last, right before the prompt: whatever the agent
/// wrote above, this is what gets signed.
pub fn summary(ticket: &Ticket, narrowed: bool) -> String {
    let mut out = String::from("\nYou are signing (enforced):\n");
    let _ = writeln!(out, "  {}", ticket.id);
    // One row each: what doesn't fit says so, and is shown whole above.
    let room = WIDTH.saturating_sub(21);
    let _ = writeln!(
        out,
        "  {:<18} {}",
        Field::Template.label(),
        one_row(&field(ticket, Field::Template), room, "(see above)")
    );
    let _ = writeln!(
        out,
        "  {:<18} {}",
        Field::ExpiresAt.label(),
        ticket.limits.expires_at
    );
    for f in [
        Field::Repos,
        Field::Operations,
        Field::Branches,
        Field::ForcePush,
        Field::CommitterEmails,
    ] {
        let _ = writeln!(
            out,
            "  {:<18} {}",
            f.label(),
            one_row(&field(ticket, f), room, "(see above)")
        );
    }
    let paths = &ticket.text.expected_paths;
    let shown = if paths.is_empty() {
        "(none: not checked)".to_owned()
    } else {
        one_row(
            &format!("{}: {}", paths.len(), field(ticket, Field::ExpectedPaths)),
            room,
            "(see above)",
        )
    };
    let _ = writeln!(out, "  {:<18} {shown}", Field::ExpectedPaths.label());
    // Two rows, each within [`WIDTH`] whatever the numbers (the counts are `u32`: 77 columns
    // at their largest).
    let limits = &ticket.limits;
    let _ = writeln!(
        out,
        "  {:<18} {} signatures, {} pushes, {}/min",
        "limits", limits.max_signatures, limits.max_pushes, limits.max_ops_per_minute,
    );
    let _ = writeln!(
        out,
        "  {:<18} {}",
        Field::MaxPushSize.label(),
        limits.max_push_size
    );
    let _ = writeln!(
        out,
        "  {:<18} {}",
        Field::OnViolation.label(),
        field(ticket, Field::OnViolation)
    );
    if narrowed {
        out.push_str("  (narrowed by you: see above)\n");
    }
    out
}

/// A diff section: `title`, then `label: before → after` per changed field.
pub fn changes(title: &str, changes: &[(&'static str, String, String)]) -> String {
    let mut out = format!("\n{title}\n");
    if changes.is_empty() {
        out.push_str("  (no change)\n");
    }
    // `    - ` or `    │ ` in front: 7 columns at most (`│` counted two).
    let room = WIDTH.saturating_sub(4 + width("│ "));
    for (label, before, after) in changes {
        let _ = writeln!(out, "  {label}");
        for (sign, value) in [("-", before), ("+", after)] {
            for (i, row) in cut(value, room).into_iter().enumerate() {
                let mark = if i == 0 { sign } else { "│" };
                let _ = writeln!(out, "    {mark} {row}");
            }
        }
    }
    out
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
        let mut shown = ticket(&t, State::Pending, now, true);
        shown.push_str(&summary(&t, false));
        shown.push_str(&changes(
            "diff",
            &diff(&Ticket::from_canonical(FULL).unwrap(), &t),
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
            template: "feature".parse().unwrap(),
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
        t.text.expected_paths = (0..100)
            .map(|i| {
                format!("p{i:02}/{}", long.chars().take(1019).collect::<String>())
                    .parse()
                    .unwrap()
            })
            .collect();
        t.text.expected_paths.insert("**".parse().unwrap());
        t.text.task = forged.repeat(60);
        t.text.plan = vec![forged.repeat(8); 50];
        t.text.title = "日本".repeat(50);
        t.scope.branches = (0..50)
            .map(|i| format!("agent/{}{i}", "x".repeat(200)).parse().unwrap())
            .collect();
        t.template = "t".repeat(64).parse().unwrap();
        // The largest limits a ticket can hold (the e2e pipeline found the limits row 80
        // columns wide with ordinary ones).
        t.limits.max_signatures = u32::MAX;
        t.limits.max_pushes = u32::MAX;
        t.limits.max_ops_per_minute = u32::MAX;
        t.limits.max_push_size = writ_core::units::ByteSize::from_bytes(u64::MAX);
        for full in [false, true] {
            let mut shown = ticket(&t, State::Pending, t.created_at, full);
            shown.push_str(&summary(&t, true));
            shown.push_str(&changes("Changed", &diff(&full_ticket(), &t)));
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
            // The heading, the id, eleven rows of terms (the limits on two), the narrowing
            // note: no term ever takes a second row.
            assert_eq!(summary.len(), 14, "{summary:#?}");
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
        // Without --full, the expected paths are bounded like any agent field.
        let shown = ticket(&t, State::Pending, t.created_at, false);
        assert!(
            shown.lines().count() < 400,
            "{} rows",
            shown.lines().count()
        );
        assert!(shown.contains("more lines not shown (writ sign --full shows them)"));
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
        let at = block(&"y".repeat(room), "    ", false);
        assert_eq!(at.lines().count(), 1);
        let over = block(&"y".repeat(room + 1), "    ", false);
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
        let shown = ticket(&t, State::Pending, t.created_at, false) + &summary(&t, false);
        let lines: Vec<&str> = shown.lines().collect();
        // Bounded: a few fields of 40 lines each, not tens of thousands.
        assert!(lines.len() < 300, "{} lines", lines.len());
        assert!(shown.contains("more lines not shown (writ sign --full shows them)"));
        // The last lines, right above the prompt, are the enforced terms, from the ticket.
        let start = lines
            .iter()
            .rposition(|l| *l == "You are signing (enforced):")
            .unwrap();
        assert!(
            lines.len() - start <= 13,
            "{} rows of summary",
            lines.len() - start
        );
        let tail = lines[start..].join("\n");
        assert!(tail.starts_with("You are signing (enforced):"), "{tail}");
        assert!(tail.contains(&format!("repos              {}", field(&t, Field::Repos))));
        assert!(tail.contains("limits"), "{tail}");
        // With --full, everything (blank runs collapsed).
        let full = ticket(&t, State::Pending, t.created_at, true);
        assert!(!full.contains("more lines not shown"));
        assert!(full.lines().count() > 1_000);
    }

    #[test]
    fn a_field_at_the_line_limit_is_shown_whole() {
        let text = vec!["x"; MAX_BLOCK_LINES].join("\n");
        let shown = block(&text, "", false);
        assert_eq!(shown.lines().count(), MAX_BLOCK_LINES);
        let over = vec!["x"; MAX_BLOCK_LINES + 1].join("\n");
        let shown = block(&over, "", false);
        assert_eq!(shown.lines().count(), MAX_BLOCK_LINES + 1);
        assert!(shown.ends_with("… 1 more lines not shown (writ sign --full shows them)\n"));
        // Blank runs count once.
        assert_eq!(block("a\n\n\n\nb", "", false).lines().count(), 3);
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
        assert!(!t.text.expected_paths.is_empty(), "the fixture has paths");
        let shown = ticket(&t, State::Pending, t.created_at, false);
        let scope = shown.find("Scope (enforced)").unwrap();
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
        let shown = block(text, "  ", false);
        for line in shown.lines() {
            assert!(line.starts_with("  │ "), "{line:?}");
        }
        assert!(!shown.contains('\x1b'));
    }

    #[test]
    fn durations() {
        assert_eq!(duration(-5), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m05s");
        assert_eq!(duration(7500), "2h05m");
    }
}
