//! The trusted display: how `writ sign` shows a ticket before it is signed.
//!
//! Everything the agent wrote (title, task, plan, expected paths, origin hint, the caller's
//! executable) is untrusted. Before it reaches the terminal, [`clean`] turns every character
//! that could move the cursor, recolor, hide or reorder text into a visible `\u{…}` escape,
//! and multi-line text is printed behind a gutter (`│`) on every line, so agent text can
//! never pass for a line `writ sign` wrote itself. Warnings come from `writ sign`, never from
//! the ticket.
//!
//! The display is bounded: each agent field shows at most [`MAX_BLOCK_LINES`] lines (runs of
//! blank lines collapsed) unless `--full` is asked, and the enforced terms are repeated in a
//! short summary right before the prompt ([`summary`]), so no amount of agent text can push
//! what gets signed off the screen.

use std::fmt::Write as _;

use writ_core::lease::State;
use writ_core::text::is_hidden_char;
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::Timestamp;

/// The gutter in front of every line of agent-written text.
pub const GUTTER: &str = "│ ";

/// The most lines one agent field shows without `--full`.
pub const MAX_BLOCK_LINES: usize = 40;

/// Agent text made safe for one line of the terminal: every hidden character as `\u{…}`
/// (newlines included), and `\` as `\\`, so a typed `\u{1b}` can't pass for an escaped one.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_char(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
}

/// Text from outside the program (a daemon's error, a tool's stderr) for the terminal: each
/// line [`clean`]ed, the line breaks kept. Nothing from elsewhere reaches the terminal raw.
pub fn clean_lines(text: &str) -> String {
    text.lines().map(clean).collect::<Vec<_>>().join("\n")
}

/// Agent text over several lines, each behind the gutter and indented: runs of blank lines
/// shown as one, and, unless `full`, at most [`MAX_BLOCK_LINES`] lines, then how many more.
pub fn block(text: &str, indent: &str, full: bool) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let blank = line.trim().is_empty();
        if blank && lines.last().is_some_and(|l| l.trim().is_empty()) {
            continue;
        }
        lines.push(line);
    }
    let shown = if full {
        lines.len()
    } else {
        lines.len().min(MAX_BLOCK_LINES)
    };
    let mut out = String::new();
    for line in lines.iter().take(shown) {
        let _ = writeln!(out, "{indent}{GUTTER}{}", clean(line));
    }
    if shown < lines.len() {
        let _ = writeln!(
            out,
            "{indent}… {} more lines not shown (writ sign --full shows them)",
            lines.len() - shown
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

/// `writ ls`: one line per ticket (id, state, revision, template, time left, repos), then its
/// title behind the gutter.
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
        let _ = writeln!(
            out,
            "{}  {:<9} r{}  {:<14} {:<10} {}{lease}",
            t.id,
            t.state.to_string(),
            t.revision,
            t.template.to_string(),
            left,
            t.repos
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        let _ = writeln!(out, "    {GUTTER}{}", clean(&t.title));
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
    let _ = writeln!(
        out,
        "{kind} {} · revision {} · template {} · {state}",
        ticket.id, t.revision, ticket.template
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
    let row = |out: &mut String, f: Field| {
        let _ = writeln!(out, "  {:<18} {}", f.label(), field(ticket, f));
    };
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
    for path in &t.expected_paths {
        let _ = writeln!(out, "    {GUTTER}{}", quoted([path.as_str()]));
    }
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
    let _ = writeln!(
        out,
        "  {} · template {} · expires {}",
        ticket.id, ticket.template, ticket.limits.expires_at
    );
    for f in [
        Field::Repos,
        Field::Operations,
        Field::Branches,
        Field::ForcePush,
        Field::CommitterEmails,
        Field::ExpectedPaths,
    ] {
        let _ = writeln!(out, "  {:<18} {}", f.label(), field(ticket, f));
    }
    let limits = &ticket.limits;
    let _ = writeln!(
        out,
        "  {:<18} {} signatures, {} pushes, {}/min, {} per push, {}",
        "limits",
        limits.max_signatures,
        limits.max_pushes,
        limits.max_ops_per_minute,
        limits.max_push_size,
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
    for (label, before, after) in changes {
        let _ = writeln!(out, "  {label}");
        let _ = writeln!(out, "    - {before}");
        let _ = writeln!(out, "    + {after}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tail = lines[lines.len() - 9..].join("\n");
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
