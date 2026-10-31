//! The trusted display: how `writ sign` shows a ticket before it is signed.
//!
//! Everything the agent wrote (title, task, plan, expected paths, origin hint, the caller's
//! executable) is untrusted. Before it reaches the terminal, [`clean`] turns every character
//! that could move the cursor, recolor, hide or reorder text into a visible `\u{…}` escape,
//! and multi-line text is printed behind a gutter (`│`) on every line, so agent text can
//! never pass for a line `writ sign` wrote itself. Warnings come from `writ sign`, never from
//! the ticket.

use std::fmt::Write as _;

use writ_core::lease::State;
use writ_core::text::is_hidden_char;
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::Timestamp;

/// The gutter in front of every line of agent-written text.
pub const GUTTER: &str = "│ ";

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

/// Agent text over several lines, each behind the gutter and indented.
pub fn block(text: &str, indent: &str) -> String {
    let mut out = String::new();
    for line in text.split('\n') {
        let _ = writeln!(out, "{indent}{GUTTER}{}", clean(line));
    }
    out
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
        Field::Plan => text
            .plan
            .iter()
            .enumerate()
            .map(|(i, step)| format!("{}. {}", i + 1, clean(step)))
            .collect::<Vec<_>>()
            .join(" / "),
        Field::ExpectedPaths => list(text.expected_paths.iter().map(|p| p.as_str())),
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

/// The full display of a ticket waiting for a signature.
pub fn ticket(ticket: &Ticket, state: State, now: Timestamp) -> String {
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
    out.push_str(&block(&t.title, "    "));
    out.push_str("  task\n");
    out.push_str(&block(&t.task, "    "));
    out.push_str("  plan\n");
    if t.plan.is_empty() {
        out.push_str(&block("(none)", "    "));
    }
    for (i, step) in t.plan.iter().enumerate() {
        out.push_str(&block(&format!("{}. {step}", i + 1), "    "));
    }
    out.push_str("  expected paths\n");
    out.push_str(&block(&field(ticket, Field::ExpectedPaths), "    "));
    if let Some(feedback) = &t.previous_feedback {
        let _ = writeln!(
            out,
            "\nFeedback on revision {} (as recorded by the daemon)",
            t.revision.saturating_sub(1)
        );
        out.push_str(&block(feedback, "    "));
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
        let mut shown = ticket(&t, State::Pending, now);
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

    #[test]
    fn every_line_of_agent_text_is_behind_the_gutter() {
        let text = "first\nScope (enforced)\n  repos  everything\x1b[A";
        let shown = block(text, "  ");
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
