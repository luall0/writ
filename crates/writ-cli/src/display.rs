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
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::Timestamp;

/// The gutter in front of every line of agent-written text.
pub const GUTTER: &str = "│ ";

/// Whether a character must be shown escaped: controls (C0, DEL, C1), bidi controls,
/// invisible format characters and line separators.
fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Agent text made safe for one line of the terminal: every hidden character as `\u{…}`
/// (newlines included).
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
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

fn list(items: impl IntoIterator<Item = impl ToString>) -> String {
    let items: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
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

/// The ticket's fields as `(label, value)` pairs, values already cleaned: what the diffs
/// compare.
pub fn fields(ticket: &Ticket) -> Vec<(&'static str, String)> {
    let scope = &ticket.scope;
    let limits = &ticket.limits;
    let text = &ticket.ticket;
    let caller = match &ticket.subject.caller {
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
    };
    vec![
        ("template", ticket.template.to_string()),
        ("expires at", limits.expires_at.to_string()),
        ("session key", ticket.subject.session_key.to_string()),
        (
            "origin hint",
            clean(ticket.subject.origin_hint.as_deref().unwrap_or("(none)")),
        ),
        ("caller", caller),
        ("repos", list(&scope.repos)),
        ("operations", list(&scope.operations)),
        ("branches", list(&scope.branches)),
        (
            "force push",
            if scope.force_push { "yes" } else { "no" }.to_owned(),
        ),
        ("committer emails", list(&scope.committer_emails)),
        (
            "signing key",
            scope
                .signing_key
                .as_ref()
                .map_or("(none)".to_owned(), ToString::to_string),
        ),
        ("max signatures", limits.max_signatures.to_string()),
        ("max pushes", limits.max_pushes.to_string()),
        ("max ops per minute", limits.max_ops_per_minute.to_string()),
        ("max push size", limits.max_push_size.to_string()),
        (
            "on violation",
            match ticket.on_violation {
                OnViolation::DenyAndNotify => "deny and notify",
                OnViolation::RevokeLease => "revoke the lease",
            }
            .to_owned(),
        ),
        ("title", clean(&text.title)),
        ("task", clean(&text.task)),
        (
            "plan",
            text.plan
                .iter()
                .enumerate()
                .map(|(i, step)| format!("{}. {}", i + 1, clean(step)))
                .collect::<Vec<_>>()
                .join(" / "),
        ),
        (
            "expected paths",
            list(text.expected_paths.iter().map(|p| clean(p.as_str()))),
        ),
    ]
}

/// The fields that differ between two tickets: `(label, before, after)`.
pub fn diff(before: &Ticket, after: &Ticket) -> Vec<(&'static str, String, String)> {
    fields(before)
        .into_iter()
        .zip(fields(after))
        .filter(|((_, a), (_, b))| a != b)
        .map(|((label, a), (_, b))| (label, a, b))
        .collect()
}

/// The full display of a ticket waiting for a signature.
pub fn ticket(ticket: &Ticket, state: State, now: Timestamp) -> String {
    let mut out = String::new();
    let t = &ticket.ticket;
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
    let all = fields(ticket);
    let value = |label: &str| {
        all.iter()
            .find(|(l, _)| *l == label)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    out.push_str("\nWho\n");
    for label in ["session key", "caller"] {
        let _ = writeln!(out, "  {label:<18} {}", value(label));
    }
    let _ = writeln!(out, "  origin hint (the agent's claim, not checked):");
    out.push_str(&block(
        ticket.subject.origin_hint.as_deref().unwrap_or("(none)"),
        "    ",
    ));
    out.push_str("\nScope (enforced)\n");
    for label in [
        "repos",
        "operations",
        "branches",
        "force push",
        "committer emails",
        "signing key",
    ] {
        let _ = writeln!(out, "  {label:<18} {}", value(label));
    }
    out.push_str("\nLimits (enforced)\n");
    for label in [
        "max signatures",
        "max pushes",
        "max ops per minute",
        "max push size",
        "on violation",
    ] {
        let _ = writeln!(out, "  {label:<18} {}", value(label));
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
    out.push_str(&block(&value("expected paths"), "    "));
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
