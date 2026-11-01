//! A lease holder's lines, coalesced past a budget: per lease, the first [`MAX_LINES`] lines of
//! a [`WINDOW_SECONDS`] window are written; past it, they are counted, and the count is written
//! as one line per kind when the window is over (with the next line logged, or at the next
//! sweep). Two budgets, each with its own windows ([`Coalesced`]):
//!
//! - **denials** (decision log, Q34): every denial is still denied, and counted in the log; a
//!   lease holder sending requests it knows are refused can't grow the log faster than this;
//! - **allowed connections** (M4, the M3.6 review's S2): a lease holder looping `ssh` can't
//!   either; each command it then runs still has its own line (fetch, push, sign: those are
//!   bounded by the lease's rate).
//!
//! The same rule as the gateway's for denials before authentication, on the service's clock.
//! Grants and reductions of privilege are never held back.

use std::collections::HashMap;

use writ_core::names::TicketId;
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, EventKind, Outcome};

/// Lines written per lease, budget and window; past it, they are counted.
pub(super) const MAX_LINES: u32 = 60;

/// The window, in seconds of the service's clock.
pub(super) const WINDOW_SECONDS: i64 = 60;

/// Leases tracked at once; a lease past it has every denial written (never silence).
const MAX_TRACKED: usize = 4096;

/// One lease's current window.
struct Window {
    started: Timestamp,
    lines: u32,
    /// Lines counted, not written, by kind.
    counted: Vec<(EventKind, u64)>,
}

/// Which lines a budget counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Budget {
    /// A lease's denials.
    Denials,
    /// A lease's allowed `connect` lines (a certificate presented and accepted).
    Connections,
}

/// One budget's windows, per lease.
pub(super) struct Coalesced {
    budget: Budget,
    windows: HashMap<TicketId, Window>,
}

impl Coalesced {
    /// The budget of a lease's denials.
    pub(super) fn denials() -> Self {
        Self {
            budget: Budget::Denials,
            windows: HashMap::new(),
        }
    }

    /// The budget of a lease's allowed connections.
    pub(super) fn connections() -> Self {
        Self {
            budget: Budget::Connections,
            windows: HashMap::new(),
        }
    }

    fn counts(&self, event: &AuditEvent) -> bool {
        match self.budget {
            Budget::Denials => event.result == Outcome::Denied,
            Budget::Connections => {
                event.result == Outcome::Allowed && event.event == EventKind::Connect
            }
        }
    }

    /// Whether to write `event` now. Only a line of a lease that this budget counts counts
    /// against it; one past it is counted instead.
    pub(super) fn admit(&mut self, event: &AuditEvent) -> bool {
        let Some(lease) = &event.lease else {
            return true;
        };
        if !self.counts(event) {
            return true;
        }
        if let Some(window) = self.windows.get_mut(lease) {
            if window.lines < MAX_LINES {
                window.lines = window.lines.saturating_add(1);
                return true;
            }
            match window
                .counted
                .iter_mut()
                .find(|(kind, _)| *kind == event.event)
            {
                Some((_, count)) => *count = count.saturating_add(1),
                None => window.counted.push((event.event, 1)),
            }
            return false;
        }
        if self.windows.len() < MAX_TRACKED {
            let window = Window {
                started: event.time,
                lines: 1,
                counted: Vec::new(),
            };
            self.windows.insert(lease.clone(), window);
        }
        true
    }

    /// The lines that report what windows over at `now` counted; those windows are
    /// forgotten.
    pub(super) fn due(&mut self, now: Timestamp) -> Vec<AuditEvent> {
        let over =
            |window: &Window| now.unix().saturating_sub(window.started.unix()) >= WINDOW_SECONDS;
        let ended: Vec<TicketId> = self
            .windows
            .iter()
            .filter(|(_, window)| over(window))
            .map(|(lease, _)| lease.clone())
            .collect();
        let mut lines = Vec::new();
        for lease in ended {
            let Some(window) = self.windows.remove(&lease) else {
                continue;
            };
            for (kind, count) in window.counted {
                let (what, outcome) = match self.budget {
                    Budget::Denials => ("denials", Outcome::Denied),
                    Budget::Connections => ("connections", Outcome::Allowed),
                };
                let reason = format!(
                    "{count} more {what} of this lease since {}, counted and not logged one \
                     by one (more than {MAX_LINES} in {WINDOW_SECONDS} seconds)",
                    window.started
                );
                lines.push(
                    AuditEvent::new(now, kind, outcome)
                        .lease(&lease)
                        .reason(reason),
                );
            }
        }
        lines
    }
}
