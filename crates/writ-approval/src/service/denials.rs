//! A lease holder's denials, coalesced past a budget (decision log, Q34): per lease, the
//! first [`MAX_LINES`] denial lines of a [`WINDOW_SECONDS`] window are written; past it,
//! denials are counted, and the count is written as one line per kind when the window is
//! over (with the next line logged, or at the next sweep). Every denial is still denied, and
//! counted in the log; a lease holder sending requests it knows are refused can't grow the
//! log faster than this.
//!
//! The same rule as the gateway's for denials before authentication, on the service's clock.
//! Allowed lines and reductions of privilege are never held back.

use std::collections::HashMap;

use writ_core::names::TicketId;
use writ_core::units::Timestamp;
use writ_store::{AuditEvent, EventKind, Outcome};

/// Denial lines written per lease and window; past it, denials are counted.
pub(super) const MAX_LINES: u32 = 60;

/// The window, in seconds of the service's clock.
pub(super) const WINDOW_SECONDS: i64 = 60;

/// Leases tracked at once; a lease past it has every denial written (never silence).
const MAX_TRACKED: usize = 4096;

/// One lease's current window.
struct Window {
    started: Timestamp,
    lines: u32,
    /// Denials counted, not written, by kind.
    counted: Vec<(EventKind, u64)>,
}

#[derive(Default)]
pub(super) struct LeaseDenials {
    windows: HashMap<TicketId, Window>,
}

impl LeaseDenials {
    /// Whether to write `event` now. Only a denial of a lease counts against its budget; one
    /// past it is counted instead.
    pub(super) fn admit(&mut self, event: &AuditEvent) -> bool {
        let (Outcome::Denied, Some(lease)) = (event.result, &event.lease) else {
            return true;
        };
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
                let reason = format!(
                    "{count} more denials of this lease since {}, counted and not logged one \
                     by one (more than {MAX_LINES} in {WINDOW_SECONDS} seconds)",
                    window.started
                );
                lines.push(
                    AuditEvent::new(now, kind, Outcome::Denied)
                        .lease(&lease)
                        .reason(reason),
                );
            }
        }
        lines
    }
}
