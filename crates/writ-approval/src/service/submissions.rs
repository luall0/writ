//! Ticket submission rates (decision log): per source (an address; an IPv6 host by its /64;
//! local callers share one) and for all sources together, over a minute each, set by the
//! operator ([`SubmissionLimits`]). The rates bound what submissions make the daemon parse
//! and write to the audit log, however many sources an attacker holds.
//!
//! Every refusal is counted in the log. The first refusal of a burst writes its own line;
//! the others are counted, and the count is written when that window next lets a submission
//! through, or when the window ends (the sweep: a source that went quiet still gets its
//! count logged). The table of sources is bounded: when it is full, the window that has been
//! quiet the longest is dropped, its count written first.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use writ_core::units::Timestamp;

/// Submissions one source may make per minute, unless the operator says otherwise.
pub const DEFAULT_SUBMISSIONS_PER_SOURCE: usize = 10;

/// Submissions all sources together may make per minute, unless the operator says otherwise.
pub const DEFAULT_SUBMISSIONS_IN_ALL: usize = 60;

/// The most the operator may set per source: each tracked source keeps up to this many
/// times, for up to [`MAX_TRACKED_SOURCES`] sources.
pub const MAX_SUBMISSIONS_PER_SOURCE: usize = 1_000;

/// The most the operator may set for all sources together.
pub const MAX_SUBMISSIONS_IN_ALL: usize = 10_000;

/// Sources tracked at once; past it, the window quiet the longest is dropped.
const MAX_TRACKED_SOURCES: usize = 4096;

/// The rate window.
const WINDOW_SECONDS: i64 = 60;

/// The operator's submission rates, per minute (`submissions` in `writd.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmissionLimits {
    /// Per source address (an IPv6 host by its /64).
    pub per_source: usize,
    /// All sources together.
    pub in_all: usize,
}

impl Default for SubmissionLimits {
    fn default() -> Self {
        Self {
            per_source: DEFAULT_SUBMISSIONS_PER_SOURCE,
            in_all: DEFAULT_SUBMISSIONS_IN_ALL,
        }
    }
}

impl SubmissionLimits {
    /// Each rate at least 1 (0 would refuse every ticket) and at most its maximum.
    pub fn check(&self) -> Result<(), String> {
        let bounded = |name: &str, value: usize, max: usize| {
            if (1..=max).contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "submissions.{name}: {value}, must be from 1 to {max}"
                ))
            }
        };
        bounded("per_source", self.per_source, MAX_SUBMISSIONS_PER_SOURCE)?;
        bounded("in_all", self.in_all, MAX_SUBMISSIONS_IN_ALL)
    }
}

/// Whose line it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    /// The caller of the submission being decided.
    Caller,
    /// A source by its group, decided earlier (a window that ended or was dropped).
    Source(Option<IpAddr>),
    /// All sources together.
    All,
}

/// An audit line to write (event `submit`, denied).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Line {
    pub(super) scope: Scope,
    pub(super) reason: String,
}

/// What [`Submissions::admit`] decided: the lines to write, and the refusal for the client
/// if the submission is over a rate.
#[derive(Debug, Default)]
pub(super) struct Admission {
    pub(super) lines: Vec<Line>,
    pub(super) refused: Option<String>,
}

/// Accepted submissions in the last minute, and the refusals of the current burst.
#[derive(Debug, Default)]
struct Window {
    times: VecDeque<Timestamp>,
    /// The burst's first refusal was logged.
    burst: bool,
    /// Refusals of this burst after the first: counted, not logged one by one.
    counted: u64,
}

impl Window {
    /// Forgets the submissions older than the window ending `now`.
    fn slide(&mut self, now: Timestamp) {
        while self
            .times
            .front()
            .is_some_and(|t| t.seconds_until(now) >= WINDOW_SECONDS)
        {
            self.times.pop_front();
        }
    }

    /// A refusal: whether it is the burst's first (logged), else counted.
    fn refuse(&mut self) -> bool {
        if self.burst {
            self.counted = self.counted.saturating_add(1);
            false
        } else {
            self.burst = true;
            true
        }
    }

    /// The burst's count, taken: the burst is over.
    fn take_count(&mut self) -> u64 {
        self.burst = false;
        std::mem::take(&mut self.counted)
    }

    /// The last submission it let through.
    fn last(&self) -> Option<Timestamp> {
        self.times.back().copied()
    }
}

/// The submission rates' state. See the module documentation.
#[derive(Debug)]
pub(super) struct Submissions {
    limits: SubmissionLimits,
    max_sources: usize,
    sources: HashMap<Option<IpAddr>, Window>,
    all: Window,
}

fn source_count(count: u64) -> String {
    format!("{count} more submissions from this address were refused over the rate")
}

fn all_count(count: u64) -> String {
    format!("{count} more submissions were refused over the rate for all sources")
}

impl Submissions {
    pub(super) fn new(limits: SubmissionLimits) -> Self {
        Self::with_capacity(limits, MAX_TRACKED_SOURCES)
    }

    fn with_capacity(limits: SubmissionLimits, max_sources: usize) -> Self {
        Self {
            limits,
            max_sources,
            sources: HashMap::new(),
            all: Window::default(),
        }
    }

    /// Decides on a submission from `source` (an address, or none: a local caller) at `now`.
    /// A submission over a rate is refused and not counted against any rate.
    pub(super) fn admit(&mut self, source: Option<IpAddr>, now: Timestamp) -> Admission {
        let group = source.map(writ_core::net::source_group);
        let mut admission = Admission::default();
        if !self.sources.contains_key(&group) && self.sources.len() >= self.max_sources {
            admission.lines.extend(self.due(now));
            if self.sources.len() >= self.max_sources {
                admission.lines.extend(self.drop_quietest());
            }
        }
        self.all.slide(now);
        let per_source = self.limits.per_source;
        let window = self.sources.entry(group).or_default();
        window.slide(now);
        if window.times.len() >= per_source {
            let reason = format!("more than {per_source} submissions a minute from this address");
            if window.refuse() {
                admission.lines.push(Line {
                    scope: Scope::Caller,
                    reason: reason.clone(),
                });
            }
            admission.refused = Some(format!("{reason}; try again later"));
            return admission;
        }
        let in_all = self.limits.in_all;
        if self.all.times.len() >= in_all {
            let reason = format!("more than {in_all} submissions a minute from all sources");
            if self.all.refuse() {
                admission.lines.push(Line {
                    scope: Scope::All,
                    reason: reason.clone(),
                });
            }
            admission.refused = Some(format!("{reason}; try again later"));
            return admission;
        }
        let count = window.take_count();
        if count > 0 {
            admission.lines.push(Line {
                scope: Scope::Caller,
                reason: source_count(count),
            });
        }
        window.times.push_back(now);
        let count = self.all.take_count();
        if count > 0 {
            admission.lines.push(Line {
                scope: Scope::All,
                reason: all_count(count),
            });
        }
        self.all.times.push_back(now);
        admission
    }

    /// The windows over at `now` (nothing let through in the last minute): their counts, and
    /// the windows forgotten.
    pub(super) fn due(&mut self, now: Timestamp) -> Vec<Line> {
        let mut lines = Vec::new();
        self.sources.retain(|group, window| {
            window.slide(now);
            if !window.times.is_empty() {
                return true;
            }
            let count = window.take_count();
            if count > 0 {
                lines.push(Line {
                    scope: Scope::Source(*group),
                    reason: source_count(count),
                });
            }
            false
        });
        self.all.slide(now);
        if self.all.times.is_empty() {
            let count = self.all.take_count();
            if count > 0 {
                lines.push(Line {
                    scope: Scope::All,
                    reason: all_count(count),
                });
            }
        }
        lines
    }

    /// Drops the window quiet the longest, its count written first.
    fn drop_quietest(&mut self) -> Vec<Line> {
        let quietest = self
            .sources
            .iter()
            .min_by_key(|(_, window)| window.last())
            .map(|(group, _)| *group);
        let Some(group) = quietest else {
            return Vec::new();
        };
        let Some(mut window) = self.sources.remove(&group) else {
            return Vec::new();
        };
        let count = window.take_count();
        if count == 0 {
            return Vec::new();
        }
        vec![Line {
            scope: Scope::Source(group),
            reason: source_count(count),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: i64 = 1_793_455_331;

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_unix(START + offset).unwrap()
    }

    fn ip(n: u32) -> Option<IpAddr> {
        Some(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n)))
    }

    fn limits(per_source: usize, in_all: usize) -> SubmissionLimits {
        SubmissionLimits { per_source, in_all }
    }

    fn reasons(lines: &[Line]) -> Vec<(Scope, &str)> {
        lines.iter().map(|l| (l.scope, l.reason.as_str())).collect()
    }

    #[test]
    fn a_source_submits_up_to_its_rate_and_every_refusal_is_counted() {
        let mut rates = Submissions::new(limits(3, 100));
        for _ in 0..3 {
            let admitted = rates.admit(ip(1), at(0));
            assert_eq!(admitted.refused, None);
            assert!(admitted.lines.is_empty());
        }
        // Over: the burst's first refusal has its line, the next ones are counted.
        let first = rates.admit(ip(1), at(1));
        assert_eq!(
            first.refused.as_deref(),
            Some("more than 3 submissions a minute from this address; try again later")
        );
        assert_eq!(
            reasons(&first.lines),
            vec![(
                Scope::Caller,
                "more than 3 submissions a minute from this address"
            )]
        );
        for _ in 0..4 {
            let counted = rates.admit(ip(1), at(2));
            assert!(counted.refused.is_some());
            assert!(counted.lines.is_empty());
        }
        // Another source has its own rate.
        assert_eq!(rates.admit(ip(2), at(2)).refused, None);
        // A minute after the first three, one passes, with the burst's count.
        assert!(rates.admit(ip(1), at(59)).refused.is_some());
        let passed = rates.admit(ip(1), at(60));
        assert_eq!(passed.refused, None);
        assert_eq!(
            reasons(&passed.lines),
            vec![(
                Scope::Caller,
                "5 more submissions from this address were refused over the rate"
            )]
        );
    }

    #[test]
    fn a_source_that_goes_quiet_still_gets_its_count_logged() {
        let mut rates = Submissions::new(limits(2, 100));
        rates.admit(ip(1), at(0));
        rates.admit(ip(1), at(10));
        for _ in 0..3 {
            assert!(rates.admit(ip(1), at(20)).refused.is_some());
        }
        // The window holds a submission until 70: not over yet.
        assert!(rates.due(at(69)).is_empty());
        assert_eq!(
            reasons(&rates.due(at(70))),
            vec![(
                Scope::Source(ip(1)),
                "2 more submissions from this address were refused over the rate"
            )]
        );
        assert!(rates.sources.is_empty(), "the window is forgotten");
        // A window that was never over the rate ends without a line.
        rates.admit(ip(3), at(100));
        assert!(rates.due(at(160)).is_empty());
        assert!(rates.sources.is_empty());
    }

    #[test]
    fn all_sources_together_stop_at_their_rate() {
        let mut rates = Submissions::new(limits(10, 3));
        for n in 0..3 {
            assert_eq!(rates.admit(ip(n), at(0)).refused, None);
        }
        let over = rates.admit(ip(10), at(1));
        assert_eq!(
            over.refused.as_deref(),
            Some("more than 3 submissions a minute from all sources; try again later")
        );
        assert_eq!(
            reasons(&over.lines),
            vec![(
                Scope::All,
                "more than 3 submissions a minute from all sources"
            )]
        );
        for n in 11..14 {
            let counted = rates.admit(ip(n), at(2));
            assert!(counted.refused.is_some());
            assert!(counted.lines.is_empty());
        }
        // A refusal for all sources uses nothing of the source's own rate.
        assert!(rates.sources[&ip(10)].times.is_empty());
        // A minute on, the next one passes and carries the count.
        let passed = rates.admit(ip(20), at(60));
        assert_eq!(passed.refused, None);
        assert_eq!(
            reasons(&passed.lines),
            vec![(
                Scope::All,
                "3 more submissions were refused over the rate for all sources"
            )]
        );
    }

    #[test]
    fn the_count_for_all_sources_is_logged_when_they_go_quiet() {
        let mut rates = Submissions::new(limits(10, 1));
        rates.admit(ip(1), at(0));
        assert!(rates.admit(ip(2), at(1)).refused.is_some());
        assert!(rates.admit(ip(3), at(1)).refused.is_some());
        assert!(rates.due(at(59)).is_empty());
        assert_eq!(
            reasons(&rates.due(at(60))),
            vec![(
                Scope::All,
                "1 more submissions were refused over the rate for all sources"
            )]
        );
    }

    #[test]
    fn a_full_table_drops_the_quietest_window_and_keeps_its_count() {
        let mut rates = Submissions::with_capacity(limits(1, 100), 3);
        // Source 1, the quietest, over its rate twice (one line, one counted).
        rates.admit(ip(1), at(0));
        rates.admit(ip(1), at(1));
        rates.admit(ip(1), at(1));
        rates.admit(ip(2), at(5));
        rates.admit(ip(3), at(6));
        // A fourth source: source 1's window goes, its count written; nobody is refused.
        let admitted = rates.admit(ip(4), at(7));
        assert_eq!(admitted.refused, None);
        assert_eq!(
            reasons(&admitted.lines),
            vec![(
                Scope::Source(ip(1)),
                "1 more submissions from this address were refused over the rate"
            )]
        );
        assert_eq!(rates.sources.len(), 3);
        assert!(!rates.sources.contains_key(&ip(1)));
        // The others keep their windows: source 2 is still at its rate.
        assert!(rates.admit(ip(2), at(8)).refused.is_some());
        // Windows that are over are forgotten before anything is dropped: 2 and 3 ended
        // (source 2's one refusal had its own line, so no count), 4 stays.
        let admitted = rates.admit(ip(5), at(66));
        assert_eq!(admitted.refused, None);
        assert!(admitted.lines.is_empty());
        let mut kept: Vec<_> = rates.sources.keys().copied().collect();
        kept.sort();
        assert_eq!(kept, vec![ip(4), ip(5)]);
    }

    #[test]
    fn an_ipv6_host_is_one_source() {
        let mut rates = Submissions::new(limits(1, 100));
        let v6 = |n: u16| {
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, n,
            )))
        };
        assert_eq!(rates.admit(v6(1), at(0)).refused, None);
        assert!(rates.admit(v6(2), at(0)).refused.is_some(), "same /64");
    }

    #[test]
    fn the_operator_s_rates_are_bounded() {
        assert_eq!(SubmissionLimits::default(), limits(10, 60));
        assert_eq!(limits(1, 1).check(), Ok(()));
        assert_eq!(
            limits(MAX_SUBMISSIONS_PER_SOURCE, MAX_SUBMISSIONS_IN_ALL).check(),
            Ok(())
        );
        assert_eq!(
            limits(0, 60).check(),
            Err("submissions.per_source: 0, must be from 1 to 1000".to_owned())
        );
        assert_eq!(
            limits(10, 0).check(),
            Err("submissions.in_all: 0, must be from 1 to 10000".to_owned())
        );
        assert_eq!(
            limits(MAX_SUBMISSIONS_PER_SOURCE + 1, 60).check(),
            Err("submissions.per_source: 1001, must be from 1 to 1000".to_owned())
        );
        assert_eq!(
            limits(10, MAX_SUBMISSIONS_IN_ALL + 1).check(),
            Err("submissions.in_all: 10001, must be from 1 to 10000".to_owned())
        );
    }
}
