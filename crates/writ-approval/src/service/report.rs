//! Closing a lease and its activity report (`docs/flows.md` § 6b): the agent ends its lease
//! with a summary, and gets back what the lease and the leases it renews did, from the state
//! (the leases, their counters, the ledger) and from the audit log, read without the state
//! lock. The summary is agent-written: kept and shown as written, never acted on.

use std::collections::{BTreeMap, BTreeSet};

use writ_core::caller::CallerFacts;
use writ_core::lease::{Lease, State};
use writ_core::names::TicketId;
use writ_core::units::Timestamp;
use writ_crypto::ssh_key::PublicKey;
use writ_proto::{
    ChainLink, CloseRequest, Count, DenialCount, Phases, Report, ReportCommit, ReportPush,
};
use writ_store::{AuditEvent, AuditLine, EventKind, Outcome};

use super::{Inner, Service, fingerprint, internal, not_found};
use crate::{RefusalCode, ServiceError};

/// The most characters of a closing summary.
pub const MAX_SUMMARY_CHARS: usize = 4_000;
/// The most lines of a closing summary.
pub const MAX_SUMMARY_LINES: usize = 100;
/// The most audit lines one report reads (the chain's); past it, the report says so.
pub const MAX_REPORT_LINES: usize = 100_000;
/// The most distinct warnings one report lists.
const MAX_WARNINGS: usize = 50;

/// What the report takes from the state, under the lock.
struct Gathered {
    lease: Lease,
    /// The chain, the oldest first, then the lease itself: each with when it was submitted
    /// and when it ended, and its counters.
    links: Vec<ChainLink>,
    used_seconds: u64,
    granted_seconds: u64,
    commits: Vec<ReportCommit>,
    summary: Option<String>,
    signatures: Count,
    pushes: Count,
    end: Timestamp,
}

impl Service {
    /// `writ close`: the session holding lease `id` ends it with a summary. An active lease
    /// becomes `closed` (its certificate refused, its sessions dropped); one that already
    /// ended (expired, used up, renewed, revoked) keeps its state and gets the summary, so the
    /// agent still gets its report. To another session the lease doesn't exist. One `close`
    /// line either way.
    pub fn close(
        &self,
        id: &TicketId,
        session_key: &PublicKey,
        request: &CloseRequest,
        caller: &CallerFacts,
    ) -> Result<Report, ServiceError> {
        let session = fingerprint(session_key)?;
        let (now, mut inner) = self.begin()?;
        let denied = AuditEvent::new(now, EventKind::Close, Outcome::Denied)
            .lease(id)
            .caller(caller);
        let lease = match inner.store.lease(id).map_err(internal)? {
            Some(lease) if lease.ticket.subject.session_key == session => lease,
            _ => {
                Self::log_best_effort(&mut inner, &denied.reason("no such lease for this session"));
                return Err(not_found(id));
            }
        };
        if let Err(reason) = check_summary(&request.summary) {
            Self::log_best_effort(&mut inner, &denied.reason(reason.clone()));
            return Err(ServiceError::refused(RefusalCode::Summary, reason));
        }
        let event = AuditEvent::new(now, EventKind::Close, Outcome::Done)
            .lease(id)
            .cert(lease.cert_serial)
            .caller(caller);
        match lease.state {
            State::Active => {
                self.bar_serial(lease.cert_serial);
                inner.watches.remove(id);
                let done = Self::reduced(&mut inner, event, |inner| {
                    inner
                        .store
                        .close(id, State::Active, &request.summary, now)
                        .map_err(internal)
                });
                self.deny_serial(lease.cert_serial);
                done?;
            }
            State::Expired | State::Exhausted | State::Renewed | State::Revoked => {
                let event = event.reason(format!("already {}", lease.state));
                Self::logged(&mut inner, event, |inner| {
                    inner
                        .store
                        .close(id, lease.state, &request.summary, now)
                        .map_err(internal)
                })?;
            }
            state => {
                let reason = format!("lease {id} is {state}: nothing to close");
                Self::log_best_effort(&mut inner, &denied.reason(reason.clone()));
                return Err(ServiceError::refused(RefusalCode::WrongState, reason));
            }
        }
        let gathered = self.gather(&inner, id, now)?;
        let path = inner.audit.path().to_owned();
        drop(inner);
        self.changed.notify_waiters();
        Self::report_from(gathered, &path)
    }

    /// `writ report <lease>` (the approval API): a lease's activity report, read-only.
    pub fn report(&self, id: &TicketId) -> Result<Report, ServiceError> {
        let (now, inner) = self.begin()?;
        if inner.store.lease(id).map_err(internal)?.is_none() {
            return Err(not_found(id));
        }
        let gathered = self.gather(&inner, id, now)?;
        let path = inner.audit.path().to_owned();
        drop(inner);
        Self::report_from(gathered, &path)
    }

    /// The state's part of a report, under the lock: bounded by the chain and the ledger
    /// (each lease signs at most its template's `max_signatures`).
    fn gather(
        &self,
        inner: &Inner,
        id: &TicketId,
        now: Timestamp,
    ) -> Result<Gathered, ServiceError> {
        let lease = inner
            .store
            .lease(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id))?;
        let mut ids = inner.store.predecessors(id).map_err(internal)?;
        ids.reverse();
        ids.push(id.clone());
        let mut links = Vec::with_capacity(ids.len());
        let (mut used_seconds, mut granted_seconds) = (0u64, 0u64);
        let mut commits = Vec::new();
        for link in &ids {
            let Some(each) = inner.store.lease(link).map_err(internal)? else {
                continue;
            };
            let times = inner.store.times(link).map_err(internal)?;
            let usage = inner.store.usage(link, now).map_err(internal)?;
            used_seconds = used_seconds.saturating_add(Self::used_seconds(inner, &each, now)?);
            let granted = times
                .created_at
                .seconds_until(each.ticket.limits.expires_at);
            granted_seconds =
                granted_seconds.saturating_add(u64::try_from(granted.max(0)).unwrap_or(0));
            commits.extend(
                inner
                    .store
                    .ledger_for_lease(link)
                    .map_err(internal)?
                    .into_iter()
                    .map(|entry| ReportCommit {
                        id: entry.commit,
                        repo: entry.repo,
                        lease: entry.lease,
                        signed_at: entry.signed_at,
                    }),
            );
            links.push(ChainLink {
                id: link.clone(),
                state: each.state,
                created_at: times.created_at,
                expires_at: each.ticket.limits.expires_at,
                ended_at: (each.state != State::Active)
                    .then(|| times.updated_at.min(each.ticket.limits.expires_at)),
                signatures: usage.signatures,
                pushes: usage.pushes,
            });
        }
        commits.sort_by_key(|c| c.signed_at);
        let usage = inner.store.usage(id, now).map_err(internal)?;
        let end = links
            .last()
            .and_then(|link| link.ended_at)
            .unwrap_or(now)
            .min(lease.ticket.limits.expires_at);
        Ok(Gathered {
            signatures: Count {
                used: usage.signatures,
                max: lease.ticket.limits.max_signatures,
            },
            pushes: Count {
                used: usage.pushes,
                max: lease.ticket.limits.max_pushes,
            },
            summary: inner.store.summary(id).map_err(internal)?,
            lease,
            links,
            used_seconds,
            granted_seconds,
            commits,
            end,
        })
    }

    /// Reads the chain's lines from the audit log (no lock held) and builds the report.
    fn report_from(gathered: Gathered, path: &std::path::Path) -> Result<Report, ServiceError> {
        let ids: Vec<TicketId> = gathered.links.iter().map(|l| l.id.clone()).collect();
        let (lines, truncated) =
            writ_store::read_lines(path, &ids, MAX_REPORT_LINES).map_err(internal)?;
        Ok(build(gathered, &lines, truncated))
    }
}

/// A summary may say anything, but within the bounds of a ticket's task.
fn check_summary(summary: &str) -> Result<(), String> {
    if summary.trim().is_empty() {
        return Err("the summary is empty".to_owned());
    }
    let chars = summary.chars().count();
    if chars > MAX_SUMMARY_CHARS {
        return Err(format!(
            "the summary is too long ({chars}, at most {MAX_SUMMARY_CHARS})"
        ));
    }
    let lines = summary.split('\n').count();
    if lines > MAX_SUMMARY_LINES {
        return Err(format!(
            "the summary has {lines} lines, at most {MAX_SUMMARY_LINES}"
        ));
    }
    Ok(())
}

/// The seconds from `from` to `to`, none when `to` is earlier.
fn between(from: Timestamp, to: Timestamp) -> Option<u64> {
    u64::try_from(from.seconds_until(to)).ok()
}

/// The report, from the state's part and the chain's audit lines (in the log's order).
fn build(gathered: Gathered, lines: &[AuditLine], truncated: bool) -> Report {
    let mut pushed = Vec::new();
    let mut branches = BTreeSet::new();
    let mut denials: BTreeMap<String, u64> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut fetches = 0u64;
    let mut grants: BTreeMap<&TicketId, Timestamp> = BTreeMap::new();
    let mut signs = Vec::new();
    for line in lines {
        let allowed = line.result == "allowed";
        match (line.event.as_str(), allowed) {
            ("grant", true) => {
                if let Some(lease) = &line.lease {
                    grants.entry(lease).or_insert(line.time);
                }
            }
            ("sign", true) if line.count.is_none() => {
                signs.push(line.time);
                for warning in &line.warnings {
                    if warnings.len() < MAX_WARNINGS && !warnings.contains(warning) {
                        warnings.push(warning.clone());
                    }
                }
            }
            ("push", true) if line.count.is_none() => {
                branches.extend(line.refs.iter().cloned());
                pushed.push(ReportPush {
                    at: line.time,
                    repo: line.repo.clone(),
                    refs: line.refs.clone(),
                });
            }
            ("fetch", true) => fetches = fetches.saturating_add(line.count.unwrap_or(1)),
            ("connect" | "command" | "sign" | "push" | "fetch", false) => {
                let code = line.code.clone().unwrap_or_else(|| "counted".to_owned());
                let count = denials.entry(code).or_default();
                *count = count.saturating_add(line.count.unwrap_or(1));
            }
            _ => {}
        }
    }
    let phases = phases(&gathered, &grants, &signs, &pushed);
    let ticket = &gathered.lease.ticket;
    Report {
        lease: gathered.lease.id.clone(),
        state: gathered.lease.state,
        title: ticket.text.title.clone(),
        template: ticket.template.clone(),
        repos: ticket.scope.repos.iter().cloned().collect(),
        expected_paths: ticket
            .text
            .expected_paths
            .iter()
            .map(ToString::to_string)
            .collect(),
        summary: gathered.summary.clone(),
        estimate: ticket.text.estimate,
        chain: gathered.links.clone(),
        granted_seconds: gathered.granted_seconds,
        used_seconds: gathered.used_seconds,
        signatures: gathered.signatures,
        pushes: gathered.pushes,
        fetches,
        commits: gathered.commits.clone(),
        pushed,
        branches: branches.into_iter().collect(),
        denials: denials
            .into_iter()
            .map(|(code, count)| DenialCount { code, count })
            .collect(),
        warnings,
        phases,
        truncated,
    }
}

/// The phases, from the daemon's timestamps: the approval waits (submission to grant, each
/// lease), coding (the first grant to the first signature), CI rounds (a push to the next
/// signature after it), and the time after the last push.
fn phases(
    gathered: &Gathered,
    grants: &BTreeMap<&TicketId, Timestamp>,
    signs: &[Timestamp],
    pushed: &[ReportPush],
) -> Phases {
    let mut wait: Option<u64> = None;
    for link in &gathered.links {
        if let Some(seconds) = grants
            .get(&link.id)
            .and_then(|granted| between(link.created_at, *granted))
        {
            wait = Some(wait.unwrap_or(0).saturating_add(seconds));
        }
    }
    let first_grant = gathered
        .links
        .iter()
        .find_map(|link| grants.get(&link.id).copied());
    let coding = match (first_grant, signs.first()) {
        (Some(granted), Some(signed)) => between(granted, *signed),
        _ => None,
    };
    let mut events: Vec<(Timestamp, bool)> = signs.iter().map(|t| (*t, false)).collect();
    events.extend(pushed.iter().map(|p| (p.at, true)));
    events.sort();
    let mut rounds = Vec::new();
    let mut last_push: Option<Timestamp> = None;
    for (at, is_push) in events {
        if is_push {
            last_push = Some(at);
        } else if let Some(push) = last_push.take()
            && let Some(seconds) = between(push, at)
        {
            rounds.push(seconds);
        }
    }
    let after = pushed
        .last()
        .and_then(|push| between(push.at, gathered.end));
    Phases {
        approval_wait_seconds: wait,
        coding_seconds: coding,
        ci_rounds_seconds: rounds,
        after_last_push_seconds: after,
    }
}
