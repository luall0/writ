//! The daemon's two outbound operations an approver asks for (M6.2): a host key scan
//! (`writ admin host add`), only on an approver's signed `writ-scan/1` naming this daemon, the
//! host, the port and a nonce the daemon handed out (used once, for a few minutes), so a
//! reader key alone can't make the daemon reach a host; and an upstream check (`writ admin
//! repo check`), with a reader key, only of a repo the policy in force names. Both bounded in
//! number (a few a minute, daemon-wide) and each logged (`scan`, `check`). Running them is the
//! gateway's (the mirrors reach upstream); deciding and logging is here.

use std::collections::VecDeque;

use writ_core::caller::CallerFacts;
use writ_core::names::{KeyFingerprint, RepoName};
use writ_core::signed::{BootNonce, Scan};
use writ_core::units::Timestamp;
use writ_proto::{CheckStep, ScanNonce, ScanRequest};
use writ_store::{AuditEvent, EventKind, Outcome};

use super::{Service, internal};
use crate::{RefusalCode, ServiceError};

/// Nonces handed out and not used yet, at most.
pub const MAX_NONCES: usize = 16;

/// How long a nonce can be used, in seconds.
pub const NONCE_SECONDS: i64 = 300;

/// Scans a minute, daemon-wide.
pub const MAX_SCANS_A_MINUTE: usize = 10;

/// Checks a minute, daemon-wide.
pub const MAX_CHECKS_A_MINUTE: usize = 10;

/// The nonces handed out, and when the last scans and checks ran.
#[derive(Debug, Default)]
pub(crate) struct Outbound {
    nonces: Vec<(BootNonce, Timestamp)>,
    scans: VecDeque<Timestamp>,
    checks: VecDeque<Timestamp>,
    /// When the last TLS key rotations were asked for (M7.5).
    pub(crate) rotations: VecDeque<Timestamp>,
}

/// Whether one more fits `window` (the last minute's) under `max`: when it does, it is counted.
pub(crate) fn within(window: &mut VecDeque<Timestamp>, now: Timestamp, max: usize) -> bool {
    while window
        .front()
        .is_some_and(|t| now.unix().saturating_sub(t.unix()) >= 60)
    {
        window.pop_front();
    }
    if window.len() >= max {
        return false;
    }
    window.push_back(now);
    true
}

/// A scan whose document and signature passed: only [`Service::check_scan`] makes one, and it
/// is never copied (what holds one moves it).
#[derive(Debug)]
pub struct CheckedScan {
    scan: Scan,
    approver: KeyFingerprint,
}

impl CheckedScan {
    /// What to scan.
    pub fn scan(&self) -> &Scan {
        &self.scan
    }

    /// The approver key that signed it.
    pub fn approver(&self) -> &KeyFingerprint {
        &self.approver
    }

    /// The host and port, as a line names them, and the proxy it goes through.
    fn target(&self) -> String {
        match &self.scan.proxy {
            None => format!("{}:{}", self.scan.host, self.scan.port),
            Some(proxy) => format!(
                "{}:{} through proxy {proxy}",
                self.scan.host, self.scan.port
            ),
        }
    }
}

fn refused(reason: impl Into<String>) -> ServiceError {
    ServiceError::refused(RefusalCode::Scan, reason)
}

impl Service {
    pub(crate) fn outbound(&self) -> std::sync::MutexGuard<'_, Outbound> {
        // poisoned: what it holds is still right (nonces and times), only possibly stale.
        self.outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A nonce for one scan, used once, for [`NONCE_SECONDS`]: the oldest one goes when
    /// [`MAX_NONCES`] are out.
    pub fn scan_nonce(&self) -> Result<ScanNonce, ServiceError> {
        self.opened()?;
        let now = self.now()?;
        let nonce = BootNonce::from_bytes(writ_crypto::keys::random_array().map_err(internal)?);
        let mut outbound = self.outbound();
        outbound
            .nonces
            .retain(|(_, at)| now.unix().saturating_sub(at.unix()) < NONCE_SECONDS);
        if outbound.nonces.len() >= MAX_NONCES {
            outbound.nonces.remove(0);
        }
        outbound.nonces.push((nonce.clone(), now));
        Ok(ScanNonce {
            daemon: self.boot.daemon.clone(),
            nonce,
        })
    }

    /// Checks a scan's document and signature: a `writ-scan/1` decoded strictly, signed by an
    /// approver in force, naming this daemon and a nonce it handed out (used now, for good),
    /// within the scans' rate. A refusal is logged (`scan`, denied).
    pub fn check_scan(
        &self,
        request: &ScanRequest,
        caller: &CallerFacts,
    ) -> Result<CheckedScan, ServiceError> {
        self.opened()?;
        let checked = self.scan_document(request);
        if let Err(e) = &checked {
            self.scan_denied(None, Err(&e.to_string()), caller);
        }
        checked
    }

    fn scan_document(&self, request: &ScanRequest) -> Result<CheckedScan, ServiceError> {
        let (scan, approver) = self.approver_document(
            &request.document,
            &request.signature,
            |s: &Scan| &s.daemon,
            "scan",
            RefusalCode::Scan,
        )?;
        let now = self.now()?;
        let mut outbound = self.outbound();
        let fresh = |(nonce, at): &(BootNonce, Timestamp)| {
            nonce == &scan.nonce && now.unix().saturating_sub(at.unix()) < NONCE_SECONDS
        };
        let Some(index) = outbound.nonces.iter().position(fresh) else {
            return Err(refused(
                "the scan's nonce is unknown, used or expired (writ admin host add asks for a \
                 new one)",
            ));
        };
        // Used once, whatever comes next.
        outbound.nonces.remove(index);
        if !within(&mut outbound.scans, now, MAX_SCANS_A_MINUTE) {
            return Err(refused(format!(
                "more than {MAX_SCANS_A_MINUTE} scans a minute: try again shortly"
            )));
        }
        Ok(CheckedScan { scan, approver })
    }

    /// The line of a checked scan, before the daemon reaches the host (the review after M7.6:
    /// no line, no connection out), as for an admin change: refused when the log can't take
    /// it. It names the host, the port and the proxy, and the approver.
    pub fn scan_starting(
        &self,
        checked: &CheckedScan,
        caller: &CallerFacts,
    ) -> Result<(), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let event = AuditEvent::new(now, EventKind::Scan, Outcome::Allowed)
            .caller(caller)
            .approver(&checked.approver)
            .reason(format!("{}: scanning", checked.target()));
        Self::log(&mut inner, &event)
    }

    /// Logs what a checked scan read: done with the fingerprints, or denied with the reason
    /// (the host not reached).
    pub fn scan_logged(
        &self,
        checked: &CheckedScan,
        result: Result<&[String], &str>,
        caller: &CallerFacts,
    ) {
        self.scan_denied(Some(checked), result, caller);
    }

    fn scan_denied(
        &self,
        checked: Option<&CheckedScan>,
        result: Result<&[String], &str>,
        caller: &CallerFacts,
    ) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let target = checked.map(CheckedScan::target);
        let (outcome, reason) = match (result, &target) {
            (Ok(fingerprints), Some(target)) => (
                Outcome::Done,
                format!("{target}: {}", fingerprints.join(", ")),
            ),
            // Nothing scanned without a check: never written.
            (Ok(_), None) => return,
            (Err(why), Some(target)) => (Outcome::Denied, format!("{target}: {why}")),
            (Err(why), None) => (Outcome::Denied, why.to_owned()),
        };
        let mut event = AuditEvent::new(now, EventKind::Scan, outcome)
            .caller(caller)
            .reason(reason);
        if let Some(checked) = checked {
            event = event.approver(&checked.approver);
        }
        Self::write_best_effort(&mut inner, &event);
    }

    /// Whether `repo` may be checked now: in the policy in force, within the checks' rate. A
    /// refusal is logged (`check`, denied).
    pub fn check_allowed(&self, repo: &RepoName, caller: &CallerFacts) -> Result<(), ServiceError> {
        self.opened()?;
        let now = self.now()?;
        let refusal = if self.policy().repo(repo).is_none() {
            Some(ServiceError::refused(
                RefusalCode::UnknownRepo,
                format!("repo {repo} is not in the registry"),
            ))
        } else if !within(&mut self.outbound().checks, now, MAX_CHECKS_A_MINUTE) {
            Some(ServiceError::refused(
                RefusalCode::Check,
                format!("more than {MAX_CHECKS_A_MINUTE} checks a minute: try again shortly"),
            ))
        } else {
            None
        };
        match refusal {
            Some(error) => {
                self.check_logged(repo, &[], Some(&error.to_string()), caller);
                Err(error)
            }
            None => Ok(()),
        }
    }

    /// Logs an upstream check: allowed when every step passed, denied with the step that
    /// failed (what upstream said, cleaned and bounded by the mirrors), or with `refused`.
    pub fn check_logged(
        &self,
        repo: &RepoName,
        steps: &[CheckStep],
        refused: Option<&str>,
        caller: &CallerFacts,
    ) {
        let (Ok(now), Ok(mut inner)) = (self.now(), self.lock()) else {
            return;
        };
        let failed = steps.iter().find(|s| !s.ok);
        let (outcome, reason) = match (refused, failed) {
            (Some(why), _) => (Outcome::Denied, why.to_owned()),
            (None, Some(step)) => (Outcome::Denied, format!("{}: {}", step.what, step.said)),
            (None, None) => (
                Outcome::Allowed,
                steps
                    .iter()
                    .map(|s| format!("{}: {}", s.what, s.said))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        };
        let event = AuditEvent::new(now, EventKind::Check, outcome)
            .caller(caller)
            .repo(repo)
            .reason(reason);
        Self::write_best_effort(&mut inner, &event);
    }
}
