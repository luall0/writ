//! The audit log: append-only JSONL, one line per event.
//!
//! The file is only ever opened for appending, and [`AuditLog`] has no method that removes or
//! rewrites anything. [`AuditEvent`] has no field for key material, passphrases, tokens or
//! signatures (an approval is logged by its approver's fingerprint only), so a secret can't be
//! logged by mistake through a typed field.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use writ_core::caller::CallerFacts;
use writ_core::names::{CommitId, KeyFingerprint, RepoName, TicketId};
use writ_core::policy::Denial;
use writ_core::units::Timestamp;

use crate::Result;

/// The most characters of one text in a line (a reason, a committer, a warning, a ref, a
/// process): longer ones are cut, with `…`, when the line is written, so no request can make
/// a line large, whoever built the event.
pub const MAX_FIELD_CHARS: usize = 2048;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A ticket was submitted (allowed: pending; denied: rejected by policy).
    Submit,
    /// An approval was accepted (allowed) or refused (denied).
    Grant,
    /// The approver refused a ticket.
    Refuse,
    /// An amendment was applied to its lease.
    Amend,
    Revoke,
    Expire,
    Exhaust,
    Close,
    /// A session certificate presented to the gateway (allowed: it stands for an active
    /// lease; denied: refused, with the reason).
    Connect,
    /// An exec request the gateway doesn't serve for this caller.
    Command,
    Sign,
    Push,
    Fetch,
    Admin,
    Seal,
    Unseal,
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    /// A state change that is neither (an expiry, a close).
    Done,
}

/// One line of the audit log. Empty fields are left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub time: Timestamp,
    pub event: EventKind,
    pub result: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<TicketId>,
    /// The ticket, when it isn't the lease itself (a pending ticket, an amendment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<TicketId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<KeyFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<RepoName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitId>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committer: Option<String>,
    /// The denial's category (`DenyCode`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_addr: Option<IpAddr>,
    /// Executables of the caller's process chain (local mode), the caller first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_chain: Option<Vec<String>>,
}

impl AuditEvent {
    pub fn new(time: Timestamp, event: EventKind, result: Outcome) -> Self {
        Self {
            time,
            event,
            result,
            lease: None,
            ticket: None,
            cert: None,
            approver: None,
            repo: None,
            commit: None,
            refs: Vec::new(),
            committer: None,
            code: None,
            reason: None,
            warnings: Vec::new(),
            source_addr: None,
            process_chain: None,
        }
    }

    pub fn lease(mut self, lease: &TicketId) -> Self {
        self.lease = Some(lease.clone());
        self
    }

    pub fn ticket(mut self, ticket: &TicketId) -> Self {
        self.ticket = Some(ticket.clone());
        self
    }

    pub fn cert(mut self, serial: u64) -> Self {
        self.cert = Some(serial);
        self
    }

    pub fn approver(mut self, approver: &KeyFingerprint) -> Self {
        self.approver = Some(approver.clone());
        self
    }

    pub fn repo(mut self, repo: &RepoName) -> Self {
        self.repo = Some(repo.clone());
        self
    }

    pub fn commit(mut self, commit: &CommitId) -> Self {
        self.commit = Some(commit.clone());
        self
    }

    pub fn refs(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.refs = refs.into_iter().collect();
        self
    }

    pub fn committer(mut self, email: &str) -> Self {
        self.committer = Some(email.to_owned());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn warnings(mut self, warnings: impl IntoIterator<Item = String>) -> Self {
        self.warnings = warnings.into_iter().collect();
        self
    }

    /// The event as a denial: result `denied`, the denial's code and its full text (reason
    /// and hint).
    pub fn denial(mut self, denial: &Denial) -> Self {
        self.result = Outcome::Denied;
        self.code = Some(denial.code.to_string());
        self.reason = Some(denial.to_string());
        self
    }

    /// The event with every text cut to [`MAX_FIELD_CHARS`].
    fn bounded(&self) -> AuditEvent {
        let cut = |text: &String| writ_core::text::shown(text, MAX_FIELD_CHARS);
        let mut event = self.clone();
        event.committer = event.committer.as_ref().map(cut);
        event.code = event.code.as_ref().map(cut);
        event.reason = event.reason.as_ref().map(cut);
        event.refs = event.refs.iter().map(cut).collect();
        event.warnings = event.warnings.iter().map(cut).collect();
        event.process_chain = event
            .process_chain
            .as_ref()
            .map(|chain| chain.iter().map(cut).collect());
        event
    }

    /// What the transport said about the caller.
    pub fn caller(mut self, facts: &CallerFacts) -> Self {
        self.source_addr = facts.source_addr;
        self.process_chain = facts.process_chain.as_ref().map(|chain| {
            chain
                .iter()
                .map(|p| p.executable.to_string_lossy().into_owned())
                .collect()
        });
        self
    }
}

/// The append-only audit log file.
pub struct AuditLog {
    path: PathBuf,
    file: File,
    /// A write failed part way: the file may end in a cut line, so the next line starts
    /// with a newline (never glued onto the fragment).
    dirty: bool,
    /// Set by a test to make writes fail (feature `testing` only).
    #[cfg(feature = "testing")]
    broken: Option<std::sync::Arc<std::sync::atomic::AtomicU8>>,
}

/// Breaks and repairs an [`AuditLog`] opened with [`AuditLog::open_breakable`], so tests can
/// check that nothing changes without its log line (feature `testing`).
#[cfg(feature = "testing")]
#[derive(Debug, Clone)]
pub struct AuditBreaker(std::sync::Arc<std::sync::atomic::AtomicU8>);

#[cfg(feature = "testing")]
impl AuditBreaker {
    /// While broken, every [`AuditLog::append`] fails and writes nothing.
    pub fn set_broken(&self, broken: bool) {
        self.0
            .store(u8::from(broken), std::sync::atomic::Ordering::SeqCst);
    }

    /// While set, every [`AuditLog::append`] writes half its line, then fails (a full disk).
    pub fn set_cut_short(&self, cut: bool) {
        self.0
            .store(if cut { 2 } else { 0 }, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `line` with every character a terminal could act on, or that renders as nothing
/// (`writ_core::text::is_hidden_char`), written as a JSON `\u` escape: serde_json only
/// escapes controls below 0x20, so C1 controls, bidi and zero-width characters in an
/// agent-chosen ref or reason would otherwise reach whoever runs `cat` on the log. Such
/// characters only ever appear inside JSON strings, where the escape means the same.
fn escape_hidden(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        if c != '\n' && writ_core::text::is_hidden_char(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl AuditLog {
    /// Opens the log for appending, creating it if needed. If the last line was cut short
    /// (a crash mid-write), the next event starts on a new line; nothing is rewritten.
    pub fn open(path: &Path) -> Result<Self> {
        // Private from creation (0600): never readable by another user, whatever the umask.
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        let len = file.metadata()?.len();
        if len > 0 {
            let mut reader = File::open(path)?;
            reader.seek(SeekFrom::Start(len - 1))?;
            let mut last = [0u8; 1];
            reader.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
                file.sync_data()?;
            }
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            dirty: false,
            #[cfg(feature = "testing")]
            broken: None,
        })
    }

    /// [`AuditLog::open`], with a switch that makes writes fail (feature `testing`).
    #[cfg(feature = "testing")]
    pub fn open_breakable(path: &Path) -> Result<(Self, AuditBreaker)> {
        let switch = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let mut log = Self::open(path)?;
        log.broken = Some(switch.clone());
        Ok((log, AuditBreaker(switch)))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one event as one line, and syncs it to disk before returning.
    pub fn append(&mut self, event: &AuditEvent) -> Result<()> {
        let mut line = String::new();
        if self.dirty {
            line.push('\n');
        }
        line.push_str(&escape_hidden(&serde_json::to_string(&event.bounded())?));
        line.push('\n');
        #[cfg(feature = "testing")]
        match self
            .broken
            .as_ref()
            .map(|b| b.load(std::sync::atomic::Ordering::SeqCst))
        {
            Some(1) => {
                return Err(crate::StoreError::Io(std::io::Error::other(
                    "the audit log was broken by the test",
                )));
            }
            Some(2) => {
                self.dirty = true;
                let half = line.len() / 2;
                self.file
                    .write_all(line.as_bytes().get(..half).unwrap_or_default())?;
                return Err(crate::StoreError::Io(std::io::Error::other(
                    "the audit log was cut short by the test",
                )));
            }
            _ => {}
        }
        // Dirty until the whole line is on disk. One write of the whole line: with O_APPEND,
        // it lands after everything already there.
        self.dirty = true;
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.dirty = false;
        Ok(())
    }
}

/// A coarse scan for things that must never be in the log: private keys, SSH signatures,
/// public key blobs, tokens. Used by the tests over everything the log holds (feature
/// `testing`).
#[cfg(feature = "testing")]
pub fn looks_secret(text: &str) -> bool {
    const MARKERS: [&str; 9] = [
        "PRIVATE KEY",
        "BEGIN SSH SIGNATURE",
        "BEGIN OPENSSH",
        "AGE-SECRET-KEY",
        "ssh-ed25519 AAAA",
        "ecdsa-sha2-nistp256 AAAA",
        "ghp_",
        "github_pat_",
        "glpat-",
    ];
    MARKERS.iter().any(|m| text.contains(m))
}
