//! Notes (`ticket_link: notes`, `docs/architecture/gateway.md`): once upstream took a push to
//! a repo that asks for them, its commits wait for their note (`Writ: <lease>` under the repo's
//! `notes_ref`), recorded in the ledger with the credential that pushed them. The
//! gateway's notes job writes and pushes the waiting notes of a repo, then reports here: the
//! notes are marked written, or stay waiting for the repo's next push; one `notes` line per
//! lease either way.

use std::collections::BTreeMap;

use writ_core::config::{NotesRef, RepoEntry, TicketLink};
use writ_core::names::{CommitId, RepoName, TicketId};
use writ_store::{AuditEvent, EventKind, Outcome, PendingNote};

use super::{Service, internal};
use crate::ServiceError;

impl Service {
    /// A push upstream took under `lease`: when its repo's `ticket_link` is `notes`, its
    /// commits (those the ledger holds for this lease and repo) wait for their note, to be
    /// pushed with the repo's upstream credential. Returns whether the repo asks for notes (the
    /// gateway then starts its notes job). Nothing is logged: the push has its line.
    pub fn notes_to_write(
        &self,
        lease: &TicketId,
        repo: &RepoName,
        commits: &[CommitId],
    ) -> Result<bool, ServiceError> {
        let policy = self.policy();
        let Some(entry) = policy.repo(repo) else {
            return Ok(false);
        };
        if entry.ticket_link != TicketLink::Notes {
            return Ok(false);
        }
        let inner = self.lock()?;
        inner
            .store
            .notes_add_pending(lease, repo, commits, &entry.upstream_credential)
            .map_err(internal)?;
        Ok(true)
    }

    /// For a repo that asks for notes, the ledger's commits for it with no note state yet,
    /// newest first, at most `limit`, each with its lease (the notes reconcile looks for those
    /// upstream has); `None` for a repo that doesn't ask for notes.
    pub fn notes_unrecorded(
        &self,
        repo: &RepoName,
        limit: usize,
    ) -> Result<Option<Vec<(CommitId, TicketId)>>, ServiceError> {
        let policy = self.policy();
        match policy.repo(repo) {
            Some(entry) if entry.ticket_link == TicketLink::Notes => {}
            _ => return Ok(None),
        }
        let inner = self.lock()?;
        inner
            .store
            .notes_unrecorded(repo, limit)
            .map(Some)
            .map_err(internal)
    }

    /// The notes waiting on `repo`, oldest first, at most `limit`.
    pub fn pending_notes(
        &self,
        repo: &RepoName,
        limit: usize,
    ) -> Result<Vec<PendingNote>, ServiceError> {
        let inner = self.lock()?;
        inner.store.notes_pending(repo, limit).map_err(internal)
    }

    /// `notes` of `repo` are upstream: marked written, and one allowed `notes` line per lease
    /// (how many, with which credential). The push already happened, so the line never holds
    /// it back: one the log can't take is kept and written once it can.
    pub fn notes_pushed(&self, repo: &RepoName, notes: &[PendingNote]) -> Result<(), ServiceError> {
        let now = self.now()?;
        let mut inner = self.lock()?;
        let written = inner.store.notes_written(repo, notes).map_err(internal);
        let outcome = match &written {
            Ok(()) => Outcome::Allowed,
            Err(_) => Outcome::Denied,
        };
        let notes_ref = self.notes_ref(repo);
        for event in notes_lines(now, outcome, repo, notes_ref, notes) {
            let event = match &written {
                Ok(()) => event,
                Err(e) => event.reason(format!(
                    "pushed upstream, but not marked written (pushed again next time): {e}"
                )),
            };
            Self::write_best_effort(&mut inner, &event);
        }
        written
    }

    /// `notes` of `repo` didn't reach upstream (`reason`: upstream's refusal, cleaned, or the
    /// failure): one denied `notes` line per lease. They stay waiting, for the repo's next push.
    pub fn notes_refused(&self, repo: &RepoName, notes: &[PendingNote], reason: &str) {
        let Ok(now) = self.now() else { return };
        let Ok(mut inner) = self.lock() else { return };
        let notes_ref = self.notes_ref(repo);
        for event in notes_lines(now, Outcome::Denied, repo, notes_ref, notes) {
            Self::log_best_effort(&mut inner, &event.reason(reason));
        }
    }
}

impl Service {
    /// The ref `repo`'s notes go under (the policy's `notes_ref`).
    pub fn notes_ref(&self, repo: &RepoName) -> NotesRef {
        self.config
            .policy
            .repo(repo)
            .map(RepoEntry::notes_ref)
            .unwrap_or_default()
    }
}

/// One `notes` line per lease and credential among `notes`, with how many are that lease's.
fn notes_lines(
    now: writ_core::units::Timestamp,
    outcome: Outcome,
    repo: &RepoName,
    notes_ref: NotesRef,
    notes: &[PendingNote],
) -> Vec<AuditEvent> {
    let mut per_lease: BTreeMap<(&TicketId, &writ_core::names::KeyId), u64> = BTreeMap::new();
    for note in notes {
        let count = per_lease
            .entry((&note.lease, &note.credential))
            .or_default();
        *count = count.saturating_add(1);
    }
    per_lease
        .into_iter()
        .map(|((lease, credential), count)| {
            AuditEvent::new(now, EventKind::Notes, outcome)
                .lease(lease)
                .repo(repo)
                .refs([notes_ref.as_ref_name().to_owned()])
                .key(credential)
                .count(count)
        })
        .collect()
}
