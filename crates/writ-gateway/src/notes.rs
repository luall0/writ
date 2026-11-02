//! The notes job (`ticket_link: notes`, `docs/architecture/gateway.md` § Notes): once upstream
//! took a push to a repo that asks for notes, its commits wait for their note in the ledger,
//! and a job writes and pushes every waiting note of the repo, under the mirror lock, after the
//! push (it waits for the push's `receive-pack` to give the mirror back). A job that fails
//! leaves the notes waiting: the repo's next push writes them, or the next reconcile.
//!
//! The reconcile ([`reconcile`], after each sync of a mirror: at the daemon's start and every
//! `sync_every`) catches what a push's own job can't: the ledger's commits for a notes repo
//! that the mirror holds (so upstream has them) but that were never recorded as waiting (a
//! daemon stopped between upstream taking a push and the record; commits pushed before the
//! repo asked for notes: a backfill), and notes left waiting by a job that failed.

use std::collections::{BTreeMap, BTreeSet};

use writ_approval::{EventKind, GatewayDenial, PendingNote};
use writ_core::caller::CallerFacts;
use writ_core::names::{CommitId, KeyId, RepoName, TicketId};
use writ_mirror::{MAX_LOOKUPS, MAX_NOTES, Note};

use crate::Gateway;

/// After upstream took a push under `lease`: its commits wait for their note when the repo asks
/// for notes, and the repo's notes job starts. Off the hook's path: it never delays the push.
pub(crate) fn after_push(
    gateway: &Gateway,
    lease: &TicketId,
    repo: &RepoName,
    commits: Vec<CommitId>,
) {
    let (gateway, lease, repo) = (gateway.clone(), lease.clone(), repo.clone());
    tokio::spawn(async move {
        let service = gateway.service().clone();
        let (for_lease, for_repo) = (lease.clone(), repo.clone());
        let recorded = tokio::task::spawn_blocking(move || {
            service.notes_to_write(&for_lease, &for_repo, &commits)
        })
        .await;
        match recorded {
            Ok(Ok(true)) => write(&gateway, &repo).await,
            Ok(Ok(false)) => {}
            Ok(Err(e)) => {
                tracing::error!(repo = %repo, error = %e, "cannot record a push's notes");
                let denial = GatewayDenial::new(
                    EventKind::Notes,
                    format!("cannot record the push's notes: {e}"),
                )
                .lease(&lease)
                .repo(&repo);
                gateway.log_denial(denial, CallerFacts::default()).await;
            }
            Err(_) => tracing::error!(repo = %repo, "recording a push's notes panicked"),
        }
    });
}

/// Brings `repo`'s notes up to date, when it asks for notes: its ledger commits with no note
/// state that the mirror holds (the newest [`MAX_LOOKUPS`]) recorded as waiting, then the notes
/// job for everything waiting.
pub(crate) async fn reconcile(gateway: &Gateway, repo: &RepoName) {
    let unrecorded = {
        let (service, repo) = (gateway.service().clone(), repo.clone());
        tokio::task::spawn_blocking(move || service.notes_unrecorded(&repo, MAX_LOOKUPS)).await
    };
    let unrecorded = match unrecorded {
        Ok(Ok(Some(unrecorded))) => unrecorded,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            tracing::error!(repo = %repo, error = %e, "cannot read the ledger for notes");
            return;
        }
        Err(_) => return,
    };
    if !unrecorded.is_empty() {
        let ids: Vec<CommitId> = unrecorded.iter().map(|(id, _)| id.clone()).collect();
        let held = match gateway.shared.config.mirrors.lock(repo).await {
            Ok(guard) => guard.held_commits(&ids).await,
            Err(e) => Err(e),
        };
        let held = match held {
            Ok(held) => held,
            Err(e) => {
                tracing::warn!(repo = %repo, error = %e, "cannot look the ledger's commits up for notes");
                return;
            }
        };
        let mut by_lease: BTreeMap<TicketId, Vec<CommitId>> = BTreeMap::new();
        for (commit, lease) in unrecorded {
            if held.contains(&commit) {
                by_lease.entry(lease).or_default().push(commit);
            }
        }
        for (lease, commits) in by_lease {
            tracing::info!(repo = %repo, lease = %lease, notes = commits.len(), "notes found missing");
            let (service, for_repo) = (gateway.service().clone(), repo.clone());
            let recorded = tokio::task::spawn_blocking(move || {
                service.notes_to_write(&lease, &for_repo, &commits)
            })
            .await;
            if !matches!(recorded, Ok(Ok(_))) {
                tracing::error!(repo = %repo, "cannot record missing notes");
                return;
            }
        }
    }
    write(gateway, repo).await;
}

/// Writes and pushes the notes waiting on `repo` (at most [`MAX_NOTES`]; the rest go with the
/// next push), one batch per credential, the mirror held for it.
pub(crate) async fn write(gateway: &Gateway, repo: &RepoName) {
    let mirrors = &gateway.shared.config.mirrors;
    let held = mirrors.lock(repo).await;
    let pending = {
        let (service, repo) = (gateway.service().clone(), repo.clone());
        tokio::task::spawn_blocking(move || service.pending_notes(&repo, MAX_NOTES)).await
    };
    let pending = match pending {
        Ok(Ok(pending)) => pending,
        Ok(Err(e)) => {
            tracing::error!(repo = %repo, error = %e, "cannot read the notes waiting");
            return;
        }
        Err(_) => return,
    };
    if pending.is_empty() {
        return;
    }
    let mut guard = match held {
        Ok(guard) => guard,
        Err(e) => {
            refused(gateway, repo, pending, e.to_string()).await;
            return;
        }
    };
    let notes_ref = gateway.service().notes_ref(repo);
    for (credential, notes) in by_credential(pending) {
        let batch = batch(&notes);
        match guard.push_notes(notes_ref, &credential, &batch).await {
            Ok(how) => {
                tracing::info!(repo = %repo, notes = batch.len(), ?how, "notes pushed upstream");
                let (service, repo) = (gateway.service().clone(), repo.clone());
                let marked =
                    tokio::task::spawn_blocking(move || service.notes_pushed(&repo, &notes)).await;
                if !matches!(marked, Ok(Ok(()))) {
                    tracing::error!("notes pushed upstream, but not marked written");
                }
            }
            Err(e) => refused(gateway, repo, notes, e.to_string()).await,
        }
    }
}

/// Notes that didn't reach upstream: logged, left waiting.
async fn refused(gateway: &Gateway, repo: &RepoName, notes: Vec<PendingNote>, reason: String) {
    tracing::warn!(repo = %repo, notes = notes.len(), reason = %reason, "notes not pushed");
    let (service, repo) = (gateway.service().clone(), repo.clone());
    let _ =
        tokio::task::spawn_blocking(move || service.notes_refused(&repo, &notes, &reason)).await;
}

/// The waiting notes, by the credential that pushes them.
fn by_credential(pending: Vec<PendingNote>) -> BTreeMap<KeyId, Vec<PendingNote>> {
    let mut groups: BTreeMap<KeyId, Vec<PendingNote>> = BTreeMap::new();
    for note in pending {
        groups
            .entry(note.credential.clone())
            .or_default()
            .push(note);
    }
    groups
}

/// One note per commit: a `Writ: <lease>` line for each lease it waits under, sorted.
fn batch(notes: &[PendingNote]) -> Vec<Note> {
    let mut lines: BTreeMap<&CommitId, BTreeSet<&TicketId>> = BTreeMap::new();
    for note in notes {
        lines.entry(&note.commit).or_default().insert(&note.lease);
    }
    lines
        .into_iter()
        .map(|(commit, leases)| Note {
            commit: commit.clone(),
            text: leases
                .iter()
                .map(|lease| format!("Writ: {lease}\n"))
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(commit: u64, lease: &str, credential: &str) -> PendingNote {
        PendingNote {
            commit: format!("{commit:040x}").parse().unwrap(),
            lease: lease.parse().unwrap(),
            credential: credential.parse().unwrap(),
        }
    }

    const A: &str = "wrt_01JD8X0000000000000000000A";
    const B: &str = "wrt_01JD8X0000000000000000000B";

    #[test]
    fn a_batch_is_one_note_per_commit_with_a_line_per_lease() {
        let notes = [
            pending(2, B, "up"),
            pending(1, A, "up"),
            pending(2, A, "up"),
        ];
        assert_eq!(
            batch(&notes),
            [
                Note {
                    commit: format!("{:040x}", 1).parse().unwrap(),
                    text: format!("Writ: {A}\n"),
                },
                Note {
                    commit: format!("{:040x}", 2).parse().unwrap(),
                    text: format!("Writ: {A}\nWrit: {B}\n"),
                },
            ]
        );
    }

    #[test]
    fn notes_go_by_the_credential_that_pushed_their_commit() {
        let groups = by_credential(vec![
            pending(1, A, "upstream-02"),
            pending(2, A, "upstream-01"),
            pending(3, B, "upstream-02"),
        ]);
        let shape: Vec<(&str, usize)> = groups.iter().map(|(k, v)| (k.as_str(), v.len())).collect();
        assert_eq!(shape, [("upstream-01", 1), ("upstream-02", 2)]);
    }
}
