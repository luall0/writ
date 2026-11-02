//! Notes (`ticket_link: notes`): the daemon's notes under the repo's notes ref
//! (`refs/notes/commits` by default, or `refs/notes/writ`: `notes_ref`), written in the mirror
//! and pushed upstream as a fast-forward, after the branches they annotate.
//!
//! A batch of notes becomes one commit of its own (a tree mapping each annotated commit's id
//! to its note, no parent), merged into the mirror's notes ref with `git notes merge -s
//! cat_sort_uniq`: a note a commit already has keeps its lines, the batch's are added, no line
//! twice. The ref is pushed without force, so a remote that moved it meanwhile refuses
//! (`fetch first`, `non-fast-forward`): then that one ref is fetched from upstream, the batch
//! merged into it again, and the push tried once more. A notes commit never contains the
//! commits it annotates (a note names them by id), so none of this needs them.
//!
//! Notes commits are unsigned, under a fixed identity ([`NOTES_AUTHOR`]): no remote verifies
//! or shows a notes commit's signature, and the daemon's ledger, not the note, is the
//! reference.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::Duration;

use tokio::time::Instant;
use writ_core::config::NotesRef;
use writ_core::names::{CommitId, KeyId};

use super::access::Access;
use super::{LOCAL_WORK_DEADLINE, MAX_FETCH_OUTPUT, MirrorGuard};
use crate::git::{self, Hooks};
use crate::process::{self, RunError};
use crate::{MirrorError, Result};

/// The name and email of the notes commits the daemon makes.
pub const NOTES_AUTHOR: (&str, &str) = ("writd", "writd@writ.invalid");
/// The most notes one batch writes (each is a line of the batch's tree).
pub const MAX_NOTES: usize = 10_000;
/// The most bytes of one note's text.
pub const MAX_NOTE_TEXT: usize = 64 * 1024;
/// The most of a local git's output read (an object id, a merge's words).
const MAX_LOCAL_OUTPUT: usize = 64 * 1024;

/// One note to write: the commit it annotates, and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub commit: CommitId,
    pub text: String,
}

/// How the notes reached upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotesPushed {
    /// The mirror's notes ref was upstream's: one push, a fast-forward.
    FastForward,
    /// Upstream's had moved: fetched, the batch merged into it, pushed again.
    Merged,
}

/// What upstream said of a notes push.
#[derive(Debug, PartialEq, Eq)]
enum Pushed {
    Yes,
    /// Refused because upstream's notes ref isn't an ancestor of ours: fetch, merge, retry.
    Behind,
}

impl MirrorGuard {
    /// Writes `notes` under `notes_ref` in the mirror and pushes that ref upstream with
    /// `credential`, which must be the repo's (anything else is refused: the mirror reaches
    /// upstream with that one). A remote whose notes ref moved meanwhile gets a fetch, a merge
    /// and one retry; any other refusal, or a second one, is an error with upstream's reason.
    /// Upstream operations share the sync's deadline, local work [`LOCAL_WORK_DEADLINE`].
    pub async fn push_notes(
        &mut self,
        notes_ref: NotesRef,
        credential: &KeyId,
        notes: &[Note],
    ) -> Result<NotesPushed> {
        let notes_ref = notes_ref.as_ref_name();
        if credential != self.repo.reach.credential() {
            return Err(MirrorError::NotTheCredential {
                repo: self.repo.name.clone(),
                key: credential.clone(),
            });
        }
        if notes.is_empty() || notes.len() > MAX_NOTES {
            return Err(MirrorError::Notes(format!(
                "a batch holds from 1 to {MAX_NOTES} notes"
            )));
        }
        let local_until = from_now(LOCAL_WORK_DEADLINE);
        let batch = self.notes_commit(notes, local_until).await?;
        self.merge_notes(notes_ref, &batch, local_until).await?;
        let upstream_until = from_now(self.shared.config.timeout);
        let access = self.reach_upstream()?;
        if self
            .push_notes_ref(notes_ref, &access, upstream_until)
            .await?
            == Pushed::Yes
        {
            return Ok(NotesPushed::FastForward);
        }
        self.fetch_notes_ref(notes_ref, &access, upstream_until)
            .await?;
        self.merge_notes(notes_ref, &batch, local_until).await?;
        match self
            .push_notes_ref(notes_ref, &access, upstream_until)
            .await?
        {
            Pushed::Yes => Ok(NotesPushed::Merged),
            Pushed::Behind => Err(MirrorError::Rejected {
                repo: self.repo.name.clone(),
                reason: format!("{notes_ref} moved again while the notes were merged"),
            }),
        }
    }

    /// The batch as a commit of its own: each note's text a blob (one per distinct text), a
    /// tree naming each by the commit it annotates, a commit of that tree with no parent.
    async fn notes_commit(&self, notes: &[Note], until: Instant) -> Result<String> {
        let mut blobs: BTreeMap<&str, String> = BTreeMap::new();
        let mut tree = String::new();
        let mut seen = BTreeSet::new();
        for note in notes {
            if note.text.is_empty() || note.text.len() > MAX_NOTE_TEXT {
                return Err(MirrorError::Notes(format!(
                    "a note holds from 1 to {MAX_NOTE_TEXT} bytes"
                )));
            }
            if !seen.insert(&note.commit) {
                return Err(MirrorError::Notes(format!(
                    "two notes for commit {}",
                    note.commit
                )));
            }
            let blob = match blobs.get(note.text.as_str()) {
                Some(blob) => blob.clone(),
                None => {
                    let blob = self
                        .local_id(
                            &["hash-object", "-w", "--stdin"],
                            note.text.as_bytes().to_vec(),
                            until,
                        )
                        .await?;
                    blobs.insert(&note.text, blob.clone());
                    blob
                }
            };
            let _ = writeln!(tree, "100644 blob {blob}\t{}", note.commit);
        }
        let tree = self.local_id(&["mktree"], tree.into_bytes(), until).await?;
        self.local_id(
            &["commit-tree", &tree, "-m", "Notes written by writd"],
            Vec::new(),
            until,
        )
        .await
    }

    /// Merges the batch into the mirror's notes ref (made the batch if there is none): the
    /// lines of a note both have, sorted, each once.
    async fn merge_notes(&self, notes_ref: &str, batch: &str, until: Instant) -> Result<()> {
        let args = [
            "notes",
            "--ref",
            notes_ref,
            "merge",
            "--strategy=cat_sort_uniq",
            "--quiet",
            batch,
        ];
        let done = self.local(&args, Vec::new(), until).await?;
        if done.status.success() {
            return Ok(());
        }
        Err(MirrorError::Git {
            repo: self.repo.name.clone(),
            what: "notes merge",
            stderr: crate::shown(&done.stderr),
        })
    }

    /// Pushes the mirror's notes ref upstream, without force.
    async fn push_notes_ref(
        &self,
        notes_ref: &str,
        access: &Access,
        until: Instant,
    ) -> Result<Pushed> {
        let refspec = format!("{notes_ref}:{notes_ref}");
        let args = [
            "push",
            "--porcelain",
            "--no-verify",
            "--no-recurse-submodules",
            "--",
            self.repo.reach.url(),
            refspec.as_str(),
        ];
        let left = until.saturating_duration_since(Instant::now());
        let finished = self
            .run_upstream(access, &args, None, left, MAX_FETCH_OUTPUT)
            .await?;
        if finished.status.success() {
            return Ok(Pushed::Yes);
        }
        if is_behind(&finished.stdout, notes_ref) {
            return Ok(Pushed::Behind);
        }
        Err(
            match self.classify(access, &finished.stderr, "notes push") {
                MirrorError::Git { repo, .. } => MirrorError::Rejected {
                    repo,
                    reason: self.clean(&refused_lines(&finished.stdout, &finished.stderr)),
                },
                other => other,
            },
        )
    }

    /// Fetches upstream's notes ref into the mirror's, forced: upstream's is the one to build
    /// on. Checked and bounded like a sync, and like a sync a failed one leaves no partial pack.
    async fn fetch_notes_ref(
        &self,
        notes_ref: &str,
        access: &Access,
        until: Instant,
    ) -> Result<()> {
        let fetched = self.fetch_notes_ref_once(notes_ref, access, until).await;
        if fetched.is_err() {
            self.remove_partial_packs();
        }
        fetched
    }

    async fn fetch_notes_ref_once(
        &self,
        notes_ref: &str,
        access: &Access,
        until: Instant,
    ) -> Result<()> {
        let refspec = format!("+{notes_ref}:{notes_ref}");
        let args = [
            "fetch",
            "--porcelain",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "--no-auto-maintenance",
            "--no-show-forced-updates",
            "--",
            self.repo.reach.url(),
            refspec.as_str(),
        ];
        let left = until.saturating_duration_since(Instant::now());
        let finished = self
            .run_upstream(access, &args, None, left, MAX_FETCH_OUTPUT)
            .await?;
        if finished.status.success() {
            return Ok(());
        }
        Err(self.classify(access, &finished.stderr, "notes fetch"))
    }

    /// Runs git on the mirror (no transport), as the notes' author, `stdin` given, before
    /// `until`.
    async fn local(
        &self,
        args: &[&str],
        stdin: Vec<u8>,
        until: Instant,
    ) -> Result<process::Finished> {
        let mut cmd = git::command(&self.shared.config.git, Hooks::None);
        let (name, email) = NOTES_AUTHOR;
        cmd.env("GIT_AUTHOR_NAME", name)
            .env("GIT_AUTHOR_EMAIL", email)
            .env("GIT_COMMITTER_NAME", name)
            .env("GIT_COMMITTER_EMAIL", email)
            .arg("--git-dir")
            .arg(&self.repo.path)
            .args(args);
        let left = until.saturating_duration_since(Instant::now());
        match process::run(cmd, Some(stdin), left, MAX_LOCAL_OUTPUT).await {
            Ok(finished) => Ok(finished),
            Err(RunError::Timeout) => Err(MirrorError::ReadTimeout {
                seconds: LOCAL_WORK_DEADLINE.as_secs(),
            }),
            Err(RunError::Spawn(e) | RunError::Wait(e)) => Err(MirrorError::Spawn(e)),
        }
    }

    /// Runs git on the mirror, and reads the one object id it prints.
    async fn local_id(&self, args: &[&str], stdin: Vec<u8>, until: Instant) -> Result<String> {
        let what = args.first().copied().unwrap_or("git");
        let done = self.local(args, stdin, until).await?;
        let id = String::from_utf8_lossy(&done.stdout).trim().to_owned();
        let is_id = matches!(id.len(), 40 | 64) && id.bytes().all(|b| b.is_ascii_hexdigit());
        if done.status.success() && is_id {
            return Ok(id);
        }
        Err(MirrorError::Notes(format!(
            "{what} failed: {}",
            crate::shown(&done.stderr)
        )))
    }
}

/// Whether a push's porcelain output says the remote refused the notes ref because it holds
/// something ours doesn't (`[rejected] (fetch first)` or `(non-fast-forward)`).
fn is_behind(stdout: &[u8], notes_ref: &str) -> bool {
    let refspec = format!("\t{notes_ref}:{notes_ref}\t");
    String::from_utf8_lossy(stdout).lines().any(|line| {
        line.starts_with('!')
            && line.contains(&refspec)
            && (line.contains("(fetch first)") || line.contains("(non-fast-forward)"))
    })
}

/// What upstream said about a refused push: the refused refs (porcelain), then its own words.
fn refused_lines(stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|line| line.starts_with('!'))
        .flat_map(|line| format!("{line}\n").into_bytes())
        .chain(stderr.iter().copied())
        .collect()
}

/// `deadline` from now; a clock at its end can't add it, and gets none.
fn from_now(deadline: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(deadline).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_notes_ref_upstream_moved_is_behind() {
        for line in [
            "!\trefs/notes/writ:refs/notes/writ\t[rejected] (fetch first)",
            "!\trefs/notes/writ:refs/notes/writ\t[rejected] (non-fast-forward)",
        ] {
            assert!(
                is_behind(
                    format!("To x\n{line}\nDone\n").as_bytes(),
                    "refs/notes/writ"
                ),
                "{line}"
            );
        }
        for line in [
            "!\trefs/notes/writ:refs/notes/writ\t[remote rejected] (pre-receive hook declined)",
            "!\trefs/notes/writ:refs/notes/writ\t[remote rejected] (deny updating a hidden ref)",
            "!\trefs/heads/x:refs/heads/x\t[rejected] (fetch first)",
            " \trefs/notes/writ:refs/notes/writ\t0123..4567",
            "=\trefs/notes/writ:refs/notes/writ\t[up to date] (fetch first)",
        ] {
            assert!(
                !is_behind(
                    format!("To x\n{line}\nDone\n").as_bytes(),
                    "refs/notes/writ"
                ),
                "{line}"
            );
        }
        assert!(!is_behind(b"", "refs/notes/writ"));
        // Another notes ref than the one pushed is not this push's.
        let commits = "!\trefs/notes/commits:refs/notes/commits\t[rejected] (fetch first)";
        assert!(is_behind(commits.as_bytes(), "refs/notes/commits"));
        assert!(!is_behind(commits.as_bytes(), "refs/notes/writ"));
    }

    #[test]
    fn a_refusal_keeps_the_refused_refs_and_upstream_s_words() {
        let out = b"To x\n!\trefs/notes/writ:refs/notes/writ\t[remote rejected] (hook)\nDone\n";
        assert_eq!(
            String::from_utf8(refused_lines(out, b"remote: no notes here\n")).unwrap(),
            "!\trefs/notes/writ:refs/notes/writ\t[remote rejected] (hook)\nremote: no notes here\n"
        );
    }
}
