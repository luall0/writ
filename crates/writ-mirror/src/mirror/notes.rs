//! Notes (`ticket_link: notes`): the daemon's notes under the repo's notes ref
//! (`refs/notes/commits` by default, or `refs/notes/writ`: `notes_ref`), written in the mirror
//! and pushed upstream as a fast-forward, after the branches they annotate.
//!
//! A batch of notes becomes one commit of its own (a tree mapping each annotated commit's id
//! to its note, no parent), merged into the mirror's notes ref with `git notes merge -s
//! union`: a note a commit already has is kept as it is written, the batch's text after it (a
//! blank line between, as `git notes append` writes it); a line the commit's note holds
//! already is left out of the batch, so none is written twice. The ref is pushed without
//! force, so a remote that moved it meanwhile refuses (`fetch first`, `non-fast-forward`):
//! then that one ref is fetched from upstream, the batch
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
/// The most commits [`MirrorGuard::held_commits`] looks up at once.
pub const MAX_LOOKUPS: usize = 100_000;
/// The most of a local git's output read (an object id, a merge's words).
const MAX_LOCAL_OUTPUT: usize = 64 * 1024;
/// The most read of the notes a batch's commits have already (more: merged again, a line
/// twice at worst).
const MAX_NOTES_READ: usize = 16 * 1024 * 1024;

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
        // The whole batch checked before any git runs, here or upstream (the second review
        // after M5.5: a note's own bounds were checked only once the batch was built, after
        // upstream was asked, and a note left out as written already never was).
        check_batch(notes)?;
        let local_until = from_now(LOCAL_WORK_DEADLINE);
        let upstream_until = from_now(self.shared.config.timeout);
        let access = self.reach_upstream()?;
        // A notes ref upstream doesn't have (deleted there, or another remote since a
        // registry change) is started afresh, from the batch alone: the mirror's own would
        // put back every note it ever held, a person's deleted ones too (the review after
        // M5.5, L11).
        if !self
            .upstream_has(notes_ref, &access, upstream_until)
            .await?
        {
            self.forget_local_ref(notes_ref, local_until).await?;
        }
        self.merge_missing(notes_ref, notes, local_until).await?;
        if self
            .push_notes_ref(notes_ref, &access, upstream_until)
            .await?
            == Pushed::Yes
        {
            return Ok(NotesPushed::FastForward);
        }
        self.fetch_notes_ref(notes_ref, &access, upstream_until)
            .await?;
        self.merge_missing(notes_ref, notes, local_until).await?;
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

    /// Which of `commits` (at most [`MAX_LOOKUPS`]) the mirror holds as commits. Only
    /// upstream's objects (a sync) and those of pushes upstream took (git moves a push's
    /// objects out of its quarantine only after the daemon's yes, which comes after upstream's)
    /// get there: a commit the mirror holds is one upstream has, or had. One `cat-file`.
    pub async fn held_commits(&self, commits: &[CommitId]) -> Result<BTreeSet<CommitId>> {
        if commits.len() > MAX_LOOKUPS {
            return Err(MirrorError::Notes(format!(
                "at most {MAX_LOOKUPS} commits looked up at once"
            )));
        }
        if commits.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut input = String::new();
        for commit in commits {
            let _ = writeln!(input, "{commit}");
        }
        let until = from_now(LOCAL_WORK_DEADLINE);
        let max_output = commits.len().saturating_mul(96).max(MAX_LOCAL_OUTPUT);
        let mut cmd = git::command(&self.shared.config.git, Hooks::None);
        cmd.arg("--git-dir")
            .arg(&self.repo.path)
            .args(["cat-file", "--batch-check"]);
        let left = until.saturating_duration_since(Instant::now());
        let done = match process::run(cmd, Some(input.into_bytes()), left, max_output).await {
            Ok(done) => done,
            Err(RunError::Timeout) => {
                return Err(MirrorError::ReadTimeout {
                    seconds: LOCAL_WORK_DEADLINE.as_secs(),
                });
            }
            Err(RunError::Spawn(e) | RunError::Wait(e)) => return Err(MirrorError::Spawn(e)),
        };
        if !done.status.success() {
            return Err(MirrorError::Git {
                repo: self.repo.name.clone(),
                what: "cat-file",
                stderr: crate::shown(&done.stderr),
            });
        }
        let asked: BTreeSet<&CommitId> = commits.iter().collect();
        Ok(held(&done.stdout)
            .into_iter()
            .filter(|id| asked.contains(id))
            .collect())
    }

    /// The batch as a commit of its own: each note's text a blob (one per distinct text), a
    /// tree naming each by the commit it annotates, a commit of that tree with no parent.
    async fn notes_commit(&self, notes: &[Note], until: Instant) -> Result<String> {
        // Checked whole by `push_notes`; again here, for what was left of it.
        check_batch(notes)?;
        let mut blobs: BTreeMap<&str, String> = BTreeMap::new();
        let mut tree = String::new();
        for note in notes {
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

    /// Merges into the mirror's notes ref the lines of `notes` it doesn't hold yet (a retry
    /// after a push whose answer was lost, or a ref fetched from upstream, may hold some, of
    /// a note or all of it): no line is written twice.
    async fn merge_missing(&self, notes_ref: &str, notes: &[Note], until: Instant) -> Result<()> {
        let held = self.lines_held(notes_ref, notes, until).await;
        let missing: Vec<Note> = notes
            .iter()
            .zip(held)
            .filter_map(|(note, held)| unwritten(note, &held))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let batch = self.notes_commit(&missing, until).await?;
        self.merge_notes(notes_ref, &batch, until).await
    }

    /// For each of `notes`, in order, the lines its commit's note in `notes_ref` holds
    /// already. Read in one `cat-file --batch`, each note under every fan-out git writes
    /// (`ab…`, `ab/cd…`, `ab/cd/ef…`). Best effort: a read that fails holds nothing, and the
    /// notes are merged whole (a line twice at worst, never one lost).
    async fn lines_held(
        &self,
        notes_ref: &str,
        notes: &[Note],
        until: Instant,
    ) -> Vec<BTreeSet<String>> {
        let none = || vec![BTreeSet::new(); notes.len()];
        let mut input = String::new();
        let mut asked: Vec<usize> = Vec::new();
        for (at, note) in notes.iter().enumerate() {
            for path in fanouts(note.commit.as_str()) {
                let _ = writeln!(input, "{notes_ref}:{path}");
                asked.push(at);
            }
        }
        let mut cmd = git::command(&self.shared.config.git, Hooks::None);
        cmd.arg("--git-dir")
            .arg(&self.repo.path)
            .args(["cat-file", "--batch"]);
        let left = until.saturating_duration_since(Instant::now());
        let Ok(done) = process::run(cmd, Some(input.into_bytes()), left, MAX_NOTES_READ).await
        else {
            return none();
        };
        if !done.status.success() {
            return none();
        }
        let texts = batch_texts(&done.stdout);
        if texts.len() != asked.len() {
            return none();
        }
        let mut held = none();
        for (at, text) in asked.into_iter().zip(texts) {
            if let (Some(lines), Some(text)) = (held.get_mut(at), text) {
                lines.extend(String::from_utf8_lossy(text).lines().map(str::to_owned));
            }
        }
        held
    }

    /// Merges the batch into the mirror's notes ref (made the batch if there is none): a note
    /// a commit already has is kept as it is written (a person's paragraphs and blank lines
    /// too), the batch's text after it, a blank line between (`union`, as `git notes append`
    /// writes it; the review after M5.5, L11: `cat_sort_uniq`
    /// sorted a person's lines and dropped their blank lines).
    async fn merge_notes(&self, notes_ref: &str, batch: &str, until: Instant) -> Result<()> {
        let args = [
            "notes",
            "--ref",
            notes_ref,
            "merge",
            "--strategy=union",
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

    /// Whether upstream has `notes_ref` (`ls-remote`, the same access as the push).
    async fn upstream_has(&self, notes_ref: &str, access: &Access, until: Instant) -> Result<bool> {
        let args = [
            "ls-remote",
            "--refs",
            "--",
            self.repo.reach.url(),
            notes_ref,
        ];
        let left = until.saturating_duration_since(Instant::now());
        let finished = self
            .run_upstream(access, &args, None, left, MAX_LOCAL_OUTPUT)
            .await?;
        if !finished.status.success() {
            return Err(self.classify(access, &finished.stderr, "notes ref lookup"));
        }
        // `<id>\t<ref>` per line: upstream's name is compared whole.
        Ok(String::from_utf8_lossy(&finished.stdout)
            .lines()
            .any(|line| line.split('\t').nth(1) == Some(notes_ref)))
    }

    /// Deletes the mirror's `notes_ref` (none is fine).
    async fn forget_local_ref(&self, notes_ref: &str, until: Instant) -> Result<()> {
        let exists = self
            .local(
                &["rev-parse", "--verify", "--quiet", notes_ref],
                Vec::new(),
                until,
            )
            .await?;
        if !exists.status.success() {
            return Ok(());
        }
        let done = self
            .local(&["update-ref", "-d", notes_ref], Vec::new(), until)
            .await?;
        if done.status.success() {
            return Ok(());
        }
        Err(MirrorError::Git {
            repo: self.repo.name.clone(),
            what: "notes ref reset",
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
                    reason: self.clean(access, &refused_lines(&finished.stdout, &finished.stderr)),
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

/// The commits `cat-file --batch-check` found: its `<id> commit <size>` lines (`<id> missing`
/// and any other kind left out).
fn held(stdout: &[u8]) -> Vec<CommitId> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split(' ');
            match (words.next(), words.next()) {
                (Some(id), Some("commit")) => id.parse().ok(),
                _ => None,
            }
        })
        .collect()
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

/// A batch's bounds: 1 to [`MAX_NOTES`] notes, each of 1 to [`MAX_NOTE_TEXT`] bytes, one per
/// commit.
fn check_batch(notes: &[Note]) -> Result<()> {
    if notes.is_empty() || notes.len() > MAX_NOTES {
        return Err(MirrorError::Notes(format!(
            "a batch holds from 1 to {MAX_NOTES} notes"
        )));
    }
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
    }
    Ok(())
}

/// `note` with only the lines `held` lacks (in its order, each as written, its line ending
/// too: never longer than the note), or `None` when it lacks none.
fn unwritten(note: &Note, held: &BTreeSet<String>) -> Option<Note> {
    let text: String = note
        .text
        .split_inclusive('\n')
        .filter(|line| {
            let bare = line.strip_suffix('\n').unwrap_or(line);
            !held.contains(bare.strip_suffix('\r').unwrap_or(bare))
        })
        .collect();
    (!text.is_empty()).then(|| Note {
        commit: note.commit.clone(),
        text,
    })
}

/// The paths a commit's note may be under in a notes tree: none, one and two levels of
/// fan-out (`ab/cd…`), as git writes them for a growing number of notes.
fn fanouts(id: &str) -> Vec<String> {
    let mut paths = vec![id.to_owned()];
    if let (Some(a), Some(b), Some(rest)) = (id.get(..2), id.get(2..4), id.get(4..)) {
        paths.push(format!("{a}/{b}{rest}"));
        paths.push(format!("{a}/{b}/{rest}"));
    }
    paths
}

/// The contents `cat-file --batch` printed, one per input line: `None` for one it found
/// missing (or that isn't a blob). Malformed output gives fewer: the caller then trusts none.
fn batch_texts(out: &[u8]) -> Vec<Option<&[u8]>> {
    let mut texts = Vec::new();
    let mut rest = out;
    while !rest.is_empty() {
        let Some(end) = rest.iter().position(|&b| b == b'\n') else {
            break;
        };
        let (header, after) = rest.split_at(end);
        let after = after.get(1..).unwrap_or_default();
        let header = String::from_utf8_lossy(header);
        let fields: Vec<&str> = header.split(' ').collect();
        match fields.as_slice() {
            [_, "blob", size] => {
                let Ok(size) = size.parse::<usize>() else {
                    break;
                };
                let Some(content) = after.get(..size) else {
                    break;
                };
                texts.push(Some(content));
                // The content, then its newline.
                rest = after.get(size.saturating_add(1)..).unwrap_or_default();
            }
            [_, _, size] => {
                let Ok(size) = size.parse::<usize>() else {
                    break;
                };
                texts.push(None);
                rest = after.get(size.saturating_add(1)..).unwrap_or_default();
            }
            _ => {
                // `<name> missing` (or ambiguous): no content follows.
                texts.push(None);
                rest = after;
            }
        }
    }
    texts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_s_output_is_read_one_input_at_a_time() {
        // As git 2.43 prints it: a blob, a path not there, a commit (not a note), a blob.
        let note = "Zeta: person line\n\nalpha detail\n\nWrit: wrt_1\n";
        let out = format!(
            "6b917266 blob {}\n{note}\nrefs/notes/commits:ab/cd missing\n62a08054 commit 5\nabcde\n\
             1111 blob 3\nxyz\n",
            note.len()
        );
        let texts = batch_texts(out.as_bytes());
        assert_eq!(
            texts,
            [Some(note.as_bytes()), None, None, Some(&b"xyz"[..])]
        );
        // Cut short or malformed: fewer texts than inputs, which the caller trusts none of.
        assert_eq!(batch_texts(b"6b91 blob 99\nshort\n").len(), 0);
        assert_eq!(batch_texts(b"6b91 blob x\n").len(), 0);
        assert!(batch_texts(b"").is_empty());
    }

    /// The second review after M5.5: a note was skipped only when its commit held all of its
    /// lines, so a batch with one line written already (a push whose answer was lost) and one
    /// new wrote the first again.
    #[test]
    fn only_the_lines_a_note_lacks_are_written() {
        let commit: CommitId = "8b137891791fe96927ad78e64b0aad7bded08bdc".parse().unwrap();
        let note = Note {
            commit: commit.clone(),
            text: "Writ: wrt_A\nWrit: wrt_B\n".to_owned(),
        };
        let held = |lines: &[&str]| lines.iter().map(|l| (*l).to_owned()).collect();
        assert_eq!(unwritten(&note, &held(&[])), Some(note.clone()));
        assert_eq!(
            unwritten(&note, &held(&["Reviewed by Sam", "", "Writ: wrt_A"])),
            Some(Note {
                commit,
                text: "Writ: wrt_B\n".to_owned()
            })
        );
        assert_eq!(
            unwritten(&note, &held(&["Writ: wrt_B", "Writ: wrt_A"])),
            None
        );
        // Kept as written: no newline added (a note of the largest size stays within it).
        let bare = Note {
            commit: note.commit.clone(),
            text: "x".repeat(MAX_NOTE_TEXT),
        };
        assert_eq!(unwritten(&bare, &held(&[])), Some(bare.clone()));
        let last = Note {
            commit: note.commit.clone(),
            text: "Writ: wrt_A\nWrit: wrt_B".to_owned(),
        };
        assert_eq!(
            unwritten(&last, &held(&["Writ: wrt_A"])).map(|n| n.text),
            Some("Writ: wrt_B".to_owned())
        );
    }

    /// The second review after M5.5: a note's bounds were checked once the batch was built,
    /// after upstream was asked, and an empty note, left out as holding no new line, never.
    #[test]
    fn a_batch_is_checked_whole_before_anything_runs() {
        let commit: CommitId = "8b137891791fe96927ad78e64b0aad7bded08bdc".parse().unwrap();
        let other: CommitId = "8b137891791fe96927ad78e64b0aad7bded08bdd".parse().unwrap();
        let note = |commit: &CommitId, text: &str| Note {
            commit: commit.clone(),
            text: text.to_owned(),
        };
        let reason = |notes: &[Note]| match check_batch(notes) {
            Err(MirrorError::Notes(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(
            reason(&[]),
            format!("a batch holds from 1 to {MAX_NOTES} notes")
        );
        for text in [String::new(), "x".repeat(MAX_NOTE_TEXT + 1)] {
            assert_eq!(
                reason(&[note(&commit, &text)]),
                format!("a note holds from 1 to {MAX_NOTE_TEXT} bytes")
            );
        }
        assert_eq!(
            reason(&[note(&commit, "a\n"), note(&commit, "b\n")]),
            format!("two notes for commit {commit}")
        );
        check_batch(&[note(&commit, "x"), note(&other, &"x".repeat(MAX_NOTE_TEXT))]).unwrap();
    }

    #[test]
    fn a_note_is_looked_for_under_every_fan_out() {
        let id = "8b137891791fe96927ad78e64b0aad7bded08bdc";
        assert_eq!(
            fanouts(id),
            [
                id.to_owned(),
                "8b/137891791fe96927ad78e64b0aad7bded08bdc".to_owned(),
                "8b/13/7891791fe96927ad78e64b0aad7bded08bdc".to_owned()
            ]
        );
    }

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
    fn only_the_commits_cat_file_found_are_held() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        let out = format!("{a} commit 210\n{b} missing\n{c} tree 30\ngarbage\n");
        let found: Vec<String> = held(out.as_bytes())
            .iter()
            .map(|id| id.to_string())
            .collect();
        assert_eq!(found, [a]);
        assert!(held(b"").is_empty());
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
