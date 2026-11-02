//! Syncing a mirror from upstream: upstream's branches and tags fetched atomically, its
//! `HEAD` followed, a failed sync's partial pack removed, the mirror repacked past
//! [`MAX_PACKS`](super::MAX_PACKS) packs.

use std::time::Duration;

use tokio::time::Instant;

use super::access::Access;
use super::open::{local, remove_leftovers};
use super::{LOCAL_WORK_DEADLINE, MAX_FETCH_OUTPUT, MAX_HEAD_OUTPUT, MAX_MOVES_KEPT, MAX_PACKS};
use super::{MirrorGuard, RefMove, SyncReport};
use crate::git::{self, Hooks};
use crate::process;
use crate::{Result, shown};

impl MirrorGuard {
    /// Fetches upstream's branches and tags, then points the mirror's `HEAD` at upstream's
    /// default branch, both within the sync's deadline and through one agent socket.
    pub(super) async fn fetch(&self) -> Result<SyncReport> {
        let shared = &self.shared;
        let repo = &self.repo;
        let started = Instant::now();
        let access = self.reach_upstream()?;
        let upstream = repo.reach.url();
        let fetched = self
            .upstream_git(
                &access,
                &[
                    "fetch",
                    "--porcelain",
                    "--atomic",
                    "--prune",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--no-recurse-submodules",
                    "--no-auto-maintenance",
                    "--no-show-forced-updates",
                    "--",
                    upstream,
                    "+refs/heads/*:refs/heads/*",
                    "+refs/tags/*:refs/tags/*",
                ],
                shared.config.timeout,
                MAX_FETCH_OUTPUT,
            )
            .await?;
        let left = shared.config.timeout.saturating_sub(started.elapsed());
        let head = self
            .upstream_git(
                &access,
                &["ls-remote", "--symref", "--", upstream, "HEAD"],
                left,
                MAX_HEAD_OUTPUT,
            )
            .await?;
        drop(access);
        self.follow_head(&head).await;
        Ok(parse_moves(&fetched))
    }

    /// Runs git against upstream through `access`, within `deadline`, keeping at most
    /// `max_stdout` bytes of its output. A failure is classified from its stderr.
    async fn upstream_git(
        &self,
        access: &Access,
        args: &[&str],
        deadline: Duration,
        max_stdout: usize,
    ) -> Result<Vec<u8>> {
        let finished = self
            .run_upstream(access, args, None, deadline, max_stdout)
            .await?;
        if !finished.status.success() {
            return Err(self.classify(access, &finished.stderr, "sync"));
        }
        Ok(finished.stdout)
    }

    /// Points the mirror's `HEAD` at upstream's default branch (from `ls-remote --symref`'s
    /// `ref: refs/heads/<name>\tHEAD`), so a clone checks it out. Only a branch the mirror
    /// has; anything else leaves `HEAD` as it is (git refuses an invalid name itself).
    async fn follow_head(&self, ls_remote: &[u8]) {
        let text = String::from_utf8_lossy(ls_remote);
        let Some(target) = text.lines().find_map(|line| {
            line.strip_prefix("ref: ")
                .and_then(|rest| rest.strip_suffix("\tHEAD"))
                .filter(|name| name.starts_with("refs/heads/"))
        }) else {
            return;
        };
        let path = &self.repo.path;
        let git_in = |args: &[&str]| {
            let mut cmd = git::command(&self.shared.config.git, Hooks::None);
            cmd.arg("--git-dir").arg(path).args(args);
            cmd
        };
        let current = local(git_in(&["symbolic-ref", "-q", "HEAD"])).await;
        if matches!(&current, Ok(out) if out.stdout.trim_ascii() == target.as_bytes()) {
            return;
        }
        let exists = local(git_in(&["show-ref", "--verify", "--quiet", "--", target])).await;
        if !matches!(&exists, Ok(out) if out.status.success()) {
            return;
        }
        match local(git_in(&["symbolic-ref", "HEAD", target])).await {
            Ok(out) if out.status.success() => {
                tracing::info!(repo = %self.repo.name, head = target, "mirror HEAD follows upstream");
            }
            _ => {
                tracing::warn!(repo = %self.repo.name, "cannot point the mirror's HEAD at upstream's")
            }
        }
    }

    /// Removes what a failed or killed fetch left in the pack directory (`tmp_*`). Only a
    /// fetch writes there while the mirror is held (a push writes into its own quarantine).
    pub(super) fn remove_partial_packs(&self) {
        let pack = self.repo.path.join("objects").join("pack");
        if let Err(e) = remove_leftovers(&pack, |name| name.starts_with("tmp_")) {
            tracing::warn!(repo = %self.repo.name, error = %e, "cannot remove a failed sync's pack");
        }
    }

    /// Repacks the mirror once it holds more than [`MAX_PACKS`] packs. A failure only costs
    /// speed: logged, never fatal.
    pub(super) async fn repack_if_needed(&self) {
        let pack = self.repo.path.join("objects").join("pack");
        let packs = std::fs::read_dir(&pack)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".pack"))
                    .count()
            })
            .unwrap_or(0);
        if packs <= MAX_PACKS {
            return;
        }
        let mut cmd = git::command(&self.shared.config.git, Hooks::None);
        cmd.arg("--git-dir")
            .arg(&self.repo.path)
            .args(["repack", "-a", "-d", "-q"]);
        match process::run(cmd, None, LOCAL_WORK_DEADLINE, 0).await {
            Ok(done) if done.status.success() => {}
            Ok(done) => tracing::warn!(
                repo = %self.repo.name,
                stderr = %shown(&done.stderr),
                "repack failed"
            ),
            Err(e) => tracing::warn!(repo = %self.repo.name, error = ?e, "repack failed"),
        }
    }
}

/// `git fetch --porcelain`'s lines: `<flag> <old> <new> <ref>`. Up to-date refs (`=`) and
/// unreadable lines are left out.
fn parse_moves(stdout: &[u8]) -> SyncReport {
    let mut moved = Vec::new();
    let mut more: usize = 0;
    for line in String::from_utf8_lossy(stdout).lines() {
        let mut chars = line.chars();
        let Some(flag) = chars.next() else { continue };
        let mut parts = chars.as_str().trim_start().split(' ');
        let (Some(old), Some(new), Some(name), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if flag == '=' {
            continue;
        }
        if moved.len() < MAX_MOVES_KEPT {
            moved.push(RefMove {
                flag,
                name: writ_core::text::shown(name, 256),
                old: old.to_owned(),
                new: new.to_owned(),
            });
        } else {
            more = more.saturating_add(1);
        }
    }
    SyncReport::Synced { moved, more }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_lines_become_ref_moves() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let out = format!(
            "* {z} {a} refs/heads/new\n+ {a} {z} refs/heads/forced\n= {a} {a} refs/heads/same\n\
             - {a} {z} refs/heads/gone\ngarbage\n"
        );
        let SyncReport::Synced { moved, more } = parse_moves(out.as_bytes()) else {
            panic!("synced");
        };
        let names: Vec<(char, &str)> = moved.iter().map(|m| (m.flag, m.name.as_str())).collect();
        assert_eq!(
            names,
            [
                ('*', "refs/heads/new"),
                ('+', "refs/heads/forced"),
                ('-', "refs/heads/gone")
            ]
        );
        assert_eq!(more, 0);
    }

    #[test]
    fn a_report_keeps_a_bounded_number_of_moves() {
        let a = "a".repeat(40);
        let line = |n: usize| format!("* {a} {a} refs/heads/b{n}\n");
        let out: String = (0..MAX_MOVES_KEPT + 3).map(line).collect();
        let SyncReport::Synced { moved, more } = parse_moves(out.as_bytes()) else {
            panic!("synced");
        };
        assert_eq!(moved.len(), MAX_MOVES_KEPT);
        assert_eq!(more, 3);
        let out: String = (0..MAX_MOVES_KEPT).map(line).collect();
        assert_eq!(
            parse_moves(out.as_bytes()),
            SyncReport::Synced {
                moved: (0..MAX_MOVES_KEPT)
                    .map(|n| RefMove {
                        flag: '*',
                        name: format!("refs/heads/b{n}"),
                        old: a.clone(),
                        new: a.clone(),
                    })
                    .collect(),
                more: 0,
            }
        );
    }
}
