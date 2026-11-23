//! What `writ ls` shows in a repository (`docs/architecture/clients.md`, what `writ ls` shows
//! in a repository): in a repository `writ init` wired, or at a workspace root, only the
//! tickets and leases of its repositories. The lease of the session the repository's commands
//! use is shown and marked yours; another session's active lease there, or a waiting
//! amendment of one, is counted and never named, so an agent isn't handed an id to wander
//! onto. Elsewhere, or with `writ ls --global`, everything shows.
//!
//! A nudge, never a boundary (hard rule 1): `--global` and the reader key are open to any
//! program of the user. The daemon's scope and `writ run`'s binding are what refuse.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context as _;
use writ_core::lease::State;
use writ_core::names::{RepoName, TicketId};
use writ_proto::Summary;

use crate::display::clean;
use crate::{wiring, workspace};

/// Where `writ ls` runs, when that is a wired repository or a workspace root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// What the header names: `demo`, or `the workspace's repositories (api, web)`.
    pub label: String,
    /// The registry names in scope.
    pub repos: BTreeSet<RepoName>,
    /// The lease of the session the repository's commands use, if one can be used.
    pub mine: Option<TicketId>,
}

/// The tickets `writ ls` shows in a scope, and how many it leaves unnamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scoped {
    pub shown: Vec<Summary>,
    /// Other sessions' active leases in scope, and waiting amendments of them.
    pub hidden: usize,
}

/// The scope of a command run in `dir` with the Writ home `home`: a workspace root's members,
/// else the wired repository `dir` is in, else none (not a repository, or not wired). A
/// record that can't be read is an error, never "no scope": it is the agent's to write.
pub fn here(home: &Path, dir: &Path) -> anyhow::Result<Option<Scope>> {
    let (repos, pinned, label) = if let Some(found) = workspace::load(dir)? {
        let repos: BTreeSet<RepoName> = found.members.iter().map(|m| m.repo.clone()).collect();
        let names: Vec<String> = repos.iter().map(|r| clean(r.as_str())).collect();
        let label = format!("the workspace's repositories ({})", names.join(", "));
        (repos, found.lease, label)
    } else {
        // Not in a git repository: no scope. In one, its record must read.
        let Ok(common) = wiring::common_dir(dir) else {
            return Ok(None);
        };
        let Some(wired) = wiring::load_common(&common)
            .context("cannot tell which repository this is (writ ls --global lists every one)")?
        else {
            return Ok(None);
        };
        let label = clean(wired.repo.as_str());
        (BTreeSet::from([wired.repo]), wired.lease, label)
    };
    // A session that can't be used (ended, unknown here) makes no lease yours: the list then
    // hides more, never less.
    let mine = wiring::choose_session(home, pinned.as_ref())
        .and_then(|session| session.resolved(home))
        .ok()
        .and_then(|session| match session {
            wiring::SessionRef::Lease(id) => Some(id),
            wiring::SessionRef::Current => None,
        });
    Ok(Some(Scope { label, repos, mine }))
}

/// `tickets` as `scope` shows them: those of its repositories only; yours (your lease and its
/// amendments), the waiting tickets that start a lease and the ended ones shown; every other
/// active lease, and every waiting amendment of one, counted.
pub fn apply(scope: &Scope, tickets: Vec<Summary>) -> Scoped {
    let mut shown = Vec::new();
    let mut hidden: usize = 0;
    for ticket in tickets {
        if !ticket.repos.iter().any(|r| scope.repos.contains(r)) {
            continue;
        }
        let yours = scope.mine.as_ref() == Some(&ticket.lease);
        let hide = !yours
            && match ticket.state {
                // A lease in force: the id another session would use.
                State::Active => true,
                // An amendment names the lease it amends; a new ticket grants nothing yet.
                State::Pending => ticket.lease != ticket.id,
                // Ended: nothing to use.
                State::Refused
                | State::Applied
                | State::Closed
                | State::Exhausted
                | State::Expired
                | State::Revoked
                | State::Renewed => false,
            };
        if hide {
            hidden = hidden.saturating_add(1);
        } else {
            shown.push(ticket);
        }
    }
    Scoped { shown, hidden }
}

/// The line under the list that counts what it leaves unnamed, if anything.
pub fn hidden_line(hidden: usize) -> Option<String> {
    match hidden {
        0 => None,
        1 => Some(
            "1 more here belongs to another session, not shown: writ ls --global lists it."
                .to_owned(),
        ),
        n => Some(format!(
            "{n} more here belong to other sessions, not shown: writ ls --global lists them."
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use writ_core::units::Timestamp;

    use super::*;

    const MINE: &str = "wrt_01JD8X0000000000000000000A";
    const OTHER: &str = "wrt_01JD8X0000000000000000000B";
    const WAITING: &str = "wrt_01JD8X0000000000000000000C";
    const AMENDS_OTHER: &str = "wrt_01JD8X0000000000000000000D";
    const AMENDS_MINE: &str = "wrt_01JD8X0000000000000000000E";
    const ELSEWHERE: &str = "wrt_01JD8X0000000000000000000F";
    const ENDED: &str = "wrt_01JD8X0000000000000000000G";

    fn id(text: &str) -> TicketId {
        text.parse().unwrap()
    }

    fn repo(name: &str) -> RepoName {
        name.parse().unwrap()
    }

    fn ticket(id_: &str, lease: &str, state: State, repos: &[&str]) -> Summary {
        Summary {
            id: id(id_),
            lease: id(lease),
            state,
            templates: vec!["feature".parse().unwrap()],
            revision: 1,
            repos: repos.iter().map(|r| repo(r)).collect(),
            created_at: Timestamp::from_unix(1_000).unwrap(),
            expires_at: Timestamp::from_unix(9_000).unwrap(),
            title: "A title".to_owned(),
            unsigned: false,
        }
    }

    fn scope(mine: Option<&str>) -> Scope {
        Scope {
            label: "demo".to_owned(),
            repos: BTreeSet::from([repo("demo")]),
            mine: mine.map(id),
        }
    }

    fn all() -> Vec<Summary> {
        vec![
            ticket(MINE, MINE, State::Active, &["demo"]),
            ticket(OTHER, OTHER, State::Active, &["demo", "web"]),
            ticket(WAITING, WAITING, State::Pending, &["demo"]),
            ticket(AMENDS_OTHER, OTHER, State::Pending, &["demo"]),
            ticket(AMENDS_MINE, MINE, State::Pending, &["demo"]),
            ticket(ELSEWHERE, ELSEWHERE, State::Active, &["web"]),
            ticket(ENDED, ENDED, State::Closed, &["demo"]),
        ]
    }

    fn ids(scoped: &Scoped) -> Vec<&str> {
        scoped.shown.iter().map(|t| t.id.as_str()).collect()
    }

    /// Yours, a waiting new ticket and an ended one shown; another session's lease on the
    /// same repository and a waiting amendment of it counted, their ids nowhere; another
    /// repository's lease left out.
    #[test]
    fn only_this_repository_shows_and_other_sessions_leases_are_counted_not_named() {
        let scoped = apply(&scope(Some(MINE)), all());
        assert_eq!(ids(&scoped), [MINE, WAITING, AMENDS_MINE, ENDED]);
        assert_eq!(scoped.hidden, 2);
        for shown in &scoped.shown {
            assert_ne!(shown.lease.as_str(), OTHER, "another session's lease named");
            assert_ne!(
                shown.id.as_str(),
                ELSEWHERE,
                "another repository's lease shown"
            );
        }
    }

    /// No usable session: no lease is yours, so every active one is counted (more hidden,
    /// never less).
    #[test]
    fn without_a_session_every_active_lease_is_counted() {
        let scoped = apply(&scope(None), all());
        assert_eq!(ids(&scoped), [WAITING, ENDED]);
        assert_eq!(scoped.hidden, 4);
    }

    /// A workspace's scope holds each member: a lease on any of them is in it.
    #[test]
    fn a_workspace_scope_holds_every_member() {
        let mut both = scope(Some(MINE));
        both.repos.insert(repo("web"));
        let scoped = apply(&both, all());
        assert_eq!(ids(&scoped), [MINE, WAITING, AMENDS_MINE, ENDED]);
        assert_eq!(scoped.hidden, 3);
    }

    #[test]
    fn the_hidden_line_counts_and_names_the_flag() {
        assert_eq!(hidden_line(0), None);
        assert_eq!(
            hidden_line(1).unwrap(),
            "1 more here belongs to another session, not shown: writ ls --global lists it."
        );
        assert_eq!(
            hidden_line(3).unwrap(),
            "3 more here belong to other sessions, not shown: writ ls --global lists them."
        );
    }
}
