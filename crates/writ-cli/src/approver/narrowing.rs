//! What `writ sign` may narrow before signing: each flag only narrows, and anything that
//! would widen the ticket is refused here (a convenience; the daemon checks again).
//!
//! A ticket's terms are the lease's, then each repository's (M6.1.5). The flags on a
//! repository's terms take `<repo>:<value>` for that repository (`--branch api:agent/x`,
//! `--drop-op web:push`, `--max-pushes api:2`), or the value alone for every repository.

use std::collections::BTreeSet;

use anyhow::{Context, bail};
use writ_core::names::{Email, RepoName};
use writ_core::narrow;
use writ_core::pattern::BranchPattern;
use writ_core::ticket::Operation;
use writ_core::ticket::{OnViolation, RepoTerms, Ticket};
use writ_core::units::{ByteSize, Duration};

/// A flag's value for one repository (`<repo>:<value>`), or for every repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scoped<T> {
    pub repo: Option<RepoName>,
    pub value: T,
}

impl<T: std::str::FromStr> std::str::FromStr for Scoped<T>
where
    T::Err: std::fmt::Display,
{
    type Err = String;

    /// `<repo>:<value>` or `<value>`: neither a registry name nor a branch pattern, an
    /// operation or a size holds a `:`.
    fn from_str(text: &str) -> Result<Self, String> {
        match text.split_once(':') {
            Some((repo, value)) => Ok(Self {
                repo: Some(repo.parse().map_err(|e| format!("{e}"))?),
                value: value.parse().map_err(|e: T::Err| e.to_string())?,
            }),
            None => Ok(Self {
                repo: None,
                value: text.parse().map_err(|e: T::Err| e.to_string())?,
            }),
        }
    }
}

/// What `writ sign` may narrow before signing. Each flag only narrows.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct Narrowing {
    /// Shorter lease: it ends at most this long after the ticket was created (e.g. 2h).
    #[arg(long)]
    pub ttl: Option<Duration>,
    /// Drop a repo (repeatable).
    #[arg(long = "drop-repo", value_name = "REPO")]
    pub drop_repos: Vec<RepoName>,
    /// Drop an operation: fetch, commit_sign or push, in one repo (`web:push`) or every one
    /// (repeatable).
    #[arg(long = "drop-op", value_name = "[REPO:]OP")]
    pub drop_ops: Vec<Scoped<Operation>>,
    /// Replace a repo's branches (`api:agent/x`; alone, every repo's not named); each must be
    /// within a submitted one (repeatable).
    #[arg(long = "branch", value_name = "[REPO:]PATTERN")]
    pub branches: Vec<Scoped<BranchPattern>>,
    /// Drop a committer email (repeatable).
    #[arg(long = "drop-email", value_name = "EMAIL")]
    pub drop_emails: Vec<Email>,
    /// Lower a repo's signatures (`api:5`), or cap every repo's (repeatable).
    #[arg(long, value_name = "[REPO:]N")]
    pub max_signatures: Vec<Scoped<u32>>,
    /// Lower a repo's pushes (`api:2`), or cap every repo's (repeatable).
    #[arg(long, value_name = "[REPO:]N")]
    pub max_pushes: Vec<Scoped<u32>>,
    /// The lease's rate.
    #[arg(long)]
    pub max_ops_per_minute: Option<u32>,
    /// Lower a repo's push size (`api:10MB`), or cap every repo's (repeatable).
    #[arg(long, value_name = "[REPO:]SIZE")]
    pub max_push_size: Vec<Scoped<ByteSize>>,
    /// Turn force push off, in every repo.
    #[arg(long)]
    pub no_force_push: bool,
    /// Revoke the lease on the first out-of-scope request.
    #[arg(long)]
    pub revoke_on_violation: bool,
}

/// The repositories a scoped flag reaches: the one named (it must be in the ticket), or every
/// one.
fn reached<'t, T>(
    t: &'t mut Ticket,
    flag: &str,
    scoped: &Scoped<T>,
) -> anyhow::Result<Vec<(&'t RepoName, &'t mut RepoTerms)>> {
    match &scoped.repo {
        Some(repo) => {
            let Some((name, terms)) = t.repos.iter_mut().find(|(name, _)| *name == repo) else {
                bail!("--{flag} {repo}:…: the ticket doesn't name repo {repo}");
            };
            Ok(vec![(name, terms)])
        }
        None => Ok(t.repos.iter_mut().collect()),
    }
}

/// Lowers a count: to `value` in the repository named (refused above its current one), or
/// capped at `value` in every repository.
fn lower<T: Copy + PartialOrd + std::fmt::Display>(
    t: &mut Ticket,
    flag: &str,
    values: &[Scoped<T>],
    field: impl Fn(&mut RepoTerms) -> &mut T,
) -> anyhow::Result<()> {
    for scoped in values {
        let named = scoped.repo.is_some();
        for (repo, terms) in reached(t, flag, scoped)? {
            let current = field(terms);
            if scoped.value > *current {
                if named {
                    bail!(
                        "--{flag} {repo}:{} is above the ticket's {current}; it can only lower it",
                        scoped.value
                    );
                }
                continue;
            }
            *current = scoped.value;
        }
    }
    Ok(())
}

impl Narrowing {
    /// The ticket narrowed by these flags. Refuses a flag that would widen anything.
    pub fn apply(&self, submitted: &Ticket) -> anyhow::Result<Ticket> {
        let mut t = submitted.clone();
        if let Some(ttl) = self.ttl {
            let end = t.created_at.checked_add(ttl).context("--ttl is too long")?;
            if end > t.limits.expires_at {
                bail!("--ttl {ttl} would extend the lease; it can only shorten it");
            }
            t.limits.expires_at = end;
        }
        for repo in &self.drop_repos {
            if t.repos.remove(repo).is_none() {
                bail!("--drop-repo {repo}: the ticket doesn't ask for it");
            }
        }
        if t.repos.is_empty() {
            bail!("--drop-repo leaves no repository: refuse the ticket instead");
        }
        for scoped in &self.drop_ops {
            let mut dropped = false;
            for (_, terms) in reached(&mut t, "drop-op", scoped)? {
                dropped |= terms.operations.remove(&scoped.value);
            }
            if !dropped {
                bail!("--drop-op {}: the ticket doesn't ask for it", scoped.value);
            }
        }
        // Branches named for a repository replace its own; the others replace the branches of
        // every repository no flag names.
        let named: BTreeSet<&RepoName> = self
            .branches
            .iter()
            .filter_map(|b| b.repo.as_ref())
            .collect();
        let every: BTreeSet<BranchPattern> = self
            .branches
            .iter()
            .filter(|b| b.repo.is_none())
            .map(|b| b.value.clone())
            .collect();
        for repo in &named {
            if !t.repos.contains_key(*repo) {
                bail!("--branch {repo}:…: the ticket doesn't name repo {repo}");
            }
        }
        for (repo, terms) in &mut t.repos {
            if named.contains(repo) {
                terms.branches = self
                    .branches
                    .iter()
                    .filter(|b| b.repo.as_ref() == Some(repo))
                    .map(|b| b.value.clone())
                    .collect();
            } else if !every.is_empty() {
                terms.branches = every.clone();
            }
        }
        for email in &self.drop_emails {
            if !t.common.committer_emails.remove(email) {
                bail!("--drop-email {email}: the ticket doesn't ask for it");
            }
        }
        lower(&mut t, "max-signatures", &self.max_signatures, |terms| {
            &mut terms.limits.max_signatures
        })?;
        lower(&mut t, "max-pushes", &self.max_pushes, |terms| {
            &mut terms.limits.max_pushes
        })?;
        lower(&mut t, "max-push-size", &self.max_push_size, |terms| {
            &mut terms.limits.max_push_size
        })?;
        if let Some(value) = self.max_ops_per_minute {
            if value > t.limits.max_ops_per_minute {
                bail!(
                    "--max-ops-per-minute {value} is above the ticket's {}; it can only lower it",
                    t.limits.max_ops_per_minute
                );
            }
            t.limits.max_ops_per_minute = value;
        }
        if self.no_force_push {
            for terms in t.repos.values_mut() {
                terms.force_push = false;
            }
        }
        if self.revoke_on_violation {
            t.on_violation = OnViolation::RevokeLease;
        }
        // Convenience: the daemon checks this again.
        narrow::check(submitted, &t).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use writ_core::canonical::Canonical;

    use super::*;

    const FULL: &[u8] = include_bytes!("../../../writ-core/tests/fixtures/ticket-full.json");

    fn ticket() -> Ticket {
        Ticket::from_canonical(FULL).unwrap()
    }

    fn error(narrowing: Narrowing) -> String {
        format!("{:#}", narrowing.apply(&ticket()).unwrap_err())
    }

    #[test]
    fn no_flag_signs_the_ticket_as_submitted() {
        assert_eq!(Narrowing::default().apply(&ticket()).unwrap(), ticket());
    }

    #[test]
    fn each_flag_narrows() {
        let t = ticket();
        let narrowed = Narrowing {
            ttl: Some("1h".parse().unwrap()),
            drop_ops: vec![Operation::Push],
            branches: vec!["agent/oauth-x".parse().unwrap()],
            drop_emails: Vec::new(),
            max_signatures: Some(2),
            max_pushes: Some(0),
            max_ops_per_minute: Some(5),
            max_push_size: Some("1KB".parse().unwrap()),
            no_force_push: true,
            revoke_on_violation: true,
            ..Narrowing::default()
        }
        .apply(&t)
        .unwrap();
        assert_eq!(
            narrowed.limits.expires_at,
            t.created_at.checked_add("1h".parse().unwrap()).unwrap()
        );
        assert!(!narrowed.scope.operations.contains(&Operation::Push));
        assert_eq!(narrowed.scope.operations.len(), 2);
        assert_eq!(narrowed.scope.branches.len(), 1);
        assert_eq!(narrowed.limits.max_signatures, 2);
        assert_eq!(narrowed.limits.max_pushes, 0);
        assert_eq!(narrowed.limits.max_ops_per_minute, 5, "equal is allowed");
        assert_eq!(narrowed.limits.max_push_size, "1KB".parse().unwrap());
        assert!(!narrowed.scope.force_push);
        assert_eq!(narrowed.on_violation, OnViolation::RevokeLease);
        // Everything else is untouched.
        assert_eq!(narrowed.id, t.id);
        assert_eq!(narrowed.text, t.text);
        assert_eq!(narrowed.scope.repos, t.scope.repos);
    }

    #[test]
    fn a_ttl_can_only_shorten_the_lease() {
        // The ticket ends 2h after it was created.
        let exact = Narrowing {
            ttl: Some("2h".parse().unwrap()),
            ..Narrowing::default()
        };
        assert_eq!(exact.apply(&ticket()).unwrap(), ticket());
        let longer = error(Narrowing {
            ttl: Some("7201s".parse().unwrap()),
            ..Narrowing::default()
        });
        assert!(longer.contains("would extend the lease"), "{longer}");
    }

    #[test]
    fn limits_can_only_be_lowered() {
        for (narrowing, flag) in [
            (
                Narrowing {
                    max_signatures: Some(4),
                    ..Narrowing::default()
                },
                "--max-signatures 4 is above the ticket's 3",
            ),
            (
                Narrowing {
                    max_pushes: Some(3),
                    ..Narrowing::default()
                },
                "--max-pushes 3 is above the ticket's 2",
            ),
            (
                Narrowing {
                    max_ops_per_minute: Some(6),
                    ..Narrowing::default()
                },
                "--max-ops-per-minute 6 is above the ticket's 5",
            ),
            (
                Narrowing {
                    max_push_size: Some("1000001B".parse().unwrap()),
                    ..Narrowing::default()
                },
                "--max-push-size",
            ),
        ] {
            let message = error(narrowing);
            assert!(message.contains(flag), "{message}");
        }
    }

    #[test]
    fn only_what_the_ticket_asks_for_can_be_dropped() {
        let repo = error(Narrowing {
            drop_repos: vec!["other".parse().unwrap()],
            ..Narrowing::default()
        });
        assert!(
            repo.contains("--drop-repo other: the ticket doesn't ask for it"),
            "{repo}"
        );
        let email = error(Narrowing {
            drop_emails: vec!["someone@example.org".parse().unwrap()],
            ..Narrowing::default()
        });
        assert!(
            email.contains("--drop-email someone@example.org"),
            "{email}"
        );
        let twice = error(Narrowing {
            drop_ops: vec![Operation::Push, Operation::Push],
            ..Narrowing::default()
        });
        assert!(
            twice.contains("--drop-op push: the ticket doesn't ask for it"),
            "{twice}"
        );
    }

    #[test]
    fn branches_must_stay_within_the_submitted_ones() {
        let wider = error(Narrowing {
            branches: vec!["agent/*".parse().unwrap()],
            ..Narrowing::default()
        });
        assert!(wider.contains("branch"), "{wider}");
        let other = error(Narrowing {
            branches: vec!["main".parse().unwrap()],
            ..Narrowing::default()
        });
        assert!(other.contains("branch"), "{other}");
    }
}
