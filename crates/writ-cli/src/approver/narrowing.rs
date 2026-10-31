//! What `writ sign` may narrow before signing: each flag only narrows, and anything that
//! would widen the ticket is refused here (a convenience; the daemon checks again).

use std::collections::BTreeSet;

use anyhow::{Context, bail};
use writ_core::names::{Email, RepoName};
use writ_core::narrow;
use writ_core::pattern::BranchPattern;
use writ_core::ticket::Operation;
use writ_core::ticket::{OnViolation, Ticket};
use writ_core::units::{ByteSize, Duration};

/// What `writ sign` may narrow before signing. Each flag only narrows.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct Narrowing {
    /// Shorter lease: it ends at most this long after the ticket was created (e.g. 2h).
    #[arg(long)]
    pub ttl: Option<Duration>,
    /// Drop a repo (repeatable).
    #[arg(long = "drop-repo", value_name = "REPO")]
    pub drop_repos: Vec<RepoName>,
    /// Drop an operation: fetch, commit_sign or push (repeatable).
    #[arg(long = "drop-op", value_name = "OP")]
    pub drop_ops: Vec<Operation>,
    /// Replace the branches; each must be within a submitted one (repeatable).
    #[arg(long = "branch", value_name = "PATTERN")]
    pub branches: Vec<BranchPattern>,
    /// Drop a committer email (repeatable).
    #[arg(long = "drop-email", value_name = "EMAIL")]
    pub drop_emails: Vec<Email>,
    #[arg(long)]
    pub max_signatures: Option<u32>,
    #[arg(long)]
    pub max_pushes: Option<u32>,
    #[arg(long)]
    pub max_ops_per_minute: Option<u32>,
    #[arg(long)]
    pub max_push_size: Option<ByteSize>,
    /// Turn force push off.
    #[arg(long)]
    pub no_force_push: bool,
    /// Revoke the lease on the first out-of-scope request.
    #[arg(long)]
    pub revoke_on_violation: bool,
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
            if !t.scope.repos.remove(repo) {
                bail!("--drop-repo {repo}: the ticket doesn't ask for it");
            }
        }
        for op in &self.drop_ops {
            if !t.scope.operations.remove(op) {
                bail!("--drop-op {op}: the ticket doesn't ask for it");
            }
        }
        if !self.branches.is_empty() {
            t.scope.branches = self.branches.iter().cloned().collect::<BTreeSet<_>>();
        }
        for email in &self.drop_emails {
            if !t.scope.committer_emails.remove(email) {
                bail!("--drop-email {email}: the ticket doesn't ask for it");
            }
        }
        let lower = |name: &str, value: Option<u32>, current: &mut u32| -> anyhow::Result<()> {
            if let Some(value) = value {
                if value > *current {
                    bail!("--{name} {value} is above the ticket's {current}; it can only lower it");
                }
                *current = value;
            }
            Ok(())
        };
        lower(
            "max-signatures",
            self.max_signatures,
            &mut t.limits.max_signatures,
        )?;
        lower("max-pushes", self.max_pushes, &mut t.limits.max_pushes)?;
        lower(
            "max-ops-per-minute",
            self.max_ops_per_minute,
            &mut t.limits.max_ops_per_minute,
        )?;
        if let Some(size) = self.max_push_size {
            if size > t.limits.max_push_size {
                bail!("--max-push-size {size} is above the ticket's; it can only lower it");
            }
            t.limits.max_push_size = size;
        }
        if self.no_force_push {
            t.scope.force_push = false;
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
        assert!(!wider.is_empty());
        let other = Narrowing {
            branches: vec!["main".parse().unwrap()],
            ..Narrowing::default()
        };
        assert!(other.apply(&ticket()).is_err());
    }
}
