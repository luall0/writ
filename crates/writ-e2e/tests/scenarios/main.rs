//! The end-to-end scenarios (docs/end-to-end.md#scenarios), run by `make e2e` in the runner
//! container: one module per scenario, each on its own Forgejo repository and its own agent,
//! each checking what the agent reads, the audit line, Forgejo's state through its API, and
//! the daemon's mirror. Ignored outside the pipeline (`cargo test` compiles them only).
//!
//! Every scenario takes the stack shared ([`Stack::shared`]) or alone
//! ([`Stack::exclusive`]: it stops or restarts a container), and leaves it working.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

mod approval_popup;
mod concurrency;
mod daemon_management;
mod hardening_limits;
mod hostile_upstream;
mod https_upstream;
mod keystore_recipients;
mod local_mode;
mod narrowing;
mod notes;
mod notes_reconcile;
mod openpgp_commits;
mod operator_setup;
mod per_repository;
mod protocol_versions;
mod push_denials;
mod remote_protection;
mod restart;
mod revocation_and_expiry;
mod sealed_keystore;
mod sessions_and_renewals;
mod ticket_lifecycle;
mod unsigned_fetch;
mod upstream_moved;
mod upstream_proxies;
mod verified_commits;
mod versions;
mod whole_repo;
mod workspaces;
mod wrapper_mode;

use std::process::Output;

use writ_e2e::agent::{Agent, expect, ticket};
use writ_e2e::{Stack, stderr};

/// A lease for `repo` (branches `agent/*`, one hour) and a clone of it from Forgejo, wired in
/// wrapper mode (`writ init <repo>`): the lease id and the clone's directory.
fn wired(stack: &Stack, agent: &Agent, repo: &str) -> (String, String) {
    let lease = agent.lease(stack, &ticket(&[repo], &["agent/*"], "1h", ""));
    agent.clone_from_forgejo(stack, repo, "work");
    agent.ok_in("work", &format!("writ init {repo} --agents none"));
    (lease, "work".to_owned())
}

/// A push refused by the daemon: git's exit 1, the reason the agent reads, and the last
/// `push denied` line of the lease with its code.
fn assert_push_refused(stack: &Stack, lease: &str, out: &Output, reason: &str, code: &str) {
    expect(out, 1, reason);
    assert!(
        stderr(out).contains(reason),
        "expected {reason:?} in:\n{}",
        stderr(out)
    );
    let denied = stack.audited(lease, "push", "denied");
    let last = denied.last().expect("a push denied line");
    assert_eq!(last["code"], code, "{last}");
}
