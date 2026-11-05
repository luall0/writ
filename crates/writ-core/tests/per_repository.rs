//! M6.1.5, per-repository tickets: one ticket for repositories under different templates,
//! each repository held to its own part, the lease's terms the strictest of its templates,
//! one signing key per lease. Each rule on both sides.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use writ_core::config::PolicyConfig;
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, Lease, RepoUsage, State, TicketRecord, Usage};
use writ_core::narrow;
use writ_core::policy::{self, DenyCode};
use writ_core::ticket::{Operation, Ticket};
use writ_core::units::Duration;

/// Three repositories, four templates: `backend` for api (push on agent/*, key k1, 4h, 20 a
/// minute, 3 renewals), `frontend` for web (commit_sign on review/*, key k1, 2h, 30 a minute,
/// 1 renewal), `docs-own-key` for docs (key k2), `read-only` for api and docs (no key).
const POLICY: &str = r#"
keys:
  k1: { use: signing, format: ssh, algorithm: ed25519 }
  k2: { use: signing, format: ssh, algorithm: ed25519 }
  upstream-01: { use: upstream, kind: ssh, algorithm: ed25519 }
upstream_hosts:
  remote.invalid: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
repos:
  api:
    upstream: ssh://git@remote.invalid/api.git
    upstream_credential: upstream-01
    templates: [backend, read-only]
    protected_refs: ["refs/heads/main"]
  web:
    upstream: ssh://git@remote.invalid/web.git
    upstream_credential: upstream-01
    templates: [frontend]
  docs:
    upstream: ssh://git@remote.invalid/docs.git
    upstream_credential: upstream-01
    templates: [docs-own-key, read-only]
templates:
  backend:
    operations: [fetch, commit_sign, push]
    branches: ["agent/*"]
    committer_emails: ["api@example.org", "both@example.org"]
    signing_key: k1
    max_ttl: 4h
    max_signatures: 10
    max_pushes: 4
    max_ops_per_minute: 20
    max_push_size: 10MB
    paths_check: deny
    max_renewals: 3
  frontend:
    operations: [fetch, commit_sign]
    branches: ["review/*"]
    committer_emails: ["both@example.org", "web@example.org"]
    signing_key: k1
    max_ttl: 2h
    max_signatures: 6
    max_pushes: 0
    max_ops_per_minute: 30
    max_push_size: 1MB
    paths_check: deny
    max_renewals: 1
  docs-own-key:
    operations: [fetch, commit_sign, push]
    branches: ["docs/*"]
    committer_emails: ["both@example.org"]
    signing_key: k2
    max_ttl: 8h
    max_signatures: 10
    max_pushes: 10
    max_ops_per_minute: 30
    max_push_size: 10MB
  read-only:
    operations: [fetch]
    max_ttl: 8h
    max_signatures: 0
    max_pushes: 0
    max_ops_per_minute: 30
    max_push_size: 0
"#;

/// api and web, each under its own template (neither named: each the only one that fits).
const TWO: &str = r#"
repos:
  api:
    operations: [fetch, commit_sign, push]
    branches: ["agent/login"]
    expected_paths: ["src/auth/**"]
    limits: { max_signatures: 10, max_pushes: 4 }
  web:
    operations: [fetch, commit_sign]
    branches: ["review/login"]
    expected_paths: ["app/login/**"]
    limits: { max_signatures: 6 }
ticket:
  title: Login across the API and the web app
  task: Add the login route to the API and its button to the web app
"#;

fn two_config() -> PolicyConfig {
    PolicyConfig::from_yaml(POLICY).unwrap()
}

fn submit(yaml: &str) -> Result<Ticket, fit::Rejection> {
    fit::submit(&two_config(), &request(yaml), &submission(1))
}

fn rejected(yaml: &str, expected: &str) {
    match submit(yaml) {
        Ok(ticket) => panic!("accepted: {ticket:?}"),
        Err(rejection) => assert!(
            rejection.reasons.iter().any(|r| r.contains(expected)),
            "{expected:?} not in {:?}",
            rejection.reasons
        ),
    }
}

fn active(ticket: Ticket) -> Lease {
    let record = TicketRecord::pending(ticket.clone());
    lease::activate(&two_config(), &record, ticket, approval(), 7, later(30)).unwrap()
}

/// A world on [`POLICY`] with the lease.
fn world(lease: Lease) -> World {
    World {
        config: two_config(),
        ..World::new(lease)
    }
}

/// A commit in `repo` by both@example.org touching `path`.
fn sign_in(lease: &Lease, repo_name: &str, path: &str) -> policy::SignRequest {
    policy::SignRequest {
        repo: repo(repo_name),
        committer_email: "both@example.org".to_owned(),
        author_email: "both@example.org".to_owned(),
        committer_name: None,
        author_name: None,
        touched_paths: Some(vec![path.to_owned()]),
        ..sign_request(lease)
    }
}

/// A push in `repo` to `branch`, its commits signed under the lease there.
fn push_in(lease: &Lease, repo_name: &str, branch: &str) -> policy::PushRequest {
    let mut push = push_request(lease);
    push.repo = repo(repo_name);
    push.updates[0].name = format!("refs/heads/{branch}");
    for commit in &mut push.commits {
        commit.signed_under[0].repo = repo(repo_name);
    }
    push
}

fn denied<T: std::fmt::Debug>(result: Result<T, policy::Denial>, code: DenyCode, reason: &str) {
    match result {
        Ok(allowed) => panic!("allowed: {allowed:?}"),
        Err(denial) => {
            assert_eq!(denial.code, code, "{denial}");
            assert!(denial.reason.contains(reason), "{reason:?} not in {denial}");
        }
    }
}

#[test]
fn two_repositories_under_two_templates_are_one_lease_each_held_to_its_part() {
    let ticket = submit(TWO).unwrap();
    // Each repository's template, the one that fits it; the lease's terms the strictest.
    assert_eq!(ticket.repos[&repo("api")].template.as_str(), "backend");
    assert_eq!(ticket.repos[&repo("web")].template.as_str(), "frontend");
    assert_eq!(
        ticket.common.committer_emails,
        ["both@example.org".parse().unwrap()].into(),
        "omitted: the emails every signing template allows"
    );
    assert_eq!(ticket.common.signing_key, Some("k1".parse().unwrap()));
    assert_eq!(
        ticket.created_at.seconds_until(ticket.limits.expires_at),
        2 * 3600,
        "omitted: frontend's max_ttl, the smaller"
    );
    assert_eq!(
        ticket.limits.max_ops_per_minute, 20,
        "omitted: backend's rate"
    );
    let lease = active(ticket);
    let w = world(lease.clone());

    // An operation one part allows and the other doesn't.
    assert!(policy::decide_push(&w.ctx(), &push_in(&lease, "api", "agent/login")).is_ok());
    denied(
        policy::decide_push(&w.ctx(), &push_in(&lease, "web", "review/login")),
        DenyCode::Operation,
        "push not allowed in repo web",
    );
    // A branch: each part's own.
    denied(
        policy::decide_push(&w.ctx(), &push_in(&lease, "api", "review/login")),
        DenyCode::Ref,
        "review/login",
    );
    // A path: each part's expected paths (both templates deny the others).
    assert!(policy::decide_sign(&w.ctx(), &sign_in(&lease, "api", "src/auth/a.rs")).is_ok());
    assert!(policy::decide_sign(&w.ctx(), &sign_in(&lease, "web", "app/login/b.ts")).is_ok());
    denied(
        policy::decide_sign(&w.ctx(), &sign_in(&lease, "web", "src/auth/a.rs")),
        DenyCode::Paths,
        "src/auth/a.rs",
    );
    denied(
        policy::decide_sign(&w.ctx(), &sign_in(&lease, "api", "app/login/b.ts")),
        DenyCode::Paths,
        "app/login/b.ts",
    );
    // A repository the ticket doesn't name.
    denied(
        policy::decide_fetch(
            &w.ctx(),
            &writ_core::policy::FetchRequest { repo: repo("docs") },
        ),
        DenyCode::Repo,
        "docs",
    );
}

#[test]
fn each_repository_s_counts_hold_on_both_sides() {
    let lease = active(submit(TWO).unwrap());
    let mut w = world(lease.clone());
    let used = |signatures, pushes| RepoUsage { signatures, pushes };
    // api's last signature, web untouched: both allowed.
    w.usage = Usage {
        repos: [(repo("api"), used(9, 0))].into(),
        ops_last_minute: 0,
    };
    assert!(policy::decide_sign(&w.ctx(), &sign_in(&lease, "api", "src/auth/a.rs")).is_ok());
    // api's used up: refused there (`limit`, the lease still running), web still signs.
    w.usage.repos.insert(repo("api"), used(10, 0));
    denied(
        policy::decide_sign(&w.ctx(), &sign_in(&lease, "api", "src/auth/a.rs")),
        DenyCode::Limit,
        "all 10 signatures used in repo api",
    );
    assert!(policy::decide_sign(&w.ctx(), &sign_in(&lease, "web", "app/login/b.ts")).is_ok());
    assert!(!lease::is_exhausted(&lease.ticket, &w.usage));
    // Pushes in api: the fourth allowed, a fifth refused.
    w.usage.repos.insert(repo("api"), used(10, 3));
    assert!(policy::decide_push(&w.ctx(), &push_in(&lease, "api", "agent/login")).is_ok());
    w.usage.repos.insert(repo("api"), used(10, 4));
    denied(
        policy::decide_push(&w.ctx(), &push_in(&lease, "api", "agent/login")),
        DenyCode::Limit,
        "repo api",
    );
    // A ticket asking more than a part's template: rejected naming the repository.
    rejected(
        &TWO.replace("max_signatures: 6", "max_signatures: 7"),
        "repos.web fits no template: frontend: limits.max_signatures is 7, over the template's 6",
    );
    assert!(submit(&TWO.replace("max_signatures: 6", "max_signatures: 5")).is_ok());
}

#[test]
fn the_lease_s_time_and_rate_are_the_strictest_template_s_on_both_sides() {
    let with = |limits: &str| format!("{TWO}limits:\n{limits}");
    assert!(submit(&with("  ttl: 2h\n")).is_ok());
    rejected(
        &with("  ttl: 7201s\n"),
        "the lease would last 7201s, over the template frontend's max_ttl (2h)",
    );
    assert!(submit(&with("  max_ops_per_minute: 20\n")).is_ok());
    rejected(
        &with("  max_ops_per_minute: 21\n"),
        "limits.max_ops_per_minute is 21, over the template backend's 20",
    );
    // api alone: backend's own bounds (4h) are its lease's.
    let web_block = TWO
        .find("  web:\n")
        .zip(TWO.find("ticket:\n"))
        .and_then(|(start, end)| TWO.get(start..end))
        .unwrap();
    let api_only = TWO.replacen(web_block, "", 1);
    assert!(submit(&format!("{api_only}limits:\n  ttl: 4h\n")).is_ok());
}

#[test]
fn the_lease_s_renewals_are_the_strictest_template_s_on_both_sides() {
    let mut lease = active(submit(TWO).unwrap());
    lease.state = State::Expired;
    let renewal = TWO.replace("ticket:\n", &format!("ticket:\n  renews: {}\n", lease.id));
    let renewing = |renewals| Submission {
        renews: Some(lease::Renewed {
            lease: &lease,
            renewals,
            grace: Duration::from_seconds(86_400),
        }),
        now: later(7_300),
        ..submission(2)
    };
    let renewed = fit::submit(&two_config(), &request(&renewal), &renewing(0)).unwrap();
    // A renewal keeps each repository's template.
    assert_eq!(renewed.repos[&repo("api")].template.as_str(), "backend");
    assert_eq!(renewed.repos[&repo("web")].template.as_str(), "frontend");
    // frontend allows one renewal, backend three: the second is refused, naming frontend.
    let error = fit::submit(&two_config(), &request(&renewal), &renewing(1)).unwrap_err();
    assert!(
        error
            .reasons
            .iter()
            .any(|r| r.contains("template frontend allows 1 renewals of a lease")),
        "{:?}",
        error.reasons
    );
}

#[test]
fn templates_that_sign_with_different_keys_cannot_share_a_lease() {
    let docs = r#"  docs:
    operations: [fetch, commit_sign, push]
    branches: ["docs/login"]
"#;
    let three = TWO.replace("ticket:\n", &format!("{docs}ticket:\n"));
    rejected(
        &three,
        "the repositories sign with different keys: api (template backend, key k1), docs \
         (template docs-own-key, key k2), web (template frontend, key k1); a lease signs with \
         one key (ask one lease per repository)",
    );
    // docs without commit_sign: its key is unused, so the lease may hold it, its template
    // named (docs-own-key and read-only both fit a fetch).
    let fetch_only = |template: &str| {
        TWO.replace(
            "ticket:\n",
            &format!("  docs:\n    template: {template}\n    operations: [fetch]\nticket:\n"),
        )
    };
    rejected(
        &TWO.replace("ticket:\n", "  docs:\n    operations: [fetch]\nticket:\n"),
        "repos.docs fits several templates (docs-own-key, read-only): name one in \
         repos.docs.template",
    );
    for template in ["read-only", "docs-own-key"] {
        let ticket = submit(&fetch_only(template)).unwrap();
        assert_eq!(ticket.common.signing_key, Some("k1".parse().unwrap()));
        assert_eq!(ticket.repos[&repo("docs")].template.as_str(), template);
    }
}

#[test]
fn a_repository_is_held_to_a_template_that_allows_it() {
    // A template named that doesn't allow the repository.
    rejected(
        &TWO.replace("  web:\n", "  web:\n    template: backend\n"),
        "repos.web: repo web does not allow the template backend (repos.web.templates)",
    );
    // Terms no template of the repository allows: the whole ticket, naming the repository.
    rejected(
        &TWO.replace(
            "branches: [\"review/login\"]",
            "branches: [\"agent/login\"]",
        ),
        "repos.web fits no template",
    );
    // The lease's emails within every signing part's template.
    rejected(
        &format!("common:\n  committer_emails: [\"api@example.org\"]\n{TWO}"),
        "repos.web fits no template: frontend: committer email api@example.org is not allowed by \
         the template frontend",
    );
    assert!(
        submit(&format!(
            "common:\n  committer_emails: [\"both@example.org\"]\n{TWO}"
        ))
        .is_ok()
    );
}

#[test]
fn amendments_and_renewals_are_checked_repository_by_repository() {
    let lease = active(submit(TWO).unwrap());
    // A narrowing in one repository, kept; a widening in the other, refused naming it.
    let mut narrower = lease.ticket.clone();
    narrower
        .repos
        .get_mut(&repo("api"))
        .unwrap()
        .operations
        .remove(&Operation::Push);
    assert!(narrow::widenings(&lease.ticket, &narrower).is_empty());
    let mut wider = narrower.clone();
    wider
        .repos
        .get_mut(&repo("web"))
        .unwrap()
        .branches
        .insert("review/other".parse().unwrap());
    assert_eq!(
        narrow::widenings(&lease.ticket, &wider),
        ["repos.web.branches adds review/other"]
    );
    // A renewal adding a path in one repository: refused, naming it.
    let mut ended = lease.clone();
    ended.state = State::Expired;
    let renewal = TWO
        .replace("[\"app/login/**\"]", "[\"app/login/**\", \"app/other/**\"]")
        .replace("ticket:\n", &format!("ticket:\n  renews: {}\n", ended.id));
    let error = fit::submit(
        &two_config(),
        &request(&renewal),
        &Submission {
            renews: Some(lease::Renewed {
                lease: &ended,
                renewals: 0,
                grace: Duration::from_seconds(86_400),
            }),
            now: later(7_300),
            ..submission(3)
        },
    )
    .unwrap_err();
    assert!(
        error
            .reasons
            .iter()
            .any(|r| r.contains("repos.web.expected_paths adds app/other/**")),
        "{:?}",
        error.reasons
    );
}
