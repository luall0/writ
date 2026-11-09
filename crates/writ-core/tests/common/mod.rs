//! Shared builders for writ-core's integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use writ_core::caller::CallerFacts;
use writ_core::config::{ObjectFormat, PolicyConfig, PushMode};
use writ_core::fit::{self, Submission};
use writ_core::lease::{self, APPROVAL_NAMESPACE, Approval, Lease, TicketRecord, Usage};
use writ_core::names::{CommitId, KeyFingerprint, RepoName, TicketId};
use writ_core::policy::{
    Context, FetchRequest, LedgerRef, ObjectKind, PushRequest, PushedCommit, RefUpdate, SignRequest,
};
use writ_core::ticket::{Ticket, TicketRequest};
use writ_core::units::Timestamp;

pub const POLICY: &str = include_str!("../fixtures/policy.yaml");

pub const AGENT_EMAIL: &str = "user+agent@example.org";

/// The name of the commits in [`sign_request`].
pub const AGENT_NAME: &str = "Writ agent";

/// The ticket most tests start from: feature-branch, omega-code, agent/oauth-*, 2h.
pub const REQUEST: &str = r#"
repos:
  omega-code:
    template: feature-branch
    operations: [fetch, commit_sign, push]
    branches: ["agent/oauth-*"]
    expected_paths: ["src/auth/**", "tests/auth/**"]
    limits:
      max_signatures: 3
      max_pushes: 2
      max_push_size: 1MB
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login to the web app, behind a feature flag
  plan:
    - Add OAuth client config and callback route
    - Store tokens in the existing session store
    - Feature flag and tests
limits:
  ttl: 2h
  max_ops_per_minute: 5
"#;

/// A usage of `signatures` and `pushes` in `omega-code`, and `ops` in the rate window.
pub fn usage_in(signatures: u32, pushes: u32, ops: u32) -> Usage {
    let mut usage = Usage {
        ops_last_minute: ops,
        ..Usage::default()
    };
    *used(&mut usage) = writ_core::lease::RepoUsage { signatures, pushes };
    usage
}

/// What a lease used in `omega-code` (mutable, for a test to set it).
pub fn used(usage: &mut Usage) -> &mut writ_core::lease::RepoUsage {
    usage.repos.entry(repo("omega-code")).or_default()
}

/// The terms of `omega-code` in a ticket.
pub fn om(ticket: &Ticket) -> &writ_core::ticket::RepoTerms {
    ticket.repos.get(&repo("omega-code")).unwrap()
}

/// The terms of `omega-code` in a ticket (mutable, for a test to change them).
pub fn omega(ticket: &mut Ticket) -> &mut writ_core::ticket::RepoTerms {
    ticket.repos.get_mut(&repo("omega-code")).unwrap()
}

/// `yaml` (a request in the layout of [`REQUEST`]) with the `omega-code` block's terms given
/// to each of `repos` instead, in order.
pub fn with_repos(yaml: &str, repos: &[&str]) -> String {
    // Lines before the block, the block's own lines (indented four spaces), then the rest.
    let mut before = String::new();
    let mut body = String::new();
    let mut after = String::new();
    let mut seen = false;
    for line in yaml.split_inclusive('\n') {
        if !seen && line == "  omega-code:\n" {
            seen = true;
        } else if !seen {
            before.push_str(line);
        } else if after.is_empty() && line.starts_with("    ") {
            body.push_str(line);
        } else {
            after.push_str(line);
        }
    }
    assert!(seen, "an omega-code block");
    let blocks: String = repos
        .iter()
        .map(|repo| format!("  {repo}:\n{body}"))
        .collect();
    format!("{before}{blocks}{after}")
}

pub fn config() -> PolicyConfig {
    PolicyConfig::from_yaml(POLICY).unwrap()
}

pub fn t(unix: i64) -> Timestamp {
    Timestamp::from_unix(unix).unwrap()
}

/// 2026-10-31T14:02:11Z, when test tickets are submitted.
pub fn t0() -> Timestamp {
    "2026-10-31T14:02:11Z".parse().unwrap()
}

pub fn later(seconds: i64) -> Timestamp {
    t(t0().unix() + seconds)
}

pub fn fp(c: char) -> KeyFingerprint {
    format!("SHA256:{}", c.to_string().repeat(43))
        .parse()
        .unwrap()
}

pub fn ticket_id(n: u64) -> TicketId {
    TicketId::from_parts(1_793_455_331_000 + n, [n as u8; 10])
}

pub fn commit(n: u64) -> CommitId {
    format!("{n:040x}").parse().unwrap()
}

pub fn repo(name: &str) -> RepoName {
    name.parse().unwrap()
}

pub fn request(yaml: &str) -> TicketRequest {
    TicketRequest::from_yaml(yaml).unwrap()
}

pub fn submission(n: u64) -> Submission<'static> {
    Submission {
        id: ticket_id(n),
        now: t0(),
        session_key: fp('S'),
        amends: None,
        renews: None,
        revises: None,
        min_ttl: fit::DEFAULT_MIN_TTL,
        chain: None,
    }
}

/// Submits [`REQUEST`] (or another request) as ticket 1.
pub fn submitted(yaml: &str) -> Ticket {
    fit::submit(&config(), &request(yaml), &submission(1)).unwrap()
}

pub fn approval() -> Approval {
    Approval {
        approver: fp('A'),
        namespace: APPROVAL_NAMESPACE.to_owned(),
        sshsig: "-----BEGIN SSH SIGNATURE-----\ntest\n-----END SSH SIGNATURE-----".to_owned(),
    }
}

/// The ticket, signed as is, as an active lease with certificate serial 7.
pub fn lease_of(ticket: Ticket) -> Lease {
    let record = TicketRecord::pending(ticket.clone());
    lease::activate(&config(), &record, ticket, approval(), 7, later(30)).unwrap()
}

/// [`REQUEST`] as an active lease.
pub fn lease() -> Lease {
    lease_of(submitted(REQUEST))
}

/// A lease, its usage, its caller and the time of a request.
pub struct World {
    pub config: PolicyConfig,
    pub lease: Lease,
    pub usage: Usage,
    pub caller: CallerFacts,
    pub now: Timestamp,
}

impl World {
    pub fn new(lease: Lease) -> Self {
        Self {
            config: config(),
            lease,
            usage: Usage::default(),
            caller: CallerFacts::default(),
            now: later(60),
        }
    }

    pub fn ctx(&self) -> Context<'_> {
        Context {
            config: &self.config,
            lease: &self.lease,
            usage: &self.usage,
            caller: &self.caller,
            now: self.now,
        }
    }
}

/// A commit that passes every check of [`lease`].
pub fn sign_request(lease: &Lease) -> SignRequest {
    SignRequest {
        repo: repo("omega-code"),
        object: ObjectKind::Commit,
        object_format: Some(ObjectFormat::Sha1),
        committer_email: AGENT_EMAIL.to_owned(),
        author_email: AGENT_EMAIL.to_owned(),
        committer_name: Some(AGENT_NAME.to_owned()),
        author_name: Some(AGENT_NAME.to_owned()),
        writ_trailers: vec![lease.id.to_string()],
        touched_paths: Some(vec!["src/auth/login.rs".to_owned()]),
    }
}

/// A push of two commits signed under the lease to agent/oauth-login, fast-forward.
pub fn push_request(lease: &Lease) -> PushRequest {
    let signed = |n| PushedCommit {
        paths: None,
        id: commit(n),
        signed_under: vec![LedgerRef {
            paths: None,
            lease: lease.id.clone(),
            repo: repo("omega-code"),
        }],
    };
    PushRequest {
        repo: repo("omega-code"),
        mode: PushMode::Gateway,
        updates: vec![RefUpdate {
            name: "refs/heads/agent/oauth-login".to_owned(),
            old: Some(commit(1)),
            new: Some(commit(3)),
            fast_forward: true,
            case_twin: false,
        }],
        commits: vec![signed(2), signed(3)],
        pack_size: 10_000,
        predecessors: Vec::new(),
    }
}

pub fn fetch_request() -> FetchRequest {
    FetchRequest {
        repo: repo("omega-code"),
    }
}
