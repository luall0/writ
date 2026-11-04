//! `Service::sign` on the fakes and a manual clock: what a commit must be to be signed, every
//! denial with its exact code, every limit on both sides, a failing signer or audit log
//! (nothing signed, counted or recorded), the ledger, and `on_violation`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use writ_approval::testing::{START, TestService, TestServiceBuilder};
use writ_approval::{SignObject, SignedCommit, Signing};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::policy::{CertIdentity, Denial, DenyCode, ObjectKind};
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg, PrivateKey};
use writ_git::Commit;
use writ_git::object::{HashAlgo, ObjectType};
use writ_git::paths::{Evidence, touched};
use writ_platform::testing::FakeClock;
use writ_proto::Decision;
use writ_store::Store;

const POLICY: &str = include_str!("../../writ-core/tests/fixtures/policy.yaml");

const EMAIL: &str = "user+agent@example.org";

/// A feature-branch lease on omega-code (`ticket_link: trailer`, `paths_check: warn`) and
/// homelab-scripts (`ledger_only`).
const FEATURE: &str = r#"
template: feature-branch
scope:
  repos: [omega-code, homelab-scripts]
  operations: [fetch, commit_sign, push]
  branches: ["agent/oauth-*"]
ticket:
  title: Add OAuth login
  task: Add GitHub OAuth login behind a feature flag
  expected_paths: ["src/**"]
"#;

/// A quick-fix lease (`paths_check: deny`, 10 signatures, 10 a minute).
const QUICK_FIX: &str = r#"
template: quick-fix
scope:
  repos: [omega-code]
  operations: [fetch, commit_sign, push]
  branches: ["agent/fix-*"]
ticket:
  title: Fix the login
  task: Fix it
  expected_paths: ["src/**"]
"#;

struct Harness {
    _dir: tempfile::TempDir,
    test: TestService,
    clock: Arc<FakeClock>,
    db: std::path::PathBuf,
}

impl std::ops::Deref for Harness {
    type Target = TestService;
    fn deref(&self) -> &TestService {
        &self.test
    }
}

impl Harness {
    fn new() -> Self {
        Self::with_policy(POLICY)
    }

    fn with_policy(policy: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::at_unix(START));
        let test = TestServiceBuilder::new(policy)
            .clock(clock.clone())
            .build(dir.path());
        let db = dir.path().join("leases.db");
        Self {
            _dir: dir,
            test,
            clock,
            db,
        }
    }

    /// An active lease for `yaml`: its id and the certificate's identity.
    fn lease(&self, yaml: &str) -> (TicketId, CertIdentity) {
        self.lease_with(&generate(KeyKind::Ed25519).unwrap(), yaml)
    }

    /// The same, submitted with the session key `key`.
    fn lease_with(&self, key: &PrivateKey, yaml: &str) -> (TicketId, CertIdentity) {
        let submitted = self
            .service
            .submit(key.public_key(), yaml.as_bytes(), &CallerFacts::default())
            .unwrap();
        let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
        self.service
            .approve(&ticket.id, &self.approval(&ticket), &CallerFacts::default())
            .unwrap();
        let decision = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.service.wait(&ticket.id, key.public_key()))
            .unwrap();
        let Decision::Active { certificate, .. } = decision else {
            panic!("expected an active lease, got {decision:?}");
        };
        let cert = Certificate::from_openssh(&certificate).unwrap();
        let identity = CertIdentity {
            key_id: cert.key_id().to_owned(),
            serial: cert.serial(),
            session_key: cert
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
                .parse()
                .unwrap(),
        };
        (ticket.id, identity)
    }

    fn sign(
        &self,
        cert: &CertIdentity,
        commit: &Built,
        repo: &str,
    ) -> Result<SignedCommit, Denial> {
        self.service.sign(&signing(cert, commit, repo))
    }

    fn ledger(&self, lease: &TicketId) -> Vec<writ_store::LedgerEntry> {
        Store::open(&self.db)
            .unwrap()
            .ledger_for_lease(lease)
            .unwrap()
    }

    fn signatures(&self, lease: &TicketId) -> u32 {
        let now = writ_core::units::Timestamp::from_unix(i64::try_from(START).unwrap()).unwrap();
        Store::open(&self.db)
            .unwrap()
            .usage(lease, now)
            .unwrap()
            .signatures
    }
}

/// A commit with its evidence, as the gateway would have parsed it.
struct Built {
    commit: Commit,
    evidence: Vec<(ObjectType, Vec<u8>)>,
}

/// A commit on a one-file parent, changing `path`, by `email`, with `message`.
fn build(path: &str, email: &str, message: &str) -> Built {
    build_in(HashAlgo::Sha1, path, email, message)
}

/// The same, in a repository of object format `algo`.
fn build_in(algo: HashAlgo, path: &str, email: &str, message: &str) -> Built {
    let blob = |text: &str| algo.hash(ObjectType::Blob, text.as_bytes()).unwrap();
    // A tree from (name, mode, raw id) entries; paths with one `/` get a subtree.
    let tree = |entries: &[(&str, &str, Vec<u8>)]| {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let mut content = Vec::new();
        for (name, mode, raw) in sorted {
            content.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            content.extend(raw);
        }
        let id = algo.hash(ObjectType::Tree, &content).unwrap();
        (id, content)
    };
    let raw = |id: &writ_git::ObjectId| -> Vec<u8> {
        (0..id.as_str().len() / 2)
            .map(|i| u8::from_str_radix(&id.as_str()[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    let (old_tree, old_content) = tree(&[("README", "100644", raw(&blob("r")))]);
    let parent = format!(
        "tree {old_tree}\nauthor A <{EMAIL}> 1 +0000\ncommitter A <{EMAIL}> 1 +0000\n\nseed\n"
    );
    let parent_id = algo.hash(ObjectType::Commit, parent.as_bytes()).unwrap();
    let mut evidence = vec![
        (ObjectType::Commit, parent.into_bytes()),
        (ObjectType::Tree, old_content),
    ];
    let (dir, file) = path.split_once('/').unwrap();
    let (sub, sub_content) = tree(&[(file, "100644", raw(&blob("new")))]);
    let (new_tree, new_content) = tree(&[
        ("README", "100644", raw(&blob("r"))),
        (dir, "40000", raw(&sub)),
    ]);
    evidence.push((ObjectType::Tree, sub_content));
    evidence.push((ObjectType::Tree, new_content));
    let bytes = format!(
        "tree {new_tree}\nparent {parent_id}\nauthor A <{email}> 1 +0000\n\
         committer A <{email}> 1 +0000\n\n{message}"
    );
    Built {
        commit: Commit::parse(bytes.into_bytes()).unwrap(),
        evidence,
    }
}

/// What the gateway hands the service for `commit`.
fn signing(cert: &CertIdentity, built: &Built, repo: &str) -> Signing {
    let evidence = Evidence::new(built.commit.algo(), built.evidence.clone());
    Signing {
        cert: cert.clone(),
        caller: CallerFacts::default(),
        repo: repo.parse().unwrap(),
        format: writ_crypto::algorithm::SignatureFormat::Ssh,
        object: SignObject::Commit {
            commit: built.commit.clone(),
            touched_paths: touched(&built.commit, &evidence).ok(),
        },
    }
}

fn trailer(lease: &TicketId) -> String {
    format!("Change\n\nWrit: {lease}\n")
}

fn denied(result: Result<SignedCommit, Denial>, code: DenyCode, reason: &str) {
    match result {
        Err(denial) => {
            assert_eq!(denial.code, code, "{denial}");
            assert!(
                denial.to_string().contains(reason),
                "{reason:?} not in {denial}"
            );
        }
        Ok(signed) => panic!("expected a {code} denial, got a signature: {signed:?}"),
    }
}

#[test]
fn a_commit_is_signed_counted_and_recorded_as_git_writes_it() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let built = build("src/oauth.rs", EMAIL, &trailer(&lease));
    let signed = h.sign(&cert, &built, "omega-code").unwrap();
    assert!(signed.warnings.is_empty(), "{:?}", signed.warnings);
    // An SSHSIG by the template's key over the commit's bytes, in git's namespace.
    let key = h.signing_key("agent-ed25519-01");
    writ_crypto::sshsig::verify(&[key], "git", built.commit.bytes(), &signed.signature).unwrap();
    // The ledger holds the commit with its signature in it: the unsigned bytes (the same
    // commit pushed without the signature) have another id.
    let expected = writ_git::signed::signed_id(&built.commit, &signed.signature).unwrap();
    assert_eq!(signed.commit.as_str(), expected.as_str());
    let unsigned = HashAlgo::Sha1
        .hash(ObjectType::Commit, built.commit.bytes())
        .unwrap();
    assert_ne!(signed.commit.as_str(), unsigned.as_str());
    let ledger = h.ledger(&lease);
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].commit, signed.commit);
    assert_eq!(ledger[0].repo.as_str(), "omega-code");
    assert_eq!(ledger[0].key.as_str(), "agent-ed25519-01");
    assert_eq!(h.signatures(&lease), 1);
    let lines = h.events("sign", "allowed");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["commit"], signed.commit.as_str());
    assert_eq!(lines[0]["committer"], EMAIL);
    assert_eq!(lines[0]["repo"], "omega-code");
}

#[test]
fn only_what_the_lease_allows_is_signed() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let good = trailer(&lease);
    denied(
        h.sign(
            &cert,
            &build("src/a.rs", "me@personal.example", &good),
            "omega-code",
        ),
        DenyCode::Committer,
        "committer email \"me@personal.example\" not allowed",
    );
    denied(
        h.sign(&cert, &build("src/a.rs", EMAIL, "Change\n"), "omega-code"),
        DenyCode::TicketLink,
        &format!("repo omega-code needs a `Writ: {lease}` trailer"),
    );
    let other = "Change\n\nWrit: wrt_01JD8X0000000000000000000Z\n";
    denied(
        h.sign(&cert, &build("src/a.rs", EMAIL, other), "omega-code"),
        DenyCode::TicketLink,
        "exactly one",
    );
    let twice = format!("Change\n\nWrit: {lease}\nwrit: {lease}\n");
    denied(
        h.sign(&cert, &build("src/a.rs", EMAIL, &twice), "omega-code"),
        DenyCode::TicketLink,
        "exactly one",
    );
    denied(
        h.sign(&cert, &build("src/a.rs", EMAIL, &good), "dotfiles"),
        DenyCode::Repo,
        "repo dotfiles not allowed",
    );
    // `ledger_only`: no trailer needed there.
    h.sign(
        &cert,
        &build("src/a.rs", EMAIL, "Change\n"),
        "homelab-scripts",
    )
    .unwrap();
    // A tag (a violation), or anything else that isn't a commit (malformed, no violation):
    // refused after the lease checks.
    for (object, code, reason) in [
        (
            ObjectKind::Tag,
            DenyCode::ObjectType,
            "only commits are signed (no tags: releases stay a human act)",
        ),
        (
            ObjectKind::Other,
            DenyCode::Invalid,
            "only commits are signed: this is not a commit",
        ),
    ] {
        let mut request = signing(&cert, &build("src/a.rs", EMAIL, &good), "omega-code");
        request.object = SignObject::Other(object);
        denied(h.service.sign(&request), code, reason);
    }
    // A certificate no lease stands for.
    let mut stranger = cert.clone();
    stranger.serial += 1;
    denied(
        h.sign(&stranger, &build("src/a.rs", EMAIL, &good), "omega-code"),
        DenyCode::NoLease,
        "no lease matches this certificate",
    );
    assert_eq!(h.ledger(&lease).len(), 1, "only the ledger_only commit");
    assert_eq!(h.events("sign", "denied").len(), 8);
}

#[test]
fn paths_outside_the_ticket_warn_or_deny() {
    let h = Harness::new();
    let (feature, cert) = h.lease(FEATURE);
    let outside = build("docs/notes.md", EMAIL, &trailer(&feature));
    let signed = h.sign(&cert, &outside, "omega-code").unwrap();
    assert_eq!(
        signed.warnings,
        ["files outside expected_paths: docs/notes.md"]
    );
    assert_eq!(
        h.events("sign", "allowed")[0]["warnings"][0],
        "files outside expected_paths: docs/notes.md"
    );
    // Without the objects to compare, the paths are unknown: a warning too.
    let unknown = Signing {
        object: SignObject::Commit {
            commit: outside.commit.clone(),
            touched_paths: None,
        },
        ..signing(&cert, &outside, "omega-code")
    };
    assert_eq!(
        h.service.sign(&unknown).unwrap().warnings,
        ["paths not checked"]
    );

    let (fix, cert) = h.lease(QUICK_FIX);
    h.sign(
        &cert,
        &build("src/login.rs", EMAIL, &trailer(&fix)),
        "omega-code",
    )
    .unwrap();
    denied(
        h.sign(
            &cert,
            &build("docs/notes.md", EMAIL, &trailer(&fix)),
            "omega-code",
        ),
        DenyCode::Paths,
        "files outside expected_paths: docs/notes.md",
    );
    let unknown = Signing {
        object: SignObject::Commit {
            commit: build("src/login.rs", EMAIL, &trailer(&fix)).commit,
            touched_paths: None,
        },
        ..signing(
            &cert,
            &build("src/login.rs", EMAIL, &trailer(&fix)),
            "omega-code",
        )
    };
    denied(
        h.service.sign(&unknown),
        DenyCode::Paths,
        "the commit's paths could not be checked against expected_paths",
    );
}

#[test]
fn signatures_stop_at_the_count_and_the_rate() {
    let h = Harness::new();
    let few = FEATURE.to_owned() + "limits:\n  max_signatures: 2\n";
    let (lease, cert) = h.lease(&few);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    for _ in 0..2 {
        h.sign(&cert, &commit, "omega-code").unwrap();
    }
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Limit,
        &format!("lease {lease}: all 2 signatures used"),
    );
    assert_eq!(h.signatures(&lease), 2);

    // Three a minute: the fourth waits for the window to move.
    let slow = FEATURE.to_owned() + "limits:\n  max_ops_per_minute: 3\n";
    let (lease, cert) = h.lease(&slow);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    for _ in 0..3 {
        h.sign(&cert, &commit, "omega-code").unwrap();
    }
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Rate,
        "over 3 operations per minute",
    );
    h.clock.advance(60);
    h.sign(&cert, &commit, "omega-code").unwrap();
    assert_eq!(h.signatures(&lease), 4);
}

#[test]
fn the_sweep_prunes_operations_no_window_counts() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    for _ in 0..3 {
        h.sign(&cert, &commit, "omega-code").unwrap();
    }
    let rows = || Store::open(&h.db).unwrap().ops_rows().unwrap();
    let kept = writ_core::policy::RATE_WINDOW_SECONDS + writ_store::OPS_KEPT_PAST_WINDOW_SECONDS;
    h.clock.advance(u64::try_from(kept - 1).unwrap());
    h.service.sweep();
    assert_eq!(rows(), 3, "kept until past the margin");
    h.clock.advance(1);
    h.service.sweep();
    assert_eq!(rows(), 0, "pruned by the daemon's timer sweep");
    // The lease's counters are its own: pruning the rate's rows takes nothing back.
    assert_eq!(h.signatures(&lease), 3);
}

#[test]
fn an_expired_or_revoked_lease_signs_nothing() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    h.sign(&cert, &commit, "omega-code").unwrap();
    // feature-branch: 4h. One second before, it signs; at expires_at, it doesn't.
    h.clock.advance(4 * 3600 - 1);
    h.sign(&cert, &commit, "omega-code").unwrap();
    h.clock.advance(1);
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::NotActive,
        &format!("lease {lease} is expired"),
    );

    let (lease, cert) = h.lease(FEATURE);
    h.service
        .revoke(&lease, &h.revocation(&lease), &CallerFacts::default())
        .unwrap();
    denied(
        h.sign(
            &cert,
            &build("src/a.rs", EMAIL, &trailer(&lease)),
            "omega-code",
        ),
        DenyCode::NotActive,
        &format!("lease {lease} is revoked"),
    );
}

#[test]
fn a_failing_signer_or_audit_log_signs_nothing_and_keeps_the_slot() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    h.signer.set_failing(true);
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Invalid,
        "the signer failed (see the daemon's log)",
    );
    h.signer.set_failing(false);
    h.audit_breaker.set_broken(true);
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Invalid,
        "the audit log can't be written; nothing was done",
    );
    h.audit_breaker.set_broken(false);
    assert!(h.ledger(&lease).is_empty(), "nothing recorded");
    // The slots were taken before signing, and never given back: a failure can't be retried
    // past the limits.
    assert_eq!(h.signatures(&lease), 2, "both slots used");
    // Both refusals are logged (the second once the log works again).
    assert_eq!(h.events("sign", "denied").len(), 1);
    h.sign(&cert, &commit, "omega-code").unwrap();
    assert_eq!(h.events("sign", "denied").len(), 2);
    assert_eq!(h.ledger(&lease).len(), 1);
}

#[test]
fn a_violation_revokes_only_a_lease_that_asks_for_it() {
    let h = Harness::new();
    let wrong = |lease: &TicketId| build("src/a.rs", "me@personal.example", &trailer(lease));

    // The default (deny_and_notify): denied, the lease goes on.
    let (lease, cert) = h.lease(FEATURE);
    denied(
        h.sign(&cert, &wrong(&lease), "omega-code"),
        DenyCode::Committer,
        "not allowed",
    );
    assert!(!h.service.is_revoked(cert.serial));
    h.sign(
        &cert,
        &build("src/a.rs", EMAIL, &trailer(&lease)),
        "omega-code",
    )
    .unwrap();

    // revoke_lease: running out isn't a violation; a wrong committer is.
    let strict = FEATURE.to_owned() + "limits:\n  max_signatures: 1\non_violation: revoke_lease\n";
    let (lease, cert) = h.lease(&strict);
    let good = build("src/a.rs", EMAIL, &trailer(&lease));
    h.sign(&cert, &good, "omega-code").unwrap();
    denied(
        h.sign(&cert, &good, "omega-code"),
        DenyCode::Limit,
        "all 1 signatures used",
    );
    assert!(
        !h.service.is_revoked(cert.serial),
        "a limit is no violation"
    );
    let (lease, cert) = h.lease(&(FEATURE.to_owned() + "on_violation: revoke_lease\n"));
    denied(
        h.sign(&cert, &wrong(&lease), "omega-code"),
        DenyCode::Committer,
        "not allowed",
    );
    assert!(h.service.is_revoked(cert.serial));
    assert_eq!(h.service.show(&lease).unwrap().state, State::Revoked);
    let revoked = h.events("revoke", "done");
    assert_eq!(revoked.len(), 1);
    assert!(
        revoked[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("violation (committer): outside ticket"),
        "{}",
        revoked[0]
    );
}

#[test]
fn agent_text_stays_short_in_denials_warnings_and_the_log() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    // A committer email of a megabyte: refused, shown cut in the reason and the line.
    let huge = format!("{}@example.org", "x".repeat(1024 * 1024));
    let denial = h
        .sign(
            &cert,
            &build("src/a.rs", &huge, &trailer(&lease)),
            "omega-code",
        )
        .unwrap_err();
    assert_eq!(denial.code, DenyCode::Committer);
    assert!(
        denial.reason.contains(&format!("\"{}…\"", "x".repeat(256))),
        "{denial}"
    );
    assert!(
        denial.to_string().len() < 1024,
        "{} bytes",
        denial.to_string().len()
    );
    // A path of 4,000 bytes outside expected_paths (paths_check: warn): signed, the warning
    // shows it cut.
    let long = format!("docs/{}", "p".repeat(4000));
    let signed = h
        .sign(&cert, &build(&long, EMAIL, &trailer(&lease)), "omega-code")
        .unwrap();
    let shown: String = long.chars().take(256).collect();
    assert_eq!(
        signed.warnings,
        [format!("files outside expected_paths: {shown}…")]
    );
    for line in h
        .events("sign", "denied")
        .iter()
        .chain(&h.events("sign", "allowed"))
    {
        assert!(
            line.to_string().len() < 8 * 1024,
            "{} bytes",
            line.to_string().len()
        );
    }
}

#[test]
fn a_lease_that_cannot_sign_is_refused_before_its_request_is_read() {
    let h = Harness::new();
    let repo = |name: &str| name.parse::<writ_core::names::RepoName>().unwrap();
    let caller = CallerFacts::default();

    // A lease that signs for the repo passes without a line (Service::sign writes it).
    let (_, cert) = h.lease(FEATURE);
    h.service
        .may_sign(&cert, &caller, &repo("omega-code"))
        .unwrap();
    assert!(h.events("sign", "allowed").is_empty());
    assert!(h.events("sign", "denied").is_empty());

    // Another repo, a lease without commit_sign, a revoked lease: refused and logged.
    let refused = |cert: &CertIdentity, name: &str, code: DenyCode, reason: &str| {
        let denial = h.service.may_sign(cert, &caller, &repo(name)).unwrap_err();
        assert_eq!(denial.code, code, "{denial}");
        assert!(
            denial.to_string().contains(reason),
            "{reason:?} not in {denial}"
        );
    };
    refused(
        &cert,
        "dotfiles",
        DenyCode::Repo,
        "repo dotfiles not allowed",
    );
    let fetch_only = FEATURE.replace("[fetch, commit_sign, push]", "[fetch]");
    let (_, reader) = h.lease(&fetch_only);
    refused(
        &reader,
        "omega-code",
        DenyCode::Operation,
        "commit_sign not allowed",
    );
    let (lease, ended) = h.lease(FEATURE);
    h.service
        .revoke(&lease, &h.revocation(&lease), &caller)
        .unwrap();
    refused(&ended, "omega-code", DenyCode::NotActive, "is revoked");
    let lines = h.events("sign", "denied");
    let codes: Vec<&str> = lines.iter().map(|l| l["code"].as_str().unwrap()).collect();
    assert_eq!(codes, ["repo", "operation", "not_active"]);

    // A violation found here revokes a lease that asks for it.
    let (lease, strict) = h.lease(&(FEATURE.to_owned() + "on_violation: revoke_lease\n"));
    refused(&strict, "dotfiles", DenyCode::Repo, "not allowed");
    assert!(h.service.is_revoked(strict.serial));
    assert_eq!(h.service.show(&lease).unwrap().state, State::Revoked);
}

#[test]
fn a_violation_bars_the_certificate_even_when_its_revocation_fails() {
    // The M3 review's F4: the deny list comes before the lock is released and before the
    // revocation is recorded. Here recording it fails (its lease lookup): the certificate is
    // refused all the same, and the next request of the lease with it; the revocation is
    // recorded by the next sweep.
    let h = Harness::new();
    let (lease, cert) = h.lease(&(FEATURE.to_owned() + "on_violation: revoke_lease\n"));
    // Service::sign looks the lease up once; the revocation's lookup fails.
    h.store_breaker.fail_lease_lookup_after(1);
    denied(
        h.sign(
            &cert,
            &build("src/a.rs", "me@personal.example", &trailer(&lease)),
            "omega-code",
        ),
        DenyCode::Committer,
        "not allowed",
    );
    assert!(h.service.is_revoked(cert.serial), "on the deny list");
    // Not lost: the next request's sweep records it (the review after M5.5, L2).
    assert_eq!(
        h.service.show(&lease).unwrap().state,
        State::Revoked,
        "the revocation is recorded at the next request"
    );
    denied(
        h.sign(
            &cert,
            &build("src/a.rs", EMAIL, &trailer(&lease)),
            "omega-code",
        ),
        DenyCode::NotActive,
        &format!("lease {lease} is revoked"),
    );
    assert!(h.ledger(&lease).is_empty());
}

#[test]
fn a_lease_s_denials_are_counted_past_sixty_lines_a_minute() {
    // Q34: a lease holder sending requests it knows are refused can't grow the log faster
    // than 60 denial lines a minute; the rest are counted, and the count logged.
    let h = Harness::new();
    let caller = CallerFacts::default();
    let outside: writ_core::names::RepoName = "dotfiles".parse().unwrap();
    let (lease, cert) = h.lease(FEATURE);
    let (other, other_cert) = h.lease(FEATURE);
    let lines_of = |id: &TicketId| {
        h.events("sign", "denied")
            .into_iter()
            .filter(|l| l["lease"] == id.as_str())
            .collect::<Vec<_>>()
    };
    for _ in 0..60 {
        let denial = h.service.may_sign(&cert, &caller, &outside).unwrap_err();
        assert_eq!(denial.code, DenyCode::Repo);
    }
    assert_eq!(
        lines_of(&lease).len(),
        60,
        "every one of the first 60 is a line"
    );
    // Past the budget: still denied, counted, no line; another lease is unaffected; an
    // allowed signature is never held back.
    for _ in 0..5 {
        let denial = h.service.may_sign(&cert, &caller, &outside).unwrap_err();
        assert_eq!(denial.code, DenyCode::Repo);
    }
    assert_eq!(lines_of(&lease).len(), 60);
    h.service
        .may_sign(&other_cert, &caller, &outside)
        .unwrap_err();
    assert_eq!(lines_of(&other).len(), 1);
    h.sign(
        &cert,
        &build("src/a.rs", EMAIL, &trailer(&lease)),
        "omega-code",
    )
    .unwrap();
    assert_eq!(h.events("sign", "allowed").len(), 1);
    // One second short of the window, still counted; at the window, the count is written by
    // the next sweep (here, any call), then lines resume.
    h.clock.advance(59);
    h.service.may_sign(&cert, &caller, &outside).unwrap_err();
    assert_eq!(lines_of(&lease).len(), 60);
    h.clock.advance(1);
    h.service.list(false).unwrap();
    let lines = lines_of(&lease);
    assert_eq!(lines.len(), 61);
    let reason = lines[60]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("6 more denials of this lease since"),
        "{reason}"
    );
    h.service.may_sign(&cert, &caller, &outside).unwrap_err();
    assert_eq!(lines_of(&lease).len(), 62);
}

#[test]
fn a_lease_s_connections_are_counted_past_sixty_lines_a_minute() {
    // M3.6 review's S2: a lease holder looping `ssh` can't grow the log faster than 60
    // allowed connect lines a minute; the rest are counted, and the count logged. Each
    // connection is still allowed.
    let h = Harness::new();
    let caller = CallerFacts::default();
    let (lease, cert) = h.lease(FEATURE);
    let (other, other_cert) = h.lease(FEATURE);
    let lines_of = |id: &TicketId| {
        h.events("connect", "allowed")
            .into_iter()
            .filter(|l| l["lease"] == id.as_str())
            .collect::<Vec<_>>()
    };
    for _ in 0..60 {
        h.service.authorize(&cert, &caller, None).unwrap();
    }
    assert_eq!(
        lines_of(&lease).len(),
        60,
        "every one of the first 60 is a line"
    );
    for _ in 0..5 {
        assert!(
            h.service.authorize(&cert, &caller, None).is_ok(),
            "past the budget, still allowed"
        );
    }
    assert_eq!(lines_of(&lease).len(), 60);
    // Another lease, a denial, a command's own line: unaffected.
    h.service.authorize(&other_cert, &caller, None).unwrap();
    assert_eq!(lines_of(&other).len(), 1);
    let outside: writ_core::names::RepoName = "dotfiles".parse().unwrap();
    h.service.may_sign(&cert, &caller, &outside).unwrap_err();
    assert_eq!(h.events("sign", "denied").len(), 1);
    // One second short of the window, still counted; at the window, the count is written by
    // the next sweep (here, any call), then lines resume.
    h.clock.advance(59);
    h.service.authorize(&cert, &caller, None).unwrap();
    assert_eq!(lines_of(&lease).len(), 60);
    h.clock.advance(1);
    h.service.list(false).unwrap();
    let lines = lines_of(&lease);
    assert_eq!(lines.len(), 61);
    let reason = lines[60]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("6 more connections of this lease since"),
        "{reason}"
    );
    h.service.authorize(&cert, &caller, None).unwrap();
    assert_eq!(lines_of(&lease).len(), 62);
}

#[test]
fn a_template_whose_key_the_signer_lacks_keeps_the_daemon_sealed() {
    use writ_approval::testing::TestServiceBuilder;
    use writ_approval::{Opened, RefusalCode, ServiceError};
    let dir = tempfile::tempdir().unwrap();
    let h = TestServiceBuilder::new(POLICY).sealed().build(dir.path());
    let opened = |signer: writ_signer::software::SoftwareSigner| Opened {
        signer: Arc::new(signer),
        ..h.opened()
    };
    let caller = writ_core::caller::CallerFacts::default();
    let other = writ_signer::testing::software_signer(&["another-key"], KeyKind::Ed25519);
    match h.service.unseal(opened(other), None, &caller) {
        Err(error @ ServiceError::Refused { .. }) => {
            assert_eq!(error.code(), Some(RefusalCode::Unseal));
            assert_eq!(
                error.to_string(),
                "invalid configuration: template feature-branch signs with key \
                 agent-ed25519-01, which the signer doesn't hold"
            );
        }
        Err(other) => panic!("expected a refused unseal, got {other}"),
        Ok(()) => panic!("unsealed without the template's signing key"),
    }
    assert!(h.service.is_sealed());
    let held = writ_signer::testing::software_signer(&["agent-ed25519-01"], KeyKind::P256);
    h.service.unseal(opened(held), None, &caller).unwrap();
    assert!(!h.service.is_sealed());
}

#[test]
fn a_commit_is_signed_only_in_its_repo_s_object_format() {
    // omega-code is a SHA-256 repository; homelab-scripts keeps the default, SHA-1.
    let policy = POLICY.replacen(
        "    ticket_link: trailer\n",
        "    ticket_link: trailer\n    object_format: sha256\n",
        1,
    );
    assert_ne!(policy, POLICY, "the fixture changed");
    let h = Harness::with_policy(&policy);
    let (lease, cert) = h.lease(FEATURE);
    let message = trailer(&lease);
    denied(
        h.sign(&cert, &build("src/a.rs", EMAIL, &message), "omega-code"),
        DenyCode::ObjectFormat,
        "repo omega-code is sha256 (object_format in the registry), the commit is sha1",
    );
    let sha256 = build_in(HashAlgo::Sha256, "src/a.rs", EMAIL, &message);
    let signed = h.sign(&cert, &sha256, "omega-code").unwrap();
    assert_eq!(signed.commit.as_str().len(), 64);
    let expected = writ_git::signed::signed_id(&sha256.commit, &signed.signature).unwrap();
    assert_eq!(signed.commit.as_str(), expected.as_str());
    denied(
        h.sign(&cert, &sha256, "homelab-scripts"),
        DenyCode::ObjectFormat,
        "repo homelab-scripts is sha1 (object_format in the registry), the commit is sha256",
    );
    h.sign(
        &cert,
        &build("src/a.rs", EMAIL, "Change\n"),
        "homelab-scripts",
    )
    .unwrap();
}

/// How long a test waits for the service to answer while a signature is held at the gate:
/// a bound on a hang (the call waiting behind the signer), never a pause.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// Runs `f` on its own thread and returns its result, failing if it doesn't come back in
/// time: what must answer while a signature is in flight can't hang the test instead.
fn answers<T: Send>(what: &str, f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();
        scope.spawn(move || tx.send(f()).unwrap());
        rx.recv_timeout(PATIENCE)
            .unwrap_or_else(|_| panic!("{what} waited behind the signer"))
    })
}

/// A signed admin change replacing `target` (as in force now) by `text`, put in force.
fn apply_admin(h: &Harness, target: writ_core::authority::AdminTarget, text: &str) -> u64 {
    use writ_approval::AdminParsed;
    use writ_core::authority::{AdminTarget, AdminText};
    use writ_core::config::PolicyConfig;
    use writ_core::signed::{Admin, Replaced};
    let shown = h.service.admin_show(target).unwrap();
    let document = Admin::new(
        shown.daemon.clone(),
        target,
        Replaced {
            version: shown.version,
            digest: shown.digest.clone(),
        },
        AdminText::try_from(text.to_owned()).unwrap(),
    )
    .canonical_bytes()
    .unwrap();
    let request = writ_proto::AdminRequest {
        signature: writ_crypto::sshsig::sign(
            &h.approver,
            writ_core::lease::APPROVAL_NAMESPACE,
            &document,
        )
        .unwrap(),
        document: String::from_utf8(document).unwrap(),
    };
    let checked = h
        .service
        .check_admin(&request, &CallerFacts::default())
        .unwrap();
    assert_eq!(target, AdminTarget::Policy, "a policy change only, here");
    h.service
        .commit_admin(
            &checked,
            AdminParsed::Policy(PolicyConfig::from_yaml(text).unwrap()),
            vec![],
            Default::default(),
            &CallerFacts::default(),
        )
        .unwrap()
        .version
}

#[test]
fn a_revocation_completes_while_a_signature_is_in_flight() {
    // M3.5: the signer runs outside the state lock. While it is stuck, the service answers;
    // a revocation that completes meanwhile discards the signature when it comes back.
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &commit, "omega-code"));
        h.signer.wait_entered();

        // Approvals, `writ wait` and `writ ls` answer meanwhile (submit, approve, wait).
        let (other, _) = answers("an approval and its wait", || h.lease(FEATURE));
        let listing = answers("a listing", || h.service.list(false).unwrap());
        assert!(listing.tickets.iter().any(|t| t.id == other));
        answers("a revocation", || {
            h.service
                .revoke(&lease, &h.revocation(&lease), &CallerFacts::default())
                .unwrap()
        });
        assert!(h.service.is_revoked(cert.serial));

        closed.open();
        denied(
            in_flight.join().unwrap(),
            DenyCode::NotActive,
            &format!(
                "lease {lease} is revoked (while the commit was being signed); \
                 the signature was discarded"
            ),
        );
    });
    assert!(h.ledger(&lease).is_empty(), "nothing recorded");
    assert_eq!(h.signatures(&lease), 1, "its slot stays used");
    assert!(h.events("sign", "allowed").is_empty());
    let denied_lines = h.events("sign", "denied");
    assert_eq!(denied_lines.len(), 1, "one line for the call");
    assert_eq!(denied_lines[0]["code"], "not_active");
}

#[test]
fn a_lease_that_expires_while_signing_discards_the_signature() {
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &commit, "omega-code"));
        h.signer.wait_entered();
        // feature-branch: 4h. Its expiry comes while the backend signs.
        h.clock.advance(4 * 3600);
        closed.open();
        denied(
            in_flight.join().unwrap(),
            DenyCode::Expired,
            &format!(
                "lease {lease} has expired (while the commit was being signed); \
                 the signature was discarded"
            ),
        );
    });
    assert!(h.ledger(&lease).is_empty());
    assert_eq!(h.service.show(&lease).unwrap().state, State::Expired);
}

#[test]
fn a_violation_while_a_signature_is_in_flight_discards_it() {
    // The M3 review's F4 with M3.5's phases: a violation bars the certificate before the
    // lock is released, and the last phase checks the deny list, not only the store. Here
    // recording the revocation fails: the store still says active when the signature in
    // flight settles (the last phase doesn't sweep), and it is refused all the same.
    let h = Harness::new();
    let (lease, cert) = h.lease(&(FEATURE.to_owned() + "on_violation: revoke_lease\n"));
    let good = build("src/a.rs", EMAIL, &trailer(&lease));
    let wrong = build("src/b.rs", "me@personal.example", &trailer(&lease));
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &good, "omega-code"));
        h.signer.wait_entered();
        // The violation looks the lease up once; the revocation's lookup fails.
        h.store_breaker.fail_lease_lookup_after(1);
        denied(
            answers("a violation", || h.sign(&cert, &wrong, "omega-code")),
            DenyCode::Committer,
            "not allowed",
        );
        assert!(h.service.is_revoked(cert.serial), "on the deny list");
        closed.open();
        denied(
            in_flight.join().unwrap(),
            DenyCode::NotActive,
            &format!("lease {lease} is revoked (while the commit was being signed)"),
        );
    });
    assert!(h.ledger(&lease).is_empty());
    // The revocation the store couldn't record is recorded by the next sweep, which every
    // request runs first (the review after M5.5, L2): kept only in memory, a restart would
    // have brought the lease back.
    assert_eq!(h.service.show(&lease).unwrap().state, State::Revoked);
    let revoked = h.events("revoke", "done");
    assert!(
        revoked
            .iter()
            .any(|e| e["lease"] == lease.as_str() && e["reason"].as_str().is_some()),
        "{revoked:?}"
    );
    // Recorded once: a later sweep has nothing left to do.
    let lines = h.events("revoke", "done").len();
    h.service.sweep();
    assert_eq!(h.events("revoke", "done").len(), lines);
}

#[test]
fn the_last_signature_in_flight_is_not_refused_as_used_up() {
    // Its slot makes the lease used up as soon as it is taken: the sweep waits until the
    // signature is settled, so the signature's own last check doesn't refuse it.
    let h = Harness::new();
    let only_sign = FEATURE.replace("[fetch, commit_sign, push]", "[commit_sign]")
        + "limits:\n  max_signatures: 1\n";
    let (lease, cert) = h.lease(&only_sign);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &commit, "omega-code"));
        h.signer.wait_entered();
        answers("the daemon's sweep", || h.service.sweep());
        assert_eq!(h.service.show(&lease).unwrap().state, State::Active);
        denied(
            answers("a second signature", || {
                h.sign(&cert, &commit, "omega-code")
            }),
            DenyCode::Exhausted,
            &format!("lease {lease} is used up"),
        );
        closed.open();
        in_flight.join().unwrap().unwrap();
    });
    assert_eq!(h.ledger(&lease).len(), 1);
    assert_eq!(h.service.show(&lease).unwrap().state, State::Exhausted);
    assert!(h.service.is_revoked(cert.serial));

    // A failed last signature keeps its slot too: the lease is used up once it is settled.
    let (lease, cert) = h.lease(&only_sign);
    h.signer.set_failing(true);
    denied(
        h.sign(
            &cert,
            &build("src/a.rs", EMAIL, &trailer(&lease)),
            "omega-code",
        ),
        DenyCode::Invalid,
        "the signer failed",
    );
    assert_eq!(h.service.show(&lease).unwrap().state, State::Exhausted);
    assert!(h.service.is_revoked(cert.serial));
}

#[test]
fn a_busy_or_late_signer_is_refused_with_its_reason() {
    use writ_signer::SignerError;
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    h.signer.fail_with(|_| SignerError::Busy);
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Invalid,
        "the signer is busy; retry shortly",
    );
    h.signer.fail_with(|id| SignerError::Timeout(id.clone()));
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Invalid,
        "the signer did not sign in time (see the daemon's log)",
    );
    h.signer.fail_with(|_| SignerError::Unavailable);
    denied(
        h.sign(&cert, &commit, "omega-code"),
        DenyCode::Invalid,
        "the signer failed (see the daemon's log)",
    );
    h.signer.set_failing(false);
    assert_eq!(h.signatures(&lease), 3, "each one used its slot");
    assert!(h.ledger(&lease).is_empty());
    h.sign(&cert, &commit, "omega-code").unwrap();
}

#[test]
fn a_lease_amended_while_signing_discards_the_signature() {
    // The decision was made on the terms in force when the signature started: new terms
    // (an amendment approved meanwhile) discard it, whatever they say.
    let h = Harness::new();
    let key = generate(KeyKind::Ed25519).unwrap();
    let (lease, cert) = h.lease_with(&key, FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &commit, "omega-code"));
        h.signer.wait_entered();
        let amendment =
            FEATURE.to_owned() + &format!("  amends: {lease}\nlimits:\n  max_signatures: 5\n");
        let submitted = h
            .service
            .submit(
                key.public_key(),
                amendment.as_bytes(),
                &CallerFacts::default(),
            )
            .unwrap();
        let amendment = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
        answers("an amendment's approval", || {
            h.service
                .approve(
                    &amendment.id,
                    &h.approval(&amendment),
                    &CallerFacts::default(),
                )
                .unwrap()
        });
        closed.open();
        denied(
            in_flight.join().unwrap(),
            DenyCode::NotActive,
            &format!(
                "lease {lease}: its terms changed while the commit was being signed; \
                 the signature was discarded"
            ),
        );
    });
    assert!(h.ledger(&lease).is_empty());
}

#[test]
fn a_push_s_paths_are_walked_only_for_commits_this_lease_signed_here_with_their_paths() {
    let h = Harness::new();
    let (lease, _) = h.lease(FEATURE);
    let (other_lease, _) = h.lease(FEATURE);
    let id = |c: char| -> writ_core::names::CommitId { c.to_string().repeat(40).parse().unwrap() };
    let entry =
        |commit: char, lease: &TicketId, repo: &str, paths: Option<&str>| writ_store::LedgerEntry {
            commit: id(commit),
            lease: lease.clone(),
            repo: repo.parse().unwrap(),
            key: "agent-ed25519-01".parse().unwrap(),
            signed_at: writ_core::units::Timestamp::from_unix(i64::try_from(START).unwrap())
                .unwrap(),
            paths_digest: paths.map(str::to_owned),
        };
    let store = Store::open(&h.db).unwrap();
    for e in [
        entry('a', &lease, "omega-code", Some("digest")),
        entry('b', &lease, "omega-code", None),
        entry('c', &other_lease, "omega-code", Some("digest")),
        entry('d', &lease, "homelab-scripts", Some("digest")),
    ] {
        store.ledger_append(&e).unwrap();
    }
    let commits: Vec<_> = "abcde".chars().map(id).collect();
    let to_check = h
        .service
        .paths_to_check(&lease, &"omega-code".parse().unwrap(), &commits)
        .unwrap();
    // Only `a`: `b`'s paths were unknown at signing (nothing to compare), `c` is another
    // lease's, `d` another repo's, `e` signed by nobody (all three refused whatever their
    // paths).
    assert_eq!(to_check, std::collections::BTreeSet::from([id('a')]));
    // Nothing logged: a read.
    assert!(h.events("push", "allowed").is_empty());
    assert!(h.events("push", "denied").is_empty());
}

/// What the real `gpg` says about `signature` over `data`, the certificate `cert` imported
/// into a throwaway `GNUPGHOME` (never the user's own). The test clock runs in 2027: gpg is
/// told to ignore a key or signature from its future.
fn gpg_verify(cert: &str, data: &[u8], signature: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("gnupg");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::write(dir.path().join("cert.asc"), cert).unwrap();
    std::fs::write(dir.path().join("data"), data).unwrap();
    std::fs::write(dir.path().join("sig.asc"), signature).unwrap();
    let gpg = |args: &[&str]| {
        std::process::Command::new("gpg")
            .args(["--batch", "--no-tty", "--ignore-time-conflict", "--homedir"])
            .arg(&home)
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap()
    };
    let imported = gpg(&["--import", "cert.asc"]);
    assert!(imported.status.success(), "{imported:?}");
    let out = gpg(&["--status-fd", "1", "--verify", "sig.asc", "data"]);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn an_openpgp_lease_signs_in_openpgp_only_and_gpg_verifies_its_commits() {
    use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat};
    for (algorithm, hash) in [
        (KeyAlgorithm::Ed25519, Hash::Sha512),
        (KeyAlgorithm::P256, Hash::Sha256),
        (KeyAlgorithm::Rsa3072, Hash::Sha384),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let policy = format!(
            "{POLICY}\nsigning_keys:\n  agent-ed25519-01:\n    uids: [\"Agent <{EMAIL}>\"]\n"
        );
        let test = TestServiceBuilder::new(&policy)
            .clock(Arc::new(FakeClock::at_unix(START)))
            .openpgp(algorithm, hash)
            .build(dir.path());
        let h = Harness {
            _dir: dir,
            test,
            clock: Arc::new(FakeClock::at_unix(START)),
            db: std::path::PathBuf::new(),
        };
        let key = generate(KeyKind::Ed25519).unwrap();
        let (lease, cert) = h.lease_with(&key, FEATURE);
        // The grant carries the certificate, with the policy's user id.
        let decision = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(h.service.wait(&lease, key.public_key()))
            .unwrap();
        let Decision::Active {
            signing_certificate: Some(certificate),
            ..
        } = decision
        else {
            panic!("{algorithm}: no certificate in {decision:?}");
        };
        assert!(certificate.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));

        // git asked for an SSH signature: denied, logged, nothing signed and no slot used.
        let commit = build("src/a.rs", EMAIL, &trailer(&lease));
        let ssh = h.service.sign(&signing(&cert, &commit, "omega-code"));
        denied(
            ssh,
            DenyCode::SignatureFormat,
            "signs in openpgp, and git asked for ssh",
        );
        let audit = std::fs::read_to_string(&h.audit_path).unwrap();
        let line = audit
            .lines()
            .rev()
            .find(|l| l.contains("\"event\":\"sign\""))
            .unwrap();
        assert!(line.contains("\"code\":\"signature_format\""), "{line}");

        // In OpenPGP: signed, and the real gpg verifies it with the lease's certificate.
        let mut openpgp = signing(&cert, &commit, "omega-code");
        openpgp.format = SignatureFormat::Openpgp;
        let signed = h.service.sign(&openpgp).unwrap();
        assert!(
            signed
                .signature
                .starts_with("-----BEGIN PGP SIGNATURE-----\n\n"),
            "{}",
            signed.signature
        );
        let status = gpg_verify(&certificate, commit.commit.bytes(), &signed.signature);
        assert!(
            status.contains("[GNUPG:] VALIDSIG "),
            "{algorithm}: {status}"
        );
        assert!(
            status.contains("[GNUPG:] GOODSIG ") && status.contains(EMAIL),
            "{algorithm}: {status}"
        );
        // The ledger holds the commit git writes with this signature in it.
        assert_eq!(
            signed.commit,
            writ_git::signed::signed_id(&commit.commit, &signed.signature)
                .unwrap()
                .to_commit_id()
                .unwrap()
        );
    }
}

#[test]
fn a_policy_change_and_a_revocation_complete_while_an_openpgp_signature_is_in_flight() {
    // The review after M5.5 (S5): an OpenPGP signature held the lock on the OpenPGP keys
    // while the signer ran, and an admin change of the policy, which replaces those keys
    // under the state lock, waited for it, holding every revocation and approval behind it.
    use writ_core::authority::AdminTarget;
    use writ_crypto::algorithm::{Hash, KeyAlgorithm, SignatureFormat};
    let dir = tempfile::tempdir().unwrap();
    let policy =
        format!("{POLICY}\nsigning_keys:\n  agent-ed25519-01:\n    uids: [\"Agent <{EMAIL}>\"]\n");
    let test = TestServiceBuilder::new(&policy)
        .clock(Arc::new(FakeClock::at_unix(START)))
        .openpgp(KeyAlgorithm::Ed25519, Hash::Sha512)
        .build(dir.path());
    let h = Harness {
        _dir: dir,
        test,
        clock: Arc::new(FakeClock::at_unix(START)),
        db: std::path::PathBuf::new(),
    };
    let (lease, cert) = h.lease(FEATURE);
    let (other, _) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let mut openpgp = signing(&cert, &commit, "omega-code");
    openpgp.format = SignatureFormat::Openpgp;

    let shown = h.service.admin_show(AdminTarget::Policy).unwrap();
    let text = format!("{}# changed while a signature was in flight\n", shown.text);
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.service.sign(&openpgp));
        let held = h.signer.wait_entered();
        // Only the commit's signature is held: the policy change certifies the OpenPGP
        // user ids with the signer too, and those go through.
        let signer = Arc::downgrade(&h.signer);
        h.signer.on_enter(Box::new(move |call| {
            if call != held
                && let Some(signer) = signer.upgrade()
            {
                signer.release(call);
            }
        }));
        let applied = answers("a policy change", || {
            apply_admin(&h, AdminTarget::Policy, &text)
        });
        assert_eq!(applied, shown.version + 1);
        answers("a revocation", || {
            h.service
                .revoke(&other, &h.revocation(&other), &CallerFacts::default())
                .unwrap()
        });
        closed.open();
        // The signature in flight still completes: the key it signs with didn't change.
        let signed = in_flight.join().unwrap().unwrap();
        assert!(
            signed
                .signature
                .starts_with("-----BEGIN PGP SIGNATURE-----\n\n"),
            "{}",
            signed.signature
        );
    });
    assert_eq!(h.service.show(&other).unwrap().state, State::Revoked);
}

#[test]
fn a_template_tightened_while_signing_discards_the_signature() {
    // The review after M5.5 (L3): the last phase checked the lease's state, not the policy;
    // a template tightened below the lease by a signed change while the backend signed still
    // handed the signature out.
    use writ_core::authority::AdminTarget;
    let h = Harness::new();
    let (lease, cert) = h.lease(FEATURE);
    let commit = build("src/a.rs", EMAIL, &trailer(&lease));
    let shown = h.service.admin_show(AdminTarget::Policy).unwrap();
    let tight = shown
        .text
        .replacen("max_signatures: 50", "max_signatures: 1", 1);
    assert_ne!(tight, shown.text, "the fixture changed");
    let closed = h.signer.close();
    std::thread::scope(|scope| {
        let in_flight = scope.spawn(|| h.sign(&cert, &commit, "omega-code"));
        h.signer.wait_entered();
        answers("a policy change", || {
            apply_admin(&h, AdminTarget::Policy, &tight)
        });
        closed.open();
        denied(
            in_flight.join().unwrap(),
            DenyCode::Config,
            &format!("lease {lease} no longer fits template feature-branch: "),
        );
    });
    assert!(h.ledger(&lease).is_empty(), "nothing recorded");
    let lines = h.events("sign", "denied");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["code"], "config");
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .ends_with("(changed while the commit was being signed); the signature was discarded"),
        "{}",
        lines[0]
    );
}

/// A push of `commit` (its paths' digest as git would compute it again) to a new branch,
/// under the lease of `cert`.
fn pushing(
    cert: &CertIdentity,
    commit: &writ_core::names::CommitId,
    paths: Option<String>,
) -> writ_approval::Pushing {
    writ_approval::Pushing {
        cert: cert.clone(),
        caller: CallerFacts::default(),
        repo: "omega-code".parse().unwrap(),
        updates: vec![writ_core::policy::RefUpdate {
            name: "refs/heads/agent/oauth-login".to_owned(),
            old: None,
            new: Some(commit.clone()),
            fast_forward: true,
            case_twin: false,
        }],
        commits: vec![(commit.clone(), paths)],
        pack_size: 100,
    }
}

#[test]
fn a_renewal_ends_its_lease_and_pushes_what_that_lease_signed() {
    let h = Harness::new();
    let key = generate(KeyKind::Ed25519).unwrap();
    let (first, first_cert) = h.lease_with(&key, FEATURE);
    let ours = h
        .sign(
            &first_cert,
            &build("src/a.rs", EMAIL, &trailer(&first)),
            "omega-code",
        )
        .unwrap();
    let (other, other_cert) = h.lease(FEATURE);
    let theirs = h
        .sign(
            &other_cert,
            &build("src/b.rs", EMAIL, &trailer(&other)),
            "omega-code",
        )
        .unwrap();
    // The lease runs out with its commit signed and not pushed.
    h.clock.advance(4 * 3600);
    h.service.sweep();
    let renewal = format!("{FEATURE}  renews: {first}\n");
    let (second, second_cert) = h.lease_with(&key, &renewal);
    assert_ne!(second, first, "a lease of its own");
    assert_eq!(
        second_cert.session_key, first_cert.session_key,
        "for the same key"
    );
    let store = Store::open(&h.db).unwrap();
    assert_eq!(store.lease(&first).unwrap().unwrap().state, State::Renewed);
    assert!(h.service.is_revoked(first_cert.serial));
    assert!(!h.service.is_revoked(second_cert.serial));
    // The renewal pushes what the lease it renews signed.
    let digest = |lease: &TicketId| h.ledger(lease)[0].paths_digest.clone();
    h.service
        .push(&pushing(&second_cert, &ours.commit, digest(&first)))
        .unwrap();
    // Not another lease's commit, nor through the renewed lease's certificate.
    let refused = h
        .service
        .push(&pushing(&second_cert, &theirs.commit, digest(&other)))
        .unwrap_err();
    assert_eq!(refused.code, DenyCode::Unsigned, "{refused}");
    let ended = h
        .service
        .push(&pushing(&first_cert, &ours.commit, digest(&first)))
        .unwrap_err();
    assert_eq!(ended.code, DenyCode::NotActive, "{ended}");
    assert!(ended.to_string().contains("is renewed"), "{ended}");
    // Renewed once: another renewal of it is refused.
    let again = h
        .service
        .submit(
            key.public_key(),
            renewal.as_bytes(),
            &CallerFacts::default(),
        )
        .unwrap_err();
    assert_eq!(again.code(), Some(writ_approval::RefusalCode::Rejected));
    assert!(
        again.reason_text().contains("it was renewed already"),
        "{}",
        again.reason_text()
    );
    // Logged: the grant names the lease it renews, the renewed lease's end has its line.
    let grants = h.events("grant", "allowed");
    let grant = grants
        .iter()
        .find(|l| l["lease"] == second.as_str())
        .unwrap();
    assert_eq!(grant["reason"], format!("renews lease {first}"));
    let renewed = h.events("renew", "done");
    assert_eq!(renewed.len(), 1);
    assert_eq!(renewed[0]["lease"], first.as_str());
    assert_eq!(renewed[0]["cert"], first_cert.serial);
}

#[test]
fn a_renewal_is_refused_past_its_grace_or_from_another_session() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::at_unix(START));
    let test = TestServiceBuilder::new(POLICY)
        .clock(clock.clone())
        .renew_grace(writ_core::units::Duration::from_seconds(60))
        .build(dir.path());
    let h = Harness {
        _dir: dir,
        db: std::path::PathBuf::new(),
        test,
        clock,
    };
    let key = generate(KeyKind::Ed25519).unwrap();
    let (first, _) = h.lease_with(&key, FEATURE);
    let renewal = format!("{FEATURE}  renews: {first}\n");
    let submit = |key: &PrivateKey| {
        h.service.submit(
            key.public_key(),
            renewal.as_bytes(),
            &CallerFacts::default(),
        )
    };
    let reasons = |result: Result<writ_proto::Submitted, writ_approval::ServiceError>| match result
    {
        Err(writ_approval::ServiceError::Refused { code, reasons, .. }) => {
            assert_eq!(code, writ_approval::RefusalCode::Rejected);
            reasons.join("; ")
        }
        other => panic!("expected a rejection, got {other:?}"),
    };
    // Another session: the lease doesn't exist for it.
    let stranger = generate(KeyKind::Ed25519).unwrap();
    assert!(
        reasons(submit(&stranger)).contains(&format!("ticket {first} (renews) does not exist"))
    );
    // Expired 59 seconds ago: taken (withdrawn again); 60: refused.
    h.clock.advance(4 * 3600 + 59);
    let taken = submit(&key).unwrap();
    h.service
        .revoke(&taken.id, &h.revocation(&taken.id), &CallerFacts::default())
        .unwrap();
    h.clock.advance(1);
    assert!(reasons(submit(&key)).contains("more than renew_grace (1m) ago"));
}

#[test]
fn the_report_matches_the_audit_log_phase_by_phase() {
    let h = Harness::new();
    let key = generate(KeyKind::Ed25519).unwrap();
    let (lease, cert) = h.lease_with(&key, FEATURE);
    let digest = |n: usize| h.ledger(&lease)[n].paths_digest.clone();
    // Coding: five minutes to the first commit (outside expected_paths: a warning).
    h.clock.advance(300);
    let first = h
        .sign(
            &cert,
            &build("docs/a.md", EMAIL, &trailer(&lease)),
            "omega-code",
        )
        .unwrap();
    h.clock.advance(300);
    h.service
        .push(&pushing(&cert, &first.commit, digest(0)))
        .unwrap();
    // A CI round: twenty minutes from the push to the fix.
    h.clock.advance(1200);
    let second = h
        .sign(
            &cert,
            &build("src/b.rs", EMAIL, &trailer(&lease)),
            "omega-code",
        )
        .unwrap();
    h.clock.advance(200);
    h.service
        .push(&pushing(&cert, &second.commit, digest(1)))
        .unwrap();
    h.clock.advance(100);
    let report = h
        .service
        .close(
            &lease,
            key.public_key(),
            &writ_proto::CloseRequest {
                summary: "OAuth login behind a flag".to_owned(),
            },
            &CallerFacts::default(),
        )
        .unwrap();
    assert_eq!(report.phases.coding_seconds, Some(300));
    assert_eq!(report.phases.ci_rounds_seconds, [1200]);
    assert_eq!(report.phases.after_last_push_seconds, Some(100));
    assert_eq!(report.used_seconds, 2100);
    // Every signature and push the audit log holds, and nothing else.
    let signed: Vec<_> = h
        .events("sign", "allowed")
        .iter()
        .map(|l| l["commit"].as_str().unwrap().to_owned())
        .collect();
    let reported: Vec<_> = report.commits.iter().map(|c| c.id.to_string()).collect();
    assert_eq!(reported, signed);
    assert_eq!(report.pushed.len(), h.events("push", "allowed").len());
    assert_eq!(report.branches, ["refs/heads/agent/oauth-login"]);
    assert_eq!(report.signatures.used, 2);
    assert_eq!(report.pushes.used, 2);
    assert_eq!(report.warnings, ["files outside expected_paths: docs/a.md"]);
    assert!(!report.truncated);
}
