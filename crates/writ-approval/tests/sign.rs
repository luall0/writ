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
use writ_approval::{SignedCommit, Signing};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::lease::State;
use writ_core::names::TicketId;
use writ_core::policy::{CertIdentity, Denial, DenyCode, SignRequest};
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, HashAlg};
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
        let key = generate(KeyKind::Ed25519).unwrap();
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
        namespace: "git".to_owned(),
        request: SignRequest {
            repo: repo.parse().unwrap(),
            object: writ_core::policy::ObjectKind::Commit,
            object_format: Some(built.commit.algo().object_format()),
            committer_email: built.commit.committer_email().to_owned(),
            writ_trailers: built.commit.writ_trailers(),
            touched_paths: touched(&built.commit, &evidence).ok(),
        },
        commit: Some(built.commit.clone()),
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
    // A tag, or anything that isn't a commit: refused after the lease checks.
    for object in [
        writ_core::policy::ObjectKind::Tag,
        writ_core::policy::ObjectKind::Other,
    ] {
        let mut request = signing(&cert, &build("src/a.rs", EMAIL, &good), "omega-code");
        request.request.object = object;
        request.commit = None;
        denied(
            h.service.sign(&request),
            DenyCode::ObjectType,
            "only commits are signed (no tags: releases stay a human act)",
        );
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
    let mut unknown = signing(&cert, &outside, "omega-code");
    unknown.request.touched_paths = None;
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
    let mut unknown = signing(
        &cert,
        &build("src/login.rs", EMAIL, &trailer(&fix)),
        "omega-code",
    );
    unknown.request.touched_paths = None;
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
fn a_failing_signer_or_audit_log_signs_nothing() {
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
    assert_eq!(h.signatures(&lease), 0, "nothing counted");
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
fn a_template_whose_key_the_signer_lacks_is_a_startup_error() {
    use writ_approval::{Service, ServiceConfig, ServiceError, ServicePlatform};
    use writ_crypto::allowed_signers::AllowedSigner;
    use writ_platform::testing::{FakeWatcher, RecordingNotifier};
    let dir = tempfile::tempdir().unwrap();
    let start = |signer: writ_signer::software::SoftwareSigner| {
        let approver = generate(KeyKind::Ed25519).unwrap();
        Service::new(
            ServiceConfig {
                policy: writ_core::config::PolicyConfig::from_yaml(POLICY).unwrap(),
                approvers: vec![AllowedSigner {
                    principals: "me".into(),
                    key: approver.public_key().clone(),
                }],
                decisions: writ_proto::Decisions::Signed,
                max_pending: 20,
            },
            writ_crypto::ca::CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap()),
            Store::open_in_memory().unwrap(),
            writ_store::AuditLog::open(&dir.path().join("audit.jsonl")).unwrap(),
            ServicePlatform {
                notifier: Arc::new(RecordingNotifier::new()),
                signer: Arc::new(signer),
                watcher: Arc::new(FakeWatcher::new()),
                clock: Arc::new(FakeClock::at_unix(START)),
            },
        )
    };
    let other = writ_signer::testing::software_signer(&["another-key"], KeyKind::Ed25519);
    match start(other) {
        Err(ServiceError::Config(message)) => assert_eq!(
            message,
            "template feature-branch signs with key agent-ed25519-01, which the signer doesn't hold"
        ),
        Err(other) => panic!("expected a configuration error, got {other}"),
        Ok(_) => panic!("started without the template's signing key"),
    }
    let held = writ_signer::testing::software_signer(&["agent-ed25519-01"], KeyKind::P256);
    assert!(start(held).is_ok());
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
