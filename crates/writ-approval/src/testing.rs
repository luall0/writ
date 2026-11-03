//! Test support (feature `testing`): a service on the platform fakes, and the approver's
//! signatures, so every crate's tests build them the same way.
//!
//! Panics on any failure: it only ever runs in tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use writ_core::authority::{AdminTarget, TextDigest};
use writ_core::canonical::Canonical;
use writ_core::config::PolicyConfig;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_core::names::TicketId;
use writ_core::signed::{BootNonce, Refusal, Revocation, Unseal};
use writ_core::ticket::Ticket;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Fingerprint, HashAlg, PrivateKey};
use writ_crypto::sshsig;
use writ_platform::testing::{FakeClock, FakeWatcher, RecordingNotifier};
use writ_platform::{Clock, Notifier, SessionWatcher};
use writ_proto::{
    ApproveRequest, Decisions, PassphraseText, RefuseRequest, RevokeRequest, UnsealRequest,
};
use writ_signer::software::SoftwareSigner;
use writ_signer::testing::{FailingSigner, GatedSigner, software_signer};
use writ_store::{AuditBreaker, AuditLog, Store, StoreBreaker};

use writ_store::{AuthorityHead, AuthorityHow, AuthorityVersion};

use crate::{InForce, Opened, Service, ServiceConfig, ServicePlatform, SubmissionLimits};

/// The boot nonce of every [`TestService`].
pub const NONCE: [u8; 16] = [7; 16];

/// The time a [`TestService`] starts at by default: 2027-01-15T08:00:00Z.
pub const START: u64 = 1_800_000_000;

/// How to build a [`TestService`]. Defaults: `decisions: signed`, 20 pending tickets at most,
/// a fake watcher, a recording notifier, a fake clock at [`START`], and a software signer
/// with an Ed25519 key for each template's `signing_key` (that can be held at a gate or made
/// to fail).
pub struct TestServiceBuilder {
    policy: PolicyConfig,
    policy_text: String,
    signer_kind: KeyKind,
    decisions: Decisions,
    max_pending: usize,
    submissions: SubmissionLimits,
    watcher: Arc<dyn SessionWatcher>,
    notifier: Arc<dyn Notifier>,
    clock: Arc<dyn Clock>,
    sealed: bool,
}

impl TestServiceBuilder {
    pub fn new(policy_yaml: &str) -> Self {
        Self {
            policy: PolicyConfig::from_yaml(policy_yaml).expect("the test policy parses"),
            policy_text: policy_yaml.to_owned(),
            signer_kind: KeyKind::Ed25519,
            decisions: Decisions::Signed,
            max_pending: 20,
            submissions: SubmissionLimits::default(),
            watcher: Arc::new(FakeWatcher::new()),
            notifier: Arc::new(RecordingNotifier::new()),
            clock: Arc::new(FakeClock::at_unix(START)),
            sealed: false,
        }
    }

    /// Leaves the service sealed, as the daemon starts with the sealed keystore
    /// ([`TestService::open`] unseals it). Open by default, as with the development keystore.
    pub fn sealed(mut self) -> Self {
        self.sealed = true;
        self
    }

    pub fn decisions(mut self, decisions: Decisions) -> Self {
        self.decisions = decisions;
        self
    }

    pub fn max_pending(mut self, max_pending: usize) -> Self {
        self.max_pending = max_pending;
        self
    }

    /// The submission rates (the daemon's defaults otherwise).
    pub fn submissions(mut self, submissions: SubmissionLimits) -> Self {
        self.submissions = submissions;
        self
    }

    pub fn watcher(mut self, watcher: Arc<dyn SessionWatcher>) -> Self {
        self.watcher = watcher;
        self
    }

    pub fn notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The algorithm of the signing keys (Ed25519 by default).
    pub fn signer_kind(mut self, kind: KeyKind) -> Self {
        self.signer_kind = kind;
        self
    }

    /// Starts the service with its store and audit log in `dir`, and one approver key.
    pub fn build(self, dir: &Path) -> TestService {
        self.try_build(dir).unwrap()
    }

    /// [`TestServiceBuilder::build`], with the service's startup error if it has one.
    pub fn try_build(self, dir: &Path) -> Result<TestService, crate::ServiceError> {
        let approver = generate(KeyKind::Ed25519).unwrap();
        let ca_key = generate(KeyKind::Ed25519).unwrap();
        let host_key = generate(KeyKind::Ed25519).unwrap();
        let daemon: writ_core::names::KeyFingerprint = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            .parse()
            .unwrap();
        let ca_fingerprint = ca_key.public_key().fingerprint(HashAlg::Sha256);
        let audit_path = dir.join("audit.jsonl");
        let (audit, audit_breaker) = AuditLog::open_breakable(&audit_path).unwrap();
        let (store, store_breaker) = Store::open_breakable(&dir.join("leases.db")).unwrap();
        // The three files' first versions, under the MAC of a key the kit hands at open; on
        // a second build in the same directory (a restart), the ones already there.
        let key_path = dir.join("authority.key");
        let authority = match std::fs::read(&key_path) {
            Ok(bytes) => writ_crypto::authority::AuthorityKey::from_bytes(&bytes).unwrap(),
            Err(_) => {
                let key = writ_crypto::authority::AuthorityKey::generate().unwrap();
                std::fs::write(&key_path, key.as_bytes()).unwrap();
                key
            }
        };
        let in_force = match store.authority_in_force().unwrap() {
            Some((head, files)) => InForce {
                versions: files
                    .iter()
                    .map(|(target, file)| (*target, (file.version, file.digest.clone())))
                    .collect(),
                mac: head.mac,
            },
            None => record_first(&store, &authority, &self.policy_text, &approver),
        };
        let ids: std::collections::BTreeSet<String> = self
            .policy
            .templates()
            .values()
            .filter_map(|t| t.signing_key.as_ref().map(|k| k.as_str().to_owned()))
            .collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        let signer = Arc::new(GatedSigner::new(FailingSigner::new(software_signer(
            &ids,
            self.signer_kind,
        ))));
        let service = Service::new(
            ServiceConfig {
                policy: self.policy,
                approvers: vec![AllowedSigner {
                    principals: "me".into(),
                    key: approver.public_key().clone(),
                }],
                decisions: self.decisions,
                max_pending: self.max_pending,
                min_ttl: writ_core::fit::DEFAULT_MIN_TTL,
                submissions: self.submissions,
                ca_public: ca_key.public_key().clone(),
                daemon: daemon.clone(),
                in_force,
                recipient: None,
            },
            NONCE,
            store,
            audit,
            ServicePlatform {
                notifier: self.notifier,
                watcher: self.watcher,
                clock: self.clock,
            },
        )?;
        let test = TestService {
            service,
            approver,
            ca_key,
            ca_fingerprint,
            audit_breaker,
            store_breaker,
            audit_path,
            signer,
            daemon,
            authority: *authority.as_bytes(),
        };
        if !self.sealed {
            test.open()?;
        }
        Ok(test)
    }
}

/// Records the three files' first versions (the policy, the kit's approver, no reader) under
/// `authority`'s MAC.
fn record_first(
    store: &Store,
    authority: &writ_crypto::authority::AuthorityKey,
    policy_text: &str,
    approver: &PrivateKey,
) -> InForce {
    let approvers_text = format!("me {}\n", approver.public_key().to_openssh().unwrap());
    let texts = [
        (AdminTarget::Policy, policy_text.to_owned()),
        (AdminTarget::Approvers, approvers_text),
        (AdminTarget::Readers, String::new()),
    ];
    let unsigned = InForce {
        versions: texts
            .iter()
            .map(|(target, text)| (*target, (1, TextDigest::of(text))))
            .collect(),
        mac: String::new(),
    };
    let in_force = InForce {
        mac: authority.sign_head(&unsigned.entries()).unwrap(),
        ..unsigned
    };
    let rows: Vec<AuthorityVersion> = texts
        .iter()
        .map(|(target, text)| AuthorityVersion {
            target: *target,
            version: 1,
            text: text.clone(),
            digest: TextDigest::of(text),
            how: AuthorityHow::Init,
            document: None,
            signature: None,
            approver: None,
            applied_at: writ_core::units::Timestamp::from_unix(1_800_000_000).unwrap(),
        })
        .collect();
    let head = AuthorityHead {
        versions: in_force
            .versions
            .iter()
            .map(|(t, (v, _))| (*t, *v))
            .collect(),
        mac: in_force.mac.clone(),
    };
    store.record_authority(&rows, &head).unwrap();
    in_force
}

/// A running service and what tests need around it.
pub struct TestService {
    pub service: Arc<Service>,
    /// The one key in `approvers`.
    pub approver: PrivateKey,
    /// The key of the CA that issues session certificates (to make one by hand, for no lease).
    pub ca_key: PrivateKey,
    /// The fingerprint of the CA that issues session certificates.
    pub ca_fingerprint: Fingerprint,
    /// Makes the audit log fail, to check that nothing changes without its line.
    pub audit_breaker: AuditBreaker,
    /// Makes one lease lookup fail, to check what a fault in the middle leaves behind.
    pub store_breaker: StoreBreaker,
    pub audit_path: PathBuf,
    /// The signer commits are signed with: `close()` holds each signature until the test
    /// releases it, `set_failing(true)` makes it refuse.
    pub signer: Arc<GatedSigner<FailingSigner<SoftwareSigner>>>,
    /// What an unseal names: the daemon's host key fingerprint.
    pub daemon: writ_core::names::KeyFingerprint,
    /// The authority MAC's key the kit hands at open.
    pub authority: [u8; 32],
}

impl TestService {
    /// Unseals the service with its CA and signer, as the development keystore does at start
    /// (no approver).
    pub fn open(&self) -> Result<(), crate::ServiceError> {
        self.service.unseal(
            self.opened(),
            None,
            &writ_core::caller::CallerFacts::default(),
        )
    }

    /// What an unseal brings: the kit's CA, signer and authority key.
    pub fn opened(&self) -> Opened {
        Opened {
            ca: self.ca(),
            signer: self.signer.clone(),
            authority: writ_crypto::authority::AuthorityKey::from_bytes(&self.authority).unwrap(),
        }
    }

    /// An unseal request for this boot, signed by `signer` (the approver, or another key).
    pub fn unseal_request(&self, signer: &PrivateKey, passphrase: &str) -> UnsealRequest {
        let document = Unseal::new(self.daemon.clone(), BootNonce::from_bytes(NONCE))
            .canonical_bytes()
            .unwrap();
        UnsealRequest {
            passphrase: PassphraseText::new(passphrase.to_owned()),
            signature: sshsig::sign(signer, APPROVAL_NAMESPACE, &document).unwrap(),
            unseal: String::from_utf8(document).unwrap(),
        }
    }

    /// The service's CA, to issue certificates no lease stands for.
    pub fn ca(&self) -> CertificateAuthority {
        CertificateAuthority::new(self.ca_key.clone())
    }

    /// Every audit log line, parsed.
    pub fn audit(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The audit lines with this event and result.
    pub fn events(&self, event: &str, result: &str) -> Vec<serde_json::Value> {
        self.audit()
            .into_iter()
            .filter(|e| e["event"] == event && e["result"] == result)
            .collect()
    }

    /// The public key of a signing key, as the signer lists it.
    pub fn signing_key(&self, id: &str) -> writ_crypto::ssh_key::PublicKey {
        writ_signer::public_key(&*self.signer, &id.parse().unwrap()).unwrap()
    }

    /// An approval of `ticket` (signed exactly as given) by the approver.
    pub fn approval(&self, ticket: &Ticket) -> ApproveRequest {
        sign_approval(&self.approver, ticket)
    }

    /// A signed refusal of `id` by the approver.
    pub fn refusal(&self, id: &TicketId, feedback: &str) -> RefuseRequest {
        sign_refusal(&self.approver, id, feedback)
    }

    /// A signed revocation of `id` by the approver.
    pub fn revocation(&self, id: &TicketId) -> RevokeRequest {
        sign_revocation(&self.approver, id)
    }
}

/// An approval of `ticket`'s canonical bytes by `approver` (namespace `writ-approval`).
pub fn sign_approval(approver: &PrivateKey, ticket: &Ticket) -> ApproveRequest {
    sign_approval_in(approver, ticket, APPROVAL_NAMESPACE)
}

/// The same, in any namespace (to check that other namespaces are refused).
pub fn sign_approval_in(approver: &PrivateKey, ticket: &Ticket, namespace: &str) -> ApproveRequest {
    let bytes = ticket.canonical_bytes().unwrap();
    ApproveRequest {
        signature: sshsig::sign(approver, namespace, &bytes).unwrap(),
        signed: String::from_utf8(bytes).unwrap(),
    }
}

/// A refusal of `id` with `feedback`, signed by `approver`.
pub fn sign_refusal(approver: &PrivateKey, id: &TicketId, feedback: &str) -> RefuseRequest {
    let document = Refusal::new(id.clone(), feedback.to_owned())
        .canonical_bytes()
        .unwrap();
    RefuseRequest {
        feedback: feedback.to_owned(),
        signature: Some(sshsig::sign(approver, APPROVAL_NAMESPACE, &document).unwrap()),
    }
}

/// A revocation of `id`, signed by `approver`.
pub fn sign_revocation(approver: &PrivateKey, id: &TicketId) -> RevokeRequest {
    let document = Revocation::new(id.clone()).canonical_bytes().unwrap();
    RevokeRequest {
        signature: Some(sshsig::sign(approver, APPROVAL_NAMESPACE, &document).unwrap()),
    }
}
