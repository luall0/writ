//! The replies and request bodies of each [`Command`](crate::Command).

use serde::{Deserialize, Serialize};
use writ_core::authority::{AdminTarget, PreviousToken, TextDigest};
use writ_core::config::{PathsCheck, TicketLink};
use writ_core::lease::State;
use writ_core::names::{
    CommitId, CommitterName, Email, KeyFingerprint, KeyId, RepoName, TemplateName, TicketId,
};
use writ_core::signed::BootNonce;
use writ_core::ticket::{Estimate, Operation};
use writ_core::units::{ByteSize, Duration, Timestamp};
use zeroize::Zeroizing;

/// Reply to [`Command::Request`]: the ticket is waiting for the approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitted {
    pub id: TicketId,
    /// The complete ticket the daemon built, as canonical bytes.
    pub canonical: String,
}

/// Reply to [`Command::DryRun`](crate::Command::DryRun): the ticket passed every check a
/// submission gets. Nothing was stored, nobody was told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checked {
    /// The complete ticket the daemon would build, as canonical bytes (its id is a fresh one,
    /// never used).
    pub canonical: String,
}

/// Reply to [`Command::Policy`](crate::Command::Policy): what a ticket for one repo may ask,
/// from the policy in force. Only that repo: never its upstream, its credential, another
/// repo or what a template allows elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoPolicy {
    pub repo: RepoName,
    /// The refs no lease may push (the registry's `protected_refs`).
    pub protected_refs: Vec<String>,
    /// How a commit names its lease: `trailer` means every commit needs `Writ: <lease>`.
    pub ticket_link: TicketLink,
    /// Every template that allows the repo, by name: a ticket must fit one.
    pub templates: Vec<TemplateView>,
    /// The shortest `ttl` a ticket may ask for.
    pub min_ttl: Duration,
    /// How long after its end a lease can still be renewed.
    pub renew_grace: Duration,
    /// The most active leases one source may hold at once (none: no limit).
    pub max_active_per_source: Option<u32>,
}

/// A template, as far as one repo is concerned: the largest ticket it accepts for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateView {
    pub name: TemplateName,
    pub operations: Vec<Operation>,
    /// The branch patterns a ticket's branches must be within, as written.
    pub branches: Vec<String>,
    pub committer_emails: Vec<Email>,
    /// The name every commit must carry as author and committer (none: not checked).
    pub committer_name: Option<CommitterName>,
    pub force_push: bool,
    pub max_ttl: Duration,
    pub max_signatures: u32,
    pub max_pushes: u32,
    pub max_ops_per_minute: u32,
    pub max_push_size: ByteSize,
    pub paths_check: PathsCheck,
    pub require_expected_paths: bool,
    /// How many renewals one lease's chain may have (none: no limit).
    pub max_renewals: Option<u32>,
}

/// Reply to [`Command::Wait`]: how the ticket was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum Decision {
    /// Signed: the lease (canonical bytes of the terms in force, narrowed if I narrowed them),
    /// the session certificate (OpenSSH text), and the public key commits are signed with
    /// (OpenSSH text) when the lease allows `commit_sign`.
    Active {
        lease: String,
        certificate: String,
        signing_key: Option<String>,
        /// The signing key's armored OpenPGP certificate, when it signs in OpenPGP: git
        /// verifies the lease's commits with it, and its fingerprint is `user.signingkey`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_certificate: Option<String>,
    },
    /// A signed amendment, now the terms of its lease (the certificate doesn't change), with
    /// the signing key of its terms.
    Applied {
        lease: String,
        signing_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_certificate: Option<String>,
    },
    /// Refused, with feedback, and who signed the refusal: `None` when nobody did (a daemon
    /// with `decisions: open`), so the feedback may not be the approver's.
    Refused {
        feedback: String,
        signed_by: Option<KeyFingerprint>,
    },
    /// Not signed before `expires_at`.
    Expired,
    /// Withdrawn, or the lease was revoked before the wait.
    Revoked,
    /// The lease ended another way (closed, exhausted) before the wait.
    Ended { state: State },
}

/// Reply to [`Command::Info`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub decisions: Decisions,
    /// While the daemon is sealed: what an unseal signature names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedBoot>,
    /// The sealed keystore's public recipient (`age1…`): what `writ admin token` encrypts a
    /// token to. None with the development keystore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
}

/// A sealed daemon's boot, as a `writ-unseal/1` document names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBoot {
    /// The fingerprint of the daemon's SSH host key.
    pub daemon: KeyFingerprint,
    /// Drawn at this start: a signature over it opens no other boot.
    pub nonce: BootNonce,
}

/// The keystore's passphrase on the wire: wiped on drop, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct PassphraseText(Zeroizing<String>);

impl PassphraseText {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PassphraseText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PassphraseText(<redacted>)")
    }
}

impl Serialize for PassphraseText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PassphraseText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Moved into the wiped box, never copied.
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Body of [`Command::Unseal`](crate::Command::Unseal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsealRequest {
    /// The keystore's passphrase.
    pub passphrase: PassphraseText,
    /// The canonical bytes of the `writ-unseal/1` document: this daemon, this boot.
    pub unseal: String,
    /// The approver's armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Reply to [`Command::AdminShow`](crate::Command::AdminShow): a file as it is in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminShown {
    /// The fingerprint of the daemon's SSH host key: what a `writ-admin/2` change names as
    /// `daemon`.
    pub daemon: KeyFingerprint,
    pub target: AdminTarget,
    /// What a `writ-admin/2` change names as `version`.
    pub version: u64,
    /// The digest of its text: what a `writ-admin/2` change names as `previous`.
    pub digest: TextDigest,
    pub text: String,
}

/// Body of [`Command::AdminApply`](crate::Command::AdminApply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequest {
    /// The canonical bytes of the `writ-admin/2` document: the daemon, the file, the version
    /// it replaces, the new text.
    pub document: String,
    /// The approver's armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Reply to [`Command::AdminApply`](crate::Command::AdminApply): the new version is in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminApplied {
    pub target: AdminTarget,
    pub version: u64,
    pub digest: TextDigest,
    pub signed_by: KeyFingerprint,
    /// The keys the new policy named that the keystore lacked: made by this change, to
    /// register on the remotes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created: Vec<CreatedKey>,
    /// The leases revoked because the approver key that signed them is no longer in
    /// `approvers` (a change of `approvers` only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<TicketId>,
}

/// A key a signed policy change made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatedKey {
    pub id: KeyId,
    pub role: KeyRole,
    /// Its public key (OpenSSH text).
    pub public_key: String,
}

/// What a daemon key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Signs agents' commits (a template's `signing_key`): register it on the account the
    /// commits are shown under.
    Signing,
    /// Reaches an `ssh://` upstream (a repo's `upstream_credential`): add it on the remote.
    Upstream,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "signing key",
            Self::Upstream => "upstream credential",
        }
    }
}

/// Reply to [`Command::TokenShow`](crate::Command::TokenShow): the token file in force for a
/// credential, by its digest (never the token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenShown {
    /// The fingerprint of the daemon's SSH host key: what a `writ-token/2` names as `daemon`.
    pub daemon: KeyFingerprint,
    pub id: KeyId,
    /// What a `writ-token/2` replacing it names as `previous`.
    pub previous: PreviousToken,
}

/// Body of [`Command::TokenApply`](crate::Command::TokenApply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// The canonical bytes of the `writ-token/2` document: the daemon, the credential, the
    /// file it replaces, the token sealed to the keystore's recipient.
    pub document: String,
    /// The approver's armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Reply to [`Command::TokenApply`](crate::Command::TokenApply): the token is in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenApplied {
    pub id: KeyId,
    /// The digest of the new token file.
    pub digest: TextDigest,
    pub replaced: PreviousToken,
    pub signed_by: KeyFingerprint,
}

/// Reply to [`Command::Unseal`](crate::Command::Unseal): the daemon is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unsealed {
    /// The approver key that signed the unseal.
    pub signed_by: KeyFingerprint,
}

/// Whether refusals and revocations need an approver signature (`writd.yaml`: `decisions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decisions {
    /// An SSHSIG over a `writ-refusal/1` or `writ-revocation/1` document is required.
    #[default]
    Signed,
    /// Anyone who reaches the approval listener may refuse or revoke.
    Open,
}

/// Reply to [`Command::List`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub tickets: Vec<Summary>,
}

/// One line of `writ ls`. The title is agent-written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub id: TicketId,
    /// The lease it belongs to (itself, or the lease an amendment amends).
    pub lease: TicketId,
    pub state: State,
    pub template: TemplateName,
    pub revision: u32,
    pub repos: Vec<RepoName>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub title: String,
}

/// Reply to [`Command::Show`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shown {
    pub state: State,
    /// The ticket's canonical bytes (as submitted while pending, as signed once approved).
    pub canonical: String,
    /// What it follows: the refused ticket it revises, or the lease terms it amends or renews.
    pub previous: Option<Previous>,
    /// For a renewal: the chain it continues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal: Option<Renewal>,
    /// The other active leases submitted from the same source (the daemon's record of it):
    /// display only.
    #[serde(default)]
    pub others: Others,
}

/// The chain a renewal continues, for the approver: the task as first signed, and what the
/// work used so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renewal {
    /// The canonical bytes of the chain's first lease as it was signed: the original ticket.
    pub original: String,
    /// Which renewal this one is in the chain (1 for the first).
    pub number: u32,
    /// The seconds every lease of the chain has run so far, together.
    pub used_seconds: u64,
    /// What the renewed lease used of its counts.
    pub signatures: Count,
    pub pushes: Count,
    /// The renewed lease's state (active, expired, exhausted).
    pub state: State,
}

/// A count used against its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Count {
    pub used: u32,
    pub max: u32,
}

/// The other active leases from a ticket's source: the first ones, and how many more.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Others {
    pub shown: Vec<OtherLease>,
    /// How many more there are, not shown.
    pub more: u32,
}

/// One active lease from the same source as the ticket shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtherLease {
    pub id: TicketId,
    pub repos: Vec<RepoName>,
    /// The branch patterns, as written.
    pub branches: Vec<String>,
    pub operations: Vec<Operation>,
    pub expires_at: Timestamp,
    /// A repo in common with the ticket shown, and branch patterns that intersect.
    pub overlap: bool,
}

/// The ticket a revision or an amendment follows, for the diff `writ sign` shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    pub relation: Relation,
    pub canonical: String,
}

/// How a ticket follows the one shown with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// The refused ticket this one revises.
    Revises,
    /// The terms in force of the lease this one amends.
    Amends,
    /// The terms in force of the lease this one renews.
    Renews,
}

/// Body of [`Command::Close`](crate::Command::Close).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseRequest {
    /// The agent's summary of the work: shown as written, never acted on.
    pub summary: String,
}

/// Reply to [`Command::Close`](crate::Command::Close) and
/// [`Command::Report`](crate::Command::Report): what a lease (and the leases it renews) did,
/// from the daemon's state and its audit log. Agent text (title, summary, the paths named in
/// warnings) is shown as written, escaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub lease: TicketId,
    pub state: State,
    pub title: String,
    pub template: TemplateName,
    pub repos: Vec<RepoName>,
    pub expected_paths: Vec<String>,
    pub summary: Option<String>,
    pub estimate: Option<Estimate>,
    /// Every lease of the work: the ones it renews first (the oldest first), then itself.
    pub chain: Vec<ChainLink>,
    /// Of the whole chain: the seconds its leases were granted (each one's TTL) and ran.
    pub granted_seconds: u64,
    pub used_seconds: u64,
    /// Of the lease itself.
    pub signatures: Count,
    pub pushes: Count,
    /// Fetches of the whole chain.
    pub fetches: u64,
    /// Every commit signed, from the ledger (the whole chain), in signing order.
    pub commits: Vec<ReportCommit>,
    /// Every push upstream took (the whole chain), in order.
    pub pushed: Vec<ReportPush>,
    /// The refs pushed, each once.
    pub branches: Vec<String>,
    /// The denials, by code, counted ones included.
    pub denials: Vec<DenialCount>,
    /// The warnings its signatures carried (files outside `expected_paths` with
    /// `paths_check: warn`, paths not checked), each once.
    pub warnings: Vec<String>,
    /// The time spent in each phase, derived from the daemon's timestamps: approximate.
    pub phases: Phases,
    /// Whether the audit log held more lines for the chain than the report reads.
    pub truncated: bool,
}

/// One lease of a report's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLink {
    pub id: TicketId,
    pub state: State,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    /// When it ended (none while it runs).
    pub ended_at: Option<Timestamp>,
    pub signatures: u32,
    pub pushes: u32,
}

/// A commit in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportCommit {
    pub id: CommitId,
    pub repo: RepoName,
    pub lease: TicketId,
    pub signed_at: Timestamp,
}

/// A push in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPush {
    pub at: Timestamp,
    pub repo: Option<RepoName>,
    pub refs: Vec<String>,
}

/// How many denials of one code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenialCount {
    pub code: String,
    pub count: u64,
}

/// The time of each phase of the work, from the daemon's timestamps (approximate: a commit
/// marks the end of coding, the next commit after a push the end of a CI round and its fix).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phases {
    /// From submission to the grant (each lease of the chain, together).
    pub approval_wait_seconds: Option<u64>,
    /// From the first grant to the first signature.
    pub coding_seconds: Option<u64>,
    /// For each push followed by a signature: the time between them.
    pub ci_rounds_seconds: Vec<u64>,
    /// From the last push to the end.
    pub after_last_push_seconds: Option<u64>,
}

/// Body of [`Command::Approve`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    /// The canonical bytes signed: the submitted ticket, or a narrowing of it.
    pub signed: String,
    /// The armored SSHSIG over them, namespace `writ-approval`.
    pub signature: String,
}

/// Body of [`Command::Refuse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefuseRequest {
    pub feedback: String,
    /// With `decisions: signed`: an SSHSIG over the `writ-refusal/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Body of [`Command::Revoke`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// With `decisions: signed`: an SSHSIG over the `writ-revocation/1` document.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Reply to approve, refuse and revoke: where the ticket (or lease) now stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub id: TicketId,
    pub state: State,
}

/// Body of [`Command::Prove`](crate::Command::Prove).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveRequest {
    /// The canonical bytes of the `writ-proof/1` document: the key, the namespace, the message.
    pub proof: String,
    /// The approver's armored SSHSIG over them, namespace `writ-approval`. Always required,
    /// whatever the daemon's `decisions`: a reader key alone can't have a key sign anything.
    pub signature: String,
}

/// Reply to [`Command::Prove`](crate::Command::Prove).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proved {
    /// The agent signing key's armored SSHSIG over the message, in the proof's namespace: what
    /// the remote asked for.
    pub signature: String,
    /// The key's public half (OpenSSH text), to check the signature against.
    pub public_key: String,
}
