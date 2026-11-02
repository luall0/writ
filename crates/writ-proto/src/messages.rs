//! The replies and request bodies of each [`Command`](crate::Command).

use serde::{Deserialize, Serialize};
use writ_core::lease::State;
use writ_core::names::{KeyFingerprint, RepoName, TemplateName, TicketId};
use writ_core::signed::BootNonce;
use writ_core::units::Timestamp;
use zeroize::Zeroizing;

/// Reply to [`Command::Request`]: the ticket is waiting for the approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitted {
    pub id: TicketId,
    /// The complete ticket the daemon built, as canonical bytes.
    pub canonical: String,
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
    },
    /// A signed amendment, now the terms of its lease (the certificate doesn't change), with
    /// the signing key of its terms.
    Applied {
        lease: String,
        signing_key: Option<String>,
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
    /// What it follows: the refused ticket it revises, or the lease terms it amends.
    pub previous: Option<Previous>,
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
