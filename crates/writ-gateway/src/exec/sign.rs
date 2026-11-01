//! `writ-sign git <repo>`: the body on stdin ([`SignInput`]: the object git asks to sign and
//! the objects its touched paths are computed from) parsed here, at the edge; the decision,
//! the signature and the ledger are the approval service's ([`Service::sign`]). Lease
//! holders are untrusted: the body is bounded, decoded strictly, and every evidence object
//! is checked against its id before it is read (`writ_git::paths`).

use russh::ChannelReadHalf;
use tokio::io::AsyncReadExt;
use writ_approval::{SignedCommit, Signing};
use writ_core::caller::CallerFacts;
use writ_core::names::RepoName;
use writ_core::policy::{CertIdentity, Denial, DenyCode, ObjectKind, SignRequest};
use writ_git::Commit;
use writ_git::object::ObjectType;
use writ_git::paths::{self, Evidence};
use writ_proto::sign::{EvidenceKind, MAX_SIGN_INPUT, SignInput};

use crate::Gateway;

/// Why the gateway turned a request down before the service saw it, or the service's denial.
pub(super) enum Refused {
    /// The body or the object is unreadable: refused by the gateway (logged by the caller).
    Unreadable(String),
    /// Decided (and logged) by the service.
    Denied(Denial),
}

/// What [`sign`] needs about the request.
pub(super) struct SignCommand<'a> {
    pub cert: &'a CertIdentity,
    pub facts: &'a CallerFacts,
    pub namespace: &'a str,
    pub repo: &'a RepoName,
}

/// The signed commit, or why not.
pub(super) async fn sign(
    gateway: &Gateway,
    command: SignCommand<'_>,
    rx: &mut ChannelReadHalf,
) -> Result<SignedCommit, Refused> {
    let mut body = Vec::new();
    let limit = u64::try_from(MAX_SIGN_INPUT)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    rx.make_reader()
        .take(limit)
        .read_to_end(&mut body)
        .await
        .map_err(|e| Refused::Unreadable(format!("cannot read the request: {e}")))?;
    let (cert, caller) = (command.cert.clone(), command.facts.clone());
    let (namespace, repo) = (command.namespace.to_owned(), command.repo.clone());
    let service = gateway.service().clone();
    // Off the async threads: hashing the evidence and walking the trees is bounded but can
    // take a while, and the service reads the store and syncs the audit log.
    tokio::task::spawn_blocking(move || {
        let input = SignInput::decode(&body).map_err(|e| Refused::Unreadable(e.to_string()))?;
        let (request, commit) = parse(&repo, input).map_err(Refused::Unreadable)?;
        let signing = Signing {
            cert,
            caller,
            namespace,
            request,
            commit,
        };
        service.sign(&signing).map_err(Refused::Denied)
    })
    .await
    .unwrap_or_else(|_| {
        Err(Refused::Denied(Denial {
            code: DenyCode::Invalid,
            reason: "internal error in the daemon".to_owned(),
            hint: None,
        }))
    })
}

/// The policy's facts about the object, and the commit to sign if it is one.
fn parse(repo: &RepoName, input: SignInput) -> Result<(SignRequest, Option<Commit>), String> {
    let object = writ_git::commit::kind(&input.object);
    if object != ObjectKind::Commit {
        // Refused by the policy, after the lease checks, with its own reason.
        let request = SignRequest {
            repo: repo.clone(),
            object,
            object_format: None,
            committer_email: String::new(),
            writ_trailers: Vec::new(),
            touched_paths: None,
        };
        return Ok((request, None));
    }
    let commit = Commit::parse(input.object).map_err(|e| format!("cannot sign: {e}"))?;
    let evidence = Evidence::new(
        commit.algo(),
        input.evidence.into_iter().map(|(kind, content)| {
            let kind = match kind {
                EvidenceKind::Commit => ObjectType::Commit,
                EvidenceKind::Tree => ObjectType::Tree,
            };
            (kind, content)
        }),
    );
    let touched_paths = paths::touched(&commit, &evidence)
        .inspect_err(|e| tracing::debug!(error = %e, "the commit's paths are unknown"))
        .ok();
    let request = SignRequest {
        repo: repo.clone(),
        object,
        object_format: Some(commit.algo().object_format()),
        committer_email: commit.committer_email().to_owned(),
        writ_trailers: commit.writ_trailers(),
        touched_paths,
    };
    Ok((request, Some(commit)))
}
