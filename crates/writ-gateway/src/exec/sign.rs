//! `writ-sign git <repo>`: the body on stdin ([`SignInput`]: the object git asks to sign and
//! the objects its touched paths are computed from) parsed here, at the edge; the decision,
//! the signature and the ledger are the approval service's ([`Service::sign`]). Lease
//! holders are untrusted: the body is bounded in bytes and in time, decoded strictly, and
//! every evidence object is checked against its id before it is read (`writ_git::paths`).
//! The daemon holds at most [`MAX_SIGN_REQUESTS`](crate::limits::MAX_SIGN_REQUESTS) of them
//! at once, and a lease at most the operator's share of those.

use russh::ChannelReadHalf;
use writ_approval::{SignObject, SignedCommit, Signing};
use writ_core::caller::CallerFacts;
use writ_core::names::RepoName;
use writ_core::policy::{CertIdentity, Denial, ObjectKind};
use writ_git::Commit;
use writ_git::object::ObjectType;
use writ_git::paths::{self, Evidence, PathsError};
use writ_git::tree::TreeError;
use writ_proto::sign::{EvidenceKind, MAX_SIGN_INPUT, SignInput};

use crate::{Gateway, limits};

/// Why the gateway turned a request down before the service saw it, or the service's denial.
pub(super) enum Refused {
    /// Refused by the gateway (logged by the caller): the body or the object is unreadable,
    /// too slow to arrive, or the daemon holds too many sign requests already.
    Gateway(String),
    /// Decided (and logged) by the service.
    Denied(Denial),
}

/// What [`sign`] needs about the request.
pub(super) struct SignCommand<'a> {
    pub cert: &'a CertIdentity,
    pub facts: &'a CallerFacts,
    pub repo: &'a RepoName,
    /// The format git asked for.
    pub format: writ_crypto::algorithm::SignatureFormat,
}

/// The signed commit, or why not.
pub(super) async fn sign(
    gateway: &Gateway,
    command: SignCommand<'_>,
    rx: &mut ChannelReadHalf,
) -> Result<SignedCommit, Refused> {
    // Nothing is read for a certificate whose lease can't sign for this repo (it may have
    // ended since the connection was authenticated): the service logs the refusal.
    let (cert, caller) = (command.cert.clone(), command.facts.clone());
    let (service, repo) = (gateway.service().clone(), command.repo.clone());
    tokio::task::spawn_blocking(move || service.may_sign(&cert, &caller, &repo))
        .await
        .unwrap_or_else(|_| Err(Denial::internal()))
        .map_err(Refused::Denied)?;
    // A slot first, then the body: what the daemon holds is bounded however many lease
    // holders ask at once. The slot is kept until the request is answered.
    let slot = gateway
        .shared
        .sign_slots
        .take(command.cert.serial)
        .map_err(Refused::Gateway)?;
    let body = limits::read_within(rx.make_reader(), MAX_SIGN_INPUT, limits::SIGN_BODY_DEADLINE)
        .await
        .map_err(Refused::Gateway)?;
    let (cert, caller) = (command.cert.clone(), command.facts.clone());
    let (repo, service, format) = (
        command.repo.clone(),
        gateway.service().clone(),
        command.format,
    );
    // Off the async threads: hashing the evidence and walking the trees is bounded but can
    // take a while, and the service reads the store and syncs the audit log.
    tokio::task::spawn_blocking(move || {
        // Held as long as the body is, even if the request's task is gone meanwhile.
        let _slot = slot;
        let input = SignInput::decode(&body).map_err(|e| Refused::Gateway(e.to_string()))?;
        let object = parse(input).map_err(Refused::Gateway)?;
        let signing = Signing {
            cert,
            caller,
            repo,
            format,
            object,
        };
        service.sign(&signing).map_err(Refused::Denied)
    })
    .await
    .unwrap_or_else(|_| Err(Refused::Denied(Denial::internal())))
}

/// What git asked to sign: a commit with the paths it touches, or another kind of object.
fn parse(input: SignInput) -> Result<SignObject, String> {
    let object = writ_git::commit::kind(&input.object);
    if object != ObjectKind::Commit {
        // Refused by the policy, after the lease checks, with its own reason.
        return Ok(SignObject::Other(object));
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
    let touched_paths = match paths::touched(&commit, &evidence) {
        Ok(paths) => Some(paths),
        // Refused whatever paths_check says: checked out, it would be the repository's own
        // directory. (Leaving the tree out hides it; the push-time fsck stops it then.)
        Err(PathsError::Tree(_, TreeError::DotGit)) => {
            return Err("cannot sign: the commit adds a .git entry to a tree".to_owned());
        }
        Err(e) => {
            tracing::debug!(error = %e, "the commit's paths are unknown");
            None
        }
    };
    Ok(SignObject::Commit {
        commit,
        touched_paths,
    })
}

#[cfg(test)]
mod tests {
    use writ_git::HashAlgo;

    use super::*;

    #[test]
    fn a_dot_git_entry_is_refused_whatever_paths_check_says() {
        let algo = HashAlgo::Sha1;
        let blob = algo.hash(ObjectType::Blob, b"x").unwrap();
        let raw: Vec<u8> = (0..20)
            .map(|i| u8::from_str_radix(blob.as_str().get(2 * i..2 * i + 2).unwrap(), 16).unwrap())
            .collect();
        let tree = |name: &str| {
            let mut content = format!("100644 {name}\0").into_bytes();
            content.extend_from_slice(&raw);
            content
        };
        let input = |name: &str| {
            let content = tree(name);
            let id = algo.hash(ObjectType::Tree, &content).unwrap();
            SignInput {
                object: format!(
                    "tree {id}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm\n"
                )
                .into_bytes(),
                evidence: vec![(EvidenceKind::Tree, content)],
            }
        };
        let SignObject::Commit { touched_paths, .. } = parse(input(".gitignore")).unwrap() else {
            panic!("a commit");
        };
        assert_eq!(touched_paths, Some(vec![".gitignore".to_owned()]));
        assert_eq!(
            parse(input(".GIT")).map(|_| ()),
            Err("cannot sign: the commit adds a .git entry to a tree".to_owned())
        );
    }
}
