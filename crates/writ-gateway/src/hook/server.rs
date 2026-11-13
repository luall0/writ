//! The daemon side of the hook: reads what a hook sends, decides, answers, and logs every
//! refusal. The push is decided here, when the pack is in git's quarantine and the ref updates
//! are known (`docs/flows.md` § 3):
//!
//! 1. the lease, cheaply ([`Service::may_push`](writ_approval::Service::may_push)): a lease
//!    revoked or expired while the pack was coming in moves no ref, and nothing is read for it;
//! 2. the repo's mirror held (until `receive-pack` exits), and the push read from the objects
//!    git verified ([`writ_mirror::quarantine`]): each new tip a commit, the commits the mirror
//!    doesn't have (at most the repository's `max_signatures` in the lease), fast-forwards, refs that differ only
//!    in case, the size, and the paths each commit touches, computed again;
//! 3. [`Service::push`](writ_approval::Service::push): every commit in the ledger for this
//!    lease and repo with the same paths, the refs, force pushes, size, count and rate, under
//!    one lock, one `push` line.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use writ_approval::{EventKind, GatewayDenial, Pushing};
use writ_core::caller::CallerFacts;
use writ_core::lease::Lease;
use writ_core::names::{CommitId, RepoName};
use writ_core::policy;
use writ_mirror::quarantine::Quarantine;
use writ_platform::transport::accept_retrying;

use super::{MAX_HOOK_INPUT, MAX_UPDATES, PushContext, RefUpdate};
use crate::Gateway;

/// The most new commits one push may bring, whatever the lease (each is read and walked).
pub(crate) const MAX_PUSH_COMMITS: usize = 10_000;

/// Answers hooks on the gateway's private socket until the socket itself fails. An error
/// about one connection or a passing shortage (out of file descriptors) is retried
/// ([`accept_retrying`]): it must not end the hook server, or every later push would be
/// refused until a restart.
pub(crate) async fn serve(gateway: Gateway, listener: UnixListener) {
    let listener = &listener;
    serve_from(gateway, move || async move {
        listener.accept().await.map(|(stream, _)| stream)
    })
    .await;
}

/// [`serve`], over any source of connections (a test scripts the accept results).
async fn serve_from<F, Fut>(gateway: Gateway, mut accept: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<UnixStream>>,
{
    loop {
        match accept_retrying("hook socket", &mut accept).await {
            Ok(stream) => {
                tokio::spawn(answer(gateway.clone(), stream));
            }
            Err(e) => {
                tracing::error!(error = %e, "hook socket failed; pushes are refused");
                return;
            }
        }
    }
}

/// A refused push: why, and what is known about it.
struct Refused {
    reason: String,
    context: Option<Box<PushContext>>,
    refs: Vec<String>,
    /// Already logged by the approval service (a lease decision).
    logged: bool,
    /// What the audit line says when it is more than the agent is told (upstream's words).
    detail: Option<String>,
}

impl Refused {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            context: None,
            refs: Vec::new(),
            logged: false,
            detail: None,
        }
    }
}

async fn answer(gateway: Gateway, mut stream: UnixStream) {
    let decided = match read_input(&mut stream).await {
        Ok(input) => decide(&gateway, &input).await,
        Err(reason) => Err(Refused::new(reason)),
    };
    let reply = match decided {
        Ok(()) => "ok\n".to_owned(),
        Err(refused) => {
            let reply = format!("deny {}\n", refused.reason);
            if !refused.logged {
                log_refusal(&gateway, refused).await;
            }
            reply
        }
    };
    let _ = stream.write_all(reply.as_bytes()).await;
}

/// Reads the whole input. Over [`MAX_HOOK_INPUT`] bytes, or not ending in `\n` (cut short), it
/// is refused rather than decided on in part.
pub(super) async fn read_input(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Vec<u8>, &'static str> {
    let mut input = Vec::new();
    let limit = u64::try_from(MAX_HOOK_INPUT).unwrap_or(u64::MAX);
    stream
        .take(limit.saturating_add(1))
        .read_to_end(&mut input)
        .await
        .map_err(|_| "cannot read the push")?;
    if input.len() > MAX_HOOK_INPUT {
        return Err("the push updates too many refs");
    }
    if input.last() != Some(&b'\n') {
        return Err("malformed hook input");
    }
    Ok(input)
}

/// What a hook sends: the token, the quarantine (none for a push without a pack) and the ref
/// updates. Any line that isn't a valid update refuses the push.
pub(super) fn parse_input(
    input: &[u8],
) -> Result<(&str, Option<&str>, Vec<RefUpdate>), &'static str> {
    let text = std::str::from_utf8(input).map_err(|_| "malformed hook input")?;
    let mut lines = text.split_terminator('\n');
    let token = lines
        .next()
        .filter(|t| !t.is_empty())
        .ok_or("malformed hook input")?;
    let quarantine = lines.next().ok_or("malformed hook input")?;
    let quarantine = (!quarantine.is_empty()).then_some(quarantine);
    let updates = lines
        .map(|l| RefUpdate::parse(l).ok_or("malformed ref update"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((token, quarantine, updates))
}

async fn decide(gateway: &Gateway, input: &[u8]) -> Result<(), Refused> {
    let (token, quarantine, updates) = parse_input(input).map_err(Refused::new)?;
    let context = gateway
        .shared
        .pushes
        .lock()
        .map_err(|_| Refused::new("internal error"))?
        .get(token)
        .cloned()
        .ok_or_else(|| Refused::new("unknown push"))?;
    context
        .decided
        .store(true, std::sync::atomic::Ordering::Release);
    let refs: Vec<String> = updates.iter().map(|u| u.name.to_string()).collect();
    let decided = decide_push(gateway, &context, quarantine, &updates).await;
    super::after_decision(&context.held, decided.is_ok());
    match decided {
        Ok(()) => {
            tracing::info!(
                lease = %context.cert.key_id,
                repo = %context.repo,
                refs = refs.len(),
                "push accepted upstream"
            );
            Ok(())
        }
        Err(denied) => Err(Refused {
            reason: denied.reason,
            context: Some(Box::new(context)),
            refs,
            logged: denied.logged,
            detail: denied.detail,
        }),
    }
}

/// Why a push known to the gateway is refused: the reason, and whether the service logged it
/// already (a lease decision).
struct Denied {
    reason: String,
    logged: bool,
    detail: Option<String>,
}

impl Denied {
    /// To be logged as the hook's refusal.
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            logged: false,
            detail: None,
        }
    }

    /// A lease decision, logged by the service.
    fn logged(denial: &writ_core::policy::Denial) -> Self {
        Self {
            reason: denial.to_string(),
            logged: true,
            detail: None,
        }
    }

    /// The upstream push failed: the agent is told no upstream detail, the audit line all of
    /// it (the review after M7.6, M-5).
    fn upstream(error: &writ_mirror::MirrorError) -> Self {
        Self {
            reason: error.for_agent(),
            logged: false,
            detail: Some(error.to_string()),
        }
    }
}

/// The push decided, `docs/flows.md` § 3: the lease again now that the pack is in (it may have
/// been revoked or have expired since the push started; only a refusal is logged here), the
/// mirror held and the push read from the quarantine, `Service::push`, then upstream.
async fn decide_push(
    gateway: &Gateway,
    context: &PushContext,
    quarantine: Option<&str>,
    updates: &[RefUpdate],
) -> Result<(), Denied> {
    if updates.is_empty() || updates.len() > MAX_UPDATES {
        return Err(Denied::new(format!(
            "a push updates from 1 to {MAX_UPDATES} refs"
        )));
    }
    // The lease, and its ref rules on the updates as git sent them: the cheapest checks,
    // before the mirror is held and any git runs for an update (the review after M7.6, G-9).
    let unread = updates
        .iter()
        .map(|u| {
            Ok(policy::RefUpdate {
                name: u.name.to_string(),
                old: commit_id(&u.old)?,
                new: commit_id(&u.new)?,
                // Known only once the quarantine is read: `Service::push` decides on them.
                fast_forward: true,
                case_twin: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(Denied::new)?;
    let lease = match gateway
        .may_push_refs(&context.cert, &context.caller, &context.repo, unread)
        .await
    {
        Ok(lease) => lease,
        Err(denial) => {
            // A violation may have revoked the lease: its other sessions go now.
            if gateway.service().is_revoked(context.cert.serial) {
                gateway.drop_sessions_except(context.cert.serial, context.connection);
            }
            return Err(Denied::logged(&denial));
        }
    };
    let quarantine = hold_mirror(gateway, context, quarantine).await?;
    // Bounded as a whole, the mirror held: each git it runs is killed with its group when the
    // deadline drops it.
    let read = tokio::time::timeout(
        writ_mirror::LOCAL_WORK_DEADLINE,
        read_push(gateway, &quarantine, updates, &lease, &context.repo),
    )
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "reading the push took more than {} s",
            writ_mirror::LOCAL_WORK_DEADLINE.as_secs()
        ))
    });
    let (updates, commits, pack_size) = read.map_err(Denied::new)?;
    let pushing = Pushing {
        cert: context.cert.clone(),
        caller: context.caller.clone(),
        repo: context.repo.clone(),
        updates,
        commits,
        pack_size,
    };
    let in_flight = match gateway.push(pushing.clone()).await {
        Ok(in_flight) => in_flight,
        Err(denial) => {
            // A violation may have revoked the lease: its other sessions go now.
            if gateway.service().is_revoked(context.cert.serial) {
                gateway.drop_sessions_except(context.cert.serial, context.connection);
            }
            return Err(Denied::logged(&denial));
        }
    };
    // In flight until upstream answered, whatever it said: the lease isn't marked used up by
    // the push's own count before it gets there (the review after M7.6, A-3).
    let lease = in_flight.lease().id.clone();
    let upstream = go_upstream(gateway, context, &quarantine, &pushing.updates).await;
    gateway.push_ended(in_flight).await;
    upstream?;
    // Upstream has the commits: their notes, if the repo asks for them, once git gave the
    // mirror back.
    let commits = pushing.commits.into_iter().map(|(id, _)| id).collect();
    crate::notes::after_push(gateway, &lease, &context.repo, commits);
    Ok(())
}

/// The repo's mirror, held for the push until receive-pack exits (the push's `Push` releases
/// it), and the push's quarantine in it.
async fn hold_mirror(
    gateway: &Gateway,
    context: &PushContext,
    quarantine: Option<&str>,
) -> Result<Quarantine, Denied> {
    let mirrors = gateway.mirrors().map_err(Denied::new)?;
    let guard = mirrors
        .lock(&context.repo)
        .await
        .map_err(|e| Denied::new(e.to_string()))?;
    let mirror = guard.path().to_owned();
    *context
        .held
        .lock()
        .map_err(|_| Denied::new("internal error"))? = Some(guard);
    let policy = gateway.service().policy();
    let entry = policy
        .repo(&context.repo)
        .ok_or_else(|| Denied::new(format!("repo {} is not in the registry", context.repo)))?;
    Quarantine::open(
        mirrors.git(),
        &mirror,
        quarantine.map(std::path::Path::new),
        entry.object_format,
    )
    .map_err(|e| Denied::new(e.to_string()))
}

/// The accepted push, upstream, before git moves the mirror's refs: the lease looked at once
/// more (a revocation that came while the push was read stops it here), then the upstream push
/// from the quarantine. The mirror is marked stale either way (the next fetch syncs it). A
/// push upstream refused, or failed, is refused here with the remote's reason, and logged:
/// the mirror never holds a ref the remote didn't take.
async fn go_upstream(
    gateway: &Gateway,
    context: &PushContext,
    quarantine: &Quarantine,
    updates: &[policy::RefUpdate],
) -> Result<(), Denied> {
    if let Err(denial) = gateway
        .may_push(&context.cert, &context.caller, &context.repo)
        .await
    {
        return Err(Denied::logged(&denial));
    }
    let upstream: Vec<writ_mirror::UpstreamUpdate> = updates
        .iter()
        .map(|u| writ_mirror::UpstreamUpdate {
            name: u.name.clone(),
            old: u.old.as_ref().map(|id| id.as_str().to_owned()),
            new: u.new.as_ref().map(|id| id.as_str().to_owned()),
        })
        .collect();
    // The guard leaves its slot for the push (no lock is held across an await), and goes back.
    let taken = context.held.lock().ok().and_then(|mut held| held.take());
    let Some(mut guard) = taken else {
        return Err(Denied::new("internal error"));
    };
    let pushed = guard.push_upstream(quarantine, &upstream).await;
    guard.mark_stale();
    // poisoned: the guard is dropped, releasing the mirror early; the refs git moves next are
    // the ones upstream just took, and the mirror is stale (synced again first).
    if let Ok(mut held) = context.held.lock() {
        *held = Some(guard);
    }
    pushed.map_err(|e| Denied::upstream(&e))
}

/// The facts of a push, read from the quarantine: the ref updates as the policy sees them,
/// the new commits with the digest of the paths each touches, the size.
type PushFacts = (Vec<policy::RefUpdate>, Vec<(CommitId, Option<String>)>, u64);

async fn read_push(
    gateway: &Gateway,
    quarantine: &Quarantine,
    updates: &[RefUpdate],
    lease: &Lease,
    repo: &RepoName,
) -> Result<PushFacts, String> {
    let tips: Vec<String> = updates
        .iter()
        .filter(|u| !is_zero(&u.new))
        .map(|u| u.new.clone())
        .collect();
    let kinds = quarantine.kinds(&tips).await.map_err(|e| e.to_string())?;
    if let Some((tip, kind)) = tips.iter().zip(&kinds).find(|(_, kind)| *kind != "commit") {
        return Err(format!("{tip} is a {kind}, not a commit"));
    }
    let facts = read_updates(quarantine, updates).await?;
    let commits = read_commits(gateway, quarantine, &tips, lease, repo).await?;
    let size_of = quarantine.clone();
    let pack_size = tokio::task::spawn_blocking(move || size_of.size())
        .await
        .map_err(|_| "internal error".to_owned())?
        .map_err(|e| e.to_string())?;
    Ok((facts, commits, pack_size))
}

/// Whether `id` is git's null id (a ref created, or deleted).
fn is_zero(id: &str) -> bool {
    id.bytes().all(|b| b == b'0')
}

/// An id from git's input; `None` for the null id.
fn commit_id(id: &str) -> Result<Option<CommitId>, String> {
    if is_zero(id) {
        return Ok(None);
    }
    id.parse()
        .map(Some)
        .map_err(|_| format!("{id} is not an object id"))
}

/// Each ref update as the policy sees it, read under the held mirror: its `old` must be the
/// ref's value in the mirror (git hands the hook the `old` the client wrote, unchecked: the
/// review after M7.6, G-6, a false `old` chose the ancestor a fast-forward was computed
/// against, and skipped the case check), whether it moves forward from there, and, whenever
/// the mirror has no ref of exactly this name, whether it has one with the same name ignoring
/// case.
async fn read_updates(
    quarantine: &Quarantine,
    updates: &[RefUpdate],
) -> Result<Vec<policy::RefUpdate>, String> {
    let mut facts = Vec::with_capacity(updates.len());
    for update in updates {
        let (old, new) = (commit_id(&update.old)?, commit_id(&update.new)?);
        let name = update.name.as_str();
        let state = quarantine
            .ref_state(name)
            .await
            .map_err(|e| e.to_string())?;
        if state.value.as_deref() != old.as_ref().map(CommitId::as_str) {
            let is = state.value.as_deref().unwrap_or("absent");
            let said = old.as_ref().map_or("absent", CommitId::as_str);
            return Err(format!(
                "{name} is {is} in the repo, not {said} as the push says: fetch, then push again"
            ));
        }
        let fast_forward = match (&old, &new) {
            (Some(old), Some(new)) => quarantine
                .is_ancestor(old.as_str(), new.as_str())
                .await
                .map_err(|e| e.to_string())?,
            _ => true,
        };
        let case_twin = state.value.is_none() && state.case_twin;
        facts.push(policy::RefUpdate {
            name: update.name.to_string(),
            old,
            new,
            fast_forward,
            case_twin,
        });
    }
    Ok(facts)
}

/// The commits the push brings (at most the repository's `max_signatures` in the lease, and
/// [`MAX_PUSH_COMMITS`]), each with the digest of the paths it touches when the ledger holds
/// it for this lease and repo with its paths: the others are decided without them (refused,
/// or nothing to compare), so they are never walked.
async fn read_commits(
    gateway: &Gateway,
    quarantine: &Quarantine,
    tips: &[String],
    lease: &Lease,
    repo: &RepoName,
) -> Result<Vec<(CommitId, Option<String>)>, String> {
    let signatures = lease
        .ticket
        .terms(repo)
        .map_or(0, |terms| terms.limits.max_signatures);
    let max = usize::try_from(signatures)
        .unwrap_or(usize::MAX)
        .min(MAX_PUSH_COMMITS);
    let new_commits = quarantine
        .new_commits(tips, max)
        .await
        .map_err(|e| format!("{e}: more than lease {} signed", lease.id))?
        .iter()
        .map(|id| commit_id(id)?.ok_or_else(|| "a null commit id".to_owned()))
        .collect::<Result<Vec<CommitId>, String>>()?;
    let to_check = gateway
        .paths_to_check(&lease.id, repo, new_commits.clone())
        .await?;
    let mut commits = Vec::with_capacity(new_commits.len());
    for id in new_commits {
        let paths = if to_check.contains(&id) {
            quarantine
                .touched_paths(id.as_str())
                .await
                .map_err(|e| e.to_string())?
        } else {
            None
        };
        commits.push((id, paths));
    }
    Ok(commits)
}

/// Writes the refusal to the audit log (event `push`, denied), off the async threads.
async fn log_refusal(gateway: &Gateway, refused: Refused) {
    let reason = refused.detail.unwrap_or(refused.reason);
    let mut denial = GatewayDenial::new(EventKind::Push, reason).refs(refused.refs);
    let caller = match &refused.context {
        Some(context) => {
            denial = denial.cert(&context.cert).repo(&context.repo);
            context.caller.clone()
        }
        None => CallerFacts::default(),
    };
    gateway.log_denial(denial, caller).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";

    mod revoked_mid_push {
        use super::super::decide;
        use super::A;
        use crate::hook::PushContext;
        use crate::{Gateway, GatewayConfig};
        use std::path::PathBuf;
        use writ_approval::testing::TestServiceBuilder;
        use writ_core::caller::CallerFacts;
        use writ_core::canonical::Canonical;
        use writ_core::policy::CertIdentity;
        use writ_core::ticket::Ticket;
        use writ_crypto::keys::{KeyKind, generate};
        use writ_crypto::ssh_key::{Certificate, HashAlg};
        use writ_proto::Decision;

        const POLICY: &str = r#"
keys:
  agent-01:
    use: signing
    format: ssh
    algorithm: ed25519
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [work]
    protected_refs: [refs/heads/main]
templates:
  work:
    operations: [fetch, push]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 0
    max_pushes: 5
    max_ops_per_minute: 100
    max_push_size: 1MB
"#;

        const TICKET: &str = r#"
repos:
  demo:
    operations: [fetch, push]
    branches: ["agent/x"]
ticket:
  title: Revoked mid-push
  task: The hook's decision
"#;

        #[tokio::test]
        async fn a_lease_revoked_while_the_pack_comes_in_moves_no_ref() {
            let dir = tempfile::tempdir().unwrap();
            // The fake clock (the builder's): nothing here goes through russh, which would
            // check the certificate's validity window against the real one.
            let test = TestServiceBuilder::new(POLICY).build(dir.path());
            let gateway = Gateway::start(
                GatewayConfig {
                    host_key: generate(KeyKind::Ed25519).unwrap(),
                    mirrors: Some(writ_mirror::testing::no_repos(dir.path()).await.unwrap()),
                    unsealer: None,
                    admin: None,
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: writ_crypto::readers::ReaderSet::default(),
                    sign_requests_per_lease: crate::DEFAULT_SIGN_REQUESTS_PER_LEASE,
                },
                test.service.clone(),
            )
            .await
            .unwrap();
            let key = generate(KeyKind::Ed25519).unwrap();
            let caller = CallerFacts::default();
            let submitted = test
                .service
                .submit(key.public_key(), TICKET.as_bytes(), &caller)
                .unwrap();
            let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
            test.service
                .approve(&ticket.id, &test.approval(&ticket), &caller)
                .unwrap();
            let Decision::Active { certificate, .. } = test
                .service
                .wait(&ticket.id, key.public_key())
                .await
                .unwrap()
            else {
                panic!("expected an active lease");
            };
            let certificate = Certificate::from_openssh(&certificate).unwrap();
            let cert = CertIdentity {
                key_id: certificate.key_id().to_owned(),
                serial: certificate.serial(),
                session_key: certificate
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string()
                    .parse()
                    .unwrap(),
            };
            gateway.shared.pushes.lock().unwrap().insert(
                "tok".to_owned(),
                PushContext {
                    cert,
                    repo: "demo".parse().unwrap(),
                    caller,
                    connection: 1,
                    held: std::sync::Arc::new(std::sync::Mutex::new(None)),
                    decided: std::sync::Arc::default(),
                },
            );
            let input = format!("tok\n\n{A} {A} refs/heads/agent/x\n");

            // In force: the decision goes past the lease, to the repo's mirror (none here: the
            // gateway's own tests have no upstream). The denial below is the revocation's.
            let in_force = decide(&gateway, input.as_bytes()).await;
            assert!(
                matches!(&in_force, Err(r) if r.reason == "unknown repo demo" && !r.logged),
                "{:?}",
                in_force.err().map(|r| r.reason)
            );

            test.service
                .revoke(
                    &ticket.id,
                    &test.revocation(&ticket.id),
                    &CallerFacts::default(),
                )
                .unwrap();
            let refused = match decide(&gateway, input.as_bytes()).await {
                Ok(()) => panic!("a revoked lease's push was accepted"),
                Err(refused) => refused,
            };
            assert_eq!(
                refused.reason,
                format!("lease {} is revoked", ticket.id),
                "the service's denial"
            );
            assert!(refused.logged, "logged once, by the service");
            let denied = test.events("push", "denied");
            assert_eq!(denied.len(), 1);
            assert_eq!(denied[0]["code"], "not_active");
        }

        #[tokio::test]
        async fn a_poisoned_table_never_keeps_a_revoked_push() {
            let dir = tempfile::tempdir().unwrap();
            let test = TestServiceBuilder::new(POLICY).build(dir.path());
            let gateway = Gateway::start(
                GatewayConfig {
                    host_key: generate(KeyKind::Ed25519).unwrap(),
                    mirrors: Some(writ_mirror::testing::no_repos(dir.path()).await.unwrap()),
                    unsealer: None,
                    admin: None,
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: writ_crypto::readers::ReaderSet::default(),
                    sign_requests_per_lease: crate::DEFAULT_SIGN_REQUESTS_PER_LEASE,
                },
                test.service.clone(),
            )
            .await
            .unwrap();
            let key = generate(KeyKind::Ed25519).unwrap();
            let cert = CertIdentity {
                key_id: "wrt_01JD8X0000000000000000000A".to_owned(),
                serial: 7,
                session_key: key
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string()
                    .parse()
                    .unwrap(),
            };
            gateway.shared.pushes.lock().unwrap().insert(
                "tok".to_owned(),
                PushContext {
                    cert,
                    repo: "demo".parse().unwrap(),
                    caller: CallerFacts::default(),
                    connection: 1,
                    held: std::sync::Arc::new(std::sync::Mutex::new(None)),
                    decided: std::sync::Arc::default(),
                },
            );
            // A panic while holding the tables poisons them.
            let poisoner = gateway.clone();
            let _ = std::thread::spawn(move || {
                let _pushes = poisoner.shared.pushes.lock().unwrap();
                let _sessions = poisoner.shared.sessions.lock().unwrap();
                panic!("poison");
            })
            .join();
            assert!(gateway.shared.pushes.is_poisoned());
            gateway.drop_sessions(7);
            let pushes = gateway
                .shared
                .pushes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                pushes.is_empty(),
                "the revoked lease's push is forgotten anyway"
            );
        }
    }

    mod accept_loop {
        use super::super::serve_from;
        use crate::{Gateway, GatewayConfig};
        use std::collections::VecDeque;
        use std::io;
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        use writ_approval::testing::TestServiceBuilder;
        use writ_crypto::keys::{KeyKind, generate};
        use writ_platform::clock::system::SystemClock;

        const POLICY: &str = r#"
keys:
  upstream-01:
    use: upstream
    kind: ssh
    algorithm: ed25519
upstream_hosts:
  remote.invalid:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    templates: [read]
templates:
  read:
    operations: [fetch]
    max_ttl: 1h
    max_signatures: 0
    max_pushes: 0
    max_ops_per_minute: 10
    max_push_size: 1MB
"#;

        /// Sends a hook's input for a push the daemon doesn't know, returns the answer.
        async fn ask(mut stream: UnixStream) -> String {
            stream.write_all(b"no-such-token\n\n").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            reply
        }

        #[tokio::test]
        async fn a_transient_accept_error_never_ends_the_hook_server() {
            let dir = tempfile::tempdir().unwrap();
            let test = TestServiceBuilder::new(POLICY)
                .clock(Arc::new(SystemClock))
                .build(dir.path());
            let gateway = Gateway::start(
                GatewayConfig {
                    host_key: generate(KeyKind::Ed25519).unwrap(),
                    mirrors: Some(writ_mirror::testing::no_repos(dir.path()).await.unwrap()),
                    unsealer: None,
                    admin: None,
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: writ_crypto::readers::ReaderSet::default(),
                    sign_requests_per_lease: crate::DEFAULT_SIGN_REQUESTS_PER_LEASE,
                },
                test.service.clone(),
            )
            .await
            .unwrap();
            let (first, first_server_side) = UnixStream::pair().unwrap();
            let (second, second_server_side) = UnixStream::pair().unwrap();
            // Out of descriptors and a reset before and between the connections, then the
            // socket itself gone (EBADF).
            let script = Mutex::new(VecDeque::from([
                Err(io::Error::from_raw_os_error(24)),
                Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
                Ok(first_server_side),
                Err(io::Error::from_raw_os_error(24)),
                Ok(second_server_side),
                Err(io::Error::from_raw_os_error(9)),
            ]));
            let accept = move || {
                let item = script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Err(io::Error::from_raw_os_error(9)));
                async move { item }
            };
            let server = tokio::spawn(serve_from(gateway, accept));

            // Both connections are answered: neither error ended the server.
            assert_eq!(ask(first).await, "deny unknown push\n");
            assert_eq!(ask(second).await, "deny unknown push\n");
            // A lasting error does end it.
            server.await.unwrap();
            let denied = test.events("push", "denied");
            assert_eq!(denied.len(), 2);
            assert!(denied.iter().all(|e| e["reason"] == "unknown push"));
        }
    }

    async fn read(bytes: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            let _ = ours.write_all(&bytes).await;
            let _ = ours.shutdown().await;
        });
        let result = read_input(&mut theirs).await;
        drop(theirs);
        let _ = writer.await;
        result
    }

    fn line(name: &str) -> String {
        format!("{A} {A} {name}\n")
    }

    #[tokio::test]
    async fn input_over_the_limit_is_refused_not_cut() {
        // The cut would land inside the last line: `refs/heads/main` read as `refs/heads/mai`.
        let mut input = "token\n".to_owned();
        let last = line("refs/heads/main");
        while input.len() + last.len() <= MAX_HOOK_INPUT + 3 {
            input.push_str(&line("refs/heads/agent/x"));
        }
        input.push_str(&last);
        assert!(input.len() > MAX_HOOK_INPUT);
        assert_eq!(
            read(input.into_bytes()).await,
            Err("the push updates too many refs")
        );
    }

    #[tokio::test]
    async fn input_at_the_limit_is_read_whole() {
        let mut input = "token\n".to_owned();
        while input.len() + line("refs/heads/agent/x").len() <= MAX_HOOK_INPUT {
            input.push_str(&line("refs/heads/agent/x"));
        }
        let pad = MAX_HOOK_INPUT - input.len();
        input.insert_str(0, &"t".repeat(pad));
        assert_eq!(input.len(), MAX_HOOK_INPUT);
        assert_eq!(
            read(input.clone().into_bytes()).await,
            Ok(input.into_bytes())
        );
    }

    #[tokio::test]
    async fn input_cut_short_is_refused() {
        let mut input = format!("token\n{}", line("refs/heads/main"));
        input.pop();
        assert_eq!(read(input.into_bytes()).await, Err("malformed hook input"));
        assert_eq!(read(Vec::new()).await, Err("malformed hook input"));
    }

    #[test]
    fn every_line_must_be_an_update() {
        let ok = format!("tok\n/q\n{}{}", line("refs/heads/a"), line("refs/heads/b"));
        let (token, quarantine, updates) = parse_input(ok.as_bytes()).unwrap();
        assert_eq!((token, quarantine), ("tok", Some("/q")));
        assert_eq!(updates.len(), 2);
        // No quarantine (a push that only deletes): an empty line.
        let none = format!("tok\n\n{}", line("refs/heads/a"));
        assert_eq!(parse_input(none.as_bytes()).map(|(_, q, _)| q), Ok(None));
        assert_eq!(parse_input(b"tok\n\n").map(|(_, _, u)| u.len()), Ok(0));
        for bad in [
            format!("\n\n{}", line("refs/heads/a")),
            "tok\n".to_owned(),
            format!("tok\n\n\n{}", line("refs/heads/a")),
            format!("tok\n\n{}junk\n", line("refs/heads/a")),
            format!("tok\n\n{A} {A} refs/heads/mai n\n"),
        ] {
            let error = parse_input(bad.as_bytes()).map(|_| ()).unwrap_err();
            assert!(
                matches!(error, "malformed hook input" | "malformed ref update"),
                "{bad:?}: {error}"
            );
        }
        assert_eq!(
            parse_input(&[b't', b'\n', b'\n', 0xff, b'\n']).map(|_| ()),
            Err("malformed hook input")
        );
    }
}
