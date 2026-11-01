//! The daemon side of the hook: reads what a hook sends, decides, answers, and logs every
//! refusal. The push is decided here, when the pack is in git's quarantine and the ref updates
//! are known (`docs/flows.md` § 3):
//!
//! 1. the lease, cheaply ([`Service::may_push`](writ_approval::Service::may_push)): a lease
//!    revoked or expired while the pack was coming in moves no ref, and nothing is read for it;
//! 2. the repo's mirror held (until `receive-pack` exits), and the push read from the objects
//!    git verified ([`writ_mirror::quarantine`]): each new tip a commit, the commits the mirror
//!    doesn't have (at most the lease's `max_signatures`), fast-forwards, refs that differ only
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
use writ_core::names::CommitId;
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
}

impl Refused {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            context: None,
            refs: Vec::new(),
            logged: false,
        }
    }

    fn of(reason: impl Into<String>, context: PushContext, refs: Vec<String>) -> Self {
        Self {
            reason: reason.into(),
            context: Some(Box::new(context)),
            refs,
            logged: false,
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
        .take(limit + 1)
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
    if updates.is_empty() || updates.len() > MAX_UPDATES {
        let reason = format!("a push updates from 1 to {MAX_UPDATES} refs");
        return Err(Refused::of(reason, context, refs));
    }
    // The lease again, now that the pack is in: it may have been revoked or have expired
    // since the push started. Only a refusal is logged here.
    let lease = match gateway
        .may_push(&context.cert, &context.caller, &context.repo)
        .await
    {
        Ok(lease) => lease,
        Err(denial) => {
            let mut refused = Refused::of(denial.to_string(), context, refs);
            refused.logged = true;
            return Err(refused);
        }
    };
    // The mirror, held until receive-pack exits (the push's `Push` drops it).
    let guard = match gateway.shared.config.mirrors.lock(&context.repo).await {
        Ok(guard) => guard,
        Err(e) => return Err(Refused::of(e.to_string(), context, refs)),
    };
    let mirror = guard.path().to_owned();
    let held = match context.held.lock() {
        Ok(mut held) => {
            *held = Some(guard);
            true
        }
        Err(_) => false,
    };
    if !held {
        return Err(Refused::of("internal error", context, refs));
    }
    let Some(entry) = gateway.service().policy().repo(&context.repo) else {
        let reason = format!("repo {} is not in the registry", context.repo);
        return Err(Refused::of(reason, context, refs));
    };
    let quarantine = Quarantine::open(
        &mirror,
        quarantine.map(std::path::Path::new),
        entry.object_format,
    );
    let read = match quarantine {
        Ok(quarantine) => read_push(&quarantine, &updates, &lease).await,
        Err(e) => Err(e.to_string()),
    };
    let (updates, commits, pack_size) = match read {
        Ok(read) => read,
        Err(reason) => return Err(Refused::of(reason, context, refs)),
    };
    let pushing = Pushing {
        cert: context.cert.clone(),
        caller: context.caller.clone(),
        repo: context.repo.clone(),
        updates,
        commits,
        pack_size,
    };
    if let Err(denial) = gateway.push(pushing).await {
        // A violation may have revoked the lease: its other sessions go now.
        if gateway.service().is_revoked(context.cert.serial) {
            gateway.drop_sessions_except(context.cert.serial, context.connection);
        }
        let mut refused = Refused::of(denial.to_string(), context, refs);
        refused.logged = true;
        return Err(refused);
    }
    tracing::info!(
        lease = %context.cert.key_id,
        repo = %context.repo,
        refs = refs.len(),
        "push accepted"
    );
    Ok(())
}

/// The facts of a push, read from the quarantine: the ref updates as the policy sees them,
/// the new commits with the digest of the paths each touches, the size.
type PushFacts = (Vec<policy::RefUpdate>, Vec<(CommitId, Option<String>)>, u64);

async fn read_push(
    quarantine: &Quarantine,
    updates: &[RefUpdate],
    lease: &Lease,
) -> Result<PushFacts, String> {
    let zero = |id: &str| id.bytes().all(|b| b == b'0');
    let commit_id = |id: &str| -> Result<Option<CommitId>, String> {
        if zero(id) {
            return Ok(None);
        }
        id.parse()
            .map(Some)
            .map_err(|_| format!("{id} is not an object id"))
    };
    let tips: Vec<String> = updates
        .iter()
        .filter(|u| !zero(&u.new))
        .map(|u| u.new.clone())
        .collect();
    let kinds = quarantine.kinds(&tips).await.map_err(|e| e.to_string())?;
    if let Some((tip, kind)) = tips.iter().zip(&kinds).find(|(_, kind)| *kind != "commit") {
        return Err(format!("{tip} is a {kind}, not a commit"));
    }
    let mut facts = Vec::with_capacity(updates.len());
    for update in updates {
        let (old, new) = (commit_id(&update.old)?, commit_id(&update.new)?);
        let fast_forward = match (&old, &new) {
            (Some(old), Some(new)) => quarantine
                .is_ancestor(old.as_str(), new.as_str())
                .await
                .map_err(|e| e.to_string())?,
            _ => true,
        };
        let case_twin = match old {
            None => quarantine
                .case_twin(update.name.as_str())
                .await
                .map_err(|e| e.to_string())?,
            Some(_) => false,
        };
        facts.push(policy::RefUpdate {
            name: update.name.to_string(),
            old,
            new,
            fast_forward,
            case_twin,
        });
    }
    let max = usize::try_from(lease.ticket.limits.max_signatures)
        .unwrap_or(usize::MAX)
        .min(MAX_PUSH_COMMITS);
    let new_commits = quarantine
        .new_commits(&tips, max)
        .await
        .map_err(|e| format!("{e}: more than lease {} signed", lease.id))?;
    let mut commits = Vec::with_capacity(new_commits.len());
    for id in new_commits {
        let paths = quarantine
            .touched_paths(&id)
            .await
            .map_err(|e| e.to_string())?;
        commits.push((commit_id(&id)?.ok_or("a null commit id")?, paths));
    }
    let size_of = quarantine.clone();
    let pack_size = tokio::task::spawn_blocking(move || size_of.size())
        .await
        .map_err(|_| "internal error".to_owned())?
        .map_err(|e| e.to_string())?;
    Ok((facts, commits, pack_size))
}

/// Writes the refusal to the audit log (event `push`, denied), off the async threads.
async fn log_refusal(gateway: &Gateway, refused: Refused) {
    let mut denial = GatewayDenial::new(EventKind::Push, refused.reason).refs(refused.refs);
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
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
    protected_refs: [refs/heads/main]
templates:
  work:
    repos: [demo]
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
scope:
  repos: [demo]
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
                    mirrors: writ_mirror::testing::no_repos(dir.path()).await.unwrap(),
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: Vec::new(),
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
                    mirrors: writ_mirror::testing::no_repos(dir.path()).await.unwrap(),
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: Vec::new(),
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
repos:
  demo:
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
templates:
  read:
    repos: [demo]
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
                    mirrors: writ_mirror::testing::no_repos(dir.path()).await.unwrap(),
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: Vec::new(),
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
