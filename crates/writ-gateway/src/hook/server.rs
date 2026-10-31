//! The daemon side of the hook: reads what a hook sends, decides, answers, and logs every
//! refusal. The lease is checked again here, when the ref updates are known: a lease revoked
//! (or expired) while the pack was coming in moves no ref.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use writ_approval::{EventKind, GatewayDenial};
use writ_core::caller::CallerFacts;
use writ_core::ticket::Operation;

use super::{MAX_HOOK_INPUT, PushContext, RefUpdate, check_ref_updates};
use crate::Gateway;

pub(crate) async fn serve(gateway: Gateway, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(answer(gateway.clone(), stream));
            }
            Err(e) => {
                tracing::error!(error = %e, "hook socket failed");
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

/// The token and the ref updates. Any line that isn't a valid update refuses the push.
pub(super) fn parse_input(input: &[u8]) -> Result<(&str, Vec<RefUpdate>), &'static str> {
    let text = std::str::from_utf8(input).map_err(|_| "malformed hook input")?;
    let mut lines = text.split_terminator('\n');
    let token = lines
        .next()
        .filter(|t| !t.is_empty())
        .ok_or("malformed hook input")?;
    let updates = lines
        .map(|l| RefUpdate::parse(l).ok_or("malformed ref update"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((token, updates))
}

async fn decide(gateway: &Gateway, input: &[u8]) -> Result<(), Refused> {
    let (token, updates) = parse_input(input).map_err(Refused::new)?;
    let context = gateway
        .shared
        .pushes
        .lock()
        .map_err(|_| Refused::new("internal error"))?
        .get(token)
        .cloned()
        .ok_or_else(|| Refused::new("unknown push"))?;
    let refs = || {
        updates
            .iter()
            .map(|u| u.name.to_string())
            .collect::<Vec<_>>()
    };
    // The lease again, now that the pack is in: it may have been revoked or have expired
    // since the push started (the service logs this decision).
    let lease = match gateway
        .authorize(&context.cert, &context.caller, Some(Operation::Push))
        .await
    {
        Ok(lease) => lease,
        Err(denial) => {
            let mut refused = Refused::of(denial.to_string(), context, refs());
            refused.logged = true;
            return Err(refused);
        }
    };
    if !lease.ticket.scope.repos.contains(&context.repo) {
        let reason = format!("repo {} is no longer in lease {}", context.repo, lease.id);
        return Err(Refused::of(reason, context, refs()));
    }
    // A repo that left the registry protects nothing it used to: refuse.
    let protected = match gateway.service().policy().repo(&context.repo) {
        Some(entry) => &entry.protected_refs,
        None => {
            let reason = format!("repo {} is not in the registry", context.repo);
            return Err(Refused::of(reason, context, Vec::new()));
        }
    };
    if let Err(reason) = check_ref_updates(&updates, protected) {
        return Err(Refused::of(reason, context, refs()));
    }
    tracing::info!(
        lease = %context.cert.key_id,
        repo = %context.repo,
        refs = updates.len(),
        "push accepted"
    );
    Ok(())
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
        use std::sync::Arc;
        use writ_approval::testing::TestServiceBuilder;
        use writ_core::caller::CallerFacts;
        use writ_core::canonical::Canonical;
        use writ_core::policy::CertIdentity;
        use writ_core::ticket::Ticket;
        use writ_crypto::keys::{KeyKind, generate};
        use writ_crypto::ssh_key::{Certificate, HashAlg};
        use writ_platform::clock::system::SystemClock;
        use writ_proto::Decision;

        const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
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
            let test = TestServiceBuilder::new(POLICY)
                .clock(Arc::new(SystemClock))
                .build(dir.path());
            let gateway = Gateway::start(
                GatewayConfig {
                    host_key: generate(KeyKind::Ed25519).unwrap(),
                    repos_root: dir.path().join("repos"),
                    signing_key: generate(KeyKind::Ed25519).unwrap(),
                    hook_program: PathBuf::from("/bin/false"),
                    state_dir: dir.path().join("run"),
                    readers: Vec::new(),
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
                },
            );
            let input = format!("tok\n{A} {A} refs/heads/agent/x\n");

            // In force: the push goes through (the denial below is the revocation's doing).
            assert!(decide(&gateway, input.as_bytes()).await.is_ok());

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
        let ok = format!("tok\n{}{}", line("refs/heads/a"), line("refs/heads/b"));
        let (token, updates) = parse_input(ok.as_bytes()).unwrap();
        assert_eq!(token, "tok");
        assert_eq!(updates.len(), 2);
        assert_eq!(parse_input(b"tok\n").map(|(_, u)| u.len()), Ok(0));
        for bad in [
            format!("\n{}", line("refs/heads/a")),
            format!("tok\n\n{}", line("refs/heads/a")),
            format!("tok\n{}junk\n", line("refs/heads/a")),
            format!("tok\n{A} {A} refs/heads/mai n\n"),
        ] {
            assert!(parse_input(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse_input(&[b't', b'\n', 0xff, b'\n']).is_err());
    }
}
