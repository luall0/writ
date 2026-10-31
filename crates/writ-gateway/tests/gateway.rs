//! The gateway on the platform fakes only: an in-memory transport, a fake attestor, an
//! in-process SSH client and an in-process HTTPS client pinning the daemon's certificate.
//! Who may run what on which listener, the whole ticket flow over the protocol, open sessions
//! dropped when a lease is revoked, and the audit line of everything the gateway turns away.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use writ_approval::testing::{TestServiceBuilder, sign_approval, sign_revocation};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::ticket::Ticket;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, PrivateKey};
use writ_crypto::tls::TlsIdentity;
use writ_gateway::{Gateway, GatewayConfig, Role};
use writ_platform::PeerInfo;
use writ_platform::clock::system::SystemClock;
use writ_platform::testing::{FakeAttestor, FakeConnector, FakeTransport, eventually_async};
use writ_proto::{Ack, ApiError, Command, Decision, Decisions, Info, Listing, Submitted};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
    upstream_credential: upstream-01
  other:
    upstream: ssh://git@forge.invalid/other.git
    upstream_credential: upstream-01
templates:
  work:
    repos: [demo]
    operations: [fetch, commit_sign]
    branches: ["agent/*"]
    committer_emails: ["agent@writ"]
    signing_key: agent-01
    max_ttl: 1h
    max_signatures: 10
    max_pushes: 0
    max_ops_per_minute: 100
    max_push_size: 1MB
"#;

const TICKET: &str = r#"
scope:
  repos: [demo]
  operations: [fetch, commit_sign]
  branches: ["agent/x"]
ticket:
  title: Gateway test
  task: Over the fakes
"#;

struct Accept;

impl client::Handler for Accept {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Daemon {
    dir: tempfile::TempDir,
    gateway: Gateway,
    agents: FakeConnector,
    approvals: FakeConnector,
    https: FakeConnector,
    /// The pin of the HTTPS approval API's certificate.
    pin: String,
    approver: PrivateKey,
}

fn peer() -> PeerInfo {
    PeerInfo::Memory {
        label: "test".into(),
    }
}

impl Daemon {
    async fn start(attestor: FakeAttestor) -> Self {
        let dir = tempfile::tempdir().unwrap();
        // The system clock: russh checks a certificate's validity window against it itself,
        // so the service must issue certificates valid now. Nothing here waits on time.
        let test = TestServiceBuilder::new(POLICY)
            .clock(Arc::new(SystemClock))
            .build(dir.path());
        let approver = test.approver.clone();
        let service = test.service.clone();
        let gateway = Gateway::start(
            GatewayConfig {
                host_key: generate(KeyKind::Ed25519).unwrap(),
                repos_root: dir.path().join("repos"),
                signing_key: generate(KeyKind::Ed25519).unwrap(),
                hook_program: PathBuf::from("/bin/false"),
                state_dir: dir.path().join("run"),
            },
            service,
        )
        .await
        .unwrap();
        let attestor = Arc::new(attestor);
        let generated = writ_crypto::tls::generate_self_signed().unwrap();
        let identity =
            Arc::new(TlsIdentity::from_pem(&generated.cert_pem, &generated.key_pem).unwrap());
        let pin = identity.fingerprint().to_owned();
        let (https_transport, https) = FakeTransport::new();
        let (g, a) = (gateway.clone(), attestor.clone());
        tokio::spawn(async move { g.serve_https(Arc::new(https_transport), a, identity).await });
        let (agent_transport, agents) = FakeTransport::new();
        let (approval_transport, approvals) = FakeTransport::new();
        for (transport, role) in [
            (agent_transport, Role::Agents),
            (approval_transport, Role::Approvals),
        ] {
            let (g, a) = (gateway.clone(), attestor.clone());
            tokio::spawn(async move { g.serve(Arc::new(transport), a, role).await });
        }
        Self {
            dir,
            gateway,
            agents,
            approvals,
            https,
            pin,
            approver,
        }
    }

    /// The audit log's lines with this event and result.
    fn audit(&self, event: &str, result: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["event"] == event && e["result"] == result)
            .collect()
    }

    async fn connect(connector: &FakeConnector) -> Handle<Accept> {
        let stream = connector.connect(peer()).await.unwrap();
        client::connect_stream(Arc::new(client::Config::default()), stream, Accept)
            .await
            .unwrap()
    }

    /// Connects and authenticates with a plain key; returns whether it was accepted.
    async fn with_key(
        connector: &FakeConnector,
        user: &str,
        key: &PrivateKey,
    ) -> Option<Handle<Accept>> {
        let mut handle = Self::connect(connector).await;
        let auth = handle
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
            )
            .await
            .unwrap();
        auth.success().then_some(handle)
    }

    async fn with_cert(
        connector: &FakeConnector,
        key: &PrivateKey,
        cert: &Certificate,
    ) -> Option<Handle<Accept>> {
        let mut handle = Self::connect(connector).await;
        let auth = handle
            .authenticate_openssh_cert("git", Arc::new(key.clone()), cert.clone())
            .await
            .unwrap();
        auth.success().then_some(handle)
    }
}

/// Runs a command: (stdout, stderr, exit status).
async fn exec(handle: &Handle<Accept>, line: &str, body: &[u8]) -> (Vec<u8>, String, Option<u32>) {
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, line).await.unwrap();
    if !body.is_empty() {
        channel.data_bytes(body.to_vec()).await.unwrap();
    }
    channel.eof().await.unwrap();
    let (mut out, mut err, mut status) = (Vec::new(), Vec::new(), None);
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    (out, String::from_utf8_lossy(&err).into_owned(), status)
}

async fn call<T: serde::de::DeserializeOwned>(
    handle: &Handle<Accept>,
    command: Command,
    body: &[u8],
) -> Result<T, ApiError> {
    let (out, _, _) = exec(handle, &command.line(), body).await;
    writ_proto::decode_reply(&out)
}

/// A lease through the protocol: submit, approve, wait. Returns the session key and the
/// certificate.
async fn lease(daemon: &Daemon) -> (PrivateKey, Certificate) {
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let submitted: Submitted = call(&agent, Command::Request, TICKET.as_bytes())
        .await
        .unwrap();
    let approver = Daemon::with_key(
        &daemon.approvals,
        "writ",
        &generate(KeyKind::Ed25519).unwrap(),
    )
    .await
    .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    let request = sign_approval(&daemon.approver, &ticket);
    let _: Ack = call(
        &approver,
        Command::Approve {
            id: submitted.id.clone(),
        },
        &writ_proto::encode_body(&request).unwrap(),
    )
    .await
    .unwrap();
    let decision: Decision = call(&agent, Command::Wait { id: submitted.id }, b"")
        .await
        .unwrap();
    let Decision::Active { certificate, .. } = decision else {
        panic!("expected a lease, got {decision:?}");
    };
    (key, Certificate::from_openssh(&certificate).unwrap())
}

#[tokio::test]
async fn the_ticket_flow_runs_over_the_protocol() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert).await;
    assert!(
        holder.is_some(),
        "the certificate of an active lease gets in"
    );
    let approver = Daemon::with_key(
        &daemon.approvals,
        "writ",
        &generate(KeyKind::Ed25519).unwrap(),
    )
    .await
    .unwrap();
    let info: Info = call(&approver, Command::Info, b"").await.unwrap();
    assert_eq!(info.decisions, Decisions::Signed);
    let listing: Listing = call(&approver, Command::List { all: false }, b"")
        .await
        .unwrap();
    assert_eq!(listing.tickets.len(), 1);
}

#[tokio::test]
async fn each_identity_runs_only_its_own_commands() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let id = cert.key_id().to_owned();

    // Lease holders authenticate with a certificate, as `git` only.
    assert!(
        Daemon::with_key(&daemon.agents, "git", &key)
            .await
            .is_none(),
        "plain key as git"
    );
    let session = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    for line in [
        "writ ls",
        &format!("writ approve {id}"),
        &format!("writ revoke {id}"),
        "writ-sign git",
        "git-upload-pack 'demo.git'",
    ] {
        let (_, err, status) = exec(&session, line, b"").await;
        assert_eq!(status, Some(1), "session key ran {line}");
        assert!(err.contains("not allowed"), "{line}: {err}");
    }
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    for line in ["writ ls", "writ request", &format!("writ wait {id}")] {
        let (_, err, status) = exec(&holder, line, b"").await;
        assert_eq!(status, Some(1), "lease holder ran {line}");
        assert!(err.contains("not allowed"), "{line}: {err}");
    }
    let approver = Daemon::with_key(
        &daemon.approvals,
        "writ",
        &generate(KeyKind::Ed25519).unwrap(),
    )
    .await
    .unwrap();
    for line in [
        "writ request",
        &format!("writ wait {id}"),
        "writ-sign git",
        "sh -c id",
    ] {
        let (_, err, status) = exec(&approver, line, b"").await;
        assert_eq!(status, Some(1), "approver ran {line}");
        assert!(err.contains("not allowed"), "{line}: {err}");
    }
    // A certificate on the approval listener grants nothing more than any key.
    let on_approvals = Daemon::with_cert(&daemon.approvals, &key, &cert)
        .await
        .unwrap();
    let (_, _, status) = exec(&on_approvals, "writ-sign git", b"x").await;
    assert_eq!(status, Some(1));
}

#[tokio::test]
async fn a_caller_the_attestor_cannot_attest_is_turned_away() {
    let daemon = Daemon::start(FakeAttestor::failing()).await;
    let stream = daemon.agents.connect(peer()).await.unwrap();
    let connected =
        client::connect_stream(Arc::new(client::Config::default()), stream, Accept).await;
    assert!(
        connected.is_err(),
        "no SSH session without attested caller facts"
    );
    // Logged before the connection is dropped.
    let lines = daemon.audit("connect", "denied");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("caller turned away: "),
        "{lines:?}"
    );
}

#[tokio::test]
async fn git_runs_only_on_the_lease_repos_and_every_refusal_is_logged() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    let id = cert.key_id();

    // In the registry, not in the lease.
    let (_, err, status) = exec(&holder, "git-upload-pack 'other.git'", b"").await;
    assert_eq!(status, Some(1));
    assert!(
        err.contains(&format!(
            "outside ticket {id}: repo other is not in the lease"
        )),
        "{err}"
    );
    // The lease has no push: the service denies it before any repo is looked at.
    let (_, err, status) = exec(&holder, "git-receive-pack 'demo.git'", b"").await;
    assert_eq!(status, Some(1));
    assert!(
        err.contains(&format!("outside ticket {id}: push not allowed")),
        "{err}"
    );
    // In the lease, but no repository on disk.
    let (_, err, status) = exec(&holder, "git-upload-pack 'demo.git'", b"").await;
    assert_eq!(status, Some(1));
    assert!(err.contains("unknown repo demo"), "{err}");
    // A command nobody may run.
    let (_, err, status) = exec(&holder, "sh -c id", b"").await;
    assert_eq!(status, Some(1));
    assert!(err.contains("not allowed"), "{err}");

    let fetches = daemon.audit("fetch", "denied");
    assert_eq!(fetches.len(), 2, "{fetches:?}");
    for line in &fetches {
        assert_eq!(line["cert"], cert.serial());
        assert_eq!(line["lease"], id);
    }
    assert_eq!(fetches[0]["repo"], "other");
    assert_eq!(fetches[1]["repo"], "demo");
    assert_eq!(fetches[1]["reason"], "unknown repo demo");
    // The lease doesn't allow push: the service denied it before the repo check.
    let pushes = daemon.audit("push", "denied");
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!(pushes[0]["code"], "operation");
    let commands = daemon.audit("command", "denied");
    assert_eq!(commands.len(), 1, "{commands:?}");
    assert_eq!(commands[0]["cert"], cert.serial());
    assert!(commands[0]["reason"].as_str().unwrap().contains("sh -c id"));
}

#[tokio::test]
async fn revoking_drops_open_sessions_and_refuses_the_next_connection() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    // Registered by the server once authentication completes, which the client can't see.
    eventually_async("the session to be registered", || {
        daemon.gateway.open_sessions(cert.serial()) == 1
    })
    .await;

    let approver = Daemon::with_key(
        &daemon.approvals,
        "writ",
        &generate(KeyKind::Ed25519).unwrap(),
    )
    .await
    .unwrap();
    let id: writ_core::names::TicketId = cert.key_id().parse().unwrap();
    let request = sign_revocation(&daemon.approver, &id);
    let _: Ack = call(
        &approver,
        Command::Revoke { id },
        &writ_proto::encode_body(&request).unwrap(),
    )
    .await
    .unwrap();

    eventually_async("the open session to be dropped", || holder.is_closed()).await;
    assert_eq!(daemon.gateway.open_sessions(cert.serial()), 0);
    assert!(
        Daemon::with_cert(&daemon.agents, &key, &cert)
            .await
            .is_none()
    );
}

// ----- HTTPS ----------------------------------------------------------------------------

/// One HTTPS request to the daemon's approval API: (status, body). Errors if TLS fails.
async fn https(
    daemon: &Daemon,
    pin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    // The client side the CLI uses: exactly the pinned certificate.
    let config = writ_crypto::tls::pinned_client_config(pin).unwrap();
    let stream = daemon
        .https
        .connect(peer())
        .await
        .map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("writd").unwrap(),
            stream,
        )
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
    tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "writd")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .unwrap();
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, bytes.to_vec()))
}

async fn https_call<T: serde::de::DeserializeOwned>(
    daemon: &Daemon,
    command: Command,
    body: &[u8],
) -> (u16, Result<T, ApiError>) {
    let (method, path) = command.http_route().unwrap();
    let (status, bytes) = https(daemon, &daemon.pin, method, &path, body.to_vec())
        .await
        .unwrap();
    (status, writ_proto::decode_reply(&bytes))
}

#[tokio::test]
async fn the_approval_api_works_the_same_over_https() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let submitted: Submitted = call(&agent, Command::Request, TICKET.as_bytes())
        .await
        .unwrap();

    let (status, info) = https_call::<Info>(&daemon, Command::Info, b"").await;
    assert_eq!((status, info.unwrap().decisions), (200, Decisions::Signed));
    let (_, listing) = https_call::<Listing>(&daemon, Command::List { all: true }, b"").await;
    assert_eq!(listing.unwrap().tickets[0].id, submitted.id);
    let (_, shown) = https_call::<writ_proto::Shown>(
        &daemon,
        Command::Show {
            id: submitted.id.clone(),
        },
        b"",
    )
    .await;
    assert_eq!(shown.unwrap().canonical, submitted.canonical);

    // An unsigned refusal is refused (decisions: signed), with the error envelope.
    let refuse = writ_proto::RefuseRequest {
        feedback: "no".into(),
        signature: None,
    };
    let (status, refused) = https_call::<Ack>(
        &daemon,
        Command::Refuse {
            id: submitted.id.clone(),
        },
        &writ_proto::encode_body(&refuse).unwrap(),
    )
    .await;
    assert_eq!(status, 422);
    assert!(
        refused
            .unwrap_err()
            .message
            .contains("requires an approver signature")
    );

    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    let request = sign_approval(&daemon.approver, &ticket);
    let (status, ack) = https_call::<Ack>(
        &daemon,
        Command::Approve {
            id: submitted.id.clone(),
        },
        &writ_proto::encode_body(&request).unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(ack.unwrap().state, writ_core::lease::State::Active);
    let decision: Decision = call(&agent, Command::Wait { id: submitted.id }, b"")
        .await
        .unwrap();
    assert!(matches!(decision, Decision::Active { .. }));
}

#[tokio::test]
async fn https_serves_only_the_approval_routes_and_bounds_bodies() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    for (method, path) in [
        ("POST", "/v1/request"),
        ("GET", "/"),
        ("GET", "/v1/tickets?all=1"),
        ("DELETE", "/v1/info"),
    ] {
        let (status, body) = https(&daemon, &daemon.pin, method, path, Vec::new())
            .await
            .unwrap();
        assert_eq!(status, 404, "{method} {path}");
        assert!(writ_proto::decode_reply::<Info>(&body).is_err());
    }
    let id = writ_core::names::TicketId::from_parts(1_800_000_000_000, [1; 10]);
    let (status, _) = https(
        &daemon,
        &daemon.pin,
        "POST",
        &format!("/v1/tickets/{id}/approve"),
        vec![b' '; writ_proto::MAX_BODY + 1],
    )
    .await
    .unwrap();
    assert_eq!(status, 413);
}

#[tokio::test]
async fn https_clients_refuse_another_certificate() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let other = writ_crypto::tls::fingerprint(b"another certificate");
    let error = https(&daemon, &other, "GET", "/v1/info", Vec::new())
        .await
        .unwrap_err();
    assert!(
        error.contains("doesn't match the pinned fingerprint"),
        "{error}"
    );
}

#[tokio::test]
async fn https_turns_away_a_caller_the_attestor_cannot_attest() {
    let daemon = Daemon::start(FakeAttestor::failing()).await;
    let pin = daemon.pin.clone();
    assert!(
        https(&daemon, &pin, "GET", "/v1/info", Vec::new())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bodies_are_read_up_to_their_limit_and_refused_past_it() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let too_large = format!("the request is larger than {} bytes", writ_proto::MAX_BODY);
    // At the limit: read whole, then judged as a ticket (not YAML here).
    let at_limit = vec![b'#'; writ_proto::MAX_BODY];
    let (_, err, status) = exec(&agent, "writ request", &at_limit).await;
    assert_eq!(status, Some(1));
    assert!(!err.contains(&too_large), "{err}");
    assert!(err.contains("ticket"), "{err}");
    // One byte over: refused for its size.
    let over = vec![b'#'; writ_proto::MAX_BODY + 1];
    let (_, err, status) = exec(&agent, "writ request", &over).await;
    assert_eq!(status, Some(1));
    assert!(err.contains(&too_large), "{err}");

    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    let limit = usize::try_from(writ_gateway::MAX_SIGN_INPUT).unwrap();
    let (out, err, status) = exec(&holder, "writ-sign git", &vec![b'x'; limit]).await;
    assert_eq!(status, Some(0), "{err}");
    assert!(
        String::from_utf8(out)
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE-----")
    );
    let (out, err, status) = exec(&holder, "writ-sign git", &vec![b'x'; limit + 1]).await;
    assert_eq!(status, Some(1));
    assert!(out.is_empty());
    assert!(err.contains("object too large to sign"), "{err}");
    assert_eq!(daemon.audit("sign", "denied").len(), 1);
}
