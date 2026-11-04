//! The gateway on the platform fakes only: an in-memory transport, a fake attestor, an
//! in-process SSH client and an in-process HTTPS client pinning the daemon's certificate.
//! Who may run what on which listener, the whole ticket flow over the protocol, open sessions
//! dropped when a lease is revoked, and the audit line of everything the gateway turns away.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use writ_approval::testing::{TestServiceBuilder, sign_approval, sign_revocation};
use writ_core::caller::CallerFacts;
use writ_core::canonical::Canonical;
use writ_core::net::Sources;
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
    upstream: ssh://git@remote.invalid/demo.git
    upstream_credential: upstream-01
  other:
    upstream: ssh://git@remote.invalid/other.git
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
    /// The key in the daemon's `readers`: the only one the approval API lets in.
    reader: PrivateKey,
}

fn peer() -> PeerInfo {
    PeerInfo::Memory {
        label: "test".into(),
    }
}

impl Daemon {
    async fn start(attestor: FakeAttestor) -> Self {
        Self::start_with(attestor, Sources::Any).await
    }

    /// With `agents` as the sources the agents listener accepts.
    async fn start_with(attestor: FakeAttestor, agents_sources: Sources) -> Self {
        Self::start_full(attestor, agents_sources, None).await.0
    }

    /// Sealed, with `unsealer` to open it: the daemon and an unseal request signed by the
    /// approver for this boot.
    async fn start_sealed(
        unsealer: Arc<dyn writ_gateway::Unsealer>,
    ) -> (Self, Option<writ_proto::UnsealRequest>) {
        Self::start_full(
            FakeAttestor::fixed(CallerFacts::default()),
            Sources::Any,
            Some(unsealer),
        )
        .await
    }

    async fn start_full(
        attestor: FakeAttestor,
        agents_sources: Sources,
        unsealer: Option<Arc<dyn writ_gateway::Unsealer>>,
    ) -> (Self, Option<writ_proto::UnsealRequest>) {
        let dir = tempfile::tempdir().unwrap();
        let reader = generate(KeyKind::Ed25519).unwrap();
        let readers = writ_crypto::readers::parse(&format!(
            "test {}",
            reader.public_key().to_openssh().unwrap()
        ))
        .unwrap();
        // The system clock: russh checks a certificate's validity window against it itself,
        // so the service must issue certificates valid now. Nothing here waits on time.
        let mut builder = TestServiceBuilder::new(POLICY).clock(Arc::new(SystemClock));
        if unsealer.is_some() {
            builder = builder.sealed();
        }
        let test = builder.build(dir.path());
        let unseal = unsealer
            .is_some()
            .then(|| test.unseal_request(&test.approver, "the passphrase"));
        let approver = test.approver.clone();
        let service = test.service.clone();
        let gateway = Gateway::start(
            GatewayConfig {
                host_key: generate(KeyKind::Ed25519).unwrap(),
                mirrors: Some(writ_mirror::testing::no_repos(dir.path()).await.unwrap()),
                unsealer,
                admin: None,
                hook_program: PathBuf::from("/bin/false"),
                state_dir: dir.path().join("run"),
                readers: writ_crypto::readers::ReaderSet::new(readers),
                sign_requests_per_lease: writ_gateway::DEFAULT_SIGN_REQUESTS_PER_LEASE,
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
        tokio::spawn(async move {
            g.serve_https(Arc::new(https_transport), a, identity, Sources::Any)
                .await
        });
        let (agent_transport, agents) = FakeTransport::new();
        let (approval_transport, approvals) = FakeTransport::new();
        for (transport, role, sources) in [
            (agent_transport, Role::Agents, agents_sources),
            (approval_transport, Role::Approvals, Sources::Any),
        ] {
            let (g, a) = (gateway.clone(), attestor.clone());
            tokio::spawn(async move { g.serve(Arc::new(transport), a, role, sources).await });
        }
        let daemon = Self {
            dir,
            gateway,
            agents,
            approvals,
            https,
            pin,
            approver,
            reader,
        };
        (daemon, unseal)
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
    let approver = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
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
    let approver = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
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

    // Lease holders authenticate with a certificate, as `git` only; the refusal is logged.
    assert!(
        Daemon::with_key(&daemon.agents, "git", &key)
            .await
            .is_none(),
        "plain key as git"
    );
    let refused: Vec<_> = daemon
        .audit("connect", "denied")
        .into_iter()
        .filter(|l| l["reason"] == "key refused: user \"git\" takes a certificate, not a plain key")
        .collect();
    assert_eq!(refused.len(), 1);
    let session = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    for line in [
        "writ ls",
        &format!("writ approve {id}"),
        &format!("writ revoke {id}"),
        "writ-sign git demo",
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
    let approver = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
        .await
        .unwrap();
    for line in [
        "writ request",
        &format!("writ wait {id}"),
        "writ-sign git demo",
        "sh -c id",
    ] {
        let (_, err, status) = exec(&approver, line, b"").await;
        assert_eq!(status, Some(1), "approver ran {line}");
        assert!(err.contains("not allowed"), "{line}: {err}");
    }
    // A certificate on the approval listener gets nowhere: only reader keys get in.
    assert!(
        Daemon::with_cert(&daemon.approvals, &key, &cert)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn only_reader_keys_reach_the_approval_api() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let stranger = generate(KeyKind::Ed25519).unwrap();
    // Neither as `writ` nor as any other user.
    for user in ["writ", "git", "root"] {
        assert!(
            Daemon::with_key(&daemon.approvals, user, &stranger)
                .await
                .is_none(),
            "{user}"
        );
    }
    let reader = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
        .await
        .unwrap();
    let listing: Result<Listing, ApiError> = call(&reader, Command::List { all: true }, b"").await;
    assert!(listing.unwrap().tickets.is_empty());
    // The refusals are logged, coalesced: one line for the burst from this caller.
    let lines = daemon.audit("connect", "denied");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["reason"], "key refused: not in readers");
}

#[tokio::test]
async fn the_agents_listener_turns_away_other_sources() {
    let allowed: std::net::IpAddr = "10.0.0.7".parse().unwrap();
    let facts = |addr: &str| CallerFacts {
        source_addr: Some(addr.parse().unwrap()),
        process_chain: None,
    };
    let only = Sources::Only(vec!["10.0.0.0/24".parse().unwrap()]);
    let outside = Daemon::start_with(FakeAttestor::fixed(facts("10.0.1.7")), only.clone()).await;
    let stream = outside.agents.connect(peer()).await.unwrap();
    let connected =
        client::connect_stream(Arc::new(client::Config::default()), stream, Accept).await;
    // any error: russh reports the dropped connection its own way; the audit line below is
    // the exact reason.
    assert!(connected.is_err(), "no SSH session from outside the list");
    let lines = outside.audit("connect", "denied");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        lines[0]["reason"],
        "caller turned away: its address is not allowed on this listener"
    );
    assert_eq!(lines[0]["source_addr"], "10.0.1.7");

    // From inside the list, the same request goes through.
    let inside = Daemon::start_with(FakeAttestor::fixed(facts(&allowed.to_string())), only).await;
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&inside.agents, "writ", &key)
        .await
        .unwrap();
    let submitted: Result<Submitted, ApiError> =
        call(&agent, Command::Request, TICKET.as_bytes()).await;
    assert!(submitted.is_ok(), "{submitted:?}");
}

#[tokio::test]
async fn one_connection_holds_at_most_four_channels() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(agent.channel_open_session().await.unwrap());
    }
    // any error: the refusal is the gateway dropping the open; what it logged says why.
    assert!(
        agent.channel_open_session().await.is_err(),
        "a fifth channel is refused"
    );
    let refused = daemon.audit("connect", "denied");
    assert!(
        refused.iter().any(|l| l["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("channel refused: at most 4 per connection"))),
        "{refused:?}"
    );
    // A channel closed gives its slot back. The server frees it with no signal the client
    // can see, so the open is retried until it passes, within the test deadline.
    open.pop().unwrap().close().await.unwrap();
    let reopened = tokio::time::timeout(writ_platform::testing::WAIT_LIMIT, async {
        loop {
            if let Ok(channel) = agent.channel_open_session().await {
                return channel;
            }
            // poll: the server frees the slot with no signal; bounded by WAIT_LIMIT above.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(reopened.is_ok(), "the closed channel's slot came back");
}

#[tokio::test]
async fn only_the_listed_ssh_algorithms_are_spoken() {
    use std::borrow::Cow;
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let with = |preferred: russh::Preferred| async {
        let stream = daemon.agents.connect(peer()).await.unwrap();
        let config = client::Config {
            preferred,
            ..Default::default()
        };
        client::connect_stream(Arc::new(config), stream, Accept).await
    };
    // The client's defaults meet the gateway's list.
    assert!(with(russh::Preferred::DEFAULT).await.is_ok());
    // A cipher or key exchange the gateway doesn't list: no session.
    let ctr = russh::Preferred {
        cipher: Cow::Borrowed(&[russh::cipher::AES_128_CTR]),
        ..russh::Preferred::DEFAULT
    };
    // any error: russh's negotiation failure, no algorithm in common.
    assert!(with(ctr).await.is_err(), "aes128-ctr");
    let dh = russh::Preferred {
        kex: Cow::Borrowed(&[russh::kex::DH_G14_SHA256]),
        ..russh::Preferred::DEFAULT
    };
    // any error: russh's negotiation failure, no algorithm in common.
    assert!(with(dh).await.is_err(), "diffie-hellman-group14-sha256");
}

#[tokio::test(start_paused = true)]
async fn a_connection_that_never_authenticates_is_closed() {
    use tokio::io::AsyncReadExt;
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    // A peer that opens a connection and never speaks SSH: closed after the deadline (paused
    // time runs ahead while everything waits).
    let started = tokio::time::Instant::now();
    let mut stream = daemon.agents.connect(peer()).await.unwrap();
    let mut seen = Vec::new();
    let read = stream.read_to_end(&mut seen).await;
    assert!(read.is_ok(), "{read:?}");
    assert!(
        seen.starts_with(b"SSH-2.0-"),
        "the server's id, then the close"
    );
    // Both sides of the deadline (the review after M5.5): open until 20 s from the accept,
    // closed then, and the refusal logged.
    let open_for = started.elapsed();
    assert!(
        (Duration::from_secs(20)..Duration::from_secs(21)).contains(&open_for),
        "closed after {open_for:?}"
    );
    let lines = daemon.audit("connect", "denied");
    assert!(
        lines.iter().any(|l| l["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("no SSH handshake within 20 s"))),
        "{lines:?}"
    );
}

#[tokio::test]
async fn a_caller_the_attestor_cannot_attest_is_turned_away() {
    let daemon = Daemon::start(FakeAttestor::failing()).await;
    let stream = daemon.agents.connect(peer()).await.unwrap();
    let connected =
        client::connect_stream(Arc::new(client::Config::default()), stream, Accept).await;
    // any error: the connection is dropped before the SSH handshake; the line below says why.
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

    // In the registry, not in the lease: the policy's fetch decision.
    let (_, err, status) = exec(&holder, "git-upload-pack 'other.git'", b"").await;
    assert_eq!(status, Some(1));
    assert!(
        err.contains(&format!("outside ticket {id}: repo other not allowed")),
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
    assert_eq!(fetches[0]["code"], "repo");
    assert_eq!(fetches[1]["repo"], "demo");
    assert_eq!(fetches[1]["reason"], "unknown repo demo");
    // The fetch of demo was allowed (and counted) before the gateway found no repository.
    let allowed = daemon.audit("fetch", "allowed");
    assert_eq!(allowed.len(), 1, "{allowed:?}");
    assert_eq!(allowed[0]["repo"], "demo");
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

    let approver = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
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
    https_as(daemon, pin, &daemon.reader, method, path, body).await
}

/// [`https`] with `reader` as the client certificate's key.
async fn https_as(
    daemon: &Daemon,
    pin: &str,
    reader: &PrivateKey,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    // The client side the CLI uses: exactly the pinned certificate, and the reader key.
    let config = writ_crypto::tls::pinned_client_config(pin, reader).unwrap();
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
        // any error: the body is not a reply at all (serde's message).
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
async fn https_turns_away_a_key_not_in_readers() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let refused = https_as(
        &daemon,
        &daemon.pin,
        &stranger,
        "GET",
        "/v1/info",
        Vec::new(),
    )
    .await;
    // any error: rustls or hyper reports the rejected client certificate its own way.
    assert!(refused.is_err(), "{refused:?}");
    // The daemon logs it, with the exact reason, before dropping the connection.
    eventually_async("the refused handshake to be logged", || {
        !daemon.audit("connect", "denied").is_empty()
    })
    .await;
    let lines = daemon.audit("connect", "denied");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        lines[0]["reason"],
        "TLS handshake refused: unexpected error: the client certificate is not for a reader key"
    );
    // The reader gets in, on the same listener.
    let (status, _) = https(&daemon, &daemon.pin, "GET", "/v1/info", Vec::new())
        .await
        .unwrap();
    assert_eq!(status, 200);
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
    // any error: the connection is dropped before the TLS handshake; the line says why.
    assert!(
        https(&daemon, &pin, "GET", "/v1/info", Vec::new())
            .await
            .is_err()
    );
    let lines = daemon.audit("connect", "denied");
    assert!(
        lines.iter().any(|l| l["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("caller turned away"))),
        "logged like its SSH twin: {lines:?}"
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
    // A commit for this lease, its message padded so the body is exactly `size` bytes.
    let body = |size: usize| {
        let commit = |padding: usize| {
            format!(
                "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                 author A <agent@writ> 1 +0000\ncommitter A <agent@writ> 1 +0000\n\n\
                 Subject\n\n{}\n\nWrit: {}\n",
                "x".repeat(padding),
                cert.key_id()
            )
        };
        let encode = |padding: usize| {
            writ_proto::sign::SignInput {
                object: commit(padding).into_bytes(),
                evidence: Vec::new(),
            }
            .encode()
        };
        let mut padding = size - encode(0).len();
        while encode(padding).len() > size {
            padding -= 1;
        }
        let body = encode(padding);
        assert_eq!(body.len(), size, "the fixture is exactly {size} bytes");
        body
    };
    let limit = writ_proto::sign::MAX_SIGN_INPUT;
    let (out, err, status) = exec(&holder, "writ-sign git demo", &body(limit)).await;
    assert_eq!(status, Some(0), "{err}");
    assert!(
        String::from_utf8(out)
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE-----")
    );
    let (out, err, status) = exec(&holder, "writ-sign git demo", &body(limit + 1)).await;
    assert_eq!(status, Some(1));
    assert!(out.is_empty());
    assert!(err.contains("writ: the request is too large"), "{err}");
    assert_eq!(daemon.audit("sign", "denied").len(), 1);
}

#[tokio::test]
async fn a_sign_request_that_isnt_one_is_refused_and_logged() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    let framed = |object: &str| {
        writ_proto::sign::SignInput {
            object: object.as_bytes().to_vec(),
            evidence: Vec::new(),
        }
        .encode()
    };
    let commit = format!(
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <agent@writ> 1 +0000\n\
         committer A <agent@writ> 1 +0000\n\nm\n\nWrit: {}\n",
        cert.key_id()
    );
    // The allowed case first, so each refusal below is the check's doing.
    let (_, err, status) = exec(&holder, "writ-sign git demo", &framed(&commit)).await;
    assert_eq!(status, Some(0), "{err}");
    let outside = format!(
        "writ: outside ticket {}: repo other not allowed",
        cert.key_id()
    );
    let cases: [(&str, Vec<u8>, &str); 5] = [
        (
            "writ-sign git demo",
            commit.as_bytes().to_vec(),
            "writ: not a writ-sign/1 request (update writ-sign)",
        ),
        (
            "writ-sign git demo",
            framed("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nnope\n\nm\n"),
            "writ: cannot sign: the commit's author header is missing or out of place",
        ),
        (
            "writ-sign git demo",
            framed(&commit.replace("+0000\n\n", "+0000\ngpgsig x\n\n")),
            "writ: cannot sign: the commit is signed already",
        ),
        ("writ-sign git other", framed(&commit), &outside),
        // The lease is checked before the body is read: garbage for a repo the lease doesn't
        // name gets the lease's refusal, not the body's.
        ("writ-sign git other", b"garbage".to_vec(), &outside),
    ];
    for (line, body, reason) in &cases {
        let (out, err, status) = exec(&holder, line, body).await;
        assert_eq!(status, Some(1), "{reason}");
        assert!(out.is_empty());
        assert!(err.starts_with(reason), "{reason:?} not in {err:?}");
    }
    let denied = daemon.audit("sign", "denied");
    assert_eq!(
        denied.len(),
        cases.len(),
        "every refusal logged: {denied:?}"
    );
    assert_eq!(
        denied[0]["reason"],
        "not a writ-sign/1 request (update writ-sign)"
    );
    assert_eq!(denied[0]["repo"], "demo");
    assert_eq!(denied[3]["code"], "repo");
    assert_eq!(denied[4]["code"], "repo");
}

#[tokio::test]
async fn relative_paths_are_refused_at_start() {
    // git looks a relative hooks path up inside the repository it runs in, finds no hook, and
    // takes the push unchecked: the gateway never starts on one.
    let dir = tempfile::tempdir().unwrap();
    let test = TestServiceBuilder::new(POLICY).build(dir.path());
    let mirrors = writ_mirror::testing::no_repos(dir.path()).await.unwrap();
    let config = |state_dir: PathBuf, hook_program: PathBuf| GatewayConfig {
        host_key: generate(KeyKind::Ed25519).unwrap(),
        mirrors: Some(mirrors.clone()),
        unsealer: None,
        admin: None,
        hook_program,
        state_dir,
        readers: writ_crypto::readers::ReaderSet::default(),
        sign_requests_per_lease: writ_gateway::DEFAULT_SIGN_REQUESTS_PER_LEASE,
    };
    for (state, hook, what) in [
        (
            "run",
            "/usr/bin/false",
            "state_dir run must be an absolute path",
        ),
        (
            dir.path().join("run").to_str().unwrap(),
            "writd",
            "hook_program writd must be an absolute path",
        ),
    ] {
        let started = Gateway::start(
            config(PathBuf::from(state), PathBuf::from(hook)),
            test.service.clone(),
        )
        .await;
        match started {
            Err(writ_gateway::GatewayError::Config(message)) => {
                assert!(message.contains(what), "{message}")
            }
            Err(other) => panic!("expected a configuration error, got {other}"),
            Ok(_) => panic!("started with a relative {what}"),
        }
    }
    // Both absolute: it starts (the refusals were the paths' doing).
    assert!(
        Gateway::start(
            config(dir.path().join("run"), PathBuf::from("/usr/bin/false")),
            test.service.clone(),
        )
        .await
        .is_ok()
    );
}

/// The review after M5.5 (S11): a `writ wait` ran until its ticket was decided or expired
/// whatever became of its client, so connecting, asking four waits and hanging up, again and
/// again, piled up tasks that every change of the service woke. A wait now ends with its
/// channel, and with its connection; one whose client only sent EOF keeps waiting.
#[tokio::test]
async fn a_wait_ends_with_its_channel_and_its_connection() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let service = daemon.gateway.service().clone();
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let submitted: Submitted = call(&agent, Command::Request, TICKET.as_bytes())
        .await
        .unwrap();
    let wait = Command::Wait {
        id: submitted.id.clone(),
    }
    .line();
    async fn open(handle: &Handle<Accept>, line: &str) -> russh::Channel<client::Msg> {
        let channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, line).await.unwrap();
        // EOF: the client has nothing to send. Not an end.
        channel.eof().await.unwrap();
        channel
    }
    assert_eq!(service.waiting(), 0);
    let first = open(&agent, &wait).await;
    let second = open(&agent, &wait).await;
    eventually_async("two waits", || service.waiting() == 2).await;

    // One channel closed: its wait ends, the other one goes on.
    first.close().await.unwrap();
    eventually_async("the closed channel's wait to end", || {
        service.waiting() == 1
    })
    .await;

    // Another connection's waits end when it hangs up.
    let other = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    let _kept = [open(&other, &wait).await, open(&other, &wait).await];
    eventually_async("three waits", || service.waiting() == 3).await;
    other
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    eventually_async("the lost connection's waits to end", || {
        service.waiting() == 1
    })
    .await;

    // The one left still gets its answer.
    let mut second = second;
    let approver = Daemon::with_key(&daemon.approvals, "writ", &daemon.reader)
        .await
        .unwrap();
    let ticket = Ticket::from_canonical(submitted.canonical.as_bytes()).unwrap();
    let _: Ack = call(
        &approver,
        Command::Approve { id: submitted.id },
        &writ_proto::encode_body(&sign_approval(&daemon.approver, &ticket)).unwrap(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    while let Some(message) = second.wait().await {
        match message {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let decision: Decision = writ_proto::decode_reply(&out).unwrap();
    assert!(matches!(decision, Decision::Active { .. }), "{decision:?}");
    assert_eq!(service.waiting(), 0);
}

/// An unsealer held at a gate until the test lets it finish, saying when it entered and
/// whether it ran to its end.
#[derive(Default)]
struct HeldUnsealer {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    finished: std::sync::atomic::AtomicBool,
}

struct Held(Arc<HeldUnsealer>);

impl writ_gateway::Unsealer for Held {
    fn unseal(
        &self,
        _passphrase: writ_proto::PassphraseText,
        _approver: writ_core::names::KeyFingerprint,
        _caller: CallerFacts,
    ) -> writ_platform::BoxFuture<'static, Result<(), String>> {
        let held = self.0.clone();
        Box::pin(async move {
            held.entered.notify_one();
            held.release.notified().await;
            held.finished
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    }
}

/// The review after M5.5 (S6): over HTTPS the unseal (and an admin change) ran inside the
/// request's future, which hyper drops when the client goes away. Cut off midway, the state
/// had changed and what follows (the mirrors, the readers, the open keystore) never ran: the
/// daemon stayed half open until a restart. The request now runs on its own task, to its end.
#[tokio::test]
async fn an_unseal_cut_off_by_its_https_client_still_runs_to_its_end() {
    use http_body_util::BodyExt as _;
    let held = Arc::new(HeldUnsealer::default());
    let (daemon, unseal) = Daemon::start_sealed(Arc::new(Held(held.clone()))).await;
    let body = writ_proto::encode_body(&unseal.unwrap()).unwrap();
    // The client the CLI uses, by hand, so the test can cut its connection.
    let config = writ_crypto::tls::pinned_client_config(&daemon.pin, &daemon.reader).unwrap();
    let stream = daemon.https.connect(peer()).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("writd").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let (method, path) = Command::Unseal.http_route().unwrap();
    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "writd")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
        .unwrap();
    let sent = tokio::spawn(async move {
        let response = sender.send_request(request).await?;
        response.into_body().collect().await.map(|_| ())
    });
    held.entered.notified().await;
    // Ctrl-C on the approver's side: the connection is gone, its request too.
    sent.abort();
    connection.abort();
    let _ = connection.await;
    held.release.notify_one();
    eventually_async("the unseal to run to its end", || {
        held.finished.load(std::sync::atomic::Ordering::Acquire)
    })
    .await;
}

/// The review after M5.5 (T3): the SSH environment and the authentication attempts are bounds
/// of the untrusted-input inventory with no test of their own. Every `env` request is refused,
/// `GIT_PROTOCOL` included (upload-pack speaks v0 only), and the command still runs; a key
/// is tried six times at most, the seventh attempt ends the connection.
#[tokio::test]
async fn env_requests_are_refused_and_authentication_stops_after_six_attempts() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let key = generate(KeyKind::Ed25519).unwrap();
    let agent = Daemon::with_key(&daemon.agents, "writ", &key)
        .await
        .unwrap();
    for (name, value) in [("GIT_PROTOCOL", "version=2"), ("LD_PRELOAD", "/tmp/x.so")] {
        let mut channel = agent.channel_open_session().await.unwrap();
        channel.set_env(true, name, value).await.unwrap();
        let answer = loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break "success",
                Some(ChannelMsg::Failure) => break "failure",
                Some(_) => {}
                None => break "closed",
            }
        };
        assert_eq!(answer, "failure", "{name}");
    }
    // The connection is fine after: a command runs.
    let info: Result<Submitted, ApiError> = call(&agent, Command::Request, TICKET.as_bytes()).await;
    assert!(info.is_ok(), "{info:?}");

    // Six keys not in readers, one after the other on one connection: each refused; the
    // seventh attempt isn't answered, the connection is ended.
    let mut handle = Daemon::connect(&daemon.approvals).await;
    for attempt in 1..=6 {
        let stranger = generate(KeyKind::Ed25519).unwrap();
        let auth = handle
            .authenticate_publickey("writ", PrivateKeyWithHashAlg::new(Arc::new(stranger), None))
            .await
            .unwrap_or_else(|e| panic!("attempt {attempt}: {e}"));
        assert!(
            matches!(
                auth,
                russh::client::AuthResult::Failure {
                    partial_success: false,
                    ..
                }
            ),
            "attempt {attempt}: {auth:?}"
        );
    }
    let stranger = generate(KeyKind::Ed25519).unwrap();
    let seventh = handle
        .authenticate_publickey("writ", PrivateKeyWithHashAlg::new(Arc::new(stranger), None))
        .await;
    // any error: the server disconnected ("Too many authentication attempts").
    assert!(seventh.is_err(), "{seventh:?}");
}
