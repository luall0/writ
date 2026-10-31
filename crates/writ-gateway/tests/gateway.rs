//! The gateway on the platform fakes only: an in-memory transport, a fake attestor, an
//! in-process SSH client and an in-process HTTPS client pinning the daemon's certificate. Who may run what on which listener, the whole ticket flow over the
//! protocol, and open sessions dropped when a lease is revoked.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use writ_approval::{Platform, Service, ServiceConfig, SystemClock};
use writ_core::caller::CallerFacts;
use writ_core::config::PolicyConfig;
use writ_core::lease::APPROVAL_NAMESPACE;
use writ_core::signed::Revocation;
use writ_crypto::allowed_signers::AllowedSigner;
use writ_crypto::ca::CertificateAuthority;
use writ_crypto::keys::{KeyKind, generate};
use writ_crypto::ssh_key::{Certificate, PrivateKey};
use writ_crypto::sshsig;
use writ_gateway::{Gateway, GatewayConfig, Role, TlsIdentity};
use writ_platform::PeerInfo;
use writ_platform::testing::{
    FakeAttestor, FakeConnector, FakeTransport, FakeWatcher, RecordingNotifier,
};
use writ_proto::{
    Ack, ApiError, ApproveRequest, Command, Decision, Decisions, Info, Listing, RevokeRequest,
    Submitted,
};
use writ_store::{AuditLog, Store};

const POLICY: &str = r#"
repos:
  demo:
    upstream: ssh://git@forge.invalid/demo.git
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
    _dir: tempfile::TempDir,
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
        let approver = generate(KeyKind::Ed25519).unwrap();
        let service = Service::new(
            ServiceConfig {
                policy: PolicyConfig::from_yaml(POLICY).unwrap(),
                approvers: vec![AllowedSigner {
                    principals: "me".into(),
                    key: approver.public_key().clone(),
                }],
                decisions: Decisions::Signed,
                max_pending: 20,
            },
            CertificateAuthority::new(generate(KeyKind::Ed25519).unwrap()),
            Store::open(&dir.path().join("leases.db")).unwrap(),
            AuditLog::open(&dir.path().join("audit.jsonl")).unwrap(),
            Platform {
                notifier: Arc::new(RecordingNotifier::new()),
                watcher: Arc::new(FakeWatcher::new()),
                clock: Arc::new(SystemClock),
            },
        )
        .unwrap();
        let gateway = Gateway::start(
            GatewayConfig {
                host_key: generate(KeyKind::Ed25519).unwrap(),
                repos_root: dir.path().join("repos"),
                signing_key: generate(KeyKind::Ed25519).unwrap(),
                hook_program: PathBuf::from("/bin/false"),
                state_dir: dir.path().join("run"),
                protected_refs: vec![],
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
            _dir: dir,
            gateway,
            agents,
            approvals,
            https,
            pin,
            approver,
        }
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
    let request = ApproveRequest {
        signature: sshsig::sign(
            &daemon.approver,
            APPROVAL_NAMESPACE,
            submitted.canonical.as_bytes(),
        )
        .unwrap(),
        signed: submitted.canonical.clone(),
    };
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
}

#[tokio::test]
async fn revoking_drops_open_sessions_and_refuses_the_next_connection() {
    let daemon = Daemon::start(FakeAttestor::fixed(CallerFacts::default())).await;
    let (key, cert) = lease(&daemon).await;
    let holder = Daemon::with_cert(&daemon.agents, &key, &cert)
        .await
        .unwrap();
    for _ in 0..100 {
        if daemon.gateway.open_sessions(cert.serial()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(daemon.gateway.open_sessions(cert.serial()), 1);

    let approver = Daemon::with_key(
        &daemon.approvals,
        "writ",
        &generate(KeyKind::Ed25519).unwrap(),
    )
    .await
    .unwrap();
    let id: writ_core::names::TicketId = cert.key_id().parse().unwrap();
    let document = Revocation::new(id.clone()).canonical_bytes().unwrap();
    let request = RevokeRequest {
        signature: Some(sshsig::sign(&daemon.approver, APPROVAL_NAMESPACE, &document).unwrap()),
    };
    let _: Ack = call(
        &approver,
        Command::Revoke { id },
        &writ_proto::encode_body(&request).unwrap(),
    )
    .await
    .unwrap();

    for _ in 0..200 {
        if holder.is_closed() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(holder.is_closed(), "the open session was dropped");
    assert_eq!(daemon.gateway.open_sessions(cert.serial()), 0);
    assert!(
        Daemon::with_cert(&daemon.agents, &key, &cert)
            .await
            .is_none()
    );
}

// ----- HTTPS ----------------------------------------------------------------------------

/// Accepts only the certificate with this fingerprint.
#[derive(Debug)]
struct PinnedCert(String, Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if writ_crypto::tls::fingerprint(end_entity) == self.0 {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// One HTTPS request to the daemon's approval API: (status, body). Errors if TLS fails.
async fn https(
    daemon: &Daemon,
    pin: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert(pin.to_owned(), provider)))
        .with_no_client_auth();
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

    let request = ApproveRequest {
        signature: sshsig::sign(
            &daemon.approver,
            APPROVAL_NAMESPACE,
            submitted.canonical.as_bytes(),
        )
        .unwrap(),
        signed: submitted.canonical.clone(),
    };
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
    assert!(error.contains("pin mismatch"), "{error}");
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
