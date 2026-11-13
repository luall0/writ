//! A test remote over HTTPS standing in for GitHub, Codeberg or Forgejo reached with a token:
//! a TLS server on `127.0.0.1`, port 0, with a self-signed certificate ([`HttpsRemote::ca_pem`]
//! is what the daemon trusts), running `git http-backend` on the bare repositories in a
//! directory (the same ones a [`TestRemote`](crate::remote::TestRemote) serves over SSH) for
//! requests carrying the token (HTTP Basic, any user name). It can also misbehave on demand
//! ([`HttpsMode`]).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Encoding};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;

/// How the remote answers a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsMode {
    /// Runs `git http-backend`, like a real remote.
    Serve,
    /// Takes the request and never answers.
    Hang,
    /// Answers every request (authorized or not) with this many bytes of a valid ref
    /// advertisement, each line a new branch: git keeps reading, as from a remote with
    /// endless refs.
    Flood(usize),
    /// Redirects every request to this URL (the request's path appended).
    Redirect(String),
    /// Answers an authorized request with a protocol error quoting the password it got: a
    /// hostile remote printing the token back.
    Echo,
}

struct State {
    root: PathBuf,
    token: Mutex<String>,
    mode: Mutex<HttpsMode>,
    /// Connections accepted.
    connections: AtomicUsize,
    /// Requests received, and the user names of those carrying the token.
    requests: AtomicUsize,
    users: Mutex<Vec<String>>,
    /// `git-receive-pack` posts served (pushes).
    receive_packs: AtomicUsize,
    /// A git command run in the repo before the next push's ref advertisement.
    before_push: Mutex<Option<Vec<String>>>,
}

/// A name its certificate holds that no resolver answers: reached only through a test proxy
/// that maps it ([`crate::proxy::TestProxy::map`]), so a connection that skips the proxy fails.
pub const UNRESOLVED: &str = "https-upstream.invalid";

/// A running HTTPS test remote.
pub struct HttpsRemote {
    pub port: u16,
    /// Its certificate (self-signed, for `127.0.0.1`, `localhost` and [`UNRESOLVED`]), PEM:
    /// the daemon's `ca_certs`.
    pub ca_pem: String,
    state: Arc<State>,
}

impl HttpsRemote {
    /// Starts a remote on `runtime`, serving the bare repositories in `root`
    /// (`<root>/<name>.git`) to requests carrying `token`.
    pub fn start(runtime: &tokio::runtime::Runtime, root: &Path, token: &str) -> Self {
        std::fs::create_dir_all(root).unwrap();
        let certified = rcgen::generate_simple_self_signed(vec![
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
            UNRESOLVED.to_owned(),
        ])
        .unwrap();
        let ca_pem = certified.cert.pem();
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let state = Arc::new(State {
            root: root.to_owned(),
            token: Mutex::new(token.to_owned()),
            mode: Mutex::new(HttpsMode::Serve),
            connections: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            users: Mutex::new(Vec::new()),
            receive_packs: AtomicUsize::new(0),
            before_push: Mutex::new(None),
        });
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = state.clone();
        runtime.spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                served.connections.fetch_add(1, Ordering::AcqRel);
                let (acceptor, state) = (acceptor.clone(), served.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(move |request| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(answer(&state, request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            port,
            ca_pem,
            state,
        }
    }

    /// The `https://` URL of the repository `name`.
    pub fn url(&self, name: &str) -> String {
        format!("https://127.0.0.1:{}/{name}.git", self.port)
    }

    pub fn set_mode(&self, mode: HttpsMode) {
        *self.state.mode.lock().unwrap() = mode;
    }

    /// Replaces the token it takes.
    pub fn set_token(&self, token: &str) {
        *self.state.token.lock().unwrap() = token.to_owned();
    }

    /// Runs `git <args>` in the pushed repo right before the next push reads its refs:
    /// upstream moving between the daemon's sync and its push.
    pub fn before_next_push(&self, args: &[&str]) {
        *self.state.before_push.lock().unwrap() =
            Some(args.iter().map(|a| (*a).to_owned()).collect());
    }

    /// How many connections it accepted.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::Acquire)
    }

    /// How many requests it received.
    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::Acquire)
    }

    /// The user names sent with the token, one per authorized request.
    pub fn users(&self) -> Vec<String> {
        self.state.users.lock().unwrap().clone()
    }

    /// How many pushes it served.
    pub fn receive_packs(&self) -> usize {
        self.state.receive_packs.load(Ordering::Acquire)
    }
}

type Body = Full<Bytes>;

fn status(code: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_owned())));
    *response.status_mut() = code;
    response
}

/// One `pkt-line`.
fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

async fn answer(state: &State, request: Request<Incoming>) -> Response<Body> {
    state.requests.fetch_add(1, Ordering::AcqRel);
    let mode = state.mode.lock().unwrap().clone();
    let path = request.uri().path().to_owned();
    match &mode {
        HttpsMode::Hang => std::future::pending::<()>().await,
        HttpsMode::Flood(bytes) => return flood(*bytes),
        HttpsMode::Redirect(to) => {
            let mut response = status(StatusCode::FOUND, "moved");
            let location = format!("{to}{path}");
            response
                .headers_mut()
                .insert("location", location.parse().unwrap());
            return response;
        }
        HttpsMode::Serve | HttpsMode::Echo => {}
    }
    // HTTP Basic, the token as the password; anything else is asked for credentials.
    let credentials = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| Base64::decode_vec(b64).ok())
        .and_then(|raw| String::from_utf8(raw).ok());
    let token = state.token.lock().unwrap().clone();
    let user = match credentials.as_deref().and_then(|c| c.split_once(':')) {
        Some((user, password)) if password == token => user.to_owned(),
        _ => {
            let mut response = status(StatusCode::UNAUTHORIZED, "credentials, please");
            response.headers_mut().insert(
                "www-authenticate",
                "Basic realm=\"test remote\"".parse().unwrap(),
            );
            return response;
        }
    };
    state.users.lock().unwrap().push(user.clone());
    if mode == HttpsMode::Echo {
        let mut body = pkt("# service=git-upload-pack\n");
        body.push_str("0000");
        // Verbatim, split by a character the error's cleaning drops, and in the Basic form
        // the remote received: each must be taken out (the review after M5.5, S9).
        let header = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let (head, tail) = token.split_at(token.len() / 2);
        body.push_str(&pkt(&format!(
            "ERR the password you sent is {token}, split {head}\u{200b}{tail}, as {header}\n"
        )));
        let mut response = status(StatusCode::OK, &body);
        response.headers_mut().insert(
            "content-type",
            "application/x-git-upload-pack-advertisement"
                .parse()
                .unwrap(),
        );
        return response;
    }
    backend(state, request, &user).await
}

/// A ref advertisement of `bytes` bytes (smart HTTP, protocol v0).
fn flood(bytes: usize) -> Response<Body> {
    let mut body = pkt("# service=git-upload-pack\n");
    body.push_str("0000");
    let id = "1".repeat(40);
    let mut n = 0usize;
    while body.len() < bytes {
        let caps = if n == 0 { "\0side-band-64k" } else { "" };
        body.push_str(&pkt(&format!("{id} refs/heads/b{n}{caps}\n")));
        n += 1;
    }
    let mut response = status(StatusCode::OK, &body);
    response.headers_mut().insert(
        "content-type",
        "application/x-git-upload-pack-advertisement"
            .parse()
            .unwrap(),
    );
    response
}

/// Runs `git http-backend` (CGI) for the request.
async fn backend(state: &State, request: Request<Incoming>, user: &str) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return status(StatusCode::BAD_REQUEST, "unreadable body"),
    };
    let path = parts.uri.path().to_owned();
    if parts.method == hyper::Method::POST && path.ends_with("/git-receive-pack") {
        state.receive_packs.fetch_add(1, Ordering::AcqRel);
    }
    // A push starts with its ref advertisement: upstream moves before git reads it, as it
    // would between the daemon's sync and its push.
    let advertises_for_push = parts.method == hyper::Method::GET
        && path.ends_with("/info/refs")
        && parts.uri.query() == Some("service=git-receive-pack");
    if advertises_for_push {
        let before = state.before_push.lock().unwrap().take();
        if let Some(args) = before {
            let repo = path.trim_start_matches('/').trim_end_matches("/info/refs");
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(state.root.join(repo))
                .args(&args)
                // Never the user's git config (hard rule 8).
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
        }
    }
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_PROJECT_ROOT", &state.root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REMOTE_USER", user)
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", parts.method.as_str())
        .env("PATH_INFO", &path)
        .env("QUERY_STRING", parts.uri.query().unwrap_or_default())
        .env("CONTENT_TYPE", header("content-type"))
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("HTTP_CONTENT_ENCODING", header("content-encoding"))
        .env("GIT_PROTOCOL", header("git-protocol"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&body).await;
    });
    let output = child.wait_with_output().await.unwrap();
    let _ = writer.await;
    cgi_response(&output.stdout)
}

/// A CGI program's output as a response: headers (`Status:` among them) until a blank line,
/// then the body.
fn cgi_response(output: &[u8]) -> Response<Body> {
    let split = output
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| (at, 4))
        .or_else(|| {
            output
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|at| (at, 2))
        });
    let Some((at, gap)) = split else {
        return status(StatusCode::INTERNAL_SERVER_ERROR, "no CGI headers");
    };
    let head = String::from_utf8_lossy(&output[..at]).into_owned();
    let body = Bytes::copy_from_slice(&output[at + gap..]);
    let mut headers = BTreeMap::new();
    let mut code = StatusCode::OK;
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("status") {
            let number = value.split_whitespace().next().unwrap_or("500");
            code = number
                .parse::<u16>()
                .ok()
                .and_then(|n| StatusCode::from_u16(n).ok())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        } else {
            headers.insert(name.to_owned(), value.to_owned());
        }
    }
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = code;
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
