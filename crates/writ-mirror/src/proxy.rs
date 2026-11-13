//! A SOCKS5 proxy for one upstream operation (RFC 1928, `CONNECT` without authentication):
//! git reaches an HTTPS upstream only through it, on a Unix socket in a private directory
//! (`http.proxy=socks5h://localhost/<socket>`), and so does ssh for an `ssh://` upstream behind
//! a proxy of the policy ([`tunnel`](crate::tunnel), its `ProxyCommand`). It connects only to
//! the upstream's host and port, through the repo's [`Dialer`] (directly, or through that
//! proxy), and counts the bytes upstream sends, all connections together: past the cap it ends
//! every tunnel, so a sync never takes more than `mirrors.max_fetch` (git has no limit of its
//! own on a fetch, the gap the ssh [`relay`](crate::relay) closes for `ssh://`).
//!
//! TLS (or SSH) stays end to end between git and upstream: the proxy relays ciphertext, and
//! never sees the token. A connection the dialer couldn't open is refused to git, and why is
//! kept ([`UpstreamProxy::failure`]): git only says the proxy failed. Dropping the
//! [`UpstreamProxy`] ends every tunnel and removes the socket file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::dial::{DialError, Dialer};
use crate::{MirrorError, Result};

/// Connections one proxy accepts in its life (git keeps one open, and opens another when
/// upstream closes it).
pub const MAX_CONNECTIONS: usize = 16;
/// How long git may take to ask for its tunnel (the SOCKS exchange alone: opening the tunnel
/// is bounded by the repo's dialer, a proxy's `connect_timeout`).
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
const SUCCEEDED: u8 = 0;
const NOT_ALLOWED: u8 = 2;
const HOST_UNREACHABLE: u8 = 4;
const COMMAND_NOT_SUPPORTED: u8 = 7;
const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

/// A running proxy. Dropped: every tunnel ended, its file removed.
pub struct UpstreamProxy {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
    shared: Arc<Shared>,
}

struct Shared {
    host: String,
    /// The host as an address, when the URL names one.
    address: Option<IpAddr>,
    port: u16,
    max: u64,
    received: AtomicU64,
    tunnels: AtomicUsize,
    /// Set once upstream sent more than `max`: every tunnel ends.
    over: watch::Sender<bool>,
    dialer: Dialer,
    /// Why the last connection to upstream couldn't be opened.
    failure: Mutex<Option<DialError>>,
}

impl UpstreamProxy {
    /// Serves a proxy to upstream (`host` and `port`, as the registry names them) on a new
    /// socket in `dir`, a private directory, reaching it through `dialer`, letting upstream
    /// send at most `max_bytes`.
    pub fn start(
        dir: &Path,
        host: &str,
        port: u16,
        max_bytes: u64,
        dialer: Dialer,
    ) -> Result<Self> {
        let name =
            writ_crypto::keys::random_hex(8).map_err(|source| MirrorError::NoRandomness {
                what: "the upstream proxy socket",
                source,
            })?;
        let path = dir.join(format!("{name}.proxy"));
        let listener = UnixListener::bind(&path).map_err(|source| MirrorError::Io {
            what: "cannot create the upstream proxy socket",
            path: path.clone(),
            source,
        })?;
        let shared = Arc::new(Shared {
            host: host.to_owned(),
            address: host.parse().ok(),
            port,
            max: max_bytes,
            received: AtomicU64::new(0),
            tunnels: AtomicUsize::new(0),
            over: watch::Sender::new(false),
            dialer,
            failure: Mutex::new(None),
        });
        let task = tokio::spawn(serve(listener, shared.clone()));
        Ok(Self { path, task, shared })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `http.proxy` value that sends git through this proxy.
    pub fn url(&self) -> String {
        format!("socks5h://localhost{}", self.path.display())
    }

    /// Whether upstream sent more than the cap (the operation then failed).
    pub fn too_large(&self) -> bool {
        *self.shared.over.borrow()
    }

    /// The bytes upstream sent through it.
    pub fn received(&self) -> u64 {
        self.shared.received.load(Ordering::Acquire)
    }

    /// The tunnels it opened to upstream.
    pub fn tunnels(&self) -> usize {
        self.shared.tunnels.load(Ordering::Acquire)
    }

    /// Why the last connection to upstream couldn't be opened, if one couldn't.
    pub fn failure(&self) -> Option<DialError> {
        self.shared
            .failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for UpstreamProxy {
    fn drop(&mut self) {
        // The serving task owns the tunnels (a `JoinSet`): aborting it ends them all.
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn serve(listener: UnixListener, shared: Arc<Shared>) {
    let mut tunnels = JoinSet::new();
    for _ in 0..MAX_CONNECTIONS {
        match listener.accept().await {
            Ok((stream, _)) => {
                tunnels.spawn(tunnel(stream, shared.clone()));
            }
            Err(e) => {
                tracing::debug!(error = %e, "upstream proxy accept failed");
                break;
            }
        }
    }
    drop(listener);
    while tunnels.join_next().await.is_some() {}
}

/// One connection from git: the handshake, then the tunnel until either side ends, upstream
/// goes past the cap, or the operation ends.
async fn tunnel(mut client: UnixStream, shared: Arc<Shared>) {
    let mut over = shared.over.subscribe();
    if *over.borrow_and_update() {
        return;
    }
    let Some(upstream) = open(&mut client, &shared).await else {
        return;
    };
    shared.tunnels.fetch_add(1, Ordering::AcqRel);
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let relay = async {
        let up = forward(client_read, upstream_write);
        let down = count_into(upstream_read, client_write, &shared);
        let _ = tokio::join!(up, down);
    };
    tokio::select! {
        () = relay => {}
        _ = over.wait_for(|over| *over) => {}
    }
}

/// git's SOCKS exchange within [`HANDSHAKE_DEADLINE`], then upstream through the dialer within
/// the dialer's own deadline alone: a proxy's `connect_timeout` may be longer (up to 5 min, for
/// Tor), and a dial cut short by the exchange's deadline lost its reason (the review after
/// M7.6, M-2). `None`: refused or failed, the connection ended (a dial's failure is kept for
/// the operation's error).
async fn open<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    shared: &Shared,
) -> Option<TcpStream> {
    match tokio::time::timeout(HANDSHAKE_DEADLINE, request(client, shared)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "upstream proxy handshake failed");
            return None;
        }
        Err(_) => {
            tracing::debug!("upstream proxy handshake timed out");
            return None;
        }
    }
    match connect(client, shared).await {
        Ok(upstream) => Some(upstream),
        Err(e) => {
            tracing::debug!(error = %e, "upstream proxy tunnel not opened");
            None
        }
    }
}

/// Reads git's greeting and request, and checks it asks for upstream (anything else is
/// answered and refused). An error ends the connection.
async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    shared: &Shared,
) -> std::io::Result<()> {
    greet(client).await?;
    let (command, asked, port) = read_request(client).await?;
    if command != CONNECT {
        reply(client, COMMAND_NOT_SUPPORTED).await?;
        return Err(std::io::Error::other("not a CONNECT"));
    }
    if port != shared.port || !asked.is(shared) {
        tracing::warn!(
            upstream = %shared.host,
            "git asked the upstream proxy for another destination: refused"
        );
        reply(client, NOT_ALLOWED).await?;
        return Err(std::io::Error::other("not upstream"));
    }
    Ok(())
}

/// The greeting: SOCKS5, and no authentication among the methods git offers.
async fn greet<S: AsyncRead + AsyncWrite + Unpin>(client: &mut S) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    let [version, count] = greeting;
    if version != VERSION {
        return Err(std::io::Error::other("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(count)];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTHENTICATION) {
        client.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(std::io::Error::other("no acceptable method"));
    }
    client.write_all(&[VERSION, NO_AUTHENTICATION]).await
}

/// The request: its command, the destination and the port (an unknown address type is
/// answered and refused).
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
) -> std::io::Result<(u8, Asked, u16)> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [version, command, _reserved, kind] = head;
    if version != VERSION {
        return Err(std::io::Error::other("not SOCKS5"));
    }
    let asked = match kind {
        IPV4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Asked::Address(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        IPV6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Asked::Address(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        DOMAIN => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            client.read_exact(&mut name).await?;
            Asked::Name(name)
        }
        _ => {
            reply(client, ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(std::io::Error::other("unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok((command, asked, u16::from_be_bytes(port)))
}

/// Connects to upstream (by the host the URL names, never what git sent) through the
/// dialer, within its deadline (and no other), and tells git how it went; a failure is kept,
/// for the operation's error.
async fn connect<S: AsyncWrite + Unpin>(
    client: &mut S,
    shared: &Shared,
) -> std::io::Result<TcpStream> {
    match shared.dialer.connect(&shared.host, shared.port).await {
        Ok(upstream) => {
            reply(client, SUCCEEDED).await?;
            Ok(upstream)
        }
        Err(e) => {
            tracing::debug!(upstream = %shared.host, error = %e, "cannot reach upstream");
            *shared
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(e.clone());
            reply(client, HOST_UNREACHABLE).await?;
            Err(std::io::Error::other(e.to_string()))
        }
    }
}

/// The destination git asked for.
enum Asked {
    Address(IpAddr),
    Name(Vec<u8>),
}

impl Asked {
    /// Whether it is upstream's host (a name, case aside; or the address the URL names).
    fn is(&self, shared: &Shared) -> bool {
        match self {
            Self::Address(address) => shared.address == Some(*address),
            Self::Name(name) => {
                name.eq_ignore_ascii_case(shared.host.as_bytes())
                    || std::str::from_utf8(name)
                        .ok()
                        .and_then(|name| name.parse::<IpAddr>().ok())
                        .is_some_and(|address| shared.address == Some(address))
            }
        }
    }
}

/// A reply with `status` (the bound address left empty: git doesn't use it).
async fn reply<S: AsyncWrite + Unpin>(client: &mut S, status: u8) -> std::io::Result<()> {
    client
        .write_all(&[VERSION, status, 0, IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// git to upstream, as is.
async fn forward(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
) -> std::io::Result<()> {
    tokio::io::copy(&mut from, &mut to).await?;
    to.shutdown().await
}

/// Upstream to git, counted against the cap shared by every tunnel of the operation; past it,
/// every tunnel ends.
async fn count_into(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    shared: &Shared,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return to.shutdown().await;
        }
        let n64 = u64::try_from(n).unwrap_or(u64::MAX);
        let total = shared
            .received
            .fetch_add(n64, Ordering::AcqRel)
            .saturating_add(n64);
        if total > shared.max {
            shared.over.send_replace(true);
            tracing::warn!(upstream = %shared.host, max = shared.max, "upstream sent too much");
            return Err(std::io::Error::other("upstream sent too much"));
        }
        let chunk = buf.get(..n).unwrap_or_default();
        to.write_all(chunk).await?;
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// A TCP server on 127.0.0.1 that sends `bytes` bytes to each connection, then closes it.
    async fn server(bytes: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = stream.write_all(&vec![b'x'; bytes]).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        port
    }

    /// Connects through the proxy to `host`:`port` (a name), returning the reply status and,
    /// on success, everything upstream sent.
    async fn through(proxy: &UpstreamProxy, kind: u8, host: &[u8], port: u16) -> (u8, Vec<u8>) {
        let mut stream = UnixStream::connect(proxy.path()).await.unwrap();
        stream
            .write_all(&[VERSION, 1, NO_AUTHENTICATION])
            .await
            .unwrap();
        let mut chosen = [0u8; 2];
        stream.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [VERSION, NO_AUTHENTICATION]);
        let mut request = vec![VERSION, CONNECT, 0, kind];
        if kind == DOMAIN {
            request.push(u8::try_from(host.len()).unwrap());
        }
        request.extend_from_slice(host);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut answer = [0u8; 10];
        stream.read_exact(&mut answer).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
        (answer[1], rest)
    }

    #[tokio::test]
    async fn it_tunnels_only_to_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let port = server(100).await;
        let proxy =
            UpstreamProxy::start(dir.path(), "127.0.0.1", port, 1 << 20, Dialer::Direct).unwrap();
        assert_eq!(
            proxy.url(),
            format!("socks5h://localhost{}", proxy.path().display())
        );
        // By name (what socks5h sends) and by address.
        let (status, sent) = through(&proxy, DOMAIN, b"127.0.0.1", port).await;
        assert_eq!((status, sent.len()), (SUCCEEDED, 100));
        let (status, sent) = through(&proxy, IPV4, &[127, 0, 0, 1], port).await;
        assert_eq!((status, sent.len()), (SUCCEEDED, 100));
        assert_eq!(proxy.received(), 200);
        // Anything else: refused, never connected.
        for (kind, host, to) in [
            (DOMAIN, b"localhost".as_slice(), port),
            (DOMAIN, b"127.0.0.2".as_slice(), port),
            (IPV4, [127, 0, 0, 2].as_slice(), port),
            (DOMAIN, b"127.0.0.1".as_slice(), port.wrapping_add(1)),
            (IPV6, Ipv6Addr::LOCALHOST.octets().as_slice(), port),
        ] {
            let (status, sent) = through(&proxy, kind, host, to).await;
            assert_eq!((status, sent.len()), (NOT_ALLOWED, 0), "{host:?}:{to}");
        }
        assert_eq!(proxy.tunnels(), 2);
    }

    #[tokio::test]
    async fn a_name_matches_case_aside_and_other_commands_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let shared = Shared {
            host: "Git.Example.org".to_owned(),
            address: None,
            port: 443,
            max: 1,
            received: AtomicU64::new(0),
            tunnels: AtomicUsize::new(0),
            over: watch::Sender::new(false),
            dialer: Dialer::Direct,
            failure: Mutex::new(None),
        };
        assert!(Asked::Name(b"git.example.ORG".to_vec()).is(&shared));
        assert!(!Asked::Name(b"git.example.org.evil".to_vec()).is(&shared));
        assert!(!Asked::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)).is(&shared));

        let proxy =
            UpstreamProxy::start(dir.path(), "Git.Example.org", 443, 1, Dialer::Direct).unwrap();
        let mut stream = UnixStream::connect(proxy.path()).await.unwrap();
        // BIND, not CONNECT.
        stream
            .write_all(&[VERSION, 1, NO_AUTHENTICATION])
            .await
            .unwrap();
        let mut chosen = [0u8; 2];
        stream.read_exact(&mut chosen).await.unwrap();
        stream
            .write_all(&[VERSION, 2, 0, IPV4, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();
        let mut answer = [0u8; 10];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[1], COMMAND_NOT_SUPPORTED);
        // A client that offers only username/password authentication.
        let mut stream = UnixStream::connect(proxy.path()).await.unwrap();
        stream.write_all(&[VERSION, 1, 2]).await.unwrap();
        stream.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [VERSION, NO_ACCEPTABLE_METHOD]);
        assert_eq!(proxy.tunnels(), 0);
    }

    #[tokio::test]
    async fn past_the_cap_every_tunnel_ends() {
        let dir = tempfile::tempdir().unwrap();
        let port = server(600).await;
        let start =
            |max| UpstreamProxy::start(dir.path(), "127.0.0.1", port, max, Dialer::Direct).unwrap();
        // Exactly the cap: fine.
        let proxy = start(600);
        let (_, sent) = through(&proxy, DOMAIN, b"127.0.0.1", port).await;
        assert_eq!(sent.len(), 600);
        assert!(!proxy.too_large());
        // One byte past it, over two tunnels: the second one is cut.
        let proxy = start(1199);
        let (_, first) = through(&proxy, DOMAIN, b"127.0.0.1", port).await;
        assert_eq!(first.len(), 600);
        let (_, second) = through(&proxy, DOMAIN, b"127.0.0.1", port).await;
        assert!(second.len() < 600, "{}", second.len());
        assert!(proxy.too_large());
        // Once over, a new connection gets nothing at all.
        let mut stream = UnixStream::connect(proxy.path()).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.write_all(&[VERSION, 1, NO_AUTHENTICATION]).await;
        let _ = stream.read_to_end(&mut rest).await;
        assert!(rest.is_empty(), "{rest:?}");
    }

    /// The review after M7.6 (M-2): the exchange's 30 s covered the dial through the repo's
    /// proxy too, so a `connect_timeout` above it (Tor's, 2 min in the guide) was cut at 30 s
    /// and its reason lost. The dial now gets the proxy's whole `connect_timeout` and says why
    /// it failed; git's own exchange still gets 30 s. Paused clock: time runs ahead only while
    /// everything waits.
    #[tokio::test(start_paused = true)]
    async fn a_dial_gets_its_proxy_s_whole_timeout_and_git_s_exchange_its_own_deadline() {
        use crate::dial::{DialWhy, ProxyRoute};
        // A proxy that takes the connection and never answers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                kept.push(stream);
            }
        });
        let shared = |seconds: u64| Shared {
            host: "abcdefghijklmnop.onion".to_owned(),
            address: None,
            port: 22,
            max: 1 << 20,
            received: AtomicU64::new(0),
            tunnels: AtomicUsize::new(0),
            over: watch::Sender::new(false),
            dialer: Dialer::Proxy(Arc::new(ProxyRoute {
                name: "tor".parse().unwrap(),
                url: writ_core::config::ProxyUrl::parse(&format!("socks5://127.0.0.1:{port}"))
                    .unwrap(),
                credential: None,
                password: None,
                timeout: Duration::from_secs(seconds),
            })),
            failure: Mutex::new(None),
        };
        let mut asked = vec![
            VERSION,
            1,
            NO_AUTHENTICATION,
            VERSION,
            CONNECT,
            0,
            DOMAIN,
            22,
        ];
        asked.extend_from_slice(b"abcdefghijklmnop.onion");
        asked.extend_from_slice(&22u16.to_be_bytes());

        // A connect_timeout of 60 s: the dial waits all of it, not 30 s, and says why.
        let shared60 = shared(60);
        let (mut git, mut ours) = tokio::io::duplex(1024);
        git.write_all(&asked).await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(open(&mut ours, &shared60).await.is_none());
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        assert_eq!(
            shared60.failure.lock().unwrap().clone(),
            Some(DialError::Proxy {
                proxy: "tor".parse().unwrap(),
                why: DialWhy::Timeout(60),
            })
        );
        let mut answer = [0u8; 12];
        git.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[..2], [VERSION, NO_AUTHENTICATION]);
        assert_eq!(
            answer[3], HOST_UNREACHABLE,
            "git is told, and the operation says why"
        );

        // git's own exchange is still bounded: a git that never asks is dropped at 30 s, and
        // nothing is dialed.
        let shared300 = shared(300);
        let (mut git, mut ours) = tokio::io::duplex(1024);
        git.write_all(&asked[..3]).await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(open(&mut ours, &shared300).await.is_none());
        assert_eq!(started.elapsed(), HANDSHAKE_DEADLINE);
        assert_eq!(shared300.failure.lock().unwrap().clone(), None);
    }

    #[tokio::test]
    async fn dropped_it_ends_its_tunnels_and_removes_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        // An upstream that never closes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (held, mut released) = tokio::sync::mpsc::channel::<TcpStream>(1);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = held.send(stream).await;
            }
        });
        let proxy =
            UpstreamProxy::start(dir.path(), "127.0.0.1", port, 1 << 20, Dialer::Direct).unwrap();
        let mut stream = UnixStream::connect(proxy.path()).await.unwrap();
        stream
            .write_all(&[VERSION, 1, NO_AUTHENTICATION])
            .await
            .unwrap();
        let mut chosen = [0u8; 2];
        stream.read_exact(&mut chosen).await.unwrap();
        let mut request = vec![VERSION, CONNECT, 0, IPV4, 127, 0, 0, 1];
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut answer = [0u8; 10];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[1], SUCCEEDED);
        let _upstream_side = released.recv().await.unwrap();
        let path = proxy.path().to_owned();
        drop(proxy);
        assert!(!path.exists());
        // The tunnel is gone: git's side reads the end.
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
    }
}
