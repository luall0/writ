//! A SOCKS5 proxy for one HTTPS upstream operation (RFC 1928, `CONNECT` without
//! authentication): git reaches upstream only through it, on a Unix socket in a private
//! directory (`http.proxy=socks5h://localhost/<socket>`). It connects only to the upstream's
//! host and port, and counts the bytes upstream sends, all connections together: past the cap
//! it ends every tunnel, so a sync never takes more than `mirrors.max_fetch` (git has no limit
//! of its own on a fetch, the gap the ssh [`relay`](crate::relay) closes for `ssh://`).
//!
//! TLS stays end to end between git and upstream: the proxy relays ciphertext, and never sees
//! the token. Dropping the [`UpstreamProxy`] ends every tunnel and removes the socket file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::upstream::HttpsUrl;
use crate::{MirrorError, Result};

/// Connections one proxy accepts in its life (git keeps one open, and opens another when
/// upstream closes it).
pub const MAX_CONNECTIONS: usize = 16;
/// How long git may take to ask for its tunnel.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// How long connecting to upstream may take.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(15);

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
}

impl UpstreamProxy {
    /// Serves a proxy to `upstream` on a new socket in `dir`, a private directory, letting
    /// upstream send at most `max_bytes`.
    pub fn start(dir: &Path, upstream: &HttpsUrl, max_bytes: u64) -> Result<Self> {
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
            host: upstream.host().to_owned(),
            address: upstream.host().parse().ok(),
            port: upstream.port(),
            max: max_bytes,
            received: AtomicU64::new(0),
            tunnels: AtomicUsize::new(0),
            over: watch::Sender::new(false),
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
    let upstream =
        match tokio::time::timeout(HANDSHAKE_DEADLINE, handshake(&mut client, &shared)).await {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "upstream proxy handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!("upstream proxy handshake timed out");
                return;
            }
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

/// Reads git's greeting and request, connects to upstream if it asks for upstream, and
/// answers. An error ends the connection.
async fn handshake(client: &mut UnixStream, shared: &Shared) -> std::io::Result<TcpStream> {
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
    connect(client, shared).await
}

/// The greeting: SOCKS5, and no authentication among the methods git offers.
async fn greet(client: &mut UnixStream) -> std::io::Result<()> {
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
async fn read_request(client: &mut UnixStream) -> std::io::Result<(u8, Asked, u16)> {
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

/// Connects to upstream (by the host the URL names, never what git sent) within
/// [`CONNECT_DEADLINE`], and tells git how it went.
async fn connect(client: &mut UnixStream, shared: &Shared) -> std::io::Result<TcpStream> {
    let connected = tokio::time::timeout(
        CONNECT_DEADLINE,
        TcpStream::connect((shared.host.as_str(), shared.port)),
    )
    .await;
    match connected {
        Ok(Ok(upstream)) => {
            reply(client, SUCCEEDED).await?;
            Ok(upstream)
        }
        Ok(Err(e)) => {
            reply(client, HOST_UNREACHABLE).await?;
            Err(e)
        }
        Err(_) => {
            reply(client, HOST_UNREACHABLE).await?;
            Err(std::io::Error::other("connecting to upstream timed out"))
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
async fn reply(client: &mut UnixStream, status: u8) -> std::io::Result<()> {
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
        let url = HttpsUrl::parse(&format!("https://127.0.0.1:{port}/demo.git")).unwrap();
        let proxy = UpstreamProxy::start(dir.path(), &url, 1 << 20).unwrap();
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
        let url = HttpsUrl::parse("https://Git.Example.org/u/r.git").unwrap();
        let shared = Shared {
            host: url.host().to_owned(),
            address: None,
            port: 443,
            max: 1,
            received: AtomicU64::new(0),
            tunnels: AtomicUsize::new(0),
            over: watch::Sender::new(false),
        };
        assert!(Asked::Name(b"git.example.ORG".to_vec()).is(&shared));
        assert!(!Asked::Name(b"git.example.org.evil".to_vec()).is(&shared));
        assert!(!Asked::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)).is(&shared));

        let proxy = UpstreamProxy::start(dir.path(), &url, 1).unwrap();
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
        let url = HttpsUrl::parse(&format!("https://127.0.0.1:{port}/demo.git")).unwrap();
        // Exactly the cap: fine.
        let proxy = UpstreamProxy::start(dir.path(), &url, 600).unwrap();
        let (_, sent) = through(&proxy, DOMAIN, b"127.0.0.1", port).await;
        assert_eq!(sent.len(), 600);
        assert!(!proxy.too_large());
        // One byte past it, over two tunnels: the second one is cut.
        let proxy = UpstreamProxy::start(dir.path(), &url, 1199).unwrap();
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
        let url = HttpsUrl::parse(&format!("https://127.0.0.1:{port}/demo.git")).unwrap();
        let proxy = UpstreamProxy::start(dir.path(), &url, 1 << 20).unwrap();
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
