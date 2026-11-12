//! A test proxy standing in for Dante, squid or Tor: SOCKS5 or HTTP `CONNECT` on `127.0.0.1`,
//! port 0, with an optional user and password, tunnelling only to the names it was told
//! ([`TestProxy::map`]: a name the daemon's host can't resolve, as an onion name, reached only
//! through it). It records every destination it was asked for and can misbehave on demand
//! ([`ProxyMode`]): never answer, or refuse every tunnel.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64ct::Encoding as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The protocol it speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
}

/// How it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// Tunnels to the names it knows.
    Serve,
    /// Takes the connection and never answers.
    Silent,
    /// Refuses every tunnel (SOCKS5 "not allowed", HTTP 403).
    Refuse,
}

struct State {
    kind: ProxyKind,
    credential: Option<(String, String)>,
    names: Mutex<BTreeMap<String, SocketAddr>>,
    asked: Mutex<Vec<String>>,
    mode: Mutex<ProxyMode>,
}

/// A running test proxy.
pub struct TestProxy {
    port: u16,
    state: Arc<State>,
    _task: tokio::task::JoinHandle<()>,
}

impl TestProxy {
    /// Starts a proxy of `kind`, asking for `credential` (user, password) when given.
    pub fn start(
        runtime: &tokio::runtime::Runtime,
        kind: ProxyKind,
        credential: Option<(&str, &str)>,
    ) -> Self {
        let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State {
            kind,
            credential: credential.map(|(u, p)| (u.to_owned(), p.to_owned())),
            names: Mutex::new(BTreeMap::new()),
            asked: Mutex::new(Vec::new()),
            mode: Mutex::new(ProxyMode::Serve),
        });
        let served = state.clone();
        let task = runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, served.clone()));
            }
        });
        Self {
            port,
            state,
            _task: task,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Tunnels to `name` (a host name or address, as the client asks for it) reach `to`.
    pub fn map(&self, name: &str, to: SocketAddr) {
        self.state.names.lock().unwrap().insert(name.to_owned(), to);
    }

    /// Its URL, as `proxies.<name>.url` names it (with the user when it asks for one).
    pub fn url(&self) -> String {
        let scheme = match self.state.kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        };
        match &self.state.credential {
            Some((user, _)) => format!("{scheme}://{user}@127.0.0.1:{}", self.port),
            None => format!("{scheme}://127.0.0.1:{}", self.port),
        }
    }

    /// Every destination asked for (`host:port`, as the client sent the host), in order.
    pub fn asked(&self) -> Vec<String> {
        self.state.asked.lock().unwrap().clone()
    }

    pub fn set_mode(&self, mode: ProxyMode) {
        *self.state.mode.lock().unwrap() = mode;
    }
}

async fn serve(mut stream: TcpStream, state: Arc<State>) {
    if *state.mode.lock().unwrap() == ProxyMode::Silent {
        // Holds the connection, says nothing.
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
        return;
    }
    let target = match state.kind {
        ProxyKind::Socks5 => socks5(&mut stream, &state).await,
        ProxyKind::Http => http(&mut stream, &state).await,
    };
    if let Some(mut upstream) = target {
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    }
}

/// The destination asked for, recorded, and where it goes (none: unknown, or refused).
fn destination(state: &State, host: &str, port: u16) -> Option<SocketAddr> {
    let wanted = match host.contains(':') {
        true => format!("[{host}]:{port}"),
        false => format!("{host}:{port}"),
    };
    state.asked.lock().unwrap().push(wanted);
    if *state.mode.lock().unwrap() == ProxyMode::Refuse {
        return None;
    }
    state.names.lock().unwrap().get(host).copied()
}

async fn read_exact<S: AsyncRead + Unpin>(s: &mut S, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn socks5(stream: &mut TcpStream, state: &State) -> Option<TcpStream> {
    let head = read_exact(stream, 2).await?;
    let methods = read_exact(stream, usize::from(head[1])).await?;
    let wanted = match state.credential {
        Some(_) => 2u8,
        None => 0u8,
    };
    if head[0] != 5 || !methods.contains(&wanted) {
        let _ = stream.write_all(&[5, 0xff]).await;
        return None;
    }
    stream.write_all(&[5, wanted]).await.ok()?;
    if let Some((user, password)) = &state.credential {
        let version_len = read_exact(stream, 2).await?;
        let got_user = read_exact(stream, usize::from(version_len[1])).await?;
        let password_len = read_exact(stream, 1).await?;
        let got_password = read_exact(stream, usize::from(password_len[0])).await?;
        if got_user != user.as_bytes() || got_password != password.as_bytes() {
            let _ = stream.write_all(&[1, 1]).await;
            return None;
        }
        stream.write_all(&[1, 0]).await.ok()?;
    }
    let request = read_exact(stream, 4).await?;
    let host = match request[3] {
        1 => {
            let a = read_exact(stream, 4).await?;
            std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string()
        }
        4 => {
            let a: [u8; 16] = read_exact(stream, 16).await?.try_into().ok()?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => {
            let len = read_exact(stream, 1).await?;
            String::from_utf8(read_exact(stream, usize::from(len[0])).await?).ok()?
        }
        _ => return None,
    };
    let port = read_exact(stream, 2).await?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    let refused = |status: u8| [5, status, 0, 1, 0, 0, 0, 0, 0, 0];
    let Some(to) = destination(state, &host, port) else {
        let status = match *state.mode.lock().unwrap() {
            ProxyMode::Refuse => 2,
            _ => 4,
        };
        let _ = stream.write_all(&refused(status)).await;
        return None;
    };
    match TcpStream::connect(to).await {
        Ok(upstream) => {
            stream.write_all(&refused(0)).await.ok()?;
            Some(upstream)
        }
        Err(_) => {
            let _ = stream.write_all(&refused(5)).await;
            None
        }
    }
}

async fn http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    state: &State,
) -> Option<TcpStream> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        stream.read_exact(&mut byte).await.ok()?;
        head.push(byte[0]);
    }
    let text = String::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let target = request
        .strip_prefix("CONNECT ")?
        .strip_suffix(" HTTP/1.1")?;
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok()?;
    if let Some((user, password)) = &state.credential {
        let expected = format!(
            "Proxy-Authorization: Basic {}",
            base64ct::Base64::encode_string(format!("{user}:{password}").as_bytes())
        );
        if !lines.any(|line| line == expected) {
            let _ = stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
            return None;
        }
    }
    let Some(to) = destination(state, host, port) else {
        let answer: &[u8] = match *state.mode.lock().unwrap() {
            ProxyMode::Refuse => b"HTTP/1.1 403 Forbidden\r\n\r\n",
            _ => b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        };
        let _ = stream.write_all(answer).await;
        return None;
    };
    let upstream = TcpStream::connect(to).await.ok()?;
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .ok()?;
    Some(upstream)
}
