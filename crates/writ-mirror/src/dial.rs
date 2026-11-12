//! How the daemon opens a connection to an upstream ([`Dialer`]): directly, or through the
//! repo's proxy (`proxies.<name>`, M7.2): SOCKS5 (RFC 1928, with RFC 1929's user and password)
//! or HTTP `CONNECT` (with Basic `Proxy-Authorization`). Only tunnels: what goes through is
//! TLS or SSH, end to end. Behind a proxy the upstream's name is never resolved here: SOCKS5
//! gets it as a domain name, `CONNECT` as `host:port`, and the proxy resolves it (an onion
//! name, a name only the proxy's network knows). Only the proxy's own host is resolved here.
//!
//! What the proxy answers is untrusted: read field by field, bounded ([`MAX_HEAD`] for an HTTP
//! answer's head), within the proxy's `connect_timeout`. A refusal says why, cut and cleaned,
//! and never holds the password, which lives in memory wiped on drop and goes only to the
//! proxy.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64ct::Encoding as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use writ_core::config::{Proxy, ProxyScheme, ProxyUrl};
use writ_core::names::{KeyId, ProxyName};
use zeroize::Zeroizing;

use crate::credential::UpstreamToken;

/// How long connecting to upstream directly may take.
pub const DIRECT_DEADLINE: Duration = Duration::from_secs(15);

/// The longest head of an HTTP proxy's answer read (its status line and headers).
pub const MAX_HEAD: usize = 8 * 1024;

/// The longest password SOCKS5 carries (RFC 1929: one length byte).
pub const MAX_SOCKS_PASSWORD: usize = 255;

const SOCKS_VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0;
const USER_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const USER_PASSWORD_VERSION: u8 = 1;
const CONNECT: u8 = 1;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;

/// How one repo's upstream connections are opened.
#[derive(Clone, Debug)]
pub enum Dialer {
    /// The daemon connects to upstream itself.
    Direct,
    /// Through a proxy of the policy.
    Proxy(Arc<ProxyRoute>),
}

/// A proxy as one repo reaches it: the policy's entry and its password, once added.
pub struct ProxyRoute {
    pub(crate) name: ProxyName,
    pub(crate) url: ProxyUrl,
    pub(crate) credential: Option<KeyId>,
    /// The credential's password: none until an approver adds it (`writ admin token`), and
    /// until then nothing goes through the proxy.
    pub(crate) password: Option<Arc<UpstreamToken>>,
    pub(crate) timeout: Duration,
}

impl std::fmt::Debug for ProxyRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRoute")
            .field("name", &self.name)
            .field("url", &self.url.as_str())
            .field("credential", &self.credential)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ProxyRoute {
    /// The route through `proxy` (named `name`), with its password from `tokens` when it has a
    /// credential.
    pub fn new(
        name: &ProxyName,
        proxy: &Proxy,
        tokens: &std::collections::BTreeMap<KeyId, Arc<UpstreamToken>>,
    ) -> Self {
        Self {
            name: name.clone(),
            url: proxy.url.clone(),
            credential: proxy.credential.clone(),
            password: proxy
                .credential
                .as_ref()
                .and_then(|id| tokens.get(id).cloned()),
            timeout: Duration::from_secs(proxy.connect_timeout().seconds()),
        }
    }

    pub fn name(&self) -> &ProxyName {
        &self.name
    }

    /// The credential whose password isn't in the keystore yet, if any: nothing goes through
    /// the proxy until it is added.
    pub fn missing_password(&self) -> Option<&KeyId> {
        match (&self.credential, &self.password) {
            (Some(id), None) => Some(id),
            _ => None,
        }
    }

    /// Whether `other` is the same route: the same proxy, timeout and password (a password
    /// added or replaced is another route).
    pub fn same_as(&self, other: &ProxyRoute) -> bool {
        self.name == other.name
            && self.url == other.url
            && self.credential == other.credential
            && self.timeout == other.timeout
            && match (&self.password, &other.password) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl Dialer {
    /// The dialer for a repo whose entry names `proxy` (none: directly), from the policy's
    /// `proxies`. A name the policy doesn't declare is refused (the policy checked it).
    pub fn for_repo(
        proxy: Option<&ProxyName>,
        proxies: &std::collections::BTreeMap<ProxyName, Proxy>,
        tokens: &std::collections::BTreeMap<KeyId, Arc<UpstreamToken>>,
    ) -> Result<Self, String> {
        match proxy {
            None => Ok(Self::Direct),
            Some(name) => match proxies.get(name) {
                Some(entry) => Ok(Self::Proxy(Arc::new(ProxyRoute::new(name, entry, tokens)))),
                None => Err(format!("proxy {name} is not declared in proxies")),
            },
        }
    }

    /// Whether `other` opens connections the same way.
    pub fn same_as(&self, other: &Dialer) -> bool {
        match (self, other) {
            (Self::Direct, Self::Direct) => true,
            (Self::Proxy(a), Self::Proxy(b)) => a.same_as(b),
            _ => false,
        }
    }

    /// The proxy, if any.
    pub fn proxy(&self) -> Option<&ProxyRoute> {
        match self {
            Self::Direct => None,
            Self::Proxy(route) => Some(route),
        }
    }

    /// How long opening one connection may take: [`DIRECT_DEADLINE`], or the proxy's
    /// `connect_timeout`.
    pub fn deadline(&self) -> Duration {
        match self {
            Self::Direct => DIRECT_DEADLINE,
            Self::Proxy(route) => route.timeout,
        }
    }

    /// A connection to `host` on `port` (an upstream's, as the registry names it), within
    /// [`Self::deadline`].
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, DialError> {
        match self {
            Self::Direct => {
                match tokio::time::timeout(DIRECT_DEADLINE, TcpStream::connect((host, port))).await
                {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(e)) => Err(DialError::Direct(e.kind().to_string())),
                    Err(_) => Err(DialError::Direct(format!(
                        "no connection within {}s",
                        DIRECT_DEADLINE.as_secs()
                    ))),
                }
            }
            Self::Proxy(route) => {
                let at = |why: DialWhy| DialError::Proxy {
                    proxy: route.name.clone(),
                    why,
                };
                if let Some(id) = route.missing_password() {
                    return Err(at(DialWhy::NoPassword(id.clone())));
                }
                match tokio::time::timeout(route.timeout, through(route, host, port)).await {
                    Ok(result) => result.map_err(at),
                    Err(_) => Err(at(DialWhy::Timeout(route.timeout.as_secs()))),
                }
            }
        }
    }
}

/// Why a connection to upstream couldn't be opened. Its text reaches the audit log and an
/// agent's terminal: it never holds the password.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DialError {
    /// Upstream itself can't be reached (directly).
    #[error("cannot reach upstream: {0}")]
    Direct(String),
    /// The proxy refused, failed or can't be reached.
    #[error("proxy {proxy}: {why}")]
    Proxy { proxy: ProxyName, why: DialWhy },
}

/// What went wrong with a proxy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DialWhy {
    #[error("cannot reach the proxy: {0}")]
    Unreachable(String),
    #[error("no answer within {0}s (its connect_timeout)")]
    Timeout(u64),
    #[error(
        "its password ({0}) isn't in the keystore yet: an approver adds it with `writ admin token \
         {0}`"
    )]
    NoPassword(KeyId),
    #[error("the password is longer than SOCKS5's {MAX_SOCKS_PASSWORD} bytes")]
    PasswordTooLong,
    #[error("it refused the credential")]
    CredentialRefused,
    #[error("it asks for a password, and none is configured (credential)")]
    CredentialNeeded,
    #[error("it took none of the methods offered")]
    NoMethod,
    #[error("it refused the tunnel: {0}")]
    Refused(String),
    #[error("it doesn't answer as a {scheme} proxy: {why}")]
    Protocol {
        scheme: ProxyScheme,
        why: &'static str,
    },
    #[error("it closed the connection: {0}")]
    Closed(String),
}

/// A tunnel to `host:port` through `route`'s proxy.
async fn through(route: &ProxyRoute, host: &str, port: u16) -> Result<TcpStream, DialWhy> {
    let mut stream = TcpStream::connect((route.url.host(), route.url.port()))
        .await
        // What the system said (a name it can't resolve, a refusal), not only its kind.
        .map_err(|e| DialWhy::Unreachable(crate::shown(e.to_string().as_bytes())))?;
    let credential = match (route.url.user(), &route.password) {
        (Some(user), Some(password)) => Some((user, password.expose())),
        _ => None,
    };
    match route.url.scheme() {
        ProxyScheme::Socks5 => socks5(&mut stream, credential, host, port).await?,
        ProxyScheme::Http => http_connect(&mut stream, credential, host, port).await?,
    }
    Ok(stream)
}

/// A read the proxy ended early: closed, or failed.
fn closed(e: std::io::Error) -> DialWhy {
    DialWhy::Closed(e.kind().to_string())
}

/// The SOCKS5 handshake for a tunnel to `host:port` on `stream`: the method (user and password
/// only when there is a credential, no authentication otherwise), then `CONNECT` naming the
/// host as the registry does (a name is sent as a name, for the proxy to resolve), and the
/// reply, read whole so that what follows is upstream's.
pub(crate) async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credential: Option<(&str, &str)>,
    host: &str,
    port: u16,
) -> Result<(), DialWhy> {
    let protocol = |why| DialWhy::Protocol {
        scheme: ProxyScheme::Socks5,
        why,
    };
    let method = match credential {
        Some(_) => USER_PASSWORD,
        None => NO_AUTHENTICATION,
    };
    stream
        .write_all(&[SOCKS_VERSION, 1, method])
        .await
        .map_err(closed)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(closed)?;
    match chosen {
        [SOCKS_VERSION, m] if m == method => {}
        [SOCKS_VERSION, NO_ACCEPTABLE_METHOD] if credential.is_none() => {
            return Err(DialWhy::CredentialNeeded);
        }
        [SOCKS_VERSION, NO_ACCEPTABLE_METHOD] => return Err(DialWhy::NoMethod),
        [SOCKS_VERSION, _] => return Err(protocol("it chose a method that wasn't offered")),
        _ => return Err(protocol("not a SOCKS5 answer")),
    }
    if let Some((user, password)) = credential {
        let (Ok(user_len), Ok(password_len)) =
            (u8::try_from(user.len()), u8::try_from(password.len()))
        else {
            return Err(DialWhy::PasswordTooLong);
        };
        let mut request = Zeroizing::new(Vec::with_capacity(515));
        request.extend_from_slice(&[USER_PASSWORD_VERSION, user_len]);
        request.extend_from_slice(user.as_bytes());
        request.push(password_len);
        request.extend_from_slice(password.as_bytes());
        stream.write_all(&request).await.map_err(closed)?;
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.map_err(closed)?;
        match status {
            [USER_PASSWORD_VERSION, 0] => {}
            [USER_PASSWORD_VERSION, _] => return Err(DialWhy::CredentialRefused),
            _ => return Err(protocol("not an RFC 1929 answer")),
        }
    }
    let mut request = vec![SOCKS_VERSION, CONNECT, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            request.push(IPV4);
            request.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            request.push(IPV6);
            request.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let length = u8::try_from(host.len())
                .map_err(|_| protocol("the host name is longer than 255 bytes"))?;
            request.extend_from_slice(&[DOMAIN, length]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(closed)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(closed)?;
    let [version, status, _reserved, kind] = head;
    if version != SOCKS_VERSION {
        return Err(protocol("not a SOCKS5 reply"));
    }
    if status != 0 {
        return Err(DialWhy::Refused(socks_status(status)));
    }
    // The address it bound: read and dropped, so what follows is upstream's.
    let skip = match kind {
        IPV4 => 4usize,
        IPV6 => 16,
        DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(closed)?;
            usize::from(length[0])
        }
        _ => return Err(protocol("an unknown address type in its reply")),
    };
    let mut bound = [0u8; 255 + 2];
    let bound = bound
        .get_mut(..skip.saturating_add(2))
        .ok_or(protocol("an address too long in its reply"))?;
    stream.read_exact(bound).await.map_err(closed)?;
    Ok(())
}

/// What a SOCKS5 reply's status says (RFC 1928, and Tor's own for onion services).
fn socks_status(status: u8) -> String {
    let said = match status {
        1 => "general failure",
        2 => "not allowed by its rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused by upstream",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        0xf0 => "onion service descriptor not found (Tor)",
        0xf1 => "onion service descriptor invalid (Tor)",
        0xf2 => "onion service introduction failed (Tor)",
        0xf3 => "onion service rendezvous failed (Tor)",
        0xf4 => "onion service needs client authorization (Tor)",
        0xf5 => "onion service client authorization refused (Tor)",
        0xf6 => "invalid onion address (Tor)",
        0xf7 => "onion service introduction timed out (Tor)",
        _ => return format!("status {status}"),
    };
    format!("{said} (status {status})")
}

/// The HTTP `CONNECT` for a tunnel to `host:port` on `stream`, with Basic
/// `Proxy-Authorization` when there is a credential, and the answer's head, read byte by byte
/// (at most [`MAX_HEAD`]) so that nothing of upstream's is taken with it. Only `200` opens the
/// tunnel.
pub(crate) async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credential: Option<(&str, &str)>,
    host: &str,
    port: u16,
) -> Result<(), DialWhy> {
    let protocol = |why| DialWhy::Protocol {
        scheme: ProxyScheme::Http,
        why,
    };
    let authority = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    };
    // The password's buffers sized up front: none grows (and leaves a copy) while it holds it.
    let encoded = match credential {
        Some((user, password)) => {
            let mut pair = Zeroizing::new(String::with_capacity(
                user.len().saturating_add(1).saturating_add(password.len()),
            ));
            pair.push_str(user);
            pair.push(':');
            pair.push_str(password);
            Some(Zeroizing::new(base64ct::Base64::encode_string(
                pair.as_bytes(),
            )))
        }
        None => None,
    };
    const HEADER: &str = "Proxy-Authorization: Basic ";
    let capacity = authority
        .len()
        .saturating_mul(2)
        .saturating_add(64)
        .saturating_add(HEADER.len())
        .saturating_add(encoded.as_ref().map_or(0, |e| e.len()));
    let mut request = Zeroizing::new(String::with_capacity(capacity));
    for part in [
        "CONNECT ",
        &authority,
        " HTTP/1.1\r\nHost: ",
        &authority,
        "\r\n",
    ] {
        request.push_str(part);
    }
    if let Some(encoded) = &encoded {
        request.push_str(HEADER);
        request.push_str(encoded);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.map_err(closed)?;
    let mut head: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(protocol("an answer's head longer than 8 KiB"));
        }
        stream.read_exact(&mut byte).await.map_err(closed)?;
        head.push(byte[0]);
    }
    let line = head
        .split(|b| *b == b'\n')
        .next()
        .unwrap_or_default()
        .strip_suffix(b"\r")
        .unwrap_or_default();
    let line = std::str::from_utf8(line).map_err(|_| protocol("not an HTTP status line"))?;
    let mut parts = line.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Err(protocol("not an HTTP status line"));
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") || code.len() != 3 {
        return Err(protocol("not an HTTP status line"));
    }
    // A hostile proxy could print the password back: it reaches an agent's terminal.
    let said = parts.next().unwrap_or_default().as_bytes();
    let reason = match credential {
        Some((user, password)) => crate::mirror::redacted(said, password, user),
        None => crate::shown(said),
    };
    match code {
        "200" => Ok(()),
        "407" if credential.is_some() => Err(DialWhy::CredentialRefused),
        "407" => Err(DialWhy::CredentialNeeded),
        _ if code.bytes().all(|b| b.is_ascii_digit()) => Err(DialWhy::Refused(
            format!("{code} {reason}").trim_end().to_owned(),
        )),
        _ => Err(protocol("not an HTTP status line")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proxy's answer, the credential offered, and what it must be refused as.
    type Case = (Vec<u8>, Option<(&'static str, &'static str)>, DialWhy);

    /// A proxy that has `answer` ready (all of it written at once, before the client asks:
    /// the client reads it field by field), then reads everything the client sends until the
    /// client is done; returns the handshake's result and what the client sent. A handshake
    /// that waits for more than the answer holds fails within the deadline, never hangs.
    async fn exchange(
        answer: Vec<u8>,
        handshake: impl AsyncFnOnce(&mut tokio::io::DuplexStream) -> Result<(), DialWhy>,
    ) -> (Result<(), DialWhy>, Vec<u8>) {
        let (mut client, mut proxy) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(async move {
            let _ = proxy.write_all(&answer).await;
            // Nothing more from the proxy: an answer cut short reads as its end.
            let _ = proxy.shutdown().await;
            let mut got = Vec::new();
            let _ = proxy.read_to_end(&mut got).await;
            got
        });
        let result = tokio::time::timeout(Duration::from_secs(5), handshake(&mut client))
            .await
            .expect("the handshake waited for more than the proxy said");
        drop(client);
        (result, served.await.unwrap())
    }

    #[tokio::test]
    async fn socks5_sends_the_name_for_the_proxy_to_resolve() {
        let host = "abcdefghijklmnop.onion";
        let mut answer = vec![5, 0];
        answer.extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let (result, got) = exchange(answer, async |s| socks5(s, None, host, 22).await).await;
        assert_eq!(result, Ok(()));
        let mut expected = vec![5, 1, 0, 5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
        expected.extend_from_slice(host.as_bytes());
        expected.extend_from_slice(&[0, 22]);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn socks5_sends_an_address_as_an_address() {
        let mut answer = vec![5, 0];
        answer.extend_from_slice(&[5, 0, 0, 4]);
        answer.extend_from_slice(&[0; 18]);
        let (result, got) = exchange(answer, async |s| socks5(s, None, "::1", 443).await).await;
        assert_eq!(result, Ok(()));
        assert_eq!(got.get(6), Some(&IPV6));
        assert_eq!(
            got.get(7..23),
            Some(&[0u8; 15].iter().chain(&[1]).copied().collect::<Vec<_>>()[..])
        );
    }

    #[tokio::test]
    async fn socks5_offers_only_the_password_method_with_a_credential() {
        let mut answer = vec![5, 2, 1, 0];
        answer.extend_from_slice(&[5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 1]);
        let (result, got) = exchange(answer, async |s| {
            socks5(s, Some(("writ", "s3cret")), "host", 22).await
        })
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(got.get(..3), Some(&[5, 1, 2][..]));
        assert_eq!(got.get(3..16), Some(&b"\x01\x04writ\x06s3cret"[..]));
    }

    #[tokio::test]
    async fn every_bad_socks5_answer_is_refused_with_its_reason() {
        let ok_method = vec![5, 0];
        let cases: Vec<Case> = vec![
            (
                vec![4, 0],
                None,
                DialWhy::Protocol {
                    scheme: ProxyScheme::Socks5,
                    why: "not a SOCKS5 answer",
                },
            ),
            (vec![5, 0xff], None, DialWhy::CredentialNeeded),
            (vec![5, 0xff], Some(("u", "p")), DialWhy::NoMethod),
            (
                vec![5, 2],
                None,
                DialWhy::Protocol {
                    scheme: ProxyScheme::Socks5,
                    why: "it chose a method that wasn't offered",
                },
            ),
            (
                vec![5, 2, 1, 1],
                Some(("u", "p")),
                DialWhy::CredentialRefused,
            ),
            (
                vec![5, 2, 5, 0],
                Some(("u", "p")),
                DialWhy::Protocol {
                    scheme: ProxyScheme::Socks5,
                    why: "not an RFC 1929 answer",
                },
            ),
            (
                [ok_method.clone(), vec![5, 5, 0, 1]].concat(),
                None,
                DialWhy::Refused("connection refused by upstream (status 5)".to_owned()),
            ),
            (
                [ok_method.clone(), vec![5, 0xf0, 0, 1]].concat(),
                None,
                DialWhy::Refused(
                    "onion service descriptor not found (Tor) (status 240)".to_owned(),
                ),
            ),
            (
                [ok_method.clone(), vec![5, 0x99, 0, 1]].concat(),
                None,
                DialWhy::Refused("status 153".to_owned()),
            ),
            (
                [ok_method.clone(), vec![4, 0, 0, 1]].concat(),
                None,
                DialWhy::Protocol {
                    scheme: ProxyScheme::Socks5,
                    why: "not a SOCKS5 reply",
                },
            ),
            (
                [ok_method.clone(), vec![5, 0, 0, 9]].concat(),
                None,
                DialWhy::Protocol {
                    scheme: ProxyScheme::Socks5,
                    why: "an unknown address type in its reply",
                },
            ),
            // A reply cut short: the bound address never comes.
            (
                [ok_method.clone(), vec![5, 0, 0, 1, 127]].concat(),
                None,
                DialWhy::Closed("unexpected end of file".to_owned()),
            ),
            (
                vec![],
                None,
                DialWhy::Closed("unexpected end of file".to_owned()),
            ),
        ];
        for (answer, credential, expected) in cases {
            let (result, _) = exchange(answer.clone(), async |s| {
                socks5(s, credential, "host", 22).await
            })
            .await;
            assert_eq!(result, Err(expected), "answer {answer:?}");
        }
    }

    #[tokio::test]
    async fn a_socks5_password_is_at_most_255_bytes() {
        let long = "p".repeat(256);
        let (result, _) = exchange(vec![5, 2], async |s| {
            socks5(s, Some(("u", &long)), "host", 22).await
        })
        .await;
        assert_eq!(result, Err(DialWhy::PasswordTooLong));
        let fits = "p".repeat(255);
        let mut answer = vec![5, 2, 1, 0];
        answer.extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let (result, _) = exchange(answer, async |s| {
            socks5(s, Some(("u", &fits)), "host", 22).await
        })
        .await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn http_connect_asks_for_the_tunnel_by_name_with_basic_authorization() {
        let request = "CONNECT forgejo-behind:22 HTTP/1.1\r\nHost: forgejo-behind:22\r\n\
                       Proxy-Authorization: Basic d3JpdDpzM2NyZXQ=\r\n\r\n";
        let (result, got) = exchange(
            b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nSSH-2.0".to_vec(),
            async |s| http_connect(s, Some(("writ", "s3cret")), "forgejo-behind", 22).await,
        )
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(String::from_utf8(got).unwrap(), request);
        // An IPv6 address in brackets.
        let request = "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n";
        let (result, got) = exchange(b"HTTP/1.0 200 OK\r\n\r\n".to_vec(), async |s| {
            http_connect(s, None, "::1", 443).await
        })
        .await;
        assert_eq!(result, Ok(()));
        assert_eq!(String::from_utf8(got).unwrap(), request);
    }

    #[tokio::test]
    async fn http_connect_reads_nothing_past_the_head() {
        let (mut client, mut proxy) = tokio::io::duplex(1024);
        proxy
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-upstream\r\n")
            .await
            .unwrap();
        // Its write side closed (it keeps reading): the client reads to the end after.
        proxy.shutdown().await.unwrap();
        http_connect(&mut client, None, "host", 22).await.unwrap();
        let mut rest = String::new();
        client.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, "SSH-2.0-upstream\r\n");
    }

    #[tokio::test]
    async fn every_bad_http_answer_is_refused_with_its_reason() {
        let protocol = |why| DialWhy::Protocol {
            scheme: ProxyScheme::Http,
            why,
        };
        let cases: Vec<Case> = vec![
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
                None,
                DialWhy::CredentialNeeded,
            ),
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
                Some(("u", "p")),
                DialWhy::CredentialRefused,
            ),
            (
                b"HTTP/1.1 403 Forbidden\x1b[31m\r\n\r\n".to_vec(),
                None,
                DialWhy::Refused("403 Forbidden[31m".to_owned()),
            ),
            (
                b"HTTP/1.1 502\r\n\r\n".to_vec(),
                None,
                DialWhy::Refused("502".to_owned()),
            ),
            (
                b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
                None,
                DialWhy::Refused("204 No Content".to_owned()),
            ),
            (
                b"SSH-2.0-x\r\n\r\n".to_vec(),
                None,
                protocol("not an HTTP status line"),
            ),
            (
                b"HTTP/2 200\r\n\r\n".to_vec(),
                None,
                protocol("not an HTTP status line"),
            ),
            (
                b"HTTP/1.1 2000 OK\r\n\r\n".to_vec(),
                None,
                protocol("not an HTTP status line"),
            ),
            (
                b"HTTP/1.1 2x0 OK\r\n\r\n".to_vec(),
                None,
                protocol("not an HTTP status line"),
            ),
            (
                b"HTTP/1.1 \xff\r\n\r\n".to_vec(),
                None,
                protocol("not an HTTP status line"),
            ),
            (
                b"HTTP/1.1 200 OK\r\n".to_vec(),
                None,
                DialWhy::Closed("unexpected end of file".to_owned()),
            ),
        ];
        for (answer, credential, expected) in cases {
            let (result, _) = exchange(answer.clone(), async |s| {
                http_connect(s, credential, "host", 22).await
            })
            .await;
            assert_eq!(
                result,
                Err(expected),
                "answer {:?}",
                String::from_utf8_lossy(&answer)
            );
        }
    }

    #[tokio::test]
    async fn an_endless_head_is_cut_at_8_kib_on_both_sides() {
        let head = |len: usize| {
            let mut head = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
            head.resize(len - 4, b'a');
            head.extend_from_slice(b"\r\n\r\n");
            head
        };
        let (result, _) = exchange(head(MAX_HEAD), async |s| {
            http_connect(s, None, "host", 22).await
        })
        .await;
        assert_eq!(result, Ok(()));
        let (result, _) = exchange(head(MAX_HEAD + 1), async |s| {
            http_connect(s, None, "host", 22).await
        })
        .await;
        assert_eq!(
            result,
            Err(DialWhy::Protocol {
                scheme: ProxyScheme::Http,
                why: "an answer's head longer than 8 KiB"
            })
        );
    }

    #[tokio::test]
    async fn no_message_holds_the_password() {
        let password = "pa55-w0rd-never-shown";
        let encoded = base64ct::Base64::encode_string(format!("u:{password}").as_bytes());
        for answer in [
            format!("HTTP/1.1 407 {password} {encoded}\r\n\r\n").into_bytes(),
            format!("HTTP/1.1 403 {password} {encoded}\r\n\r\n").into_bytes(),
        ] {
            let (result, _) = exchange(answer, async |s| {
                http_connect(s, Some(("u", password)), "host", 22).await
            })
            .await;
            let said = result.unwrap_err().to_string();
            assert!(
                !said.contains(password) && !said.contains(&encoded),
                "{said}"
            );
        }
        let route = ProxyRoute {
            name: "p".parse().unwrap(),
            url: ProxyUrl::parse("socks5://u@127.0.0.1:1").unwrap(),
            credential: Some("k".parse().unwrap()),
            password: Some(Arc::new(
                UpstreamToken::from_bytes(password.as_bytes()).unwrap(),
            )),
            timeout: Duration::from_secs(1),
        };
        assert!(!format!("{route:?}").contains(password));
    }
}
