//! `proxies.<name>`: the proxies a repo's upstream may be reached through
//! (`repos.<name>.proxy`), for remotes that answer only from some addresses or inside some
//! network (a Tor onion service). Each is a SOCKS5 or HTTP CONNECT proxy ([`ProxyUrl`], read
//! strictly), with an optional password ([`Proxy::credential`], a token in the keystore on the
//! proxy's host) and how long reaching upstream through it may take. Only tunnels: TLS or SSH
//! stays end to end, and the proxy resolves the upstream's name (the daemon never does).

use std::fmt;

use serde::Deserialize;

use crate::names::KeyId;
use crate::units::Duration;

/// The most proxies the policy declares.
pub const MAX_PROXIES: usize = 64;

/// How long reaching upstream through a proxy may take unless `connect_timeout` says
/// otherwise: the proxy's handshake and the tunnel's opening.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_seconds(30);

/// The shortest `connect_timeout`.
pub const MIN_CONNECT_TIMEOUT: Duration = Duration::from_seconds(1);

/// The longest `connect_timeout` (an onion service can take a minute).
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_seconds(300);

/// The longest user name (SOCKS5's field is one byte long: RFC 1929).
pub const MAX_USER: usize = 255;

/// The longest host name (DNS's).
pub const MAX_HOST: usize = 253;

/// The protocol a proxy speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProxyScheme {
    /// SOCKS5 (RFC 1928), the upstream's name sent for the proxy to resolve; with a
    /// credential, RFC 1929's user and password.
    Socks5,
    /// HTTP `CONNECT` (RFC 9110), the upstream as `host:port`; with a credential, Basic
    /// `Proxy-Authorization`.
    Http,
}

impl ProxyScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyScheme::Socks5 => "socks5",
            ProxyScheme::Http => "http",
        }
    }
}

impl fmt::Display for ProxyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A proxy's URL: `socks5://[user@]host:port` or `http://[user@]host:port`. A plain host
/// name or address (an IPv6 one in brackets), an explicit port, no path, query, fragment or
/// password (the password is the credential, in the keystore).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyUrl {
    url: String,
    scheme: ProxyScheme,
    user: Option<String>,
    host: String,
    port: u16,
}

impl ProxyUrl {
    /// Parses a proxy URL, strictly.
    pub fn parse(url: &str) -> Result<Self, &'static str> {
        if !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains(['\'', '"']) {
            return Err("printable ASCII only, no spaces or quotes");
        }
        let (scheme, rest) = match url.split_once("://") {
            Some(("socks5", rest)) => (ProxyScheme::Socks5, rest),
            Some(("http", rest)) => (ProxyScheme::Http, rest),
            Some(("socks5h", _)) => {
                return Err("write socks5://: the proxy always resolves the upstream's name");
            }
            Some(("https", _)) => {
                return Err("a TLS link to the proxy isn't supported: socks5:// or http://");
            }
            Some(("socks4" | "socks4a", _)) => return Err("SOCKS4 isn't supported: socks5://"),
            _ => return Err("must be a socks5:// or http:// URL"),
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains(['/', '?', '#']) {
            return Err("no path, query or fragment: socks5://[user@]host:port");
        }
        let (user, host_port) = match authority.rsplit_once('@') {
            Some((user, host_port)) => (Some(user), host_port),
            None => (None, authority),
        };
        if let Some(user) = user {
            if user.contains(':') {
                return Err("no password in the URL: name the key that holds it in credential");
            }
            let unreserved =
                |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~');
            if user.is_empty()
                || user.len() > MAX_USER
                || user.starts_with('-')
                || !user.chars().all(unreserved)
            {
                return Err("invalid user (letters, digits, . - _ ~, at most 255)");
            }
        }
        let (host, port) = match host_port.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or("unclosed [")?;
                if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                    return Err("invalid IPv6 address");
                }
                (host, after.strip_prefix(':'))
            }
            None => match host_port.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_port, None),
            },
        };
        let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
        if host.is_empty()
            || host.len() > MAX_HOST
            || host.starts_with('-')
            || (!host_port.starts_with('[') && !host.chars().all(plain))
        {
            return Err("invalid host");
        }
        let port = port
            .ok_or("a port is required: socks5://host:1080, http://host:3128")?
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or("invalid port")?;
        Ok(Self {
            url: url.to_owned(),
            scheme,
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    /// The user the credential's password goes with, if any.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The proxy's host, as the URL names it (an IPv6 address without its brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

impl TryFrom<String> for ProxyUrl {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        Self::parse(&value).map_err(str::to_owned)
    }
}

impl<'de> Deserialize<'de> for ProxyUrl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// A proxy of the policy. Checked against the keys by the policy
/// ([`PolicyConfig`](super::PolicyConfig)): a credential given exactly when the URL names a
/// user, a token on the proxy's host.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub url: ProxyUrl,
    /// The key holding the password (`use: upstream`, `kind: token`, `host` the proxy's).
    #[serde(default)]
    pub credential: Option<KeyId>,
    /// Left out: [`DEFAULT_CONNECT_TIMEOUT`].
    #[serde(default)]
    pub connect_timeout: Option<Duration>,
}

impl Proxy {
    /// How long reaching upstream through it may take.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proxy_url_is_read_strictly() {
        let url = ProxyUrl::parse("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(
            (url.scheme(), url.host(), url.port(), url.user()),
            (ProxyScheme::Socks5, "127.0.0.1", 9050, None)
        );
        let url = ProxyUrl::parse("http://writ@proxy.corp:3128/").unwrap();
        assert_eq!(
            (url.scheme(), url.host(), url.port(), url.user()),
            (ProxyScheme::Http, "proxy.corp", 3128, Some("writ"))
        );
        let url = ProxyUrl::parse("socks5://[::1]:1080").unwrap();
        assert_eq!((url.host(), url.port()), ("::1", 1080));
        for (bad, why) in [
            ("socks5h://tor:9050", "always resolves"),
            ("https://proxy:443", "TLS link"),
            ("socks4://proxy:1080", "SOCKS4"),
            ("ftp://proxy:21", "socks5:// or http://"),
            ("proxy:1080", "socks5:// or http://"),
            ("socks5://proxy", "a port is required"),
            ("socks5://proxy:0", "invalid port"),
            ("socks5://proxy:65536", "invalid port"),
            ("socks5://proxy:x", "invalid port"),
            ("socks5://u:p@proxy:1080", "no password"),
            ("socks5://@proxy:1080", "invalid user"),
            ("socks5://-u@proxy:1080", "invalid user"),
            ("socks5://u%20@proxy:1080", "invalid user"),
            ("socks5://proxy:1080/path", "no path"),
            ("socks5://proxy:1080?x", "no path"),
            ("socks5://proxy:1080#x", "no path"),
            ("socks5://-proxy:1080", "invalid host"),
            ("socks5://pro*xy:1080", "invalid host"),
            ("socks5://:1080", "invalid host"),
            ("socks5://[::1:1080", "unclosed ["),
            ("socks5://[zz]:1080", "invalid IPv6"),
            ("socks5://pro xy:1080", "printable ASCII"),
            ("socks5://'proxy':1080", "printable ASCII"),
        ] {
            let error = ProxyUrl::parse(bad).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn a_user_and_a_host_are_bounded_on_both_sides() {
        let user = "u".repeat(MAX_USER);
        assert!(ProxyUrl::parse(&format!("socks5://{user}@p:1")).is_ok());
        assert_eq!(
            ProxyUrl::parse(&format!("socks5://{user}u@p:1")),
            Err("invalid user (letters, digits, . - _ ~, at most 255)")
        );
        let host = "h".repeat(MAX_HOST);
        assert!(ProxyUrl::parse(&format!("socks5://{host}:1")).is_ok());
        assert_eq!(
            ProxyUrl::parse(&format!("socks5://{host}h:1")),
            Err("invalid host")
        );
    }
}
