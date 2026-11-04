//! How the daemon reaches an upstream, chosen by the registry's URL ([`Upstream`]), read
//! strictly.
//!
//! - `ssh://`: the ssh command git runs for it. Every ssh option that matters is stated
//!   (`-F /dev/null`: no config file decides anything), the host key must be the pinned one,
//!   the only key offered is the repo's credential through a one-operation agent socket, and
//!   what upstream sends goes through the byte-capping [`relay`](crate::relay).
//! - `https://`: git's own HTTPS with the repo's token, handed over by a one-operation
//!   [`credential`](crate::credential) socket, through a one-operation byte-capping
//!   [`proxy`](crate::proxy); never `http://`, which would send the token in clear.

use std::path::Path;

use crate::{MirrorError, Result};

/// A registry upstream: how the daemon reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Ssh(SshUrl),
    Https(HttpsUrl),
}

impl Upstream {
    /// Parses a registry URL: `ssh://` or `https://`, nothing else.
    pub fn parse(url: &str) -> std::result::Result<Self, &'static str> {
        if url.starts_with("ssh://") {
            SshUrl::parse(url).map(Self::Ssh)
        } else if url.starts_with("https://") {
            HttpsUrl::parse(url).map(Self::Https)
        } else if url.starts_with("http://") {
            Err("http:// would send the token in clear: use https://")
        } else {
            Err("must be an ssh:// or https:// URL")
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ssh(url) => url.as_str(),
            Self::Https(url) => url.as_str(),
        }
    }
}

/// The parts of a URL's authority: `[user@]host[:port]`.
struct Authority<'a> {
    user: Option<&'a str>,
    host: &'a str,
    port: Option<u16>,
}

/// Splits `rest` (a URL after its scheme) into its authority and path, reading the authority
/// strictly: a host that is a plain name or address, an optional port; the user is left to
/// the caller. Printable ASCII only, no quote, a path.
fn split_url<'a>(url: &str, rest: &'a str) -> std::result::Result<Authority<'a>, &'static str> {
    if !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains(['\'', '"']) {
        return Err("printable ASCII only, no spaces or quotes");
    }
    let (authority, path) = rest.split_once('/').ok_or("no repository path")?;
    if path.is_empty() {
        return Err("no repository path");
    }
    let (user, host_port) = match authority.rsplit_once('@') {
        Some((user, host_port)) => (Some(user), host_port),
        None => (None, authority),
    };
    let (host, port) = match host_port.strip_prefix('[') {
        Some(v6) => {
            let (host, after) = v6.split_once(']').ok_or("unclosed [")?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').ok_or("invalid port")?),
            };
            if !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                return Err("invalid IPv6 address");
            }
            (host, port)
        }
        None => match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        },
    };
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
    if host.is_empty() || host.starts_with('-') || !host.chars().all(plain) {
        return Err("invalid host");
    }
    let port = match port {
        None => None,
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or("invalid port")?,
        ),
    };
    Ok(Authority { user, host, port })
}

/// An `ssh://[user@]host[:port]/path` upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshUrl {
    url: String,
    host: String,
    port: Option<u16>,
}

impl SshUrl {
    /// Parses an `ssh://` URL: a host that is a plain name or address, an optional port, a
    /// path.
    pub fn parse(url: &str) -> std::result::Result<Self, &'static str> {
        let rest = url.strip_prefix("ssh://").ok_or("must be an ssh:// URL")?;
        let parts = split_url(url, rest)?;
        if let Some(user) = parts.user
            && (user.is_empty() || user.starts_with('-') || user.contains(':'))
        {
            return Err("invalid user");
        }
        Ok(Self {
            url: url.to_owned(),
            host: parts.host.to_owned(),
            port: parts.port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// The name ssh looks the host key up by: `host`, or `[host]:port` off port 22.
    pub fn known_hosts_name(&self) -> String {
        match self.port {
            None | Some(22) => self.host.clone(),
            Some(port) => format!("[{}]:{port}", self.host),
        }
    }
}

/// The port of an `https://` URL without one.
pub const HTTPS_PORT: u16 = 443;

/// An `https://[user@]host[:port]/path` upstream. The user (optional) is the name git sends
/// with the token; a password never goes in the URL, nor a query or a fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    url: String,
    user: Option<String>,
    host: String,
    port: u16,
}

impl HttpsUrl {
    /// Parses an `https://` URL: an optional user (no password: the token lives in the
    /// keystore), a host that is a plain name or address, an optional port, a path without a
    /// query or a fragment.
    pub fn parse(url: &str) -> std::result::Result<Self, &'static str> {
        let rest = url
            .strip_prefix("https://")
            .ok_or("must be an https:// URL")?;
        let parts = split_url(url, rest)?;
        if let Some(user) = parts.user {
            if user.contains(':') {
                return Err("no password in the URL: the token is in the keystore");
            }
            let unreserved =
                |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~');
            if user.is_empty() || user.starts_with('-') || !user.chars().all(unreserved) {
                return Err("invalid user");
            }
        }
        if rest.contains(['?', '#']) {
            return Err("no query or fragment");
        }
        Ok(Self {
            url: url.to_owned(),
            user: parts.user.map(str::to_owned),
            host: parts.host.to_owned(),
            port: parts.port.unwrap_or(HTTPS_PORT),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// The host, as the URL names it (an IPv6 address without its brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The user named in the URL, if any.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Whether git's `host=` (a credential request: `host` or `host:port`, an IPv6 address in
    /// brackets) names this upstream.
    pub fn is_host(&self, field: &str) -> bool {
        let (host, port) = match field.strip_prefix('[') {
            Some(v6) => match v6.split_once(']') {
                Some((host, "")) => (host, None),
                Some((host, after)) => match after.strip_prefix(':') {
                    Some(port) => (host, Some(port)),
                    None => return false,
                },
                None => return false,
            },
            None => match field.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (host, Some(port)),
                _ => (field, None),
            },
        };
        let port = match port {
            None => HTTPS_PORT,
            Some(p) => match p.parse::<u16>() {
                Ok(p) => p,
                Err(_) => return false,
            },
        };
        host.eq_ignore_ascii_case(&self.host) && port == self.port
    }
}

/// What the ssh command for one operation is made of.
#[derive(Debug, Clone, Copy)]
pub struct SshCommand<'a> {
    /// The relay program (`writd`), run as `<relay> upstream-ssh <max bytes> <ssh> …`.
    pub relay: &'a Path,
    /// The system's ssh, by absolute path.
    pub ssh: &'a Path,
    /// The pinned host keys, as the daemon wrote them.
    pub known_hosts: &'a Path,
    /// The agent socket serving the repo's credential for this operation.
    pub agent: &'a Path,
    /// The credential's public key file (picks the key in the agent).
    pub identity: &'a Path,
    /// The most bytes upstream may send.
    pub max_bytes: u64,
}

impl SshCommand<'_> {
    /// The `GIT_SSH_COMMAND` (git runs it through `sh -c`, then adds its own arguments).
    pub fn to_git_ssh_command(&self) -> Result<String> {
        let paths = [
            self.relay,
            self.ssh,
            self.known_hosts,
            self.agent,
            self.identity,
        ];
        // ssh splits an option's value at whitespace (`UserKnownHostsFile=/a b` names two
        // files): the paths given in `-o` options hold none (the review after M5.5).
        for path in [self.known_hosts, self.agent, self.identity] {
            if path.to_string_lossy().chars().any(char::is_whitespace) {
                return Err(MirrorError::Config(format!(
                    "path {} has a space, which ssh would read as two paths: choose a state \
                     directory without one",
                    path.display()
                )));
            }
        }
        let mut quoted = Vec::new();
        for path in paths {
            quoted.push(quote(path)?);
        }
        let [relay, ssh, known_hosts, agent, identity] = quoted.as_slice() else {
            return Err(MirrorError::Config("internal error".to_owned()));
        };
        let mut words = vec![
            relay.clone(),
            "upstream-ssh".to_owned(),
            self.max_bytes.to_string(),
            ssh.clone(),
            "-F".to_owned(),
            "/dev/null".to_owned(),
        ];
        let options = [
            "BatchMode=yes".to_owned(),
            format!("IdentityAgent={agent}"),
            format!("IdentityFile={identity}"),
            "IdentitiesOnly=yes".to_owned(),
            format!("UserKnownHostsFile={known_hosts}"),
            "GlobalKnownHostsFile=/dev/null".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "UpdateHostKeys=no".to_owned(),
            "CheckHostIP=no".to_owned(),
            "VerifyHostKeyDNS=no".to_owned(),
            "HashKnownHosts=no".to_owned(),
            "PreferredAuthentications=publickey".to_owned(),
            "PasswordAuthentication=no".to_owned(),
            "KbdInteractiveAuthentication=no".to_owned(),
            "HostbasedAuthentication=no".to_owned(),
            "PKCS11Provider=none".to_owned(),
            "AddKeysToAgent=no".to_owned(),
            "ForwardAgent=no".to_owned(),
            "ForwardX11=no".to_owned(),
            "ClearAllForwardings=yes".to_owned(),
            "PermitLocalCommand=no".to_owned(),
            "ProxyCommand=none".to_owned(),
            "ProxyJump=none".to_owned(),
            "ControlMaster=no".to_owned(),
            "ControlPath=none".to_owned(),
            "CanonicalizeHostname=no".to_owned(),
            "RequestTTY=no".to_owned(),
            "EscapeChar=none".to_owned(),
            "ConnectTimeout=15".to_owned(),
            "ServerAliveInterval=15".to_owned(),
            "ServerAliveCountMax=3".to_owned(),
            "LogLevel=ERROR".to_owned(),
        ];
        for option in options {
            words.push("-o".to_owned());
            words.push(option);
        }
        Ok(words.join(" "))
    }
}

/// `path` in single quotes for `sh`. A path holding a quote or anything unprintable is refused
/// rather than escaped: the daemon's own paths never need it.
pub(crate) fn quote(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .filter(|t| !t.is_empty() && t.chars().all(|c| !c.is_control() && c != '\''))
        .ok_or_else(|| {
            MirrorError::Config(format!(
                "path {} can't be passed to ssh (a quote, a control character or not UTF-8)",
                path.display()
            ))
        })?;
    Ok(format!("'{text}'"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn ssh_urls_are_read_strictly() {
        for (url, name) in [
            ("ssh://git@github.com/user/repo.git", "github.com"),
            ("ssh://github.com/user/repo.git", "github.com"),
            ("ssh://git@github.com:22/user/repo.git", "github.com"),
            (
                "ssh://git@forgejo.home:2222/user/repo.git",
                "[forgejo.home]:2222",
            ),
            ("ssh://git@127.0.0.1:2222/demo.git", "[127.0.0.1]:2222"),
            ("ssh://git@[::1]:2222/demo.git", "[::1]:2222"),
            ("ssh://git@[fd00::5]/demo.git", "fd00::5"),
        ] {
            let parsed = SshUrl::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(parsed.known_hosts_name(), name, "{url}");
            assert_eq!(parsed.as_str(), url);
        }
        for (url, why) in [
            ("https://github.com/user/repo.git", "must be an ssh:// URL"),
            ("git@github.com:user/repo.git", "must be an ssh:// URL"),
            ("ext::sh -c id", "must be an ssh:// URL"),
            ("ssh://git@github.com", "no repository path"),
            ("ssh://git@github.com/", "no repository path"),
            ("ssh://-oProxyCommand=x/repo", "invalid host"),
            ("ssh://-x@github.com/repo", "invalid user"),
            ("ssh://a:b@github.com/repo", "invalid user"),
            ("ssh://git@github.com:0/repo", "invalid port"),
            ("ssh://git@github.com:99999/repo", "invalid port"),
            ("ssh://git@[::1/repo", "unclosed ["),
            ("ssh://git@[::1]x/repo", "invalid port"),
            ("ssh://git@[zz]/repo", "invalid IPv6 address"),
            ("ssh://git@git$hub.com/repo", "invalid host"),
            (
                "ssh://git@github.com/it's.git",
                "printable ASCII only, no spaces or quotes",
            ),
            (
                "ssh://git@github.com/a b.git",
                "printable ASCII only, no spaces or quotes",
            ),
        ] {
            assert_eq!(SshUrl::parse(url), Err(why), "{url}");
        }
    }

    #[test]
    fn an_upstream_is_ssh_or_https_by_its_url() {
        assert!(matches!(
            Upstream::parse("ssh://git@github.com/user/repo.git"),
            Ok(Upstream::Ssh(_))
        ));
        assert!(matches!(
            Upstream::parse("https://github.com/user/repo.git"),
            Ok(Upstream::Https(_))
        ));
        for (url, why) in [
            (
                "http://github.com/user/repo.git",
                "http:// would send the token in clear: use https://",
            ),
            (
                "git@github.com:user/repo.git",
                "must be an ssh:// or https:// URL",
            ),
            ("file:///srv/repo.git", "must be an ssh:// or https:// URL"),
            ("ext::sh -c id", "must be an ssh:// or https:// URL"),
            (
                "HTTPS://github.com/user/repo.git",
                "must be an ssh:// or https:// URL",
            ),
            ("https://git@github.com", "no repository path"),
        ] {
            assert_eq!(Upstream::parse(url), Err(why), "{url}");
        }
    }

    #[test]
    fn https_urls_are_read_strictly() {
        for (url, user, host, port) in [
            ("https://github.com/user/repo.git", None, "github.com", 443),
            (
                "https://x-token-auth@bitbucket.org/user/repo.git",
                Some("x-token-auth"),
                "bitbucket.org",
                443,
            ),
            (
                "https://forgejo.home:8443/u/r.git",
                None,
                "forgejo.home",
                8443,
            ),
            ("https://127.0.0.1:3443/demo.git", None, "127.0.0.1", 3443),
            ("https://[::1]:3443/demo.git", None, "::1", 3443),
            ("https://[fd00::5]/demo", None, "fd00::5", 443),
        ] {
            let parsed = HttpsUrl::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(
                (parsed.user(), parsed.host(), parsed.port()),
                (user, host, port),
                "{url}"
            );
            assert_eq!(parsed.as_str(), url);
        }
        for (url, why) in [
            (
                "https://user:ghp_secret@github.com/u/r.git",
                "no password in the URL: the token is in the keystore",
            ),
            (
                "https://:ghp_secret@github.com/u/r.git",
                "no password in the URL: the token is in the keystore",
            ),
            ("https://@github.com/u/r.git", "invalid user"),
            ("https://-x@github.com/u/r.git", "invalid user"),
            ("https://us%65r@github.com/u/r.git", "invalid user"),
            ("https://github.com/u/r.git?x=1", "no query or fragment"),
            ("https://github.com/u/r.git#main", "no query or fragment"),
            ("https://github.com", "no repository path"),
            ("https://github.com/", "no repository path"),
            ("https://-oProxy/repo", "invalid host"),
            ("https://git$hub.com/repo", "invalid host"),
            ("https://github.com:0/repo", "invalid port"),
            ("https://github.com:70000/repo", "invalid port"),
            ("https://[::1/repo", "unclosed ["),
            (
                "https://github.com/a b.git",
                "printable ASCII only, no spaces or quotes",
            ),
            (
                "https://github.com/a\"b.git",
                "printable ASCII only, no spaces or quotes",
            ),
            (
                "https://github.com/\u{1b}[31m.git",
                "printable ASCII only, no spaces or quotes",
            ),
        ] {
            assert_eq!(HttpsUrl::parse(url), Err(why), "{url}");
        }
    }

    #[test]
    fn a_credential_request_names_the_upstream_by_host_and_port() {
        let default = HttpsUrl::parse("https://Git.Example.org/u/r.git").unwrap();
        for field in ["git.example.org", "GIT.example.org", "git.example.org:443"] {
            assert!(default.is_host(field), "{field}");
        }
        for field in [
            "git.example.org:8443",
            "evil.example.org",
            "git.example.org.evil",
            "git.example.org:",
            "git.example.org:x",
            "",
        ] {
            assert!(!default.is_host(field), "{field}");
        }
        let v6 = HttpsUrl::parse("https://[::1]:3443/demo.git").unwrap();
        assert!(v6.is_host("[::1]:3443"));
        for field in ["[::1]", "::1", "[::1]:443", "[::1]x", "[::1"] {
            assert!(!v6.is_host(field), "{field}");
        }
        let port = HttpsUrl::parse("https://127.0.0.1:3443/demo.git").unwrap();
        assert!(port.is_host("127.0.0.1:3443"));
        assert!(!port.is_host("127.0.0.1"));
    }

    #[test]
    fn the_ssh_command_states_every_option_and_quotes_paths() {
        let (relay, ssh, kh, agent, id) = (
            PathBuf::from("/opt/writ/writd"),
            PathBuf::from("/usr/bin/ssh"),
            PathBuf::from("/var/lib/writ/mirror/known_hosts"),
            PathBuf::from("/var/lib/writ/mirror/sockets/a.sock"),
            PathBuf::from("/var/lib/writ/mirror/upstream-01.pub"),
        );
        let command = SshCommand {
            relay: &relay,
            ssh: &ssh,
            known_hosts: &kh,
            agent: &agent,
            identity: &id,
            max_bytes: 1000,
        }
        .to_git_ssh_command()
        .unwrap();
        assert!(
            command.starts_with("'/opt/writ/writd' upstream-ssh 1000 '/usr/bin/ssh' -F /dev/null "),
            "{command}"
        );
        for option in [
            "-o UserKnownHostsFile='/var/lib/writ/mirror/known_hosts'",
            "-o StrictHostKeyChecking=yes",
            "-o IdentityAgent='/var/lib/writ/mirror/sockets/a.sock'",
            "-o IdentitiesOnly=yes",
            "-o ProxyCommand=none",
            "-o ForwardAgent=no",
            "-o GlobalKnownHostsFile=/dev/null",
        ] {
            assert!(command.contains(option), "{option} in {command}");
        }
        let quote_in_path = PathBuf::from("/tmp/it's");
        let result = SshCommand {
            relay: &quote_in_path,
            ssh: &ssh,
            known_hosts: &kh,
            agent: &agent,
            identity: &id,
            max_bytes: 1000,
        }
        .to_git_ssh_command();
        assert!(matches!(result, Err(MirrorError::Config(_))), "{result:?}");
        // A space in a path an `-o` option names: refused, not split by ssh into two. A
        // program's path (run by `sh`, quoted) may hold one.
        let spaced = PathBuf::from("/var/lib/writ/mirror/known hosts");
        let result = SshCommand {
            relay: &relay,
            ssh: &ssh,
            known_hosts: &spaced,
            agent: &agent,
            identity: &id,
            max_bytes: 1000,
        }
        .to_git_ssh_command();
        match result {
            Err(MirrorError::Config(reason)) => {
                assert!(reason.contains("has a space"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let spaced_relay = PathBuf::from("/opt/my writ/writd");
        assert!(
            SshCommand {
                relay: &spaced_relay,
                ssh: &ssh,
                known_hosts: &kh,
                agent: &agent,
                identity: &id,
                max_bytes: 1000,
            }
            .to_git_ssh_command()
            .unwrap()
            .starts_with("'/opt/my writ/writd' ")
        );
    }
}
