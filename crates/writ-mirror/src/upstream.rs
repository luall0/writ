//! How the daemon reaches an upstream: the registry's `ssh://` URL, read strictly, and the
//! ssh command git runs for it. Every ssh option that matters is stated (`-F /dev/null`: no
//! config file decides anything), the host key must be the pinned one, the only key offered
//! is the repo's credential through a one-operation agent socket, and what upstream sends goes
//! through the byte-capping [`relay`](crate::relay).

use std::path::Path;

use crate::{MirrorError, Result};

/// An `ssh://[user@]host[:port]/path` upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshUrl {
    url: String,
    host: String,
    port: Option<u16>,
}

impl SshUrl {
    /// Parses an upstream URL. Only `ssh://` (HTTPS upstreams come with M4.5); a host that is
    /// a plain name or address, an optional port, a path.
    pub fn parse(url: &str) -> std::result::Result<Self, &'static str> {
        let rest = match url.strip_prefix("ssh://") {
            Some(rest) => rest,
            None if url.starts_with("https://") => {
                return Err("HTTPS upstreams are not supported yet (M4.5)");
            }
            None => return Err("must be an ssh:// URL"),
        };
        if !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains('\'') {
            return Err("printable ASCII only, no spaces or quotes");
        }
        let (authority, path) = rest.split_once('/').ok_or("no repository path")?;
        if path.is_empty() {
            return Err("no repository path");
        }
        let host_port = match authority.rsplit_once('@') {
            Some((user, host_port)) => {
                if user.is_empty() || user.starts_with('-') || user.contains(':') {
                    return Err("invalid user");
                }
                host_port
            }
            None => authority,
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
        Ok(Self {
            url: url.to_owned(),
            host: host.to_owned(),
            port,
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
fn quote(path: &Path) -> Result<String> {
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
            (
                "https://github.com/user/repo.git",
                "HTTPS upstreams are not supported yet (M4.5)",
            ),
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
    fn the_ssh_command_states_every_option_and_quotes_paths() {
        let (relay, ssh, kh, agent, id) = (
            PathBuf::from("/opt/writ/writd"),
            PathBuf::from("/usr/bin/ssh"),
            PathBuf::from("/var/lib/writ/mirror/known hosts"),
            PathBuf::from("/var/lib/writ/mirror/agent/a.sock"),
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
            "-o UserKnownHostsFile='/var/lib/writ/mirror/known hosts'",
            "-o StrictHostKeyChecking=yes",
            "-o IdentityAgent='/var/lib/writ/mirror/agent/a.sock'",
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
    }
}
