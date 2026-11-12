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

pub use writ_core::upstream::{HTTPS_PORT, HttpsUrl, SshUrl, Upstream};

/// An `ssh://` upstream behind a proxy: ssh's `ProxyCommand` is `writd upstream-tunnel
/// <socket> <host> <port>`, the operation's byte-capping proxy reaching upstream through the
/// repo's proxy.
#[derive(Debug, Clone, Copy)]
pub struct SshTunnel<'a> {
    /// The operation's byte-capping proxy socket.
    pub socket: &'a Path,
    /// Upstream's host and port, as the registry names them.
    pub host: &'a str,
    pub port: u16,
    /// How long the proxy may take to open the tunnel: ssh waits that long, and more, for
    /// upstream's banner.
    pub connect_timeout: std::time::Duration,
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
    /// Behind a proxy: the tunnel ssh connects through (none: ssh connects itself).
    pub tunnel: Option<SshTunnel<'a>>,
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
        let (proxy_command, connect_timeout) = match &self.tunnel {
            None => (
                "ProxyCommand=none".to_owned(),
                "ConnectTimeout=15".to_owned(),
            ),
            Some(tunnel) => (
                proxy_command(self.relay, tunnel)?,
                format!(
                    "ConnectTimeout={}",
                    tunnel.connect_timeout.as_secs().saturating_add(15)
                ),
            ),
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
            proxy_command,
            "ProxyJump=none".to_owned(),
            "ControlMaster=no".to_owned(),
            "ControlPath=none".to_owned(),
            "CanonicalizeHostname=no".to_owned(),
            "RequestTTY=no".to_owned(),
            "EscapeChar=none".to_owned(),
            connect_timeout,
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

/// The `ProxyCommand` option for `tunnel`, as one word of git's `sh -c` (double quotes): ssh
/// runs its value with `sh -c "exec …"`, the relay's and the socket's paths in single quotes
/// there. Neither may hold what either shell, or ssh's own `%` tokens, would read (`"`, `$`,
/// `` ` ``, `\\`, `%`): the daemon's own paths never need it.
fn proxy_command(relay: &Path, tunnel: &SshTunnel<'_>) -> Result<String> {
    for path in [relay, tunnel.socket] {
        if path.to_string_lossy().contains(['"', '$', '`', '\\', '%']) {
            return Err(MirrorError::Config(format!(
                "path {} can't be given to ssh's ProxyCommand (one of \" $ ` \\ %)",
                path.display()
            )));
        }
    }
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_');
    if tunnel.host.is_empty() || tunnel.host.starts_with('-') || !tunnel.host.chars().all(plain) {
        return Err(MirrorError::Config(format!(
            "upstream host {:?} can't be given to ssh's ProxyCommand",
            tunnel.host
        )));
    }
    Ok(format!(
        "\"ProxyCommand={} upstream-tunnel {} {} {}\"",
        quote(relay)?,
        quote(tunnel.socket)?,
        tunnel.host,
        tunnel.port
    ))
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
            tunnel: None,
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
            tunnel: None,
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
            tunnel: None,
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
                tunnel: None,
            }
            .to_git_ssh_command()
            .unwrap()
            .starts_with("'/opt/my writ/writd' ")
        );
    }

    #[test]
    fn behind_a_proxy_ssh_connects_through_the_daemon_s_tunnel_only() {
        let (relay, ssh, kh, agent, id, socket) = (
            PathBuf::from("/opt/writ/writd"),
            PathBuf::from("/usr/bin/ssh"),
            PathBuf::from("/var/lib/writ/mirror/known_hosts"),
            PathBuf::from("/var/lib/writ/mirror/sockets/a.sock"),
            PathBuf::from("/var/lib/writ/mirror/upstream-01.pub"),
            PathBuf::from("/var/lib/writ/mirror/sockets/b.proxy"),
        );
        let command = |relay: &Path, socket: &Path, host: &str| {
            SshCommand {
                relay,
                ssh: &ssh,
                known_hosts: &kh,
                agent: &agent,
                identity: &id,
                max_bytes: 1000,
                tunnel: Some(SshTunnel {
                    socket,
                    host,
                    port: 2222,
                    connect_timeout: std::time::Duration::from_secs(120),
                }),
            }
            .to_git_ssh_command()
        };
        let line = command(&relay, &socket, "abc.onion").unwrap();
        assert!(
            line.contains(
                "-o \"ProxyCommand='/opt/writ/writd' upstream-tunnel \
                 '/var/lib/writ/mirror/sockets/b.proxy' abc.onion 2222\""
            ),
            "{line}"
        );
        assert!(!line.contains("ProxyCommand=none"), "{line}");
        assert!(line.contains("-o ProxyJump=none"), "{line}");
        assert!(line.contains("-o ConnectTimeout=135"), "{line}");
        // What either shell or ssh's tokens would read: refused, never escaped.
        for bad in [
            "/opt/w$x/writd",
            "/opt/w`x`/writd",
            "/opt/w\"x/writd",
            "/opt/w%h/writd",
            "/opt/w\\x/writd",
        ] {
            let result = command(Path::new(bad), &socket, "abc.onion");
            assert!(
                matches!(result, Err(MirrorError::Config(_))),
                "{bad}: {result:?}"
            );
            let result = command(&relay, Path::new(bad), "abc.onion");
            assert!(
                matches!(result, Err(MirrorError::Config(_))),
                "{bad}: {result:?}"
            );
        }
        for bad in ["", "-oProxyCommand=x", "a;b", "a b"] {
            let result = command(&relay, &socket, bad);
            assert!(
                matches!(result, Err(MirrorError::Config(_))),
                "{bad}: {result:?}"
            );
        }
    }
}
