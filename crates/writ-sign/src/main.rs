//! `writ-sign`: git's `gpg.ssh.program` on agent hosts.
//!
//! `-Y sign` sends the object to the daemon (`writ-sign <namespace>` over the gateway) and
//! writes the signature where git expects it. Everything else (`-Y verify`,
//! `-Y find-principals`, …) is the real `ssh-keygen`'s job.
//!
//! The daemon is found from git's configuration: `writ.url` (`ssh://git@host:port`) and the
//! SSH command git itself uses (`GIT_SSH_COMMAND`, then `core.sshCommand`). There is no
//! fallback to a plain `ssh`: it would offer the user's own keys and agent and trust their
//! `known_hosts`, so without a configured command nothing is sent.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, bail};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let is_sign = args.len() >= 2 && args[0] == "-Y" && args[1] == "sign";
    if !is_sign {
        let error = Command::new("ssh-keygen").args(&args).exec();
        eprintln!("writ-sign: cannot run ssh-keygen: {error}");
        return ExitCode::FAILURE;
    }
    match sign(&args[2..]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("writ-sign: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The `ssh-keygen -Y sign` arguments git passes: `-n <namespace> -f <key> [-U] <file>`.
struct SignRequest {
    namespace: String,
    file: PathBuf,
}

fn parse(args: &[OsString]) -> anyhow::Result<SignRequest> {
    let mut namespace = None;
    let mut files = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-n") => namespace = args.next().and_then(|a| a.to_str()).map(str::to_owned),
            // The key is the daemon's; which one git names is checked by the daemon.
            Some("-f") => {
                args.next();
            }
            Some("-U") | Some("-q") => {}
            Some(flag) if flag.starts_with('-') => bail!("unsupported option {flag}"),
            _ => files.push(PathBuf::from(arg)),
        }
    }
    let namespace = namespace.context("missing -n <namespace>")?;
    match <[PathBuf; 1]>::try_from(files) {
        Ok([file]) => Ok(SignRequest { namespace, file }),
        Err(_) => bail!("expected exactly one file to sign"),
    }
}

fn git_config(key: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--get", key])
        .output()
        .ok()?;
    let value = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (out.status.success() && !value.is_empty()).then_some(value)
}

/// `ssh://user@host[:port][/]` → (`user@host`, port).
fn parse_url(url: &str) -> anyhow::Result<(String, Option<String>)> {
    let rest = url
        .strip_prefix("ssh://")
        .with_context(|| format!("writ.url must be ssh://user@host[:port], got {url}"))?;
    let rest = rest.trim_end_matches('/');
    let (destination, port) = match rest.rsplit_once(':') {
        Some((destination, port))
            if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (destination, Some(port.to_owned()))
        }
        _ => (rest, None),
    };
    // An IPv6 address comes bracketed (`git@[::1]`); ssh takes it bare.
    let destination = match destination.split_once('[') {
        Some((user, host)) => match host.strip_suffix(']') {
            Some(ip) if ip.parse::<std::net::Ipv6Addr>().is_ok() => format!("{user}{ip}"),
            _ => bail!("invalid writ.url {url}"),
        },
        None if destination.contains(':') => bail!("invalid writ.url {url}"),
        None => destination.to_owned(),
    };
    if destination.is_empty()
        || destination.starts_with('-')
        || destination.contains('/')
        || destination.ends_with('@')
    {
        bail!("invalid writ.url {url}");
    }
    Ok((destination, port))
}

fn sign(args: &[OsString]) -> anyhow::Result<()> {
    let request = parse(args)?;
    let object = std::fs::read(&request.file)
        .with_context(|| format!("reading {}", request.file.display()))?;
    let url = git_config("writ.url").context("git config writ.url is not set (run writ init)")?;
    let (destination, port) = parse_url(&url)?;
    let ssh = ssh_command(
        std::env::var("GIT_SSH_COMMAND").ok(),
        git_config("core.sshCommand"),
    )?;

    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!("{ssh} \"$@\"")).arg("writ-sign");
    if let Some(port) = port {
        cmd.arg("-p").arg(port);
    }
    cmd.arg(destination)
        .arg(format!("writ-sign {}", request.namespace))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("cannot run ssh")?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(&object)
        .context("cannot send the object to the daemon")?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("the daemon refused to sign (see above)");
    }
    check_signature(&out.stdout)?;
    let mut sig_path = request.file.into_os_string();
    sig_path.push(".sig");
    std::fs::write(&sig_path, &out.stdout).context("cannot write the signature")?;
    Ok(())
}

/// The SSH command to reach the daemon: `GIT_SSH_COMMAND`, then `core.sshCommand`. Never a
/// plain `ssh` (see the module documentation).
fn ssh_command(from_env: Option<String>, from_config: Option<String>) -> anyhow::Result<String> {
    from_env
        .filter(|c| !c.trim().is_empty())
        .or(from_config.filter(|c| !c.trim().is_empty()))
        .context(
            "no SSH command for the daemon: set core.sshCommand to the session's key and \
             certificate (see docs/architecture/clients.md, repo setup)",
        )
}

/// What the daemon sent is one armored SSH signature, nothing else.
fn check_signature(out: &[u8]) -> anyhow::Result<()> {
    let text = std::str::from_utf8(out).ok().map(str::trim_end);
    match text {
        Some(text)
            if text.starts_with("-----BEGIN SSH SIGNATURE-----\n")
                && text.ends_with("\n-----END SSH SIGNATURE-----")
                && text.matches("-----BEGIN").count() == 1 =>
        {
            Ok(())
        }
        _ => bail!("the daemon sent something that is not an SSH signature"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_what_git_passes() {
        let r = parse(&os(&["-n", "git", "-f", "/tmp/k", "-U", "/tmp/buf"])).unwrap();
        assert_eq!(r.namespace, "git");
        assert_eq!(r.file, PathBuf::from("/tmp/buf"));
        assert!(parse(&os(&["-n", "git", "-f", "/tmp/k"])).is_err());
        assert!(parse(&os(&["-n", "git", "-O", "x", "/tmp/buf"])).is_err());
    }

    #[test]
    fn parses_urls() {
        assert_eq!(
            parse_url("ssh://git@writ.home:2222").unwrap(),
            ("git@writ.home".into(), Some("2222".into()))
        );
        assert_eq!(
            parse_url("ssh://git@writ.home/").unwrap(),
            ("git@writ.home".into(), None)
        );
        assert!(parse_url("git@writ.home:2222").is_err());
        assert!(parse_url("ssh://-oProxyCommand=x").is_err());
        assert!(parse_url("ssh://git@host/path").is_err());
        // An empty or out-of-range port is no port: the rest is then not a valid host.
        assert!(parse_url("ssh://git@host:").is_err());
        assert!(parse_url("ssh://git@host:123456").is_err());
        assert!(parse_url("ssh://git@").is_err());
        assert_eq!(
            parse_url("ssh://git@[::1]:2222").unwrap(),
            ("git@::1".into(), Some("2222".into()))
        );
        assert_eq!(
            parse_url("ssh://git@[::1]").unwrap(),
            ("git@::1".into(), None)
        );
        assert!(parse_url("ssh://git@[not-an-ip]:2222").is_err());
        assert!(parse_url("ssh://git@::1").is_err());
    }

    #[test]
    fn never_falls_back_to_a_plain_ssh() {
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            ssh_command(some("ssh -i k"), some("ssh -i c")).unwrap(),
            "ssh -i k"
        );
        assert_eq!(ssh_command(None, some("ssh -i c")).unwrap(), "ssh -i c");
        assert_eq!(
            ssh_command(some("  "), some("ssh -i c")).unwrap(),
            "ssh -i c"
        );
        assert!(ssh_command(None, None).is_err());
        assert!(ssh_command(some(""), some(" ")).is_err());
    }

    #[test]
    fn only_an_armored_signature_is_written() {
        let sig = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";
        assert!(check_signature(sig.as_bytes()).is_ok());
        for bad in [
            "",
            "ok\n",
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n",
            "junk\n-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n",
            "-----BEGIN SSH SIGNATURE-----\n-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----",
        ] {
            assert!(check_signature(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(check_signature(&[0xff, 0xfe]).is_err());
    }
}
