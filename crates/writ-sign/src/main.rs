//! `writ-sign`: git's `gpg.ssh.program` on agent hosts.
//!
//! `-Y sign` sends the object to the daemon (`writ-sign git <repo>` over the gateway), with
//! the objects it needs to see which paths the commit touches ([`evidence`]), and writes the
//! signature where git expects it. Everything else (`-Y verify`, `-Y find-principals`, …) is
//! the real `ssh-keygen`'s job.
//!
//! The daemon is found from git's configuration: `writ.url` (`ssh://git@host:port`), the repo
//! the commit is for (`writ.repo`, a registry name), and the SSH command git itself uses
//! (`GIT_SSH_COMMAND`, then `core.sshCommand`). There is no fallback to a plain `ssh`: it
//! would offer the user's own keys and agent and trust their `known_hosts`, so without a
//! configured command nothing is sent.
//!
//! The daemon's refusal reaches the agent's terminal (git prints this program's stderr when
//! it fails), escaped like any text from elsewhere ([`clean`]). When ssh itself fails, the
//! session certificate says why the daemon may have turned it away ([`diagnose`]).

mod diagnose;
mod evidence;

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, bail};
use writ_core::text::is_hidden_char;
use writ_proto::sign::SignInput;

/// ssh's exit status when it fails itself (connection, authentication).
const SSH_FAILED: i32 = 255;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let rest = match args.as_slice() {
        [y, sign, rest @ ..] if y == "-Y" && sign == "sign" => rest,
        _ => {
            // PATH: verify calls go to the agent host's own ssh-keygen, as git would call it;
            // the agent host is not a boundary (nothing here grants anything).
            let error = Command::new("ssh-keygen").args(&args).exec();
            eprintln!("writ-sign: cannot run ssh-keygen: {error}");
            return ExitCode::FAILURE;
        }
    };
    match sign(rest) {
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
    // PATH: the agent host's git, the one that called this shim.
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
        .with_context(|| format!("cannot read {}", request.file.display()))?;
    let url = git_config("writ.url")
        .context("git config writ.url is not set: the repo is not set up for Writ (writ init)")?;
    let (destination, port) = parse_url(&url)?;
    let repo = git_config("writ.repo")
        .context("git config writ.repo is not set: the repo is not set up for Writ (writ init)")?;
    if repo.starts_with('-') || repo.contains(char::is_whitespace) {
        bail!("invalid writ.repo {repo:?}");
    }
    let ssh = ssh_command(
        std::env::var("GIT_SSH_COMMAND").ok(),
        git_config("core.sshCommand"),
    )?;
    // Best effort: without it the daemon can't check the paths (refused under
    // `paths_check: deny`), but the commit may still be signed.
    let evidence = evidence::gather(&object).unwrap_or_default();
    let body = SignInput { object, evidence }.encode();

    // PATH: the agent host's sh runs the configured core.sshCommand, as git itself would.
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!("{ssh} \"$@\"")).arg("writ-sign");
    if let Some(port) = port {
        cmd.arg("-p").arg(port);
    }
    cmd.arg(destination)
        .arg(format!("writ-sign {} {repo}", request.namespace))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("cannot run ssh")?;
    let mut stdin = child.stdin.take().context("no stdin")?;
    // Written from a thread: the daemon may answer (a refusal) before reading it all.
    let writer = std::thread::spawn(move || stdin.write_all(&body));
    let out = child.wait_with_output()?;
    let _ = writer.join();
    let said = String::from_utf8_lossy(&out.stderr);
    for line in said.lines() {
        eprintln!("{}", clean(line));
    }
    match out.status.code() {
        Some(0) => {}
        Some(SSH_FAILED) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            match diagnose::explain(&ssh, now) {
                Some(why) => bail!("cannot reach the daemon with this session: {why}"),
                None => bail!("cannot reach the daemon (see above)"),
            }
        }
        _ => bail!("the daemon refused to sign (see above)"),
    }
    check_signature(&out.stdout)?;
    let mut sig_path = request.file.into_os_string();
    sig_path.push(".sig");
    std::fs::write(&sig_path, &out.stdout).with_context(|| {
        format!(
            "cannot write the signature to {}",
            std::path::Path::new(&sig_path).display()
        )
    })?;
    Ok(())
}

/// Text from elsewhere (the daemon, ssh) for the terminal: every hidden character as
/// `\u{…}`, and `\` as `\\`.
fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
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

    /// The error's message chain; a success fails the test.
    fn error_of<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected an error, got a success"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn parses_what_git_passes() {
        let r = parse(&os(&["-n", "git", "-f", "/tmp/k", "-U", "/tmp/buf"])).unwrap();
        assert_eq!(r.namespace, "git");
        assert_eq!(r.file, PathBuf::from("/tmp/buf"));
        assert_eq!(
            error_of(parse(&os(&["-n", "git", "-f", "/tmp/k"]))),
            "expected exactly one file to sign"
        );
        assert_eq!(
            error_of(parse(&os(&["-n", "git", "-O", "x", "/tmp/buf"]))),
            "unsupported option -O"
        );
        assert_eq!(
            error_of(parse(&os(&["-f", "/tmp/k", "/tmp/buf"]))),
            "missing -n <namespace>"
        );
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
        let refused = |url: &str| {
            let error = error_of(parse_url(url));
            assert!(
                error.contains("writ.url") && error.contains(url),
                "{url}: {error}"
            );
        };
        refused("git@writ.home:2222");
        refused("ssh://-oProxyCommand=x");
        refused("ssh://git@host/path");
        // An empty or out-of-range port is no port: the rest is then not a valid host.
        refused("ssh://git@host:");
        refused("ssh://git@host:123456");
        refused("ssh://git@");
        assert_eq!(
            parse_url("ssh://git@[::1]:2222").unwrap(),
            ("git@::1".into(), Some("2222".into()))
        );
        assert_eq!(
            parse_url("ssh://git@[::1]").unwrap(),
            ("git@::1".into(), None)
        );
        refused("ssh://git@[not-an-ip]:2222");
        refused("ssh://git@::1");
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
        for (env, config) in [(None, None), (some(""), some(" "))] {
            assert!(
                error_of(ssh_command(env, config)).starts_with("no SSH command for the daemon"),
            );
        }
    }

    #[test]
    fn text_from_elsewhere_is_escaped() {
        assert_eq!(
            clean("writ: files outside expected_paths: a\u{1b}[2Jb, c\\d"),
            "writ: files outside expected_paths: a\\u{1b}[2Jb, c\\\\d"
        );
        assert_eq!(clean("plain"), "plain");
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
            assert_eq!(
                error_of(check_signature(bad.as_bytes())),
                "the daemon sent something that is not an SSH signature",
                "{bad:?}"
            );
        }
        assert_eq!(
            error_of(check_signature(&[0xff, 0xfe])),
            "the daemon sent something that is not an SSH signature"
        );
    }
}
