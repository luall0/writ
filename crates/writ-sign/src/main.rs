//! `writ-sign`: git's `gpg.ssh.program` and `gpg.openpgp.program` on agent hosts.
//!
//! `-Y sign` sends the object to the daemon (`writ-sign git <repo>` over the gateway), with
//! the objects it needs to see which paths the commit touches ([`evidence`]), and writes the
//! signature where git expects it. Everything else `ssh-keygen` does (`-Y verify`,
//! `-Y find-principals`, …) is the real `ssh-keygen`'s job.
//!
//! `--status-fd=2 -bsau <key>` (git's OpenPGP signing call) sends the object on stdin the
//! same way (`writ-sign openpgp <repo>`), writes the armored signature on stdout and
//! `[GNUPG:] SIG_CREATED` on stderr, as git expects of `gpg`. A call with `--verify` goes to
//! the real `gpg` (`WRIT_GPG`, an absolute path, `/usr/bin/gpg` by default); anything else
//! is refused. No GnuPG home, keyring or agent is used to sign: the key is the daemon's.
//!
//! The daemon is found from git's configuration: `writ.url` (`ssh://git@host:port`), the repo
//! the commit is for (`writ.repo`, a registry name), and the SSH command git itself uses
//! (`GIT_SSH_COMMAND`, then `core.sshCommand`). There is no fallback to a plain `ssh`: it
//! would offer the user's own keys and agent and trust their `known_hosts`, so without a
//! configured command nothing is sent.
//!
//! The session is the one the settings name (`writ.session`, written by `writ init` or `writ
//! git`): its lease's key decides the format asked of the daemon (an OpenPGP certificate in the
//! session: OpenPGP; otherwise SSH), whichever way git called this program, so a whole-repo
//! clone follows its lease when the lease's key changes format. With `WRIT_SESSION` set, the
//! settings must be for that very session, or nothing is sent: one command, one session.
//!
//! The daemon's refusal reaches the agent's terminal (git prints this program's stderr when
//! it fails), escaped like any text from elsewhere ([`clean`]). When ssh itself fails, the
//! session certificate says why the daemon may have turned it away ([`diagnose`]).

mod diagnose;
mod evidence;

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, bail};
use writ_proto::sign::SignInput;

/// Every block is zeroed when it is freed, whatever code freed it (docs/security.md#secrets).
#[global_allocator]
static ALLOCATOR: writ_alloc::Wiping = writ_alloc::Wiping::system();

/// ssh's exit status when it fails itself (connection, authentication).
const SSH_FAILED: i32 = 255;

/// The `gpg` git's OpenPGP verify calls are handed to, when `WRIT_GPG` doesn't name one.
const DEFAULT_GPG: &str = "/usr/bin/gpg";

/// The calls `writ-sign` answers, as git makes them: what the end-to-end coverage registry
/// must list (rule 18), checked by a test against docs/end-to-end.md. `main` answers these
/// and refuses anything else.
const CALLS: &[&str] = &[
    "-Y sign",
    "-Y verify",
    "--status-fd=2 -bsau",
    "--verify",
    "--version",
];

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let rest = match args.as_slice() {
        // Its version alone (M7.9.8): never a call git makes.
        [flag] if flag == "--version" => {
            println!("writ-sign {}", writ_proto::VERSION);
            return ExitCode::SUCCESS;
        }
        [y, sign, rest @ ..] if y == "-Y" && sign == "sign" => rest,
        [y, ..] if y == "-Y" => {
            // PATH: verify calls go to the agent host's own ssh-keygen, as git would call it;
            // the agent host is not a boundary (nothing here grants anything).
            let error = Command::new("ssh-keygen").args(&args).exec();
            eprintln!("writ-sign: cannot run ssh-keygen: {error}");
            return ExitCode::FAILURE;
        }
        _ if is_gpg_sign(&args) => {
            return match sign_openpgp() {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("writ-sign: {e:#}");
                    ExitCode::FAILURE
                }
            };
        }
        _ if args.iter().any(|a| a == "--verify") => {
            let gpg = match gpg_program(std::env::var_os("WRIT_GPG")) {
                Ok(gpg) => gpg,
                Err(e) => {
                    eprintln!("writ-sign: {e:#}");
                    return ExitCode::FAILURE;
                }
            };
            let error = Command::new(&gpg).args(&args).exec();
            eprintln!("writ-sign: cannot run {}: {error}", gpg.display());
            return ExitCode::FAILURE;
        }
        _ => {
            eprintln!(
                "writ-sign: unsupported call: it answers {} (signing, verification handed to \
                 ssh-keygen or gpg, or its version)",
                CALLS.join(", ")
            );
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
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            // A TCP port: 1 to 65535, as `writ`'s own parser reads it.
            match port.parse::<u16>() {
                Ok(n) if n > 0 => (destination, Some(port.to_owned())),
                _ => bail!("invalid writ.url {url}: the port must be 1 to 65535"),
            }
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

/// Whether git called this as `gpg` to sign: `--status-fd=2 -bsau <key>`, exactly (git's
/// `sign_buffer_gpg`). The key is the daemon's to choose: whatever git names is not used.
fn is_gpg_sign(args: &[OsString]) -> bool {
    matches!(args, [fd, flags, _key] if fd == "--status-fd=2" && flags == "-bsau")
}

/// The `gpg` that verifies: `WRIT_GPG`, an absolute path, or `/usr/bin/gpg`. Never looked up
/// in `PATH`.
fn gpg_program(from_env: Option<OsString>) -> anyhow::Result<PathBuf> {
    let path = from_env
        .filter(|p| !p.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_GPG), PathBuf::from);
    if !path.is_absolute() {
        bail!(
            "WRIT_GPG must be an absolute path, got {}",
            clean(&path.display().to_string())
        );
    }
    Ok(path)
}

/// git's `gpg -bsau`: the object on stdin, sent to the daemon in OpenPGP; the armored
/// signature on stdout, `[GNUPG:] SIG_CREATED` on the status descriptor (stderr).
fn sign_openpgp() -> anyhow::Result<()> {
    use std::io::Read as _;
    let mut object = Vec::new();
    std::io::stdin()
        .take(u64::try_from(writ_proto::sign::MAX_SIGN_INPUT)?.saturating_add(1))
        .read_to_end(&mut object)
        .context("cannot read the object on stdin")?;
    if object.len() > writ_proto::sign::MAX_SIGN_INPUT {
        bail!("the object on stdin is too large");
    }
    let format = session_format()?.unwrap_or("openpgp");
    let signature = ask_daemon(format, object)?;
    check_answer(format, &signature)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&signature)
        .and_then(|()| stdout.flush())
        .context("cannot write the signature")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // git reads only that the line is there; the algorithm fields are not known here.
    eprintln!("[GNUPG:] SIG_CREATED D 0 0 00 {now} -");
    Ok(())
}

/// The object git hands `-Y sign` in a file: at most what the daemon takes
/// ([`writ_proto::sign::MAX_SIGN_INPUT`]), as the OpenPGP path reads stdin.
fn read_object(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;
    let max = u64::try_from(writ_proto::sign::MAX_SIGN_INPUT)?;
    let mut object = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(max.saturating_add(1)).read_to_end(&mut object))
        .with_context(|| format!("cannot read {}", path.display()))?;
    if object.len() > writ_proto::sign::MAX_SIGN_INPUT {
        bail!("{} is too large to sign", path.display());
    }
    Ok(object)
}

fn sign(args: &[OsString]) -> anyhow::Result<()> {
    let request = parse(args)?;
    // git signs commits in namespace `git`; anything else is no commit of a lease (the
    // daemon refuses it too, this says why first).
    if request.namespace != "git" {
        bail!(
            "writ-sign signs commits only, in namespace git, not {}",
            clean(&request.namespace)
        );
    }
    let object = read_object(&request.file)?;
    let format = session_format()?.unwrap_or("git");
    let signature = ask_daemon(format, object)?;
    check_answer(format, &signature)?;
    let mut sig_path = request.file.into_os_string();
    sig_path.push(".sig");
    std::fs::write(&sig_path, &signature).with_context(|| {
        format!(
            "cannot write the signature to {}",
            std::path::Path::new(&sig_path).display()
        )
    })?;
    Ok(())
}

/// The format the session the settings name signs in (`openpgp` when it holds its key's
/// certificate, `signing_key.asc`; `git`, SSH, otherwise), after checking `WRIT_SESSION`
/// against it; none for settings that name no session.
fn session_format() -> anyhow::Result<Option<&'static str>> {
    let Some(session) = git_config("writ.session") else {
        return Ok(None);
    };
    let session = PathBuf::from(session);
    check_session(&session, std::env::var("WRIT_SESSION").ok().as_deref())?;
    Ok(Some(if session.join("signing_key.asc").is_file() {
        "openpgp"
    } else {
        "git"
    }))
}

/// With `WRIT_SESSION` set, the settings are for that session: its own directory, or
/// `current` pointing at it. Otherwise this commit would go out under another lease than the
/// one asked for.
fn check_session(session: &Path, wanted: Option<&str>) -> anyhow::Result<()> {
    let Some(wanted) = wanted.filter(|w| !w.is_empty()) else {
        return Ok(());
    };
    let name = session
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    let lease = match name.as_deref() {
        Some("current") => std::fs::read_link(session)
            .ok()
            .map(|target| target.to_string_lossy().into_owned()),
        other => other.map(str::to_owned),
    };
    if lease.as_deref() == Some(wanted) {
        return Ok(());
    }
    bail!(
        "WRIT_SESSION names lease {}, but this repository's Writ settings are for {} ({}): one \
         command signs under one session; unset WRIT_SESSION, or work in a clone wired for \
         that lease",
        clean(wanted),
        clean(lease.as_deref().unwrap_or("no lease")),
        clean(&session.display().to_string())
    )
}

/// The daemon's answer is one armored signature in `format`, nothing else.
fn check_answer(format: &str, signature: &[u8]) -> anyhow::Result<()> {
    if format == "openpgp" {
        check_openpgp_signature(signature)
    } else {
        check_signature(signature)
    }
}

/// Sends `object` (with its evidence) to the daemon to be signed in `format` (`git`: SSH, in
/// git's namespace; `openpgp`), for the repo `writ.repo` names: the daemon's answer, or why
/// it refused (its words on stderr, escaped).
fn ask_daemon(format: &str, object: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let url = git_config("writ.url")
        .context("git config writ.url is not set: the repo is not set up for Writ (writ init)")?;
    let (destination, port) = parse_url(&url)?;
    let repo = git_config("writ.repo")
        .context("git config writ.repo is not set: the repo is not set up for Writ (writ init)")?;
    if repo.starts_with('-') || repo.contains(char::is_whitespace) {
        bail!("invalid writ.repo {repo:?}");
    }
    check_repository(git_config("writ.gitdir"))?;
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
        .arg(format!("writ-sign {format} {repo}"))
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
                // The lease id comes from the certificate file: escaped like any text.
                Some(why) => bail!("cannot reach the daemon with this session: {}", clean(&why)),
                None => bail!("cannot reach the daemon (see above)"),
            }
        }
        _ => bail!("the daemon refused to sign (see above)"),
    }
    Ok(out.stdout)
}

/// The commit is made in the repository the settings were made for (`writ.gitdir`, written by
/// `writ init`): `writ git` and `writ exec` pass the settings to every git their process
/// runs, in any repository, and a commit made elsewhere would go to the daemon labeled with
/// the wired repo. A convenience, never a boundary. (A `--whole-repo` wiring made before the
/// setting existed has none: its settings live in that repository's own config.)
fn check_repository(wired: Option<String>) -> anyhow::Result<()> {
    let Some(wired) = wired else {
        return Ok(());
    };
    // PATH: the agent host's git, the one that called this shim.
    let out = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .context("cannot run git")?;
    let here = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.success() && same_dir(Path::new(&wired), Path::new(&here)) {
        return Ok(());
    }
    bail!(
        "this commit is made in {}, but the Writ settings are for {} (writ git and writ exec \
         pass them to every git their process runs): run only that repository's work through \
         them",
        clean(&here),
        clean(&wired)
    )
}

/// Whether two paths name the same directory (links resolved); a path that can't be resolved
/// is no match.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Text from elsewhere (the daemon, ssh) for the terminal: every hidden character as
/// `\u{…}`, and `\` as `\\`.
fn clean(text: &str) -> String {
    writ_core::text::escaped(text)
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

/// What the daemon sent is one armored OpenPGP signature, nothing else.
fn check_openpgp_signature(out: &[u8]) -> anyhow::Result<()> {
    let text = std::str::from_utf8(out).ok();
    match text {
        Some(text)
            if text.starts_with("-----BEGIN PGP SIGNATURE-----\n")
                && text.ends_with("\n-----END PGP SIGNATURE-----\n")
                && text.matches("-----BEGIN").count() == 1
                && text
                    .bytes()
                    .all(|b| b == b'\n' || b == b' ' || b.is_ascii_graphic()) =>
        {
            Ok(())
        }
        _ => bail!("the daemon sent something that is not an OpenPGP signature"),
    }
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

    #[test]
    fn the_global_allocator_wipes_every_block_freed() {
        // Only a wiping allocator counts: with any other, the count never moves.
        let before = writ_alloc::testing::wiped_blocks();
        drop(std::hint::black_box(vec![0x5au8; 4096]));
        assert!(writ_alloc::testing::wiped_blocks() > before);
    }

    /// Every call is in the end-to-end coverage registry (the review after M5.5: `writ-sign`
    /// had no such test, though rule 18 says `make test` fails on a flag without its row).
    #[test]
    fn every_call_is_in_the_end_to_end_registry() {
        let registry = include_str!("../../../docs/end-to-end.md");
        for call in CALLS {
            assert!(
                registry.contains(&format!("| `writ-sign {call}`")),
                "writ-sign {call} is not in docs/end-to-end.md's coverage registry"
            );
        }
        // And each is one `main` answers: the words it matches on are there.
        let source = include_str!("main.rs");
        for word in [
            "\"-Y\"",
            "\"sign\"",
            "is_gpg_sign",
            "\"--verify\"",
            "\"--version\"",
        ] {
            assert!(source.contains(word), "{word}");
        }
    }

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
    fn writ_session_must_name_the_session_the_settings_are_for() {
        let home = tempfile::tempdir().unwrap();
        let sessions = home.path().join("sessions");
        let a = "wrt_01JD8X0000000000000000000A";
        let b = "wrt_01JD8X0000000000000000000B";
        std::fs::create_dir_all(sessions.join(a)).unwrap();
        std::fs::create_dir_all(sessions.join(b)).unwrap();
        std::os::unix::fs::symlink(a, sessions.join("current")).unwrap();
        // Unset: whatever the settings name.
        assert!(check_session(&sessions.join(b), None).is_ok());
        assert!(check_session(&sessions.join(b), Some("")).is_ok());
        // The session itself, or `current` pointing at it.
        assert!(check_session(&sessions.join(a), Some(a)).is_ok());
        assert!(check_session(&sessions.join("current"), Some(a)).is_ok());
        // Another: refused, both named.
        let error = error_of(check_session(&sessions.join(b), Some(a)));
        assert!(
            error.starts_with(&format!(
                "WRIT_SESSION names lease {a}, but this repository's Writ settings are for {b}"
            )),
            "{error}"
        );
        let error = error_of(check_session(&sessions.join("current"), Some(b)));
        assert!(error.contains(&format!("settings are for {a}")), "{error}");
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
        // Another namespace than git's: refused before anything is read or asked (the review
        // after M5.5: the namespace went to the daemon as its command's word).
        for namespace in ["file", "writ-approval", "git\u{1b}"] {
            let error = error_of(sign(&os(&[
                "-n",
                namespace,
                "-f",
                "/tmp/k",
                "/nonexistent",
            ])));
            assert!(
                error.starts_with("writ-sign signs commits only, in namespace git, not "),
                "{namespace:?}: {error}"
            );
            assert!(!error.contains('\u{1b}'), "{error:?}");
        }
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
        // A port is 1 to 65535, as `writ` reads it (the review after M5.5: 99999 was taken).
        for bad in [
            "ssh://git@host:0",
            "ssh://git@host:65536",
            "ssh://git@host:99999",
        ] {
            let error = error_of(parse_url(bad));
            assert!(
                error.contains("the port must be 1 to 65535"),
                "{bad}: {error}"
            );
        }
        for (url, port) in [("ssh://git@host:1", "1"), ("ssh://git@host:65535", "65535")] {
            assert_eq!(
                parse_url(url).unwrap(),
                ("git@host".into(), Some(port.into()))
            );
        }
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
    fn git_s_gpg_calls_are_told_apart_and_the_gpg_is_an_absolute_path() {
        assert!(is_gpg_sign(&os(&["--status-fd=2", "-bsau", "ABCDEF"])));
        for other in [
            &["--status-fd=1", "-bsau", "ABCDEF"][..],
            &["-bsau", "ABCDEF"],
            &["--status-fd=2", "-bsau"],
            &["--status-fd=2", "-bsau", "A", "extra"],
            &["--status-fd=2", "--verify", "x", "-"],
        ] {
            assert!(!is_gpg_sign(&os(other)), "{other:?}");
        }
        assert_eq!(gpg_program(None).unwrap(), PathBuf::from("/usr/bin/gpg"));
        assert_eq!(
            gpg_program(Some("/opt/gnupg/bin/gpg".into())).unwrap(),
            PathBuf::from("/opt/gnupg/bin/gpg")
        );
        assert_eq!(
            error_of(gpg_program(Some("gpg".into()))),
            "WRIT_GPG must be an absolute path, got gpg"
        );
    }

    #[test]
    fn only_an_armored_openpgp_signature_is_written() {
        let good =
            "-----BEGIN PGP SIGNATURE-----\n\nwnUEABYKAB0=\n=AbCd\n-----END PGP SIGNATURE-----\n";
        assert!(check_openpgp_signature(good.as_bytes()).is_ok());
        for bad in [
            "",
            "-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n",
            &good.replace("wnUE", "\u{1b}[2J"),
            &format!("{good}{good}"),
            good.trim_end(),
        ] {
            assert_eq!(
                error_of(check_openpgp_signature(bad.as_bytes())),
                "the daemon sent something that is not an OpenPGP signature",
                "{bad:?}"
            );
        }
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

    #[test]
    fn the_same_directory_through_a_link() {
        let root = std::env::temp_dir().join(format!("writ-sign-same-dir-{}", std::process::id()));
        let (a, b) = (root.join("a"), root.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::os::unix::fs::symlink(&a, root.join("link")).unwrap();
        let checks = (
            same_dir(&a, &root.join("link")),
            same_dir(&a, &a.join(".")),
            same_dir(&a, &b),
            same_dir(&a, &root.join("missing")),
        );
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(checks, (true, true, false, false));
    }

    #[test]
    fn the_object_to_sign_is_read_within_the_daemon_s_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("object");
        let max = writ_proto::sign::MAX_SIGN_INPUT;
        std::fs::write(&path, vec![b'x'; max]).unwrap();
        assert_eq!(read_object(&path).unwrap().len(), max, "at the bound");
        std::fs::write(&path, vec![b'x'; max + 1]).unwrap();
        assert_eq!(
            error_of(read_object(&path)),
            format!("{} is too large to sign", path.display())
        );
        assert!(
            error_of(read_object(&dir.path().join("none"))).starts_with("cannot read "),
            "a missing file"
        );
    }
}
