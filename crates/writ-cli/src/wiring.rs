//! How a repository is wired for Writ (`docs/architecture/clients.md`, repo setup): the git
//! settings that send commits to the daemon to sign and reach it with the session's key,
//! built in one place ([`settings`]) for both modes.
//!
//! - **Wrapper** (the default): nothing in the repository's git config. `writ git …` and
//!   `writ exec -- …` run git (or any program) with the settings passed through the
//!   environment (`GIT_CONFIG_COUNT`, git ≥ 2.31), so the operator's own git, in the same
//!   clone, keeps the operator's keys, email and remotes.
//! - **Whole repo** (`writ init --whole-repo`): the settings written in the repository's
//!   config, for a clone dedicated to an agent; the values they replace are kept, so
//!   `writ init --undo` puts them back.
//!
//! What `writ init` records lives in `<git common dir>/writ/config` (git config format): never
//! in the working tree, so it can't be committed, and it travels with the clone.
//!
//! The settings point at one session ([`choose_session`]): `WRIT_SESSION` when it is set, then
//! the lease the repo is pinned to (`writ init --lease`), then `<home>/sessions/current`. A
//! session named by the first two must be on this host and not ended, or the command is
//! refused: never replaced by `current`. `writ.session` names the session's directory, so
//! `writ-sign` signs with that session only, in its lease's format.
//!
//! The clone's `origin` URL, as it was when wired, is rewritten to the daemon
//! (`url.<daemon>/<repo>.git.insteadOf`, and `pushInsteadOf` so a push rule of the user's own
//! can't take a push elsewhere), so `git push origin` and `git fetch origin` under the wiring go
//! through the daemon; never the user's global config. git matches the rule as a prefix: a URL
//! that starts with the origin's text goes to the daemon too, which refuses a repository it
//! doesn't serve; nothing is sent anywhere else. `writ init` refuses an `origin` it can't send
//! there whole (a push URL, several URLs, a credential in it).
//!
//! The record is the agent's to write too: read bounded ([`read_record`]).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use writ_core::canonical::Canonical;
use writ_core::names::{RepoName, TicketId};
use writ_core::ticket::Ticket;

use crate::Paths;
use crate::display;

/// How a repository is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wrapper,
    WholeRepo,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Wrapper => "wrapper",
            Mode::WholeRepo => "whole-repo",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "wrapper" => Some(Mode::Wrapper),
            "whole-repo" => Some(Mode::WholeRepo),
            _ => None,
        }
    }
}

/// What `writ init` recorded for a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiring {
    pub mode: Mode,
    /// The daemon's agents listener as git reaches it (`ssh://git@host:port`, or
    /// `ssh://git@writ-local` through [`Wiring::socket`]).
    pub base_url: String,
    /// The daemon's Unix socket, for a local endpoint (`writ.socket`): ssh reaches it through
    /// `nc -U`.
    pub socket: Option<PathBuf>,
    pub repo: RepoName,
    /// The committer email asked for (`writ init --email`); otherwise the current lease's.
    pub email: Option<String>,
    /// The repository's shared git directory (`writ.gitdir`): `writ-sign` refuses a commit
    /// made in any other repository with these settings.
    pub common_dir: PathBuf,
    /// The clone's `origin` URL when it was wired (`writ.origin`), rewritten to the daemon.
    pub origin: Option<String>,
    /// The lease the repo is pinned to (`writ init --lease`): its session, not `current`.
    pub lease: Option<TicketId>,
    /// The workspace root it was wired from (`writ.workspace`: `writ init` there, with no
    /// repo named), whose `writ init --undo` takes it back.
    pub workspace: Option<PathBuf>,
}

/// The session a command works under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRef {
    /// `<home>/sessions/current`, whichever lease it points at.
    Current,
    /// `<home>/sessions/<lease>`.
    Lease(TicketId),
}

impl SessionRef {
    /// The session's directory under `home`.
    pub fn dir(&self, home: &Path) -> PathBuf {
        let sessions = home.join("sessions");
        match self {
            Self::Current => sessions.join("current"),
            Self::Lease(id) => sessions.join(id.as_str()),
        }
    }

    /// `current` resolved to the lease it points at now, so that every setting of one command
    /// names that one session: ssh, `writ-sign` and git would each follow the link again, and
    /// a grant meanwhile would move them to another lease half way. `current` pointing at
    /// nothing stays `Current` (no lease to sign under: the daemon refuses).
    pub fn resolved(self, home: &Path) -> anyhow::Result<SessionRef> {
        let Self::Current = self else {
            return Ok(self);
        };
        let link = self.dir(home);
        let target = match std::fs::read_link(&link) {
            Ok(target) => target,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Current),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("{} isn't a link to a lease's session", link.display())
                });
            }
        };
        let text = target.to_string_lossy();
        let id: TicketId = text.parse().map_err(|_| {
            anyhow::anyhow!(
                "{} doesn't point at a lease ({})",
                link.display(),
                display::clean(&text)
            )
        })?;
        Ok(Self::Lease(id))
    }
}

/// The file in a session's directory that says it ended (closed, renewed), with why.
pub const ENDED: &str = "ended";

/// The session a command in a repo wired as `wiring` works under: `WRIT_SESSION`, then the
/// repo's pinned lease, then `current`. One named that is unknown on this host, ended (its
/// `ended` file) or past its end is refused with the reason, never replaced by `current`.
pub fn choose_session(home: &Path, pinned: Option<&TicketId>) -> anyhow::Result<SessionRef> {
    let (id, from) = match std::env::var("WRIT_SESSION") {
        Ok(text) if !text.is_empty() => {
            let id: TicketId = text
                .parse()
                .map_err(|e| anyhow::anyhow!("WRIT_SESSION {}: {e}", display::clean(&text)))?;
            (id, "WRIT_SESSION")
        }
        _ => match pinned {
            Some(id) => (id.clone(), "the lease this repository is pinned to"),
            None => return Ok(SessionRef::Current),
        },
    };
    check_session(home, &id).map_err(|why| anyhow::anyhow!("{from} names lease {id}: {why}"))?;
    Ok(SessionRef::Lease(id))
}

/// Why the session of lease `id` can't be used, if it can't: not on this host, ended, or past
/// its end by this host's clock.
pub fn check_session(home: &Path, id: &TicketId) -> Result<(), String> {
    let dir = SessionRef::Lease(id.clone()).dir(home);
    let Ok(bytes) = std::fs::read(dir.join("lease.json")) else {
        return Err(format!(
            "no granted session for it on this host ({})",
            dir.display()
        ));
    };
    let lease = Ticket::from_canonical(&bytes)
        .map_err(|_| format!("its session's lease.json doesn't read ({})", dir.display()))?;
    if let Ok(ended) = std::fs::read_to_string(dir.join(ENDED)) {
        return Err(format!("it ended ({})", display::clean(ended.trim())));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    let ended = u64::try_from(lease.limits.expires_at.unix()).map_or(true, |end| now >= end);
    if ended {
        return Err(format!("it expired at {}", lease.limits.expires_at));
    }
    Ok(())
}

/// One git setting: its key and value.
pub type Setting = (String, String);

/// Single-quoted for `sh` (git runs `core.sshCommand` through it).
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Where a repository is wired to, for [`settings`].
pub struct Target<'a> {
    /// The daemon's agents listener as git reaches it (`ssh://git@host:port`).
    pub base_url: &'a str,
    /// The daemon's Unix socket, for a local endpoint.
    pub socket: Option<&'a Path>,
    pub repo: &'a RepoName,
    pub common_dir: &'a Path,
    /// The clone's `origin` URL, rewritten to the daemon.
    pub origin: Option<&'a str>,
    /// The session the settings point at.
    pub session: &'a SessionRef,
}

/// The settings that wire a repository, in order (`<key> <value>`).
pub fn settings(
    target: &Target<'_>,
    home: &Path,
    known_hosts: &Path,
    writ_sign: &str,
    email: Option<&str>,
) -> Vec<Setting> {
    let Target {
        base_url,
        socket,
        repo,
        common_dir,
        origin,
        session,
    } = *target;
    let session_ref = session;
    let session = session_ref.dir(home);
    let path = |p: PathBuf| p.display().to_string();
    let mut settings: Vec<(&'static str, String)> = vec![
        ("remote.writ.url", format!("{base_url}/{repo}.git")),
        (
            "remote.writ.fetch",
            "+refs/heads/*:refs/remotes/writ/*".to_owned(),
        ),
        ("writ.url", base_url.to_owned()),
        ("writ.repo", repo.to_string()),
        ("writ.gitdir", path(common_dir.to_path_buf())),
        ("writ.session", path(session.clone())),
    ];
    // The lease's key signs in OpenPGP when its session holds the key's certificate: git
    // then calls `writ-sign` as `gpg`, and names the key by its fingerprint.
    match openpgp_fingerprint(&session) {
        Some(fingerprint) => settings.extend([
            ("gpg.format", "openpgp".to_owned()),
            ("gpg.openpgp.program", writ_sign.to_owned()),
            ("user.signingkey", fingerprint),
        ]),
        None => settings.extend([
            ("gpg.format", "ssh".to_owned()),
            ("gpg.ssh.program", writ_sign.to_owned()),
            ("user.signingkey", path(session.join("signing_key.pub"))),
        ]),
    }
    settings.extend([
        ("commit.gpgSign", "true".to_owned()),
        // Tags are never signed by the daemon (releases stay a human act).
        ("tag.gpgSign", "false".to_owned()),
        (
            "core.sshCommand",
            ssh_command(&session, known_hosts, socket),
        ),
    ]);
    if let Some(email) = email {
        settings.push(("user.email", email.to_owned()));
    }
    // The lease's committer_name, when its template sets one: the daemon refuses any other.
    if let Some(name) = lease_name(&session) {
        settings.push(("user.name", name));
    }
    let mut settings: Vec<Setting> = settings
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    let daemon = format!("{base_url}/{repo}.git");
    if let Some(origin) = origin.filter(|o| !o.is_empty() && *o != daemon) {
        settings.push((format!("url.{daemon}.insteadOf"), origin.to_owned()));
        // git takes a push's URL from the push rules alone when one matches: a shorter one of
        // the user's (`url.git@github.com:.pushInsteadOf https://github.com/`) would send the
        // push past the daemon. The whole URL is the longest match there is.
        settings.push((format!("url.{daemon}.pushInsteadOf"), origin.to_owned()));
    }
    settings
}

/// Whether `url` carries a credential: any user in an `http://` or `https://` URL (a token
/// often stands as the user name), a password (`user:password@`) in any other `scheme://`
/// URL. An ssh login (`git@host:path`, `ssh://git@host/path`) is none.
pub fn has_credential(url: &str) -> bool {
    userinfo(url).is_some_and(|u| u.credential())
}

/// `url` as `writ init` shows it: a credential ([`has_credential`]) replaced with
/// `<redacted>`, the rest escaped.
pub fn shown_url(url: &str) -> String {
    match userinfo(url) {
        Some(u) if u.credential() => {
            display::clean(&format!("{}://<redacted>@{}", u.scheme, u.after))
        }
        _ => display::clean(url),
    }
}

/// `url` with its user information taken out (`https://host/path`), for the command that
/// fixes it.
pub fn without_credential(url: &str) -> String {
    match userinfo(url) {
        Some(u) => display::clean(&format!("{}://{}", u.scheme, u.after)),
        None => display::clean(url),
    }
}

/// A `scheme://userinfo@host/…` URL, cut at its user information.
struct UserInfo<'a> {
    scheme: &'a str,
    info: &'a str,
    /// What follows the `@`.
    after: &'a str,
}

impl UserInfo<'_> {
    fn credential(&self) -> bool {
        let web =
            self.scheme.eq_ignore_ascii_case("http") || self.scheme.eq_ignore_ascii_case("https");
        web || self.info.contains(':')
    }
}

/// The user information of a `scheme://userinfo@host/…` URL: what comes before the last `@`
/// of the authority (up to the first `/`, `?` or `#`).
fn userinfo(url: &str) -> Option<UserInfo<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (info, _) = authority.rsplit_once('@')?;
    let after = rest.strip_prefix(info)?.strip_prefix('@')?;
    Some(UserInfo {
        scheme,
        info,
        after,
    })
}

/// The fingerprint of the OpenPGP certificate in `session` (`signing_key.asc`, written with
/// the grant when the lease's key signs in OpenPGP), if there is one that reads.
fn openpgp_fingerprint(session: &Path) -> Option<String> {
    let text = std::fs::read_to_string(session.join("signing_key.asc")).ok()?;
    writ_crypto::openpgp::certificate_fingerprint(&text).ok()
}

/// The program that carries ssh to a local daemon's Unix socket (macOS's own netcat).
pub const NETCAT: &str = "/usr/bin/nc";

/// The SSH command to reach the daemon with the session in `session` (its directory): nothing
/// from the user's own SSH setup (no config, no agent, no other key, no prompt), only the
/// daemon's pinned host key. For a local daemon (`socket`), ssh goes through `nc -U` to its
/// socket, and checks the key pinned under [`crate::client::UNIX_HOST_ALIAS`].
pub fn ssh_command(session: &Path, known_hosts: &Path, socket: Option<&Path>) -> String {
    let mut command = format!(
        "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -i {} \
         -o {} -o {} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes",
        quote(&session.join("key").display().to_string()),
        quote(&format!(
            "CertificateFile={}",
            session.join("key-cert.pub").display()
        )),
        quote(&format!("UserKnownHostsFile={}", known_hosts.display())),
    );
    if let Some(socket) = socket {
        // ssh runs ProxyCommand through sh: the path quoted for it, the option for git's sh.
        let proxy = format!(
            "ProxyCommand={NETCAT} -U {}",
            quote(&socket.display().to_string())
        );
        command.push_str(&format!(
            " -o HostKeyAlias={} -o {}",
            crate::client::UNIX_HOST_ALIAS,
            quote(&proxy)
        ));
    }
    command
}

/// `writ-sign` next to this `writ`, if it is there; otherwise found in `PATH` by git.
pub fn writ_sign_program() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("writ-sign")))
        .filter(|path| path.is_file())
        .map_or_else(|| "writ-sign".to_owned(), |path| path.display().to_string())
}

/// The single committer email of the lease in `session`, if it allows exactly one.
pub fn lease_email(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    let lease = Ticket::from_canonical(&bytes).ok()?;
    match lease.common.committer_emails.iter().collect::<Vec<_>>()[..] {
        [only] => Some(only.as_str().to_owned()),
        _ => None,
    }
}

/// The name the lease in `session` requires of its commits (its template's
/// `committer_name`), if it requires one.
pub fn lease_name(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    let lease = Ticket::from_canonical(&bytes).ok()?;
    lease.common.committer_name.map(String::from)
}

/// The id of the lease in `session`, if there is one on this host.
pub fn lease_id(session: &Path) -> Option<String> {
    let bytes = std::fs::read(session.join("lease.json")).ok()?;
    Some(Ticket::from_canonical(&bytes).ok()?.lease_id().to_string())
}

/// Runs git in `dir`; its stdout, or why it failed.
pub fn git(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    // PATH: the agent host's own git, the one the repo is used with.
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .context("cannot run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            display::clean_lines(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The repository's shared git directory (the same for every worktree).
pub fn common_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    let out = git(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .map_err(|_| anyhow::anyhow!("not in a git repository ({})", dir.display()))?;
    Ok(PathBuf::from(out.trim_end_matches('\n')))
}

/// Whether the repository at `dir` is a linked worktree (`git worktree add`): its own git
/// directory isn't the one it shares with the others, whose `config` they all read.
pub fn is_linked_worktree(dir: &Path) -> anyhow::Result<bool> {
    let out = git(dir, &["rev-parse", "--path-format=absolute", "--git-dir"])
        .map_err(|_| anyhow::anyhow!("not in a git repository ({})", dir.display()))?;
    let own = PathBuf::from(out.trim_end_matches('\n'));
    let common = common_dir(dir)?;
    let canonical = |p: &Path| {
        std::fs::canonicalize(p).with_context(|| format!("cannot resolve {}", p.display()))
    };
    Ok(canonical(&own)? != canonical(&common)?)
}

/// `<common dir>/writ/config`, where `writ init` records what it did.
pub fn record_path(dir: &Path) -> anyhow::Result<PathBuf> {
    Ok(common_dir(dir)?.join("writ").join("config"))
}

/// The largest record read (a repository's `<git common dir>/writ/config`, a workspace's
/// `.writ-workspace`): past it, it isn't one `writ init` wrote.
pub const MAX_RECORD: u64 = 64 * 1024;

/// The entries of a record `writ init` wrote at `path` (a `what`, for the errors), or none when
/// there is none. The record is the agent's to write too: opened without following a link and
/// without blocking (a FIFO), refused unless it is a regular file of at most [`MAX_RECORD`]
/// bytes, then read whole into memory and handed to git on its stdin (`git config -f -`), so
/// what git reads is what was checked.
pub fn read_record(
    dir: &Path,
    path: &Path,
    what: &str,
) -> anyhow::Result<Option<Vec<(String, String)>>> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read as _;
    let not_one = || {
        anyhow::anyhow!(
            "{} is not a {what} (a link, or not a regular file)",
            path.display()
        )
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => return Err(not_one()),
        Err(e) => {
            return Err(std::io::Error::from(e))
                .with_context(|| format!("cannot read {}", path.display()));
        }
    };
    let meta = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        return Err(not_one());
    }
    if meta.len() > MAX_RECORD {
        bail!(
            "{} is larger than {MAX_RECORD} bytes: not a {what}",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_RECORD) {
        bail!(
            "{} is larger than {MAX_RECORD} bytes: not a {what}",
            path.display()
        );
    }
    parse_config(dir, &bytes)
        .with_context(|| format!("{} is not a {what}", path.display()))
        .map(Some)
}

/// The entries of git config text (`git config -f - --list -z`, the text on its stdin), in
/// order.
fn parse_config(dir: &Path, text: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    use std::io::Write as _;
    use std::process::Stdio;
    // PATH: the agent host's own git, the one the repo is used with.
    let mut child = Command::new("git")
        .args(["config", "-f", "-", "--list", "-z"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run git")?;
    let mut stdin = child.stdin.take().context("cannot write to git")?;
    // Written from a thread of its own: git answers as it reads, and a full stdout pipe would
    // otherwise stop both.
    let (written, out) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(text));
        let out = child.wait_with_output();
        (writer.join(), out)
    });
    let out = out.context("cannot run git")?;
    if !out.status.success() {
        bail!(
            "git config failed: {}",
            display::clean_lines(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    match written {
        Ok(result) => result.context("cannot write to git")?,
        Err(_) => bail!("cannot write to git"),
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|e| !e.is_empty())
        .map(|entry| match entry.split_once('\n') {
            Some((key, value)) => (key.to_owned(), value.to_owned()),
            None => (entry.to_owned(), String::new()),
        })
        .collect())
}

/// What `writ init` recorded in a repository whose shared git directory is `common_dir`:
/// every entry of its record, read bounded ([`read_record`]); none when it isn't wired.
pub fn record_entries(common_dir: &Path) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let path = common_dir.join("writ").join("config");
    read_record(common_dir, &path, "Writ wiring record")
}

/// What `writ init` recorded in the repository at `dir`, if it is wired.
pub fn load(dir: &Path) -> anyhow::Result<Option<Wiring>> {
    load_common(&common_dir(dir)?)
}

/// What `writ init` recorded in the repository whose shared git directory is `common_dir`,
/// if it is wired.
pub fn load_common(common_dir: &Path) -> anyhow::Result<Option<Wiring>> {
    let path = common_dir.join("writ").join("config");
    let Some(entries) = record_entries(common_dir)? else {
        return Ok(None);
    };
    let get = |key: &str| {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let invalid = || anyhow::anyhow!("{} is not a Writ wiring record", path.display());
    let mode = get("writ.mode")
        .as_deref()
        .and_then(Mode::parse)
        .ok_or_else(invalid)?;
    let base_url = get("writ.url").ok_or_else(invalid)?;
    let socket = get("writ.socket").map(PathBuf::from);
    let repo = get("writ.repo")
        .and_then(|r| r.parse().ok())
        .ok_or_else(invalid)?;
    let lease = match get("writ.lease") {
        Some(text) => Some(text.parse().map_err(|_| invalid())?),
        None => None,
    };
    Ok(Some(Wiring {
        mode,
        base_url,
        socket,
        repo,
        email: get("writ.email"),
        common_dir: common_dir.to_path_buf(),
        origin: get("writ.origin"),
        lease,
        workspace: get("writ.workspace").map(PathBuf::from),
    }))
}

/// The settings of a wired repository, with this host's paths and the session `session`.
pub fn settings_with(
    paths: &Paths,
    wiring: &Wiring,
    session: &SessionRef,
) -> anyhow::Result<Vec<Setting>> {
    let home = std::path::absolute(&paths.home).context("cannot resolve WRIT_HOME")?;
    let known_hosts =
        std::path::absolute(&paths.known_hosts).context("cannot resolve the known_hosts path")?;
    let email = wiring
        .email
        .clone()
        .or_else(|| lease_email(&session.dir(&home)));
    Ok(settings(
        &Target {
            base_url: &wiring.base_url,
            socket: wiring.socket.as_deref(),
            repo: &wiring.repo,
            common_dir: &wiring.common_dir,
            origin: wiring.origin.as_deref(),
            session,
        },
        &home,
        &known_hosts,
        &writ_sign_program(),
        email.as_deref(),
    ))
}

/// The environment that passes `settings` to git, after the `GIT_CONFIG_COUNT` entries the
/// caller already has (`existing`): later entries win, so these override the user's config.
pub fn config_env(
    existing: Option<&str>,
    settings: &[Setting],
) -> anyhow::Result<Vec<(String, OsString)>> {
    let start: usize = match existing {
        None => 0,
        Some(text) => text
            .parse()
            .with_context(|| format!("GIT_CONFIG_COUNT is not a number: {text:?}"))?,
    };
    let mut env = Vec::new();
    let mut index = start;
    for (key, value) in settings {
        env.push((format!("GIT_CONFIG_KEY_{index}"), OsString::from(key)));
        env.push((format!("GIT_CONFIG_VALUE_{index}"), OsString::from(value)));
        index = index.saturating_add(1);
    }
    env.push((
        "GIT_CONFIG_COUNT".to_owned(),
        OsString::from(index.to_string()),
    ));
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_openpgp_lease_is_wired_for_gpg_by_its_fingerprint() {
        use writ_crypto::algorithm::{Hash, KeyAlgorithm};
        use writ_crypto::keypair::KeyPair;
        use writ_crypto::openpgp::{OpenpgpKey, certificate, certification};
        let home = tempfile::tempdir().unwrap();
        let session = home.path().join("sessions/current");
        std::fs::create_dir_all(&session).unwrap();
        let key = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let pgp = OpenpgpKey::new(&key.public_key(), 1_762_128_000).unwrap();
        let prepared = certification(&pgp, Hash::Sha512, "<a@b>").unwrap();
        let (data, hash) = prepared.signer_input();
        let packet = prepared.packet(&key.sign(data, hash).unwrap()).unwrap();
        std::fs::write(
            session.join("signing_key.asc"),
            certificate(&pgp, &[("<a@b>", packet)]).unwrap(),
        )
        .unwrap();
        let wired = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                socket: None,
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: None,
                session: &SessionRef::Current,
            },
            home.path(),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            None,
        );
        let get = |key: &str| {
            wired
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("gpg.format"), Some("openpgp"));
        assert_eq!(get("gpg.openpgp.program"), Some("/usr/local/bin/writ-sign"));
        assert_eq!(get("user.signingkey"), Some(pgp.fingerprint_hex().as_str()));
        assert_eq!(get("gpg.ssh.program"), None);
        // A certificate that doesn't read: wired for SSH, as without one.
        std::fs::write(session.join("signing_key.asc"), "not a certificate").unwrap();
        let wired = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                socket: None,
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: None,
                session: &SessionRef::Current,
            },
            home.path(),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            None,
        );
        assert!(wired.iter().any(|(k, v)| k == "gpg.format" && v == "ssh"));
    }

    #[test]
    fn writes_exactly_the_documented_config() {
        let settings = settings(
            &Target {
                base_url: "ssh://git@writ.home:2222",
                socket: None,
                repo: &"omega-code".parse().unwrap(),
                common_dir: Path::new("/opt/agent/omega/.git"),
                origin: Some("git@github.com:user/omega-code.git"),
                session: &SessionRef::Current,
            },
            Path::new("/opt/agent/.writ"),
            Path::new("/opt/agent/.writ/known_hosts"),
            "/usr/local/bin/writ-sign",
            Some("user+agent@example.org"),
        );
        let expected = [
            ("remote.writ.url", "ssh://git@writ.home:2222/omega-code.git"),
            ("remote.writ.fetch", "+refs/heads/*:refs/remotes/writ/*"),
            ("writ.url", "ssh://git@writ.home:2222"),
            ("writ.repo", "omega-code"),
            ("writ.gitdir", "/opt/agent/omega/.git"),
            ("writ.session", "/opt/agent/.writ/sessions/current"),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", "/usr/local/bin/writ-sign"),
            (
                "user.signingkey",
                "/opt/agent/.writ/sessions/current/signing_key.pub",
            ),
            ("commit.gpgSign", "true"),
            ("tag.gpgSign", "false"),
            (
                "core.sshCommand",
                "ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
                 -i '/opt/agent/.writ/sessions/current/key' \
                 -o 'CertificateFile=/opt/agent/.writ/sessions/current/key-cert.pub' \
                 -o 'UserKnownHostsFile=/opt/agent/.writ/known_hosts' \
                 -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes",
            ),
            ("user.email", "user+agent@example.org"),
            (
                "url.ssh://git@writ.home:2222/omega-code.git.insteadOf",
                "git@github.com:user/omega-code.git",
            ),
            (
                "url.ssh://git@writ.home:2222/omega-code.git.pushInsteadOf",
                "git@github.com:user/omega-code.git",
            ),
        ];
        let got: Vec<(&str, &str)> = settings
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn only_a_real_origin_is_rewritten() {
        let repo: RepoName = "demo".parse().unwrap();
        let rewrites = |origin: Option<&str>| {
            settings(
                &Target {
                    base_url: "ssh://git@writ.home:2222",
                    socket: None,
                    repo: &repo,
                    common_dir: Path::new("/r/.git"),
                    origin,
                    session: &SessionRef::Current,
                },
                Path::new("/h"),
                Path::new("/k"),
                "writ-sign",
                None,
            )
            .into_iter()
            .filter(|(k, _)| k.starts_with("url."))
            .count()
        };
        // Fetch and push: a push rule of the user's can't take the push elsewhere.
        assert_eq!(rewrites(Some("ssh://git@github.com/u/demo.git")), 2);
        assert_eq!(rewrites(None), 0, "no origin");
        assert_eq!(rewrites(Some("")), 0, "an empty origin");
        assert_eq!(
            rewrites(Some("ssh://git@writ.home:2222/demo.git")),
            0,
            "origin already the daemon: no loop"
        );
    }

    #[test]
    fn a_credential_in_a_url_is_found_and_never_shown() {
        for (url, credential, shown, without) in [
            (
                "https://ghp_secret@github.com/u/r.git",
                true,
                "https://<redacted>@github.com/u/r.git",
                "https://github.com/u/r.git",
            ),
            (
                "HTTPS://me:hunter2@host/r.git",
                true,
                "HTTPS://<redacted>@host/r.git",
                "HTTPS://host/r.git",
            ),
            (
                "ssh://git:hunter2@host/r.git",
                true,
                "ssh://<redacted>@host/r.git",
                "ssh://host/r.git",
            ),
            // A login name over ssh is none; nor is an `@` in a path.
            (
                "ssh://git@host:22/r.git",
                false,
                "ssh://git@host:22/r.git",
                "ssh://host:22/r.git",
            ),
            (
                "git@github.com:u/r.git",
                false,
                "git@github.com:u/r.git",
                "git@github.com:u/r.git",
            ),
            (
                "https://host/u/r@v2.git",
                false,
                "https://host/u/r@v2.git",
                "https://host/u/r@v2.git",
            ),
            ("/srv/r.git", false, "/srv/r.git", "/srv/r.git"),
        ] {
            assert_eq!(has_credential(url), credential, "{url}");
            assert_eq!(shown_url(url), shown, "{url}");
            assert_eq!(without_credential(url), without, "{url}");
        }
        // Escaped once redacted.
        assert_eq!(
            shown_url("https://t@h/\u{1b}[2J"),
            "https://<redacted>@h/\\u{1b}[2J"
        );
    }

    #[test]
    fn current_is_resolved_once_to_the_lease_it_points_at() {
        let home = tempfile::tempdir().unwrap();
        let sessions = home.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        // No `current`: no lease to name.
        assert_eq!(
            SessionRef::Current.resolved(home.path()).unwrap(),
            SessionRef::Current
        );
        let id: TicketId = "wrt_01JD8X0000000000000000000A".parse().unwrap();
        std::os::unix::fs::symlink(id.as_str(), sessions.join("current")).unwrap();
        let resolved = SessionRef::Current.resolved(home.path()).unwrap();
        assert_eq!(resolved, SessionRef::Lease(id.clone()));
        assert_eq!(resolved.dir(home.path()), sessions.join(id.as_str()));
        // A lease named stays itself.
        let other: TicketId = "wrt_01JD8X0000000000000000000B".parse().unwrap();
        assert_eq!(
            SessionRef::Lease(other.clone())
                .resolved(home.path())
                .unwrap(),
            SessionRef::Lease(other)
        );
        // A `current` that names no lease, or isn't a link: refused, never followed.
        std::fs::remove_file(sessions.join("current")).unwrap();
        std::os::unix::fs::symlink("../../etc", sessions.join("current")).unwrap();
        let error = crate::error_of(SessionRef::Current.resolved(home.path()));
        assert!(
            error.ends_with("sessions/current doesn't point at a lease (../../etc)"),
            "{error}"
        );
        std::fs::remove_file(sessions.join("current")).unwrap();
        std::fs::create_dir(sessions.join("current")).unwrap();
        let error = crate::error_of(SessionRef::Current.resolved(home.path()));
        assert!(
            error.contains("sessions/current isn't a link to a lease's session"),
            "{error}"
        );
    }

    #[test]
    fn a_record_is_read_bounded_whatever_is_in_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let read = |p: &Path| read_record(dir.path(), p, "Writ wiring record");
        assert_eq!(read(&path).unwrap(), None);
        std::fs::write(&path, "[writ]\n\tmode = wrapper\n\trepo = demo\n").unwrap();
        assert_eq!(
            read(&path).unwrap(),
            Some(vec![
                ("writ.mode".to_owned(), "wrapper".to_owned()),
                ("writ.repo".to_owned(), "demo".to_owned()),
            ])
        );
        // At the bound read, one past it refused.
        let padded = |len: u64| {
            let mut text = String::from("[writ]\n\tmode = wrapper\n");
            while (text.len() as u64) < len - 1 {
                text.push('#');
            }
            text.push('\n');
            text
        };
        std::fs::write(&path, padded(MAX_RECORD)).unwrap();
        assert_eq!(read(&path).unwrap().map(|e| e.len()), Some(1));
        std::fs::write(&path, padded(MAX_RECORD + 1)).unwrap();
        let error = crate::error_of(read(&path));
        assert!(
            error.ends_with("is larger than 65536 bytes: not a Writ wiring record"),
            "{error}"
        );
        // A link (to /dev/zero, to a good record), a FIFO, a folder: refused at once.
        let good = dir.path().join("good");
        std::fs::write(&good, "[writ]\n\tmode = wrapper\n").unwrap();
        for target in [Path::new("/dev/zero"), good.as_path()] {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(target, &path).unwrap();
            let error = crate::error_of(read(&path));
            assert!(
                error.ends_with("is not a Writ wiring record (a link, or not a regular file)"),
                "{error}"
            );
        }
        std::fs::remove_file(&path).unwrap();
        let made = Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(made.success());
        let error = crate::error_of(read(&path));
        assert!(
            error.ends_with("is not a Writ wiring record (a link, or not a regular file)"),
            "{error}"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = crate::error_of(read(&path));
        assert!(
            error.ends_with("is not a Writ wiring record (a link, or not a regular file)"),
            "{error}"
        );
        // Text git can't read: refused, naming the record.
        let broken = dir.path().join("broken");
        std::fs::write(&broken, "[writ\n").unwrap();
        let error = crate::error_of(read(&broken));
        assert!(
            error.contains("broken is not a Writ wiring record: git config failed"),
            "{error}"
        );
    }

    #[test]
    fn paths_are_quoted_for_sh() {
        assert_eq!(quote("/a b/it's"), r"'/a b/it'\''s'");
        let ssh = ssh_command(
            Path::new("/x y/$(id)/sessions/current"),
            Path::new("/k"),
            None,
        );
        assert!(
            ssh.contains("-i '/x y/$(id)/sessions/current/key'"),
            "{ssh}"
        );
    }

    /// What `sh -c "<script> \"$@\""` passes as arguments, one per line.
    fn sh_args(script: &str) -> Vec<String> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("for a in {script}; do printf '%s\\n' \"$a\"; done"))
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_local_daemon_s_socket_survives_both_shells() {
        let socket = Path::new("/Library/App Support/it's $(id)/agents.sock");
        let ssh = ssh_command(Path::new("/s"), Path::new("/k"), Some(socket));
        // git's sh hands ssh its options: the alias, and the proxy as one option.
        let args = sh_args(ssh.strip_prefix("ssh ").unwrap());
        let alias = args
            .iter()
            .position(|a| a == "HostKeyAlias=writ-local")
            .unwrap();
        assert_eq!(args[alias - 1], "-o");
        let proxy = args
            .iter()
            .find_map(|a| a.strip_prefix("ProxyCommand="))
            .unwrap();
        // ssh's sh runs the proxy: nc, -U, the path whole.
        assert_eq!(
            sh_args(proxy),
            [NETCAT, "-U", "/Library/App Support/it's $(id)/agents.sock"]
        );
        // A TCP daemon: no proxy, no alias.
        let tcp = ssh_command(Path::new("/s"), Path::new("/k"), None);
        assert!(
            !tcp.contains("ProxyCommand") && !tcp.contains("HostKeyAlias"),
            "{tcp}"
        );
    }

    #[test]
    fn the_environment_comes_after_what_the_caller_has() {
        let settings = vec![
            ("writ.repo".to_owned(), "demo".to_owned()),
            ("commit.gpgSign".to_owned(), "true".to_owned()),
        ];
        let env = config_env(None, &settings).unwrap();
        let text: Vec<(&str, &str)> = env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            text,
            [
                ("GIT_CONFIG_KEY_0", "writ.repo"),
                ("GIT_CONFIG_VALUE_0", "demo"),
                ("GIT_CONFIG_KEY_1", "commit.gpgSign"),
                ("GIT_CONFIG_VALUE_1", "true"),
                ("GIT_CONFIG_COUNT", "2"),
            ]
        );
        // Two entries the caller set: ours follow, so ours win.
        let env = config_env(Some("2"), &settings).unwrap();
        assert_eq!(env[0].0, "GIT_CONFIG_KEY_2");
        assert_eq!(env.last().unwrap().1, "4");
        let error = crate::error_of(config_env(Some("two"), &settings));
        assert!(
            error.starts_with("GIT_CONFIG_COUNT is not a number: \"two\""),
            "{error}"
        );
    }
}
