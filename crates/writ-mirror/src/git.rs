//! The one way the daemon starts git on its repositories: a clean environment, no system or
//! global config, no prompt, no transport at all unless an upstream operation allows its own
//! ([`allow`]), and the checks Writ relies on set explicitly at the severity it needs
//! ([`HARDENING`], [`HTTPS_HARDENING`]). A library default is never the decision
//! (`docs/security.md`).

use std::path::Path;

use tokio::process::Command;

/// Environment variables git keeps from the daemon's; everything else is dropped.
const ENV_KEPT: [&str; 2] = ["PATH", "TMPDIR"];

/// `fsck` messages that only warn by default and refuse the objects here: a tree entry named
/// `.git`, `.`, `..`, empty, an absolute path, or a null id never lands in a mirror, whether it
/// comes from an agent's push or from upstream; nor does a mode git doesn't write (`40755`,
/// `100664`…, `badFilemode`) or a zero-padded one (`040000`, `zeroPaddedFilemode`), which git
/// reads by its type bits and `writ_git::tree` refuses: the paths a commit touches are never
/// computed from a tree git would read otherwise.
pub const FSCK_ERRORS: [&str; 8] = [
    "hasDotgit",
    "hasDot",
    "hasDotdot",
    "emptyName",
    "fullPathname",
    "nullSha1",
    "badFilemode",
    "zeroPaddedFilemode",
];

/// Settings every git the daemon runs gets (`-c`), whatever the repository's own config says.
pub const HARDENING: &[&str] = &[
    // Transports: none (an upstream operation allows its own: [`allow`]); never `ext::`,
    // `file://` or anything a URL could name.
    "protocol.allow=never",
    // Every object checked, from an agent or from upstream.
    "transfer.fsckObjects=true",
    "fetch.fsckObjects=true",
    "receive.fsckObjects=true",
    // A fetched pack is kept whole and lands only once checked (never unpacked loose as it
    // comes in, where a failed fetch could leave some of its objects behind).
    "fetch.unpackLimit=1",
    "transfer.unpackLimit=1",
    // Nothing else runs: no submodule, no background maintenance, no credential helper, no
    // file system monitor.
    "fetch.recurseSubmodules=false",
    "submodule.recurse=false",
    // No bundle a remote names (git's default today, set here: a default is never the
    // decision): it would have git download from other URLs than the upstream's.
    "transfer.bundleURI=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "receive.autogc=false",
    "credential.helper=",
    "core.fsmonitor=false",
    // What upload-pack serves an agent: only what refs reach, no filter. In protocol v0, the
    // only one it speaks ([`upload_pack`]): in v2, git ignores `allow*SHA1InWant` and serves
    // any object the mirror holds by its id. A commit reachable from a ref may be asked for by
    // its id (`git fetch writ <sha>`), any other object is refused ("not our ref"). The order
    // matters: `allowAnySHA1InWant=false` clears the reachable bit too, so it comes first.
    "uploadpack.allowAnySHA1InWant=false",
    "uploadpack.allowReachableSHA1InWant=true",
    "uploadpack.allowTipSHA1InWant=false",
    "uploadpack.allowFilter=false",
    // What receive-pack takes: no shallow update, no push option; the pre-receive hook
    // decides everything else (deletions and force pushes included).
    "receive.shallowUpdate=false",
    "receive.advertisePushOptions=false",
    "receive.updateServerInfo=false",
    "receive.denyDeletes=false",
    "receive.denyNonFastForwards=false",
];

/// What an HTTPS upstream operation gets on top of [`HARDENING`], besides its proxy and its
/// credential helper (per operation): the server's certificate verified, no redirect (the
/// token goes to the registry's host and nowhere else), no header, cookie or credential from
/// anywhere but the daemon, never a prompt.
pub const HTTPS_HARDENING: &[&str] = &[
    "http.sslVerify=true",
    "http.followRedirects=false",
    "http.extraHeader=",
    "http.cookieFile=",
    "http.saveCookies=false",
    "http.emptyAuth=false",
    "credential.interactive=false",
    // Resets the list of helpers: only the daemon's, given after it, answers.
    "credential.helper=",
];

/// The one transport an upstream operation uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Ssh,
    Https,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Https => "https",
        }
    }
}

/// Allows `transport`, and only it, to the git `cmd` (before its subcommand): the upstream
/// operations' git. Every other git the daemon runs reaches nothing.
pub fn allow(cmd: &mut Command, transport: Transport) {
    let name = transport.as_str();
    cmd.arg("-c")
        .arg(format!("protocol.{name}.allow=always"))
        .env("GIT_ALLOW_PROTOCOL", name);
}

/// Where git looks for hooks.
#[derive(Debug, Clone, Copy)]
pub enum Hooks<'a> {
    /// None at all: syncs and reads run no hook (`reference-transaction` included).
    None,
    /// The gateway's own hooks directory (its pre-receive hook).
    Dir(&'a Path),
}

/// The `git` at `program` (the operator's `mirrors.git`, an absolute path) with a clean
/// environment (only `PATH` and `TMPDIR`), no system or global config (the daemon user's git
/// config must not change what the daemon runs), no prompt, no transport, and [`HARDENING`].
/// What git itself starts (`sh` for an ssh command or a credential helper) is found in the
/// daemon's `PATH`: the daemon's host is trusted (docs/threat-model.md, boundary 5).
pub fn command(program: &Path, hooks: Hooks<'_>) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear();
    for name in ENV_KEPT {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("SSH_ASKPASS_REQUIRE", "never");
    for setting in HARDENING {
        cmd.arg("-c").arg(setting);
    }
    for message in FSCK_ERRORS {
        for prefix in ["fsck", "fetch.fsck", "receive.fsck"] {
            cmd.arg("-c").arg(format!("{prefix}.{message}=error"));
        }
    }
    match hooks {
        Hooks::None => cmd.args(["-c", "core.hooksPath=/dev/null"]),
        Hooks::Dir(dir) => cmd
            .arg("-c")
            .arg(format!("core.hooksPath={}", dir.display())),
    };
    cmd
}

/// `git upload-pack` on the repository at `repo` (a fetch through the gateway), with the
/// daemon's `git` at `program`: [`command`]'s clean environment, so `GIT_PROTOCOL` never
/// reaches it, whatever the client asked for, and it speaks protocol v0, where
/// [`HARDENING`]'s `uploadpack.allow*SHA1InWant` hold (in v2, git ignores them).
pub fn upload_pack(program: &Path, repo: &Path) -> Command {
    let mut cmd = command(program, Hooks::None);
    cmd.arg("upload-pack").arg("--strict").arg(repo);
    cmd
}

/// `git version` → `(major, minor)`, e.g. `git version 2.54.0 (Apple Git-157)` → `(2, 54)`.
pub fn parse_version(text: &str) -> Option<(u32, u32)> {
    let version = text.trim().strip_prefix("git version ")?;
    let mut parts = version.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_as_git_prints_them() {
        assert_eq!(
            parse_version("git version 2.54.0 (Apple Git-157)\n"),
            Some((2, 54))
        );
        assert_eq!(parse_version("git version 2.45.0"), Some((2, 45)));
        assert_eq!(parse_version("git version 3.0.0.rc1"), Some((3, 0)));
        assert_eq!(parse_version("git 2.45"), None);
        assert_eq!(parse_version("git version x"), None);
    }

    #[tokio::test]
    async fn the_daemon_user_s_config_and_environment_never_reach_git() {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(&crate::testing::git(), Hooks::None);
        cmd.args(["config", "--list", "--show-origin"])
            .current_dir(dir.path());
        let out = cmd.output().await.unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        // Only the command line's settings: no file at all.
        for line in text.lines() {
            assert!(line.starts_with("command line:"), "{line}");
        }
        assert!(text.contains("receive.fsck.hasdotgit=error"), "{text}");
        assert!(text.contains("protocol.allow=never"), "{text}");
        assert!(text.contains("core.hookspath=/dev/null"), "{text}");
    }

    /// A git command on a test repository, outside the daemon's settings.
    fn plain_git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new(crate::testing::git())
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "A")
            .env("GIT_AUTHOR_EMAIL", "a@x")
            .env("GIT_COMMITTER_NAME", "A")
            .env("GIT_COMMITTER_EMAIL", "a@x")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A pkt-line.
    fn pkt(line: &str) -> Vec<u8> {
        let mut bytes = format!("{:04x}", line.len().checked_add(4).unwrap()).into_bytes();
        bytes.extend_from_slice(line.as_bytes());
        bytes
    }

    /// Asks [`upload_pack`] for `want` as a protocol v0 client does; its exit code and output.
    async fn want(repo: &Path, want: &str) -> (Option<i32>, String) {
        use tokio::io::AsyncWriteExt as _;
        let mut cmd = upload_pack(&crate::testing::git(), repo);
        // The daemon's own environment asking for v2 changes nothing: it never reaches git.
        assert!(
            cmd.as_std()
                .get_envs()
                .all(|(name, _)| name != "GIT_PROTOCOL"),
            "GIT_PROTOCOL set"
        );
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut request = pkt(&format!("want {want}\n"));
        request.extend_from_slice(b"0000");
        request.extend(pkt("done\n"));
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&request).await.unwrap();
        drop(stdin);
        let out = child.wait_with_output().await.unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    #[tokio::test]
    async fn upload_pack_serves_what_refs_reach_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        plain_git(&work, &["init", "-q", "-b", "main"]);
        let commit = |message: &str| {
            plain_git(&work, &["commit", "-q", "--allow-empty", "-m", message]);
            plain_git(&work, &["rev-parse", "HEAD"])
        };
        let first = commit("first");
        let tip = commit("tip");
        // A commit on a branch deleted since: still in the repository, reached by no ref.
        plain_git(&work, &["checkout", "-q", "-b", "gone"]);
        let gone = commit("gone");
        plain_git(&work, &["checkout", "-q", "main"]);
        plain_git(&work, &["branch", "-q", "-D", "gone"]);
        let repo = work.join(".git");
        assert_eq!(plain_git(&repo, &["cat-file", "-t", &gone]), "commit");

        // A tip, and a commit only reachable from one: served (NAK, then the pack).
        for id in [&tip, &first] {
            let (code, out) = want(&repo, id).await;
            assert_eq!(code, Some(0), "{id}: {out}");
            assert!(out.contains("NAK") && out.contains("PACK"), "{id}: {out}");
        }
        // Reached by no ref: refused.
        let (code, out) = want(&repo, &gone).await;
        assert_eq!(code, Some(128), "{out}");
        assert!(
            out.contains(&format!("ERR upload-pack: not our ref {gone}")),
            "{out}"
        );
        assert!(!out.contains("PACK"), "{out}");
    }

    async fn ls_remote(transport: Option<Transport>, url: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(&crate::testing::git(), Hooks::None);
        if let Some(transport) = transport {
            allow(&mut cmd, transport);
        }
        cmd.args(["ls-remote", "--", url]).current_dir(dir.path());
        let out = cmd.output().await.unwrap();
        assert_eq!(out.status.code(), Some(128), "{url}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    #[tokio::test]
    async fn git_reaches_nothing_but_the_one_transport_allowed() {
        let local = tempfile::tempdir().unwrap();
        let file = format!("file://{}", local.path().display());
        for (transport, url, refused) in [
            (None, file.as_str(), "transport 'file' not allowed"),
            (
                None,
                "ssh://127.0.0.1:1/x.git",
                "transport 'ssh' not allowed",
            ),
            (
                None,
                "https://127.0.0.1:1/x.git",
                "transport 'https' not allowed",
            ),
            (
                Some(Transport::Ssh),
                "https://127.0.0.1:1/x.git",
                "transport 'https' not allowed",
            ),
            (
                Some(Transport::Ssh),
                file.as_str(),
                "transport 'file' not allowed",
            ),
            (
                Some(Transport::Https),
                "ssh://127.0.0.1:1/x.git",
                "transport 'ssh' not allowed",
            ),
            (
                Some(Transport::Https),
                "http://127.0.0.1:1/x.git",
                "transport 'http' not allowed",
            ),
            (
                Some(Transport::Https),
                "ext::sh -c id",
                "transport 'ext' not allowed",
            ),
        ] {
            let stderr = ls_remote(transport, url).await;
            assert!(stderr.contains(refused), "{transport:?} {url}: {stderr}");
        }
    }
}
