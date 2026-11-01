//! The one way the daemon starts git on its repositories: a clean environment, no system or
//! global config, no prompt, only the transports the daemon uses, and the checks Writ relies
//! on set explicitly at the severity it needs ([`HARDENING`]). A library default is never the
//! decision (`docs/security.md`).

use std::path::Path;

use tokio::process::Command;

/// Environment variables git keeps from the daemon's; everything else is dropped.
const ENV_KEPT: [&str; 2] = ["PATH", "TMPDIR"];

/// `fsck` messages that only warn by default and refuse the objects here: a tree entry named
/// `.git`, `.`, `..`, empty, an absolute path, or a null id never lands in a mirror, whether it
/// comes from an agent's push or from upstream.
pub const FSCK_ERRORS: [&str; 6] = [
    "hasDotgit",
    "hasDot",
    "hasDotdot",
    "emptyName",
    "fullPathname",
    "nullSha1",
];

/// Settings every git the daemon runs gets (`-c`), whatever the repository's own config says.
pub const HARDENING: &[&str] = &[
    // Transports: ssh only (upstream); never `ext::`, `file://` or anything a URL could name.
    "protocol.allow=never",
    "protocol.ssh.allow=always",
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
    "gc.auto=0",
    "maintenance.auto=false",
    "receive.autogc=false",
    "credential.helper=",
    "core.fsmonitor=false",
    // What upload-pack serves an agent: only what refs reach, no filter.
    "uploadpack.allowAnySHA1InWant=false",
    "uploadpack.allowReachableSHA1InWant=false",
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

/// Where git looks for hooks.
#[derive(Debug, Clone, Copy)]
pub enum Hooks<'a> {
    /// None at all: syncs and reads run no hook (`reference-transaction` included).
    None,
    /// The gateway's own hooks directory (its pre-receive hook).
    Dir(&'a Path),
}

/// A `git` with a clean environment (only `PATH` and `TMPDIR`), no system or global config
/// (the daemon user's git config must not change what the daemon runs), no prompt, ssh as the
/// only transport, and [`HARDENING`].
pub fn command(hooks: Hooks<'_>) -> Command {
    // PATH: the daemon's own PATH (the environment is cleared but for it); the daemon's host
    // and its PATH are trusted (docs/threat-model.md, boundary 5).
    let mut cmd = Command::new("git");
    cmd.env_clear();
    for name in ENV_KEPT {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "ssh")
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
        let mut cmd = command(Hooks::None);
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
}
