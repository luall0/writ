//! The local tools the scenarios drive, and the versions they need (docs/stack.md, external
//! tools). Checked once per test binary: a missing or old tool fails with what to install,
//! not with a confusing error halfway through a scenario.

use std::process::Command;
use std::sync::OnceLock;

/// `git` 2.47: the daemon's mirrors (reftable, 2.45: `writ_mirror::MIN_GIT`), its HTTPS
/// upstreams (the proxy's socket path, 2.47: `writ_mirror::MIN_GIT_HTTPS`), SSH commit signing.
pub const MIN_GIT: (u32, u32) = writ_mirror::MIN_GIT_HTTPS;
/// OpenSSH 8.9: `ssh-keygen -Y sign/verify`, certificates.
pub const MIN_OPENSSH: (u32, u32) = (8, 9);

/// Checks every tool, once; panics with what's missing.
pub fn require() {
    static CHECKED: OnceLock<Result<(), String>> = OnceLock::new();
    if let Err(problem) = CHECKED.get_or_init(check) {
        panic!("{problem}");
    }
}

fn check() -> Result<(), String> {
    let git = run("git", &["--version"])?;
    let version = parse_git(&git).ok_or(format!("unreadable `git --version`: {git:?}"))?;
    at_least("git", version, MIN_GIT)?;
    // `ssh -V` writes its version on stderr.
    let ssh = run("ssh", &["-V"])?;
    let version = parse_openssh(&ssh).ok_or(format!("unreadable `ssh -V`: {ssh:?}"))?;
    at_least("OpenSSH", version, MIN_OPENSSH)?;
    for tool in ["ssh-keygen", "ssh-agent", "ssh-add", "nc"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .map_err(|e| format!("cannot run sh: {e}"))?;
        if !found.status.success() {
            return Err(format!(
                "{tool} is not installed; the integration tests need it"
            ));
        }
    }
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program} is not installed; the integration tests need it ({e})"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(text)
}

fn at_least(tool: &str, found: (u32, u32), min: (u32, u32)) -> Result<(), String> {
    if found >= min {
        Ok(())
    } else {
        Err(format!(
            "{tool} {}.{} is too old: the integration tests need {}.{} or later",
            found.0, found.1, min.0, min.1
        ))
    }
}

/// `git version 2.54.0 (Apple Git-157)` → (2, 54).
pub fn parse_git(text: &str) -> Option<(u32, u32)> {
    major_minor(text.trim().strip_prefix("git version ")?)
}

/// `OpenSSH_10.5p1, LibreSSL 3.3.6` → (10, 5).
pub fn parse_openssh(text: &str) -> Option<(u32, u32)> {
    major_minor(text.trim().strip_prefix("OpenSSH_")?)
}

fn major_minor(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_versions() {
        assert_eq!(
            parse_git("git version 2.54.0 (Apple Git-157)\n"),
            Some((2, 54))
        );
        assert_eq!(parse_git("git version 2.34.1"), Some((2, 34)));
        assert_eq!(
            parse_openssh("OpenSSH_10.5p1, LibreSSL 3.3.6\n"),
            Some((10, 5))
        );
        assert_eq!(
            parse_openssh("OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"),
            Some((8, 9))
        );
        assert_eq!(parse_git("hub version 2.14"), None);
        assert_eq!(parse_openssh("Sun_SSH_1.5"), None);
        assert!(at_least("git", (2, 47), MIN_GIT).is_ok());
        let error = at_least("git", (2, 46), MIN_GIT).unwrap_err();
        assert!(error.contains("git") && error.contains("2.47"), "{error}");
        assert!(at_least("git", (3, 0), MIN_GIT).is_ok());
    }
}
