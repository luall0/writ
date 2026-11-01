//! Commands a client may run through the gateway. Anything else is refused. Which identity
//! may run which command is decided by the connection handler.

use writ_approval::EventKind;
use writ_core::names::RepoName;

/// A parsed exec request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// A lease holder's command: git or signing.
    Lease(LeaseCommand),
    /// `writ …`: an agent or approval command (`writ_proto::Command`).
    Writ(writ_proto::Command),
}

/// What only a lease holder may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseCommand {
    /// `git-upload-pack '<repo>.git'`: fetch.
    UploadPack { repo: RepoName },
    /// `git-receive-pack '<repo>.git'`: push.
    ReceivePack { repo: RepoName },
    /// `writ-sign git <repo>`: sign the commit sent on stdin, for a repo of the lease.
    Sign { repo: RepoName },
}

impl LeaseCommand {
    /// The audit event it is logged under.
    pub(crate) fn event(&self) -> EventKind {
        match self {
            Self::UploadPack { .. } => EventKind::Fetch,
            Self::ReceivePack { .. } => EventKind::Push,
            Self::Sign { .. } => EventKind::Sign,
        }
    }
}

impl Command {
    /// Parses the command line of an SSH exec request.
    pub(crate) fn parse(line: &[u8]) -> Option<Self> {
        let line = std::str::from_utf8(line).ok()?;
        if line.starts_with("writ ") {
            return writ_proto::Command::parse(line).map(Self::Writ);
        }
        let (program, arg) = line.split_once(' ')?;
        let command = match program {
            "git-upload-pack" => LeaseCommand::UploadPack {
                repo: repo_name(unquote(arg)?)?,
            },
            "git-receive-pack" => LeaseCommand::ReceivePack {
                repo: repo_name(unquote(arg)?)?,
            },
            "writ-sign" => {
                // The namespace git signs commits in, then a registry name (never a path).
                let (namespace, repo) = arg.split_once(' ')?;
                if namespace != "git" {
                    return None;
                }
                LeaseCommand::Sign {
                    repo: repo.parse().ok()?,
                }
            }
            _ => return None,
        };
        Some(Self::Lease(command))
    }
}

/// Git sends the path single-quoted. Embedded quotes are refused rather than unescaped.
fn unquote(arg: &str) -> Option<&str> {
    let inner = arg.strip_prefix('\'')?.strip_suffix('\'')?;
    (!inner.contains('\'')).then_some(inner)
}

/// A repo is a registry name, with or without `.git` and one leading `/` (`/omega-code.git`),
/// never a path.
fn repo_name(path: &str) -> Option<RepoName> {
    let name = path.strip_prefix('/').unwrap_or(path);
    let name = name.strip_suffix(".git").unwrap_or(name);
    name.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_commands() {
        let demo: RepoName = "demo".parse().unwrap();
        for line in [
            &b"git-upload-pack '/demo.git'"[..],
            b"git-upload-pack 'demo.git'",
            b"git-upload-pack 'demo'",
        ] {
            assert_eq!(
                Command::parse(line),
                Some(Command::Lease(LeaseCommand::UploadPack {
                    repo: demo.clone()
                }))
            );
        }
        assert_eq!(
            Command::parse(b"git-receive-pack 'demo.git'"),
            Some(Command::Lease(LeaseCommand::ReceivePack { repo: demo }))
        );
        assert_eq!(
            Command::parse(b"writ-sign git demo"),
            Some(Command::Lease(LeaseCommand::Sign {
                repo: "demo".parse().unwrap(),
            }))
        );
        assert_eq!(
            Command::parse(b"writ ls --all"),
            Some(Command::Writ(writ_proto::Command::List { all: true }))
        );
    }

    #[test]
    fn refuses_everything_else() {
        for line in [
            &b"sh -c id"[..],
            b"git-upload-pack '/../etc.git'",
            b"git-upload-pack '/a/b.git'",
            b"git-upload-pack '/.git'",
            b"git-upload-pack /demo.git",
            b"git-upload-pack 'demo'\\''.git'",
            b"git-upload-pack ''",
            b"git-upload-pack '-demo.git'",
            b"git-upload-pack '//demo.git'",
            b"git-upload-pack 'demo.git.git'",
            b"git-upload-pack '.git'",
            b"git-upload-pack 'de mo.git'",
            b"writ-sign writ-approval demo",
            b"writ-sign git",
            b"writ-sign git ../demo",
            b"writ-sign git demo extra",
            b"writ-sign git 'demo'",
            b"writ-sign git -demo",
            b"writ ls -l",
            b"writ request extra",
            b"git-upload-pack",
            b"\xff\xfe",
        ] {
            assert_eq!(
                Command::parse(line),
                None,
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }
}
