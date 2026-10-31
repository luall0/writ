//! Commands a client may run through the gateway. Anything else is refused. Which identity
//! may run which command is decided by the connection handler.

use writ_core::names::RepoName;

/// A parsed exec request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `git-upload-pack '<repo>.git'`: fetch.
    UploadPack { repo: RepoName },
    /// `git-receive-pack '<repo>.git'`: push.
    ReceivePack { repo: RepoName },
    /// `writ-sign <namespace>`: sign the object sent on stdin.
    Sign { namespace: String },
    /// `writ …`: a lease or approval command (`writ_proto::Command`).
    Writ(writ_proto::Command),
}

impl Command {
    /// Parses the command line of an SSH exec request.
    pub fn parse(line: &[u8]) -> Option<Self> {
        let line = std::str::from_utf8(line).ok()?;
        if line.starts_with("writ ") {
            return writ_proto::Command::parse(line).map(Self::Writ);
        }
        let (program, arg) = line.split_once(' ')?;
        match program {
            "git-upload-pack" => Some(Self::UploadPack {
                repo: repo_name(unquote(arg)?)?,
            }),
            "git-receive-pack" => Some(Self::ReceivePack {
                repo: repo_name(unquote(arg)?)?,
            }),
            "writ-sign" if arg == "git" => Some(Self::Sign {
                namespace: arg.to_owned(),
            }),
            _ => None,
        }
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
                Some(Command::UploadPack { repo: demo.clone() })
            );
        }
        assert_eq!(
            Command::parse(b"git-receive-pack 'demo.git'"),
            Some(Command::ReceivePack { repo: demo })
        );
        assert_eq!(
            Command::parse(b"writ-sign git"),
            Some(Command::Sign {
                namespace: "git".into()
            })
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
            b"writ-sign writ-approval",
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
