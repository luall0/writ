//! What the transport says about a caller ([`CallerFacts`]), and the lease's caller constraint.
//!
//! Facts come from the network or the kernel through a `CallerAttestor`, never from the client.
//! A constraint that needs a fact the platform can't provide denies: a lease bound to a
//! process ancestor can never be used over TCP.

use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Facts about the caller of one request, gathered by the daemon.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerFacts {
    /// Network transports: the source address (advisory, never enforced in v1).
    pub source_addr: Option<IpAddr>,
    /// Local transports with a kernel-resolved ancestry, the caller first.
    pub process_chain: Option<Vec<ProcessRef>>,
}

/// One process in a caller's ancestry, as resolved by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    /// Distinguishes a reused pid (pidversion on macOS, start time on Linux).
    pub generation: u64,
    /// Resolved by the kernel, never from the process's own name or arguments.
    pub executable: PathBuf,
    pub code_identity: Option<CodeIdentity>,
    /// Why the executable's path doesn't name this process's program in the daemon's view,
    /// when it doesn't: on Linux, a process in another pid or mount namespace than the host's
    /// (a container, a sandbox), or whose executable was deleted. Such a process can't be a
    /// session's root (the binding is refused) and never matches a lease's process. `None`
    /// on the host, and on a platform without namespaces (macOS).
    pub unbindable: Option<String>,
}

/// The longest reason a [`ProcessRef::unbindable`] holds (an attestor's own words).
pub const MAX_UNBINDABLE_CHARS: usize = 256;

/// A code signature identity (macOS): the signing identifier and the team.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeIdentity {
    pub signing_id: String,
    pub team_id: Option<String>,
}

/// The caller constraint of a lease (`subject.caller`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerConstraint {
    /// The caller must have this process in its ancestry (itself included).
    pub descends_from: ProcessMatch,
}

/// A process the caller must descend from: every field must match.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMatch {
    /// Absolute executable path, compared exactly.
    pub executable: String,
    pub pid: u32,
    pub generation: u64,
    /// When set, the process's code identity must be exactly this one.
    pub code_identity: Option<CodeIdentity>,
}

/// Why a caller doesn't satisfy a constraint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallerError {
    #[error("this lease is bound to a process, but this connection gives no process chain")]
    NoProcessChain,
    #[error("the caller does not descend from {executable} (pid {pid}, generation {generation})")]
    NotDescendant {
        executable: String,
        pid: u32,
        generation: u64,
    },
    /// The constraint can't be honored as written: the reason.
    #[error("invalid caller constraint: {0}")]
    InvalidConstraint(&'static str),
}

/// The longest executable path a constraint may name.
pub const MAX_EXECUTABLE_BYTES: usize = 1024;
/// The longest code signing identifier (`com.example.agent`).
pub const MAX_SIGNING_ID_CHARS: usize = 255;
/// The longest team identifier (ten characters on Apple platforms).
pub const MAX_TEAM_ID_CHARS: usize = 64;

impl ProcessMatch {
    fn matches(&self, process: &ProcessRef) -> bool {
        // A process whose path doesn't name its program is never the one a lease names.
        process.unbindable.is_none()
            && process.pid == self.pid
            && process.generation == self.generation
            // Compared as written, byte for byte: `Path`'s comparison normalizes (`/usr//bin/`
            // equals `/usr/bin`), and a security check never compares loosely.
            && process.executable.to_str() == Some(self.executable.as_str())
            && match &self.code_identity {
                None => true,
                Some(required) => process.code_identity.as_ref() == Some(required),
            }
    }
}

impl CallerConstraint {
    /// The executable must be a normalized absolute path (no empty, `.` or `..` component,
    /// no trailing `/`) of at most [`MAX_EXECUTABLE_BYTES`], and every field shown to the
    /// approver is bounded and free of hidden characters (the agent writes it).
    pub fn validate(&self) -> Result<(), CallerError> {
        let invalid = CallerError::InvalidConstraint;
        let executable = &self.descends_from.executable;
        let Some(relative) = executable.strip_prefix('/') else {
            return Err(invalid("the executable must be an absolute path"));
        };
        if executable.len() > MAX_EXECUTABLE_BYTES {
            return Err(invalid("the executable path is too long"));
        }
        let normalized = !relative.is_empty()
            && relative
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if !normalized {
            return Err(invalid(
                "the executable path must be normalized (no //, ., .. or trailing /)",
            ));
        }
        let hidden = |text: &str| text.chars().any(crate::text::is_hidden_char);
        if hidden(executable) {
            return Err(invalid("the executable path holds hidden characters"));
        }
        if let Some(identity) = &self.descends_from.code_identity {
            if identity.signing_id.is_empty()
                || identity.signing_id.chars().count() > MAX_SIGNING_ID_CHARS
                || hidden(&identity.signing_id)
            {
                return Err(invalid(
                    "the signing id must be 1 to 255 characters, none hidden",
                ));
            }
            if let Some(team) = &identity.team_id
                && (team.is_empty() || team.chars().count() > MAX_TEAM_ID_CHARS || hidden(team))
            {
                return Err(invalid(
                    "the team id must be 1 to 64 characters, none hidden",
                ));
            }
        }
        Ok(())
    }
}

/// Checks the facts against a lease's caller constraint. No constraint: any caller holding
/// the certificate. Missing or empty process chain with a constraint: denied.
pub fn check(
    constraint: Option<&CallerConstraint>,
    facts: &CallerFacts,
) -> Result<(), CallerError> {
    let Some(constraint) = constraint else {
        return Ok(());
    };
    constraint.validate()?;
    let chain = match &facts.process_chain {
        Some(chain) if !chain.is_empty() => chain,
        _ => return Err(CallerError::NoProcessChain),
    };
    if chain.iter().any(|p| constraint.descends_from.matches(p)) {
        Ok(())
    } else {
        let m = &constraint.descends_from;
        Err(CallerError::NotDescendant {
            executable: m.executable.clone(),
            pid: m.pid,
            generation: m.generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint(executable: &str) -> CallerConstraint {
        CallerConstraint {
            descends_from: ProcessMatch {
                executable: executable.to_owned(),
                pid: 10,
                generation: 1,
                code_identity: None,
            },
        }
    }

    fn reason(c: &CallerConstraint) -> &'static str {
        match c.validate() {
            Err(CallerError::InvalidConstraint(why)) => why,
            other => panic!("expected an invalid constraint, got {other:?}"),
        }
    }

    #[test]
    fn the_executable_is_a_normalized_bounded_path() {
        assert_eq!(constraint("/usr/local/bin/agent").validate(), Ok(()));
        for (path, why) in [
            ("agent", "the executable must be an absolute path"),
            ("/", "must be normalized"),
            ("/usr//bin/agent", "must be normalized"),
            ("/usr/./bin/agent", "must be normalized"),
            ("/usr/bin/../agent", "must be normalized"),
            ("/usr/bin/agent/", "must be normalized"),
            ("/usr/bin/age\u{202e}nt", "hidden characters"),
            ("/usr/bin/agent\u{e0041}", "hidden characters"),
        ] {
            assert!(reason(&constraint(path)).contains(why), "{path:?}");
        }
        // The length limit, both sides.
        let at = format!("/{}", "a".repeat(MAX_EXECUTABLE_BYTES - 1));
        assert_eq!(constraint(&at).validate(), Ok(()));
        let over = format!("/{}", "a".repeat(MAX_EXECUTABLE_BYTES));
        assert_eq!(
            reason(&constraint(&over)),
            "the executable path is too long"
        );
    }

    #[test]
    fn code_identities_are_bounded() {
        let with = |signing_id: &str, team_id: Option<&str>| {
            let mut c = constraint("/usr/bin/agent");
            c.descends_from.code_identity = Some(CodeIdentity {
                signing_id: signing_id.to_owned(),
                team_id: team_id.map(str::to_owned),
            });
            c
        };
        assert_eq!(
            with("com.example.agent", Some("ABCDE12345")).validate(),
            Ok(())
        );
        assert_eq!(
            with(&"s".repeat(MAX_SIGNING_ID_CHARS), None).validate(),
            Ok(())
        );
        for c in [
            with("", None),
            with(&"s".repeat(MAX_SIGNING_ID_CHARS + 1), None),
            with("com.\u{200b}example", None),
        ] {
            assert!(reason(&c).starts_with("the signing id"), "{c:?}");
        }
        for c in [
            with("x", Some("")),
            with("x", Some(&"t".repeat(MAX_TEAM_ID_CHARS + 1))),
            with("x", Some("T\u{202e}")),
        ] {
            assert!(reason(&c).starts_with("the team id"), "{c:?}");
        }
        assert_eq!(
            with("x", Some(&"t".repeat(MAX_TEAM_ID_CHARS))).validate(),
            Ok(())
        );
    }

    #[test]
    fn the_executable_is_compared_as_written() {
        let process = |executable: &str| ProcessRef {
            pid: 10,
            generation: 1,
            executable: PathBuf::from(executable),
            code_identity: None,
            unbindable: None,
        };
        let c = constraint("/usr/bin/agent");
        let facts = |executable: &str| CallerFacts {
            source_addr: None,
            process_chain: Some(vec![process(executable)]),
        };
        assert_eq!(check(Some(&c), &facts("/usr/bin/agent")), Ok(()));
        // A process whose path doesn't name its program never matches, even by every field.
        let mut elsewhere = process("/usr/bin/agent");
        elsewhere.unbindable = Some("in another mount namespace".to_owned());
        let facts_elsewhere = CallerFacts {
            source_addr: None,
            process_chain: Some(vec![elsewhere]),
        };
        assert!(matches!(
            check(Some(&c), &facts_elsewhere),
            Err(CallerError::NotDescendant { .. })
        ));
        // `Path` would call these equal; the check doesn't.
        for other in ["/usr//bin/agent", "/usr/bin/./agent", "/usr/bin/agent/"] {
            assert!(
                matches!(
                    check(Some(&c), &facts(other)),
                    Err(CallerError::NotDescendant { .. })
                ),
                "{other}"
            );
        }
    }
}
