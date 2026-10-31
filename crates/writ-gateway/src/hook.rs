//! git's pre-receive hook, called back into the daemon.
//!
//! `git receive-pack` stores the pushed objects in a quarantine and runs the pre-receive
//! hook with the ref updates before anything is visible. The hook ([`client`], run by git in
//! its own process) only forwards them, with the push's token, to the daemon over a private
//! Unix socket; the daemon ([`server`]) decides. Git deletes the quarantine when the hook
//! refuses.
//!
//! The exchange: the hook sends `<token>\n` then git's ref update lines, each ending in `\n`,
//! and closes its side; the daemon answers `ok\n` or `deny <reason>\n`. Anything the daemon
//! can't read whole (over [`MAX_HOOK_INPUT`], cut short, not UTF-8) is denied.

mod client;
mod server;

pub use client::run_pre_receive;
pub(crate) use server::serve;

use std::collections::BTreeSet;

use writ_core::caller::CallerFacts;
use writ_core::names::RepoName;
use writ_core::pattern::{RefName, RefPattern};
use writ_core::policy::CertIdentity;

/// The most the daemon reads from a hook: the token line and every ref update line.
pub(crate) const MAX_HOOK_INPUT: usize = 1 << 20;

/// What the daemon knows about a push in progress.
#[derive(Debug, Clone)]
pub(crate) struct PushContext {
    /// The session certificate the push came with (its key id is the lease).
    pub cert: CertIdentity,
    pub repo: RepoName,
    pub caller: CallerFacts,
}

/// One line of the pre-receive input: `<old> <new> <ref>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: RefName,
}

impl RefUpdate {
    /// Parses one line; `None` if it isn't exactly two object ids and a valid ref name.
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split(' ');
        let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
        let is_oid =
            |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
        if parts.next().is_some() || !is_oid(old) || !is_oid(new) {
            return None;
        }
        Some(Self {
            old: old.to_owned(),
            new: new.to_owned(),
            name: name.parse().ok()?,
        })
    }
}

/// The M0 push check, until M4's: no update may touch one of the repo's protected refs.
pub(crate) fn check_ref_updates(
    updates: &[RefUpdate],
    protected: &BTreeSet<RefPattern>,
) -> Result<(), String> {
    match updates
        .iter()
        .find(|u| protected.iter().any(|p| p.protects(&u.name)))
    {
        Some(update) => Err(format!("{} is protected", update.name)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    fn update(name: &str) -> RefUpdate {
        RefUpdate {
            old: A.into(),
            new: B.into(),
            name: name.parse().unwrap(),
        }
    }

    #[test]
    fn parses_ref_updates() {
        assert_eq!(
            RefUpdate::parse(&format!("{A} {B} refs/heads/agent/x")),
            Some(update("refs/heads/agent/x"))
        );
        let sha256 = "a".repeat(64);
        assert!(RefUpdate::parse(&format!("{sha256} {sha256} refs/heads/x")).is_some());
        for bad in [
            format!("{A} {B} HEAD"),
            format!("{A} zz refs/heads/x"),
            format!("{A} {B} refs/heads/x extra"),
            format!("{A} {B} refs/heads/a..b"),
            format!("{A} {B} refs/heads/x "),
            format!("{A}  {B} refs/heads/x"),
            format!("{} {B} refs/heads/x", &A[..39]),
            format!("{A} {B}"),
            String::new(),
        ] {
            assert_eq!(RefUpdate::parse(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn protected_refs_are_refused() {
        let protected: BTreeSet<RefPattern> = ["refs/heads/main", "refs/tags/*"]
            .iter()
            .map(|p| p.parse().unwrap())
            .collect();
        let check = |names: &[&str]| {
            let updates: Vec<RefUpdate> = names.iter().map(|n| update(n)).collect();
            check_ref_updates(&updates, &protected)
        };
        assert_eq!(check(&["refs/heads/agent/x"]), Ok(()));
        assert_eq!(check(&[]), Ok(()));
        assert_eq!(
            check(&["refs/heads/main"]),
            Err("refs/heads/main is protected".into())
        );
        assert_eq!(
            check(&["refs/tags/v1"]),
            Err("refs/tags/v1 is protected".into())
        );
        // One protected update among others denies the whole push.
        assert_eq!(
            check(&["refs/heads/agent/x", "refs/heads/main"]),
            Err("refs/heads/main is protected".into())
        );
        // Exact patterns match exactly, but never by case alone: on APFS `MAIN` is `main`.
        assert_eq!(check(&["refs/heads/mainline", "refs/heads/main/x"]), Ok(()));
        for name in ["refs/heads/Main", "refs/heads/MAIN", "refs/TAGS/v1"] {
            assert_eq!(check(&[name]), Err(format!("{name} is protected")));
        }
        assert_eq!(
            check_ref_updates(&[update("refs/heads/main")], &BTreeSet::new()),
            Ok(())
        );
    }
}
