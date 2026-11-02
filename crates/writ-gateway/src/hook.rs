//! git's pre-receive hook, called back into the daemon.
//!
//! `git receive-pack` stores the pushed objects in a quarantine and runs the pre-receive
//! hook with the ref updates before anything is visible. The hook ([`client`], run by git in
//! its own process) only forwards them, with the push's token, to the daemon over a private
//! Unix socket; the daemon ([`server`]) decides. Git deletes the quarantine when the hook
//! refuses.
//!
//! The exchange: the hook sends `<token>\n`, the quarantine git made for the push
//! (`GIT_QUARANTINE_PATH`, an empty line when the push sent no pack) and `\n`, then git's ref
//! update lines, each ending in `\n`, and closes its side; the daemon answers `ok\n` or
//! `deny <reason>\n`. Anything the daemon can't read whole (over [`MAX_HOOK_INPUT`], cut short,
//! not UTF-8) is denied. The quarantine path is believed only if it is one of the mirror's
//! (`writ_mirror::quarantine`).

mod client;
mod server;

pub use client::run_pre_receive;
pub(crate) use server::serve;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use writ_core::caller::CallerFacts;
use writ_core::names::RepoName;
use writ_core::pattern::RefName;
use writ_core::policy::CertIdentity;

/// The most the daemon reads from a hook: the token line and every ref update line.
pub(crate) const MAX_HOOK_INPUT: usize = 1 << 20;

/// The most ref updates one push may carry.
pub(crate) const MAX_UPDATES: usize = 1_000;

/// How long a push may keep its mirror once its hook said yes. receive-pack moves the refs at
/// once, then reports to the client: a client that doesn't read a report larger than the pipe
/// keeps receive-pack from exiting, so past this the mirror is released anyway. The refs
/// moved long before; one that hasn't is checked against its old value when it does, and
/// fails rather than moving past what the decision saw (upstream's `--force-with-lease`
/// checked it there too).
pub(crate) const REF_UPDATE_GRACE: Duration = Duration::from_secs(10);

/// Drops what `held` holds once `grace` has passed, if it still holds anything (a push's
/// mirror is released at receive-pack's exit, whichever comes first).
pub(crate) fn release_after<T: Send + 'static>(held: Arc<Mutex<Option<T>>>, grace: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        // Released even from a poisoned lock: a held mirror stops every other push and sync.
        held.lock().unwrap_or_else(PoisonError::into_inner).take();
    });
}

/// What the daemon knows about a push in progress.
#[derive(Clone)]
pub(crate) struct PushContext {
    /// The session certificate the push came with (its key id is the lease).
    pub cert: CertIdentity,
    pub repo: RepoName,
    pub caller: CallerFacts,
    /// The connection the push came on (the gateway's number for it).
    pub connection: u64,
    /// The repo's mirror, held from the hook's decision until `receive-pack` has moved the
    /// refs and exited: no sync or other push changes it in between.
    pub held: Arc<Mutex<Option<writ_mirror::MirrorGuard>>>,
    /// Set once the hook reached the push (then it logs the outcome): a push git refused
    /// before its hook ran (a pack too large, an object `fsck` refuses) is logged by the gateway.
    pub decided: Arc<std::sync::atomic::AtomicBool>,
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
            format!("{} {B} refs/heads/x", A.get(..39).unwrap()),
            format!("{A} {B}"),
            String::new(),
        ] {
            assert_eq!(RefUpdate::parse(&bad), None, "{bad:?}");
        }
    }

    /// Sets a flag when dropped: what a mirror guard is to the grace.
    struct Guard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_decided_push_keeps_its_mirror_for_the_grace_and_no_longer() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = Arc::new(Mutex::new(Some(Guard(dropped.clone()))));
        release_after(held.clone(), REF_UPDATE_GRACE);
        let released = || dropped.load(std::sync::atomic::Ordering::Acquire);
        tokio::task::yield_now().await;
        tokio::time::advance(REF_UPDATE_GRACE - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!released(), "held just before the grace ends");
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(released(), "released when it ends");
        assert!(held.lock().unwrap().is_none());

        // Released at receive-pack's exit first: the grace finds the slot empty.
        let held = Arc::new(Mutex::new(Some(Guard(Arc::default()))));
        release_after(held.clone(), REF_UPDATE_GRACE);
        held.lock().unwrap().take();
        tokio::time::advance(REF_UPDATE_GRACE).await;
        tokio::task::yield_now().await;
        assert!(held.lock().unwrap().is_none());
    }
}
