//! [`ProcessChain`]: local mode's attestor on Linux (`attestor: linux_process_chain`). A Unix
//! socket's caller is the pid and start time its peer reader took at connect
//! ([`crate::peer::pidfd_peer`]); its ancestry is each parent `/proc` gives, read one process
//! at a time by a [`ReadProcess`] (the capped helper in the daemon), each read while a pidfd
//! showed it running. A TCP caller gets its source address and no chain.
//!
//! - **The caller** read again with another start time than its peer's is refused: its pid
//!   is another process's now.
//! - **A parent** is linked when it started no later than its child: a pid reused by a later
//!   process breaks the link, and the chain ends there. A parent gone, or one this reader
//!   can't read (another user's, to a reader without `CAP_SYS_PTRACE`), ends it too: a lease
//!   bound to a process past the end is refused, never matched against another one.
//! - **The namespaces:** pids and paths are the daemon's view (the kernel translates them), so
//!   the chain runs through a sandbox as through anything else. A process in another pid or
//!   mount namespace than the host's, or whose executable was deleted, has a path that doesn't
//!   name its program in that view: it is marked `unbindable`, so it is never a session's
//!   root, nor matched as a lease's process.
//! - Linux has no code signature: no process carries a code identity.

use std::sync::Arc;

use writ_core::caller::{CallerFacts, MAX_UNBINDABLE_CHARS, ProcessRef};
use writ_platform::{CallerAttestor, PeerInfo, PlatformError, Result};

use crate::procfs::{Namespaces, ReadError};
use crate::read::{Entry, ReadProcess};

/// The most processes a chain holds, the caller first: deeper ancestors are left out (a
/// lease bound to one is refused).
pub const MAX_CHAIN: usize = 64;

/// Local mode's attestor on Linux.
pub struct ProcessChain {
    reader: Arc<dyn ReadProcess>,
    host: Namespaces,
}

impl std::fmt::Debug for ProcessChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessChain")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl ProcessChain {
    /// An attestor reading through `reader`, the host's namespaces read once now.
    pub fn new(reader: Arc<dyn ReadProcess>) -> Result<Self> {
        let host = reader.host().map_err(|e| {
            PlatformError::Attestation(format!("the host's namespaces can't be read: {e}"))
        })?;
        Ok(Self { reader, host })
    }

    /// The process running as `pid` now, as a chain would hold it.
    pub fn current(&self, pid: u32) -> Result<ProcessRef> {
        self.reader
            .read(pid)
            .map(|entry| self.process(&entry))
            .map_err(|e| PlatformError::Attestation(e.to_string()))
    }

    /// The caller and its ancestry, the caller first.
    fn chain(&self, pid: u32, generation: u64) -> Result<Vec<ProcessRef>> {
        let caller = self
            .reader
            .read(pid)
            .map_err(|e| PlatformError::Attestation(format!("the caller: {e}")))?;
        if caller.start != generation {
            return Err(PlatformError::Attestation(format!(
                "the caller: pid {pid} is another process now"
            )));
        }
        let mut chain = vec![self.process(&caller)];
        let mut child = caller;
        while child.ppid != 0 && chain.len() < MAX_CHAIN {
            match self.reader.read(child.ppid) {
                Ok(parent) if parent.start <= child.start => {
                    chain.push(self.process(&parent));
                    child = parent;
                }
                // Started after its child: not the parent that made it, the pid reused.
                Ok(_) | Err(ReadError::Gone(_)) => break,
                Err(ReadError::Unreadable(why)) => {
                    tracing::debug!(%why, "the caller's chain ends at an ancestor it can't read");
                    break;
                }
            }
        }
        Ok(chain)
    }

    fn process(&self, entry: &Entry) -> ProcessRef {
        ProcessRef {
            pid: entry.pid,
            generation: entry.start,
            executable: entry.executable.clone(),
            code_identity: None,
            unbindable: unbindable(entry, self.host),
        }
    }
}

/// Why `entry`'s path doesn't name its program in the host's view, if it doesn't.
pub fn unbindable(entry: &Entry, host: Namespaces) -> Option<String> {
    let mut why = Vec::new();
    if entry.namespaces.pid != host.pid {
        why.push(format!(
            "in another pid namespace than the host's (pid:[{}])",
            entry.namespaces.pid
        ));
    }
    if entry.namespaces.mnt != host.mnt {
        why.push(format!(
            "in another mount namespace than the host's (mnt:[{}])",
            entry.namespaces.mnt
        ));
    }
    if entry.deleted {
        why.push("its executable was deleted".to_owned());
    }
    (!why.is_empty()).then(|| writ_core::text::shown(&why.join("; "), MAX_UNBINDABLE_CHARS))
}

impl CallerAttestor for ProcessChain {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts> {
        match peer {
            PeerInfo::Tcp { remote } => Ok(CallerFacts {
                source_addr: Some(remote.ip()),
                process_chain: None,
            }),
            PeerInfo::Unix {
                pid: Some(pid),
                generation: Some(generation),
                ..
            } => Ok(CallerFacts {
                source_addr: None,
                process_chain: Some(self.chain(*pid, *generation)?),
            }),
            PeerInfo::Unix { .. } => Err(PlatformError::Attestation(
                "a Unix peer without its pid and start time (its pidfd wasn't read)".to_owned(),
            )),
            _ => Err(PlatformError::Attestation(
                "the Linux process chain attestor attests Unix socket and TCP peers only"
                    .to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;

    const HOST: Namespaces = Namespaces { pid: 10, mnt: 20 };

    /// A process table the tests write: what `/proc` would say, or why it wouldn't.
    #[derive(Default)]
    struct Table(Mutex<HashMap<u32, std::result::Result<Entry, ReadError>>>);

    impl Table {
        fn put(&self, pid: u32, ppid: u32, start: u64, exe: &str) {
            self.0.lock().unwrap().insert(
                pid,
                Ok(Entry {
                    pid,
                    ppid,
                    start,
                    executable: PathBuf::from(exe),
                    deleted: false,
                    namespaces: HOST,
                }),
            );
        }
        fn edit(&self, pid: u32, f: impl FnOnce(&mut Entry)) {
            if let Some(Ok(entry)) = self.0.lock().unwrap().get_mut(&pid) {
                f(entry);
            }
        }
        fn fail(&self, pid: u32, error: ReadError) {
            self.0.lock().unwrap().insert(pid, Err(error));
        }
    }

    impl ReadProcess for Table {
        fn read(&self, pid: u32) -> std::result::Result<Entry, ReadError> {
            self.0
                .lock()
                .unwrap()
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| Err(ReadError::Gone(format!("pid {pid}: gone"))))
        }
        fn host(&self) -> std::result::Result<Namespaces, ReadError> {
            Ok(HOST)
        }
    }

    /// A session: pid 1, a shell, `writ run`, a harness, git (the caller).
    fn session() -> Arc<Table> {
        let table = Arc::new(Table::default());
        table.put(1, 0, 1, "/usr/lib/systemd/systemd");
        table.put(100, 1, 50, "/usr/bin/bash");
        table.put(200, 100, 60, "/usr/local/bin/writ");
        table.put(300, 200, 70, "/usr/bin/node");
        table.put(400, 300, 80, "/usr/bin/git");
        table
    }

    fn unix(pid: u32, generation: u64) -> PeerInfo {
        PeerInfo::Unix {
            uid: 1000,
            gid: 1000,
            pid: Some(pid),
            generation: Some(generation),
        }
    }

    fn pids(facts: &CallerFacts) -> Vec<u32> {
        facts
            .process_chain
            .as_ref()
            .unwrap()
            .iter()
            .map(|p| p.pid)
            .collect()
    }

    fn refusal(attestor: &ProcessChain, peer: &PeerInfo) -> String {
        match attestor.attest(peer) {
            Err(PlatformError::Attestation(why)) => why,
            other => panic!("expected an attestation error, got {other:?}"),
        }
    }

    #[test]
    fn the_chain_runs_from_the_caller_to_pid_1() {
        let attestor = ProcessChain::new(session()).unwrap();
        let facts = attestor.attest(&unix(400, 80)).unwrap();
        assert_eq!(pids(&facts), [400, 300, 200, 100, 1]);
        let chain = facts.process_chain.unwrap();
        assert_eq!(chain[2].executable, PathBuf::from("/usr/local/bin/writ"));
        assert!(
            chain
                .iter()
                .all(|p| p.code_identity.is_none() && p.unbindable.is_none())
        );
        assert_eq!((chain[0].generation, chain[4].generation), (80, 1));
    }

    #[test]
    fn a_caller_whose_pid_was_reused_is_refused() {
        let attestor = ProcessChain::new(session()).unwrap();
        assert_eq!(
            refusal(&attestor, &unix(400, 79)),
            "the caller: pid 400 is another process now"
        );
        assert_eq!(
            refusal(&attestor, &unix(999, 1)),
            "the caller: pid 999: gone"
        );
    }

    #[test]
    fn a_parent_reused_or_gone_ends_the_chain_there() {
        let table = session();
        // The harness ended and its pid went to a later process: the link breaks.
        table.put(300, 1, 90, "/usr/bin/sleep");
        let attestor = ProcessChain::new(table.clone()).unwrap();
        assert_eq!(pids(&attestor.attest(&unix(400, 80)).unwrap()), [400]);
        // Started in the same tick as its child: still its parent.
        table.put(300, 200, 80, "/usr/bin/node");
        assert_eq!(
            pids(&attestor.attest(&unix(400, 80)).unwrap()),
            [400, 300, 200, 100, 1]
        );
        table.fail(
            200,
            ReadError::Gone("pid 200 ended while it was read".to_owned()),
        );
        assert_eq!(pids(&attestor.attest(&unix(400, 80)).unwrap()), [400, 300]);
    }

    #[test]
    fn a_parent_that_can_t_be_read_ends_the_chain_and_a_caller_that_can_t_is_refused() {
        let table = session();
        let denied = |pid: u32| {
            ReadError::Unreadable(format!("pid {pid}: its executable: Permission denied"))
        };
        table.fail(100, denied(100));
        let attestor = ProcessChain::new(table.clone()).unwrap();
        assert_eq!(
            pids(&attestor.attest(&unix(400, 80)).unwrap()),
            [400, 300, 200]
        );
        table.fail(400, denied(400));
        assert_eq!(
            refusal(&attestor, &unix(400, 80)),
            "the caller: pid 400: its executable: Permission denied"
        );
    }

    #[test]
    fn a_chain_holds_at_most_its_bound() {
        let table = Arc::new(Table::default());
        let deepest = u32::try_from(MAX_CHAIN).unwrap() + 10;
        for pid in 1..=deepest {
            table.put(pid, pid - 1, u64::from(pid), "/usr/bin/sh");
        }
        let attestor = ProcessChain::new(table).unwrap();
        let facts = attestor.attest(&unix(deepest, u64::from(deepest))).unwrap();
        assert_eq!(facts.process_chain.unwrap().len(), MAX_CHAIN);
        let at = u32::try_from(MAX_CHAIN).unwrap();
        let facts = attestor.attest(&unix(at, u64::from(at))).unwrap();
        assert_eq!(facts.process_chain.unwrap().len(), MAX_CHAIN);
    }

    #[test]
    fn a_sandboxed_or_deleted_process_is_walked_and_marked_unbindable() {
        let table = session();
        table.edit(400, |git| git.namespaces = Namespaces { pid: 11, mnt: 21 });
        table.edit(300, |node| node.deleted = true);
        let attestor = ProcessChain::new(table).unwrap();
        let chain = attestor
            .attest(&unix(400, 80))
            .unwrap()
            .process_chain
            .unwrap();
        assert_eq!(chain.len(), 5);
        assert_eq!(
            chain[0].unbindable.as_deref(),
            Some(
                "in another pid namespace than the host's (pid:[11]); in another mount \
                 namespace than the host's (mnt:[21])"
            )
        );
        assert_eq!(
            chain[1].unbindable.as_deref(),
            Some("its executable was deleted")
        );
        assert_eq!(chain[2].unbindable, None);
        let only_mount = Entry {
            namespaces: Namespaces { pid: 10, mnt: 22 },
            ..attestor.reader.read(100).unwrap()
        };
        assert_eq!(
            unbindable(&only_mount, HOST).as_deref(),
            Some("in another mount namespace than the host's (mnt:[22])")
        );
    }

    #[test]
    fn a_peer_without_its_start_time_or_of_another_kind_is_refused() {
        let attestor = ProcessChain::new(session()).unwrap();
        let no_generation = PeerInfo::Unix {
            uid: 1000,
            gid: 1000,
            pid: Some(400),
            generation: None,
        };
        assert_eq!(
            refusal(&attestor, &no_generation),
            "a Unix peer without its pid and start time (its pidfd wasn't read)"
        );
        let memory = PeerInfo::Memory {
            label: "test".to_owned(),
        };
        assert_eq!(
            refusal(&attestor, &memory),
            "the Linux process chain attestor attests Unix socket and TCP peers only"
        );
    }
}
