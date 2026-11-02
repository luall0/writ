//! The stack, set up once per run ([`crate::setup::run`], on the first scenario's first use),
//! then used by every scenario: [`Stack::shared`] by most, side by side;
//! [`Stack::exclusive`] by those that stop, restart or change a container (Forgejo stopped,
//! its host key changed, the daemon restarted), which wait for the others to finish and hold
//! the stack alone, and leave it working.
//!
//! A setup that fails fails every scenario with its reason, instead of each trying again on
//! a half-made stack.

use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde_json::Value;

use crate::docker::Host;
use crate::forgejo::Forgejo;
use crate::setup::Report;

/// The stack, ready: the daemon's host (its operator), the approver, the agents' host,
/// Forgejo, and what the setup saw.
pub struct Stack {
    /// The operator on the daemon's host, in the daemon's directory (`/home/writ`).
    pub operator: Host,
    /// The approver's machine, with its `WRIT_*` settings (HTTPS approval API by default).
    pub approver: Host,
    /// The agents' host, in its home: each scenario makes its own agent there
    /// ([`Stack::agent`](crate::agent)).
    pub agents_home: Host,
    pub forgejo: Forgejo,
    pub report: Report,
}

static STACK: OnceLock<Result<Stack, String>> = OnceLock::new();
static USE: RwLock<()> = RwLock::new(());

/// The stack while a scenario uses it: shared or alone.
pub enum Held {
    Shared(RwLockReadGuard<'static, ()>),
    Alone(RwLockWriteGuard<'static, ()>),
}

/// The stack, held for one scenario.
pub struct InUse {
    _held: Held,
    stack: &'static Stack,
}

impl std::ops::Deref for InUse {
    type Target = Stack;

    fn deref(&self) -> &Stack {
        self.stack
    }
}

fn ready() -> &'static Stack {
    let stack = STACK.get_or_init(|| {
        std::panic::catch_unwind(crate::setup::run).map_err(|panic| {
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "the setup panicked".to_owned())
        })
    });
    match stack {
        Ok(stack) => stack,
        Err(why) => panic!("the operator setup failed, so no scenario can run:\n{why}"),
    }
}

impl Stack {
    /// The stack, beside the other scenarios that share it.
    pub fn shared() -> InUse {
        // A scenario that failed while holding the lock doesn't make the stack unusable:
        // each scenario leaves it working, or fails with its own reason.
        let held = USE
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        InUse {
            _held: Held::Shared(held),
            stack: ready(),
        }
    }

    /// The stack alone: no other scenario runs until this one ends.
    pub fn exclusive() -> InUse {
        let held = USE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        InUse {
            _held: Held::Alone(held),
            stack: ready(),
        }
    }

    /// Every line of the daemon's audit log, parsed.
    pub fn audit(&self) -> Vec<Value> {
        self.operator
            .read("data/audit.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The audit lines with this event and result about `lease` (as the lease, or the ticket).
    pub fn audited(&self, lease: &str, event: &str, result: &str) -> Vec<Value> {
        self.audit()
            .into_iter()
            .filter(|e| e["event"] == event && e["result"] == result)
            .filter(|e| e["lease"] == lease || e["ticket"] == lease)
            .collect()
    }

    /// Where a ref of the daemon's mirror of `repo` points, if it exists.
    pub fn mirror_ref(&self, repo: &str, name: &str) -> Option<String> {
        let out = self.operator.run(&format!(
            "git -C data/repos/{repo}.git rev-parse --verify -q '{name}^{{commit}}'"
        ));
        (out.status.code() == Some(0)).then(|| crate::stdout(&out).trim().to_owned())
    }

    /// Whether the daemon's mirror of `repo` holds the object `sha` at all.
    pub fn mirror_has(&self, repo: &str, sha: &str) -> bool {
        let out = self
            .operator
            .run(&format!("git -C data/repos/{repo}.git cat-file -e '{sha}'"));
        out.status.code() == Some(0)
    }
}
