//! The daemon's capabilities (docs/architecture/platform.md): the one it may start with,
//! `CAP_SYS_PTRACE`, is for the process reader alone. `writd run` starts the helper while it
//! holds it, then drops every capability before it reads a secret; the helper keeps that one
//! and drops the rest.

use rustix::thread::{CapabilitySet, CapabilitySets, capabilities, set_capabilities};

/// Whether this process may read every process's `/proc` (`CAP_SYS_PTRACE` permitted), and
/// a program it starts inherits it (in its ambient set, as systemd's `AmbientCapabilities`
/// puts it, or as root).
pub fn passes_ptrace_on() -> std::io::Result<bool> {
    let sets = capabilities(None)?;
    if !sets.permitted.contains(CapabilitySet::SYS_PTRACE) {
        return Ok(false);
    }
    let ambient = rustix::thread::capability_is_in_ambient_set(CapabilitySet::SYS_PTRACE)?;
    Ok(ambient || rustix::process::geteuid().is_root())
}

/// Whether this process holds any capability at all, in any set.
pub fn holds_any() -> std::io::Result<bool> {
    let sets = capabilities(None)?;
    Ok(!(sets.effective.is_empty() && sets.permitted.is_empty() && sets.inheritable.is_empty()))
}

/// Drops every capability: the ambient set, then the effective, permitted and inheritable
/// ones (a capability dropped from the permitted set can't be taken back), and checks.
pub fn drop_all() -> std::io::Result<()> {
    keep(CapabilitySet::empty())
}

/// Keeps `CAP_SYS_PTRACE` alone (the helper), effective and permitted, nothing inheritable.
pub fn keep_ptrace_only() -> std::io::Result<()> {
    keep(CapabilitySet::SYS_PTRACE)
}

fn keep(only: CapabilitySet) -> std::io::Result<()> {
    rustix::thread::clear_ambient_capability_set()?;
    set_capabilities(
        None,
        CapabilitySets {
            effective: only,
            permitted: only,
            inheritable: CapabilitySet::empty(),
        },
    )?;
    let now = capabilities(None)?;
    if now.effective != only || now.permitted != only || !now.inheritable.is_empty() {
        return Err(std::io::Error::other(format!(
            "the capabilities are {now:?} after keeping only {only:?}"
        )));
    }
    Ok(())
}
