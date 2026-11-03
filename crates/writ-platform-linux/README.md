# writ-platform-linux

Linux-only implementations of the platform interfaces (`writ-platform`'s traits). On another
OS the crate is empty; `writd/src/platform.rs` picks it on Linux.

## What it does

| Interface | Implementation |
|---|---|
| `ProcessHardening` | `hardening::Hardening`: `RLIMIT_CORE` 0 and not dumpable (required), `mlockall(MCL_CURRENT \| MCL_FUTURE \| MCL_ONFAULT)` when the lock limit is unlimited or with `CAP_IPC_LOCK` (otherwise a warning naming the fix) |

Through `rustix`: no `unsafe`. Each implementation runs its interface's contract suite
(`writ_platform::contract`), in a test binary of its own when it changes the process.

## Scope

- Only per-process calls: never a setting of the whole system (docs/operators/hardening.md).
- Later: the `SO_PEERCRED` + `/proc` attestor, a pidfd session watcher, a TPM.
