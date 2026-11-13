# writ-platform-macos

macOS-only implementations of the platform interfaces (`writ-platform`'s traits). On another
OS the crate is empty; `writd/src/platform.rs` picks it on macOS.

## What it does

| Interface | Implementation |
|---|---|
| `ProcessHardening` | `hardening::Hardening`: `RLIMIT_CORE` 0 and `PT_DENY_ATTACH` (required; a traced process is refused in a release build, skipped with a warning in a debug one, never killed); memory locking unavailable (an info line) |

The calls `rustix` doesn't wrap (`ptrace`, `proc_pidinfo`) are in `sys`, the crate's one
`unsafe` module, each with its `SAFETY` comment. Each implementation runs its interface's
contract suite (`writ_platform::contract`), in a test binary of its own when it changes the
process.

## Scope

- Only per-process calls: never a setting of the whole system (docs/operators/hardening.md).
- Later (M7, M7.5): the process chain attestor, the kqueue session watcher, the Secure
  Enclave `Signer`, and (M7.6) the Secure Enclave's `KeystoreUnwrap`.
