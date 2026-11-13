# writ-platform

Everything that depends on the OS, the hardware or the deployment, behind small interfaces,
with the portable implementations.

## What it does

| Interface | Portable implementation |
|---|---|
| `Transport`: how clients reach the daemon | `transport::tcp::TcpTransport` |
| `CallerAttestor`: what the network or kernel says about the caller | `attest::network::NetworkAttestor` |
| `SessionWatcher`: a notice when a session's process ends | `watch::none::NoSessionWatcher` |
| `KeystoreUnwrap`: one way to unwrap a keystore file (the data key, a secret) | `unlock::passphrase::PassphraseUnwrap`, `unlock::x25519::X25519Unwrap` |
| `Notifier`: telling the approver something happened | `notify::telegram::TelegramNotifier` |
| `Clock`: what time it is | `clock::system::SystemClock` |
| `ProcessHardening`: no core dump, no debugger, memory out of swap | `harden::none::NoHardening` (refuses every step: Linux and macOS have theirs) |

Each interface is a module (the trait and its types); each implementation a file in it. Also:
`fs`, private files for the daemon (0700 directories, new 0600 files, a check that a secret
file isn't readable by others).

With the `testing` feature: a fake of each interface (`testing`) and the contract suite every
implementation must pass (`contract`).

## Scope

- Implementations that work on every platform the daemon runs on (macOS, Linux). macOS-only
  and Linux-only ones go in `writ-platform-macos` / `writ-platform-linux`, laid out the same way.
- A platform that can't provide a fact leaves it empty or says `Unsupported`; it never invents
  one. A notification is never an approval.
- `writd/src/platform.rs` picks the implementations; nothing else does.

## Depends on

`writ-core` (caller facts). Never on the core crates above it, and clients never depend on it.

## Docs

[Platform interfaces](../../docs/architecture/platform.md).
