# Platform interfaces

The daemon core is platform-agnostic. Everything that depends on the OS, the hardware or the
deployment sits behind a small interface, with implementations chosen at startup. A
**deployment mode is a configuration, not a code path**: detached and local mode run the same
core with different implementations plugged in ([Q30](../decisions.md)).

Adding a platform feature (the Mac's Secure Enclave, a Unix socket with process chain checks,
a YubiKey) means writing an implementation of an existing interface and registering it in
`writd`'s wiring. Nothing in the policy, the gateway, the store or the clients changes.

## The interfaces

| Interface | What it abstracts | v1 implementations | Later |
|---|---|---|---|
| `Signer` | Where keys live and how they sign ([signer.md](signer.md)) | Software (age keystore) | YubiKey PIV, TPM, Secure Enclave, ssh-agent |
| `Transport` | How clients reach the daemon; every transport carries the same SSH protocol | TCP (SSH gateway); Unix socket (local mode) | — |
| `CallerAttestor` | What the network or the kernel says about the caller, as `CallerFacts` | Network (source address); macOS process chain (local mode) | Linux process chain |
| `SessionWatcher` | A notice when a session's root process exits, to revoke its lease | None (detached); macOS (local mode) | Linux |
| `KeystoreUnlock` | How the keystore's data key is recovered at unseal | Passphrase + approver signature | age plugin recipients (Secure Enclave, YubiKey), recovery recipient |
| `Notifier` | How I'm told something is waiting or went wrong | ntfy | Native macOS notifications, approver apps |

Shapes (to settle in code, kept in sync here):

```rust
/// How clients reach the daemon. Every transport carries the same SSH protocol:
/// only the byte stream and what is known about its peer differ.
pub trait Transport: Send + Sync {
    /// Waits for the next client connection.
    async fn accept(&self) -> Result<Connection>;
}

pub struct Connection {
    pub stream: Box<dyn AsyncStream>,
    /// Raw peer information from the transport (socket address, or the kernel's peer
    /// credentials on a Unix socket). Never something the client claims about itself.
    pub peer: PeerInfo,
}

/// Turns raw peer information into facts the policy can use.
pub trait CallerAttestor: Send + Sync {
    fn attest(&self, peer: &PeerInfo) -> Result<CallerFacts>;
}

/// Calls back once when a process ends (kqueue `NOTE_EXIT` on macOS, a pidfd on Linux).
pub trait SessionWatcher: Send + Sync {
    fn watch(&self, process: &ProcessRef, on_exit: Box<dyn FnOnce() + Send>) -> Result<WatchHandle>;
}

/// Recovers the keystore's data key at unseal time.
pub trait KeystoreUnlock: Send + Sync {
    fn unlock(&self, request: &UnsealRequest) -> Result<DataKey>;
}

/// Tells me something happened. Never an approval channel.
pub trait Notifier: Send + Sync {
    fn notify(&self, notification: &Notification) -> Result<()>;
}
```

## Caller facts and the policy

`CallerFacts` is a plain type in `writ-core`, so the policy stays pure and testable:

```rust
pub struct CallerFacts {
    /// Network transports: the source address (advisory, or pinned later).
    pub source_addr: Option<IpAddr>,
    /// Local transports with a kernel-resolved ancestry, the caller first.
    pub process_chain: Option<Vec<ProcessRef>>,
}

pub struct ProcessRef {
    pub pid: u32,
    /// Distinguishes a reused pid (pidversion on macOS, start time on Linux).
    pub generation: u64,
    /// Resolved by the kernel, never from the process's own name or arguments.
    pub executable: PathBuf,
    pub code_identity: Option<CodeIdentity>,
}
```

A lease may require a caller (e.g. "descends from this Omega Code session",
[lease model](../lease-model.md#ticket--lease-schema-draft)). `writ-core` checks it against the
facts; **missing facts fail closed**: a lease that requires a process ancestor can never be
used over TCP, because the network attestor can't provide a process chain. That is the whole
difference between modes, as far as the policy is concerned.

## Where the code lives

| Crate | Holds |
|---|---|
| `writ-core` | `CallerFacts`, `ProcessRef` and the caller checks (pure) |
| `writ-platform` | The traits above (except `Signer`), the portable implementations (TCP transport, network attestor, no-op watcher, ntfy, passphrase unlock), and fakes for tests behind a `testing` feature |
| `writ-signer` | The `Signer` trait, the software backend, cross-platform hardware backends behind Cargo features (YubiKey) |
| `writ-platform-macos` | Everything macOS-only: Unix socket transport extras, process chain attestor (libproc, code signature), kqueue watcher, the Secure Enclave `Signer` (M7.5, [macOS Secure Enclave](macos-secure-enclave.md)) and later `KeystoreUnlock` |
| `writ-platform-linux` | Linux-only implementations (later: `SO_PEERCRED` + `/proc` attestor, pidfd watcher, TPM) |
| `writd` | `platform.rs`: builds the set of implementations from the configuration and the target OS. The **only** place outside the platform crates with `#[cfg(target_os = …)]` |

The Unix socket transport itself is portable (Unix), so it lives in `writ-platform`; what is
read from its peer is the attestor's job.

## Rules

- **No code branches on the mode.** There is no `if local { … }` in the core: behavior comes
  from which implementations are plugged in and from lease constraints.
- **No `#[cfg(target_os)]` outside `writ-platform-*` and `writd/src/platform.rs`.**
- **Every interface has a contract test suite** in `writ-platform` (or `writ-signer`) that
  every implementation runs, and a fake used by the core's tests
  ([Testing](../testing.md)).
- **Facts come from the kernel or the network, never from the client.** A client can't send
  its own `CallerFacts`.
- **A platform that can't provide a fact leaves it empty**, and any constraint needing it
  denies.

## Configuration presets

`writd` reads which implementations to use from its config. The two modes are presets of it:

```yaml
# detached (Docker on Linux)
transports: [{ tcp: "0.0.0.0:2222" }]
attestor: network
session_watcher: none
signer: { software: /var/lib/writ/keys }
unlock: passphrase
notifiers: [{ ntfy: https://ntfy.home/writ }]
```

```yaml
# local (native on the Mac)
transports: [{ unix: ~/Library/Application Support/Writ/writd.sock }]
attestor: macos_process_chain
session_watcher: macos
signer: { software: /var/db/writ/keys }   # se-keychain or se-cryptokit from M7.5
unlock: passphrase
notifiers: [{ ntfy: https://ntfy.home/writ }]
```

Asking for an implementation the build doesn't have (e.g. `macos_process_chain` on Linux) is
a startup error, never a silent fallback.
