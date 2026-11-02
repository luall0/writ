# Signer and sealing

Code: `crates/writ-signer` (trait, software backend, cross-platform hardware backends behind
Cargo features). Platform-only backends, like the Secure Enclave, live in their platform crate
(`writ-platform-macos`) and implement the same trait ([Platform interfaces](platform.md)).

## Signer interface

Keys sit behind an interface; the daemon never depends on the backend.

```rust
/// Where keys live and how they sign. Used as a trait object (`Arc<dyn Signer>`).
pub trait Signer: Send + Sync {
    /// The keys this backend exposes (public parts only): `KeyInfo { id, public_key }`.
    fn list_keys(&self) -> Result<Vec<KeyInfo>, SignerError>;
    /// Signs raw `data` with the key `id`. The caller builds what is signed (an SSHSIG's
    /// signed data) and wraps the signature; the signature is in SSH encoding.
    fn sign(&self, id: &KeyId, data: &[u8]) -> Result<Signature, SignerError>;
    /// What this backend can do (algorithms, exportability, touch requirement).
    fn capabilities(&self) -> Capabilities;
}
```

`writ_signer::sshsig` builds an SSHSIG (what `ssh-keygen -Y sign` writes) through any
backend. Errors never carry key material (`SignerError`), and every backend runs the
contract suite (`writ_signer::contract`): its signatures verify with the public key it lists,
only for the bytes signed, and an unknown key is refused by name. The software backend
(`writ_signer::software::SoftwareSigner`) holds Ed25519 and P-256 keys moved in by whoever
loaded them, wiped on drop, never printed.

### The queue in front of a backend

A backend may be slow, hold one session at a time, or hang (a Secure Enclave, a YubiKey, a
device pulled out). The daemon never calls one directly: each use goes through a
`QueuedSigner` (`writ_signer::queue`), a decorator that is itself a `Signer`, so the core
doesn't change:

- **one worker thread owns the backend** and signs one job at a time, in order (a device that
  takes one session at a time is never asked for two);
- **a bounded queue**: past its capacity, a signature is refused at once with
  `SignerError::Busy`, so nothing piles up behind a stuck device;
- **a deadline per job**: the caller gets `SignerError::Timeout` past it; a job whose caller
  gave up is skipped (nothing is signed for nobody), and a late result is thrown away;
- **`list_keys` and `capabilities` from a cache** filled at startup: they never wait behind
  the device (the approval service lists keys to show the lease's public key).
- **a backend that panics is not trusted again**: the worker answers that job
  `SignerError::Unavailable`, writes one error line to the daemon's log (the queue and the
  key), and stops; every later signature through that queue is `Unavailable` until the
  daemon restarts. (A backend that aborts the process instead, as CryptoKit does on a bad
  blob, is M7.5's to contain.)

**One queue per use**: the agent keys (commit signatures) now; the TLS key (M5, maybe on the
Secure Enclave in M7.5) and the upstream credential (M4) get their own, so a device stuck on
commit signing can't take the HTTPS approval API (and revocation over HTTPS) down with it.
`writd/src/platform.rs` builds them: the agent keys' queue holds 16 jobs with a 10 s deadline.

The approval service never calls the signer under its state lock either: `Service::sign`
decides and reserves under the lock, signs outside it, and checks again under the lock before
the signature leaves ([Flows § 2](../flows.md#2-signed-commit),
[Policy and state](policy-and-state.md#policy-engine)). A `Busy` or `Timeout` reaches the
agent as a denial ("the signer is busy; retry shortly", "the signer did not sign in time"),
its slot used.

The contract suite has a decorator section (`writ_signer::contract::queued_signer_contract`):
behind a queue, a backend passes the whole contract, a full queue answers `Busy` at once, a
backend held stuck (by `testing::GatedSigner`, released on a signal) answers `Timeout`, its keys
are still listed, and an abandoned job is never signed. Every backend runs it.

The daemon signs commits with `sshsig`, in git's namespace `git`, with the key the lease's
template names (`signing_key`): templates' key ids are the signer's, and the daemon refuses to
start when a template names a key its signer doesn't hold. Until the sealed keystore (M5),
the development keystore (`keystore: { dev: … }`, refused by release builds) generates one
Ed25519 key per template `signing_key` on first start, in `<keys>/signing/<id>` (0600), and
hands them to the software backend (likewise one key per `upstream_credential` of an `ssh://`
repo, in `<keys>/upstream/<id>`; an `https://` repo's credential is a token the operator writes
in `<keys>/tokens/<id>`, never generated, held outside the `Signer` since it doesn't sign:
[gateway](gateway.md#https-with-a-token)). The lease's public key reaches the agent with the grant
(`signing_key.pub` in its session), for git's `user.signingkey` and for `allowed_signers`
when verifying. `writd signing-keys <writd.yaml>` prints each signing key with the templates
that name it, for the operator to register on an account, so the remote shows the commits as
verified (GitHub: a signing key and the committer email verified on the account; Forgejo and
Gitea also ask for a proof, signed through [`writ prove-key`](approvals.md#proving-a-signing-key-to-a-remote)).

| Backend | Algorithms | Key exportable? | Notes |
|---|---|---|---|
| **Software** (v1) | ed25519, P-256 | While unsealed, by root on the host | Encrypted keystore at rest, sealed start |
| **YubiKey PIV** | P-256, P-384, ed25519 (recent firmware) | No | Touch policy must be `never` for unattended agent keys; USB passthrough to the container |
| **Secure Enclave** | P-256 | No | Local mode on a Mac only. v1: a CryptoKit key under the dedicated `_writd` user (`se-cryptokit`, M7.5); a keychain access group (`se-keychain`) is [parked](../backlog/parked/keychain-secure-enclave-signer.md). See [macOS Secure Enclave](macos-secure-enclave.md) |
| **TPM 2.0** | P-256 | No | Possible future backend on the server |
| **Cloud KMS** (AWS, Google Cloud, Azure, Vault Transit…) | P-256, ed25519 on some | No | Possible future backend for a host with no hardware: a network call per signature, and a credential for the service on the daemon ([backlog](../backlog/README.md#cloud-kms-signer-backend)) |
| **ssh-agent** (any socket: Secretive, yubikey-agent, 1Password…) | Whatever the agent holds | Depends on what backs it | Lets the daemon reuse an existing agent. Caveat: if agents run as the same user and can reach that socket, they can bypass Writ; only safe when the socket is out of the agents' reach (other user, other host) |

The same interface also holds the **upstream credentials** (the SSH key the daemon uses to
push to remotes), so those can move to a YubiKey too.

And, since M5, the **HTTPS approval API's TLS key** (`tls-01`, P-256, in the boot tier):
rustls signs each handshake through a small adapter (`writ_crypto::tls::remote`: its signing
key asks a `TlsKey`, which `writ_signer::tls::TlsSigner` implements over a `Signer`; the SSH
signature's `r` and `s` are DER-encoded for TLS), on its own queue (`writ-tls`, 32 jobs, 5 s
each), run with the async worker handed over (`block_in_place`) so a slow device never
stalls the listeners. The self-signed certificate is made the same way, signed through the
`Signer` (`writ_crypto::tls::remote::self_signed`), and a certificate that isn't the key's is
refused at start. No PEM key file exists. Its backend is a config choice like any key's
(software by default, the Secure Enclave from M7.5); a new key means a new certificate, so
approvers re-pin it once.

Each key signs in SSH today, with the algorithm the development keystore gives it (Ed25519).
From [M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms), each signing key is
declared with its format (SSH or OpenPGP), algorithm (Ed25519, P-256, P-384, RSA 3072/4096)
and hash, checked against its backend at start, and `sign` takes the hash to use.

v1 ships the software backend; the others are in the [backlog](../backlog/README.md) (and
the Secure Enclave in local mode, `se-cryptokit`, in
[M7.5](../roadmap.md#m75--secure-enclave-signer-on-the-mac)).

## Startup and sealing

The daemon always **starts sealed**: it serves nothing except the unseal endpoint until
unlocked ([Q17](../decisions.md)).

- Software keys are stored in an encrypted keystore (age format), with a random data key:
  the data key is an age X25519 **identity** (`DataKey::identity`), wrapped with the
  passphrase (age scrypt, `identity.age`), and **each secret is its own age file** encrypted
  to that identity's recipient (`recipient`, printed by `writd init`): the CA key, the agent
  signing keys, the upstream credentials, each with its public half beside it (`.pub`, read by
  the commands that print a key with no unseal, and checked against the key when it is
  opened). A secret is read only through one seam (`SecretFiles` in `writd`'s keystore: the
  identities that may open a file), so a hardware recipient (M7.6) is one more identity there,
  with no format change.
- **The boot tier** (`keystore.sealed.boot`, its own directory): the keys a sealed daemon
  authenticates itself with to the client that brings the passphrase, readable at start: the
  SSH host key and the HTTPS approval API's TLS key and certificate. Without hardware, what a
  daemon uses before any human input can be rebuilt from its disk; the
  [threat model](../threat-model.md#residual-risks-v1) says what that leaves.
- `writd init <writd.yaml>` makes the keystore once, as the daemon's user, into empty
  directories (a failure leaves them empty): the passphrase twice (at least 12 characters,
  one line of stdin when it isn't a terminal), the identity, the boot tier, the CA key and
  every key the policy names. It never makes a token.
- v1: `writ unseal` on the Mac asks for the keystore passphrase **and** signs an unseal
  approval with Secretive. Both travel over the authenticated channel; the daemon decrypts in
  memory only.
- Later: the data key is wrapped to hardware recipients (age plugins for the Secure Enclave or
  YubiKey), so unsealing needs no passphrase, and the tokens with it, each unwrapped only
  when used ([M7.6](../roadmap.md#m76--hardware-wrapped-secrets)). M5 makes each secret its
  own age file for this. Secretive can't do this part because SSH keys
  only sign; they can't decrypt.
- A recovery recipient (offline YubiKey or paper key) avoids losing everything with one device.
- Hardware signer backends (YubiKey, TPM) don't need the keystore; sealing then only gates the
  daemon.
- How the data key is recovered is a `KeystoreUnlock` implementation (passphrase + approver
  signature in v1; age plugin recipients later), so new unseal methods plug in without
  touching the sealing logic ([Platform interfaces](platform.md)).

The unseal sequence is [Flows § 7](../flows.md#7-daemon-startup-sealed). Until unsealed, every
request fails closed with "daemon sealed".

Secrets held in memory (decrypted keys, the data key, tokens: `UpstreamToken`, `BotToken`) are zeroized on drop and never
printed through `Debug` or logs.
