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

The daemon signs commits with `sshsig`, in git's namespace `git`, with the key the lease's
template names (`signing_key`): templates' key ids are the signer's, and the daemon refuses to
start when a template names a key its signer doesn't hold. Until the sealed keystore (M5),
the development keystore (`keystore: { dev: … }`, refused by release builds) generates one
Ed25519 key per template `signing_key` on first start, in `<keys>/signing/<id>` (0600), and
hands them to the software backend. The lease's public key reaches the agent with the grant
(`signing_key.pub` in its session), for git's `user.signingkey` and for `allowed_signers`
when verifying.

| Backend | Algorithms | Key exportable? | Notes |
|---|---|---|---|
| **Software** (v1) | ed25519, P-256 | While unsealed, by root on the host | Encrypted keystore at rest, sealed start |
| **YubiKey PIV** | P-256, P-384, ed25519 (recent firmware) | No | Touch policy must be `never` for unattended agent keys; USB passthrough to the container |
| **Secure Enclave** | P-256 | No | Local mode on a Mac only. v1: a CryptoKit key under the dedicated `_writd` user (`se-cryptokit`, M7.5); a keychain access group (`se-keychain`) needs a paid Apple account. See [macOS Secure Enclave](macos-secure-enclave.md) |
| **TPM 2.0** | P-256 | No | Possible future backend on the server |
| **ssh-agent** (any socket: Secretive, yubikey-agent, 1Password…) | Whatever the agent holds | Depends on what backs it | Lets the daemon reuse an existing agent. Caveat: if agents run as the same user and can reach that socket, they can bypass Writ; only safe when the socket is out of the agents' reach (other user, other host) |

The same interface also holds the **upstream credentials** (the SSH key the daemon uses to
push to remotes), so those can move to a YubiKey too.

And, from M5, the **HTTPS approval API's TLS key** (P-256): rustls signs each handshake through
a small adapter that asks the `Signer` for a raw signature and DER-encodes it, and the
self-signed certificate is made the same way. Its backend is a config choice like any key's
(software by default, the Secure Enclave from M7.5); a new key means a new certificate, so
approvers re-pin it once.

v1 ships the software backend; the others are in the [backlog](../backlog/README.md) (and
the Secure Enclave in local mode, `se-cryptokit`, in
[M7.5](../roadmap.md#m75--secure-enclave-signer-on-the-mac)).

## Startup and sealing

The daemon always **starts sealed**: it serves nothing except the unseal endpoint until
unlocked ([Q17](../decisions.md)).

- Software keys are stored in an encrypted keystore (age format), with a random data key.
- v1: `writ unseal` on the Mac asks for the keystore passphrase **and** signs an unseal
  approval with Secretive. Both travel over the authenticated channel; the daemon decrypts in
  memory only.
- Later: the data key is wrapped to hardware recipients (age plugins for the Secure Enclave or
  YubiKey), so unsealing needs no passphrase. Secretive can't do this part because SSH keys
  only sign; they can't decrypt.
- A recovery recipient (offline YubiKey or paper key) avoids losing everything with one device.
- Hardware signer backends (YubiKey, TPM) don't need the keystore; sealing then only gates the
  daemon.
- How the data key is recovered is a `KeystoreUnlock` implementation (passphrase + approver
  signature in v1; age plugin recipients later), so new unseal methods plug in without
  touching the sealing logic ([Platform interfaces](platform.md)).

The unseal sequence is [Flows § 7](../flows.md#7-daemon-startup-sealed). Until unsealed, every
request fails closed with "daemon sealed".

Secrets held in memory (decrypted keys, the data key, tokens) are zeroized on drop and never
printed through `Debug` or logs.
