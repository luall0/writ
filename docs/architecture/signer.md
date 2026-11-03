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
    /// Signs `data` with the key `id` and the signer hash `hash`: the backend hashes `data`
    /// and signs the digest (ECDSA, RSA PKCS#1 v1.5), or with `None` signs `data` itself
    /// (Ed25519). A pair it doesn't sign with is `Unsupported`, named, never replaced.
    fn sign(&self, id: &KeyId, data: &[u8], hash: Option<Hash>)
        -> Result<RawSignature, SignerError>;
    /// What this backend can do: the (algorithm, signer hash) pairs it supports,
    /// exportability, touch requirement, whether it takes keys made outside it.
    fn capabilities(&self) -> Capabilities;
    /// Takes a key made outside the backend (moved in, never copied) under `id`, usable at
    /// once. A backend that can't take one (a device makes its own keys) answers
    /// `CannotTakeKeys`, the default; an id it holds already is `DuplicateKey`.
    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError>;
}
```

### Formats, algorithms and hashes

Since [M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms) the caller names the
hash (`writ_crypto::algorithm`). Two hashes are at play:

- the **format's hash**, the one a key is declared with: the SSHSIG message hash (`ssh`), or
  the digest an OpenPGP signature covers (`openpgp`);
- the **signer hash**, what the `Signer` is asked for: `None` for Ed25519 (it signs the
  SSHSIG's data, or the OpenPGP digest, itself), the curve's own hash for ECDSA (P-256 with
  SHA-256, P-384 with SHA-384, in both formats), the declared hash for RSA (PKCS#1 v1.5:
  `rsa-sha2-256` or `rsa-sha2-512` in SSH, never `ssh-rsa`'s SHA-1).

| Format | Algorithms | Format's hashes (left out: the strongest the backend allows) |
|---|---|---|
| `ssh` | `ed25519`, `p256`, `p384`, `rsa3072`, `rsa4096` | `sha256`, `sha512` |
| `openpgp` | `ed25519` (EdDSA, algorithm 22), `rsa3072`, `rsa4096` | `sha256`, `sha384`, `sha512` |
| `openpgp` | `p256` / `p384` (ECDSA) | `sha256` / `sha384` only (RFC 6637's pairing) |

`writ_crypto::algorithm::check` takes a declared key (format, algorithm, optional hash) and
a backend's pairs, and answers the hash to use or why the combination is refused (the format
doesn't take the algorithm, the format doesn't take the hash with it, the backend can't
sign the algorithm or the signer hash): refused, never adjusted. RSA under 3072 bits has no
name to declare (`rsa2048` is refused with the reason).

The keys are `writ_crypto::keypair::KeyPair`, Writ's own private key type: Ed25519, P-256 and
P-384 through `ssh-key` (pure Rust), RSA through `aws-lc-rs` (constant time; `ssh-key` signs
RSA only through the banned `rsa` crate). A signature comes back as a `RawSignature`: the
algorithm, the signer hash, and the signature in one fixed encoding (Ed25519's 64 bytes,
ECDSA's `r ‖ s`, RSA's `s`), which adapters turn into an SSH signature (`to_ssh`), TLS's
DER, or OpenPGP's MPIs; `writ_crypto::keypair::verify` checks one against a public key.

**Adding a key live** (M5): a signed policy change that names an agent signing key or an
`ssh://` upstream credential the keystore lacks makes the daemon create it (Ed25519), seal
it to the keystore's recipient with its public half, and hand it to the running signer
through `add_key`. The software backend holds its keys behind a lock and takes the key by
move. `QueuedSigner` sends it through its worker, so it lands in order with the signatures
queued before it, then refreshes the key list it answers `list_keys` from. The contract
suite checks a key added is listed and signs, an id held already is refused by name, and a
backend without the verb answers `Unsupported` and lists nothing new.

`add_key` is the verb for a key made outside the backend, which only a software backend can
take. A device that makes its own keys (the Secure Enclave, a YubiKey) gets its own verb
with its milestone (M7.5: e.g. `create_key(id, algorithm)`), and M5.5's declared
algorithms and formats may reshape `add_key`: each backend implements the verb that fits it
and answers `Unsupported` for the other, the daemon picks by backend. Both milestones change
this interface first (its contract tests, this page), as hard rule 4 asks.

`writ_signer::sshsig` builds an SSHSIG (what `ssh-keygen -Y sign` writes) through any
backend, with the message hash it is given (`sha256` or `sha512`). Errors never carry key
material (`SignerError`), and every backend runs the contract suite
(`writ_signer::contract`): for each key it holds, every pair it declares for that key's
algorithm signs, the signature verifies with the public key it lists only for the bytes
signed, and its SSHSIGs verify; a pair it doesn't declare is refused by name
(`Unsupported`), never signed with something else; an unknown key is refused by name. The
software backend (`writ_signer::software::SoftwareSigner`) holds `KeyPair`s moved in by
whoever loaded them, wiped on drop, never printed, and declares every pair Writ signs with;
its tests hold one key of each algorithm.

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
- **`list_keys` and `capabilities` from a cache** filled at startup and refreshed when a key
  is added: they never wait behind the device (the approval service lists keys to show the
  lease's public key).
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
| **Software** (v1) | ed25519, P-256, P-384, RSA 3072/4096 (each with its hashes) | While unsealed, by root on the host | Encrypted keystore at rest, sealed start |
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
- **After unseal the identity stays open**, in memory wiped on drop, behind the same seam:
  a key a signed policy change creates is sealed to the recipient, and a token
  [`writ admin token`](approvals.md#writ-admin-token) brings is opened through it, as a
  start would. Every secret it opens is already in memory once unsealed; what holding it adds
  (a memory read opens the secrets added afterwards too) is a
  [residual risk](../threat-model.md#residual-risks-v1), closed by hardware recipients
  (M7.6).
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

How it is built: the approval service starts sealed (`writ_approval::Service`: no CA key, no
signer) and the gateway without mirrors; `writ info` names the boot to unseal (the host key's
fingerprint and a nonce drawn at start). `writ unseal` sends the passphrase with an approver's
SSHSIG over `writ-unseal/1` (`{daemon, nonce}`); the service checks it
(`Service::check_unseal`), then the daemon's `Unsealer` (`writd`'s `daemon::Opener`) unwraps
the identity through `KeystoreUnlock`, opens every secret through the one seam, starts the
signers and the mirrors (`Gateway::set_mirrors`), and hands the service its keys
(`Service::unseal`, which checks the CA is the one whose public half the daemon started with
and that the signer holds every template's key, and logs `unseal` before anything is
served). The notifiers whose token is sealed (`notifiers[].telegram.token.sealed`) start
then; those whose token is in the boot tier (`token.boot`) were told of the sealed start.

Secrets held in memory (decrypted keys, the data key, tokens: `UpstreamToken`, `BotToken`) are zeroized on drop and never
printed through `Debug` or logs.
