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
    /// exportability, touch requirement, whether it takes keys made outside it
    /// (`takes_keys`), whether it makes its own (`makes_keys`).
    fn capabilities(&self) -> Capabilities;
    /// Takes a key made outside the backend (moved in, never copied) under `id`, usable at
    /// once. A backend that can't take one (a device makes its own keys) answers
    /// `CannotTakeKeys`, the default; an id it holds already is `DuplicateKey`.
    fn add_key(&self, id: KeyId, key: KeyPair) -> Result<KeyInfo, SignerError>;
    /// Makes a key of `algorithm` in the backend under `id`, usable at once: its public half
    /// and `stored`, the opaque bytes the daemon keeps to give the key back at the next start
    /// (`Created { info, stored }`). A backend that makes no key itself (software) answers
    /// `MakesNoKeys`, the default; an id it holds is `DuplicateKey`, an algorithm it doesn't
    /// make `Unsupported`.
    fn create_key(&self, id: KeyId, algorithm: KeyAlgorithm) -> Result<Created, SignerError>;
    /// Drops the key `id` (wiped; a device's key forgotten), no longer listed nor signed
    /// with: a key the policy no longer declares (M6.2). `UnknownKey` for an id it doesn't
    /// hold; `CannotTakeKeys`, the default, for a backend that neither takes nor makes keys.
    fn remove_key(&self, id: &KeyId) -> Result<(), SignerError>;
}
```

### Formats, algorithms and hashes

Since [M5.5](../history/m5.5-signature-formats-and-key-algorithms.md) the caller names the
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

**Adding a key live** (M5, declared in the policy since M6.2): a signed policy change that
declares a signing key or an `ssh` upstream credential the keystore lacks makes the daemon
create it as `keys.<id>` declares it, seal it to the keystore's recipient with its public
half, and hand it to the running signer through `add_key`. The software backend holds its keys behind a lock and takes the key by
move. `QueuedSigner` sends it through its worker, so it lands in order with the signatures
queued before it, then refreshes the key list it answers `list_keys` from. The contract
suite checks a key added is listed and signs, an id held already is refused by name, and a
backend without the verb answers `Unsupported` and lists nothing new.

**Removing a key** (M6.2): a signed policy change that no longer declares a key (or declares
its id for another use) deletes it once the change is in force: `remove_key` on the signer
that held it (through `QueuedSigner`'s worker, in order: a signature queued before it still
signs, none after it does), then its sealed file, public half and certificate. The `admin`
line keeps its public half and fingerprint, so what it signed stays verifiable, and declaring
the id again makes a new key. A deletion cut short (the daemon stopped) is finished at the
next unseal: the keys the keystore holds that the policy in force doesn't declare are deleted,
each said in the audit log. The contract suite checks a removed key is no longer listed nor
signed with, removing it again is refused by name, and the id then takes a new key.

**Two verbs for a new key** (M7.5, [decision log](../decisions.md)): `add_key` for a key made
outside the backend, which only a software backend takes; `create_key` for a device that
makes its own (the Secure Enclave; a YubiKey or a TPM later). Each backend implements the one
that fits it and answers the other refused by name (`CannotTakeKeys`, `MakesNoKeys`); the
daemon picks by the backend's `Capabilities`. What `create_key` answers in `stored` (a
`writ_signer::Stored`: wiped on drop, its `Debug` its length only) is opaque to the daemon:
sealed in the keystore like a software key, and handed back to the backend's constructor
at the next start. Through `QueuedSigner`, `create_key` and `remove_key` go through the
worker like `add_key`, in order, and refresh the cached key list. The contract suite's
`create_key_contract` checks a key made is listed at once and signs, its id refused twice,
an algorithm the backend declares no pair for refused by name with nothing listed, a backend
built again from the stored bytes signing with the same key, and a removed id making a new
key; `writ_signer::testing::FakeDevice` (P-256 keys it makes itself, no key taken) runs it
alone and behind a queue, as every device backend does.

**Several backends for one use** (M7.5): a use's keys (the agent keys, the upstream
credentials) may live on a software backend and a device at once. The daemon's signer for a
use is a `writ_signer::route::Routed`, itself a `Signer`, over its backends by name, each
behind its own `QueuedSigner`: a signature or a removal goes to the backend that lists the
key (none: `UnknownKey`; two: `DuplicateKey`, refused, never one picked, and refused at
construction too); a new key goes to the backend named (`add_key_on`, `create_key_on`),
refused when another holds its id. A stuck device never holds up a software key (tested with
the device held at a gate).

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
  daemon restarts. A backend that aborts its process instead, as CryptoKit does on a bad
  blob, runs in a helper process ([below](#a-helper-process)), so the abort costs one job.

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

### A helper process

A backend whose library can't be called from Rust, or may take its process down, runs in a
helper process: `writ_signer::helper::HelperSigner` is a `Signer` over one (M7.5, the Secure
Enclave's `writ-se`, a Swift program calling CryptoKit). The Rust side is generic, so it is
tested on every OS against a fake helper (`writ-fake-se`, built with `testing` only).

- **The protocol** (`writ-se/1`) over the helper's stdin and stdout, one request at a time:
  frames of a 4-byte big-endian length and a body; a request is an operation byte then its
  fields, an answer a status byte (0 ok, 1 refused) then its fields, each field a 4-byte length
  and its bytes. `hello` answers the protocol's name (the startup check; a helper without its
  device refuses with a code, `no-secure-enclave`); `create <algorithm>` answers the key's
  stored bytes and public point (SEC1, uncompressed); `public <stored>` its public point;
  `sign <stored> <data>` the signature over the data's SHA-256, `r ‖ s`; and for the
  keystore's hardware recipient (M7.6, `writ_signer::helper::agreement`), `create-agreement
  <algorithm>` a P-256 key-agreement key's stored bytes and point, `public-agreement <stored>`
  its point, `agree <stored> <peer>` the ECDH shared secret (32 bytes). A refusal is one code
  of at most 64 bytes of `[a-z0-9-]`. P-256 with SHA-256 is the only pair in this build.
- **The helper keeps no state:** each request carries its stored bytes, so a new helper
  answers as the old one did. It starts on first use, with an empty environment and its
  stderr discarded.
- **What it answers is untrusted:** an answer past 64 KiB, a field count or length other than
  the operation's, a point that isn't one, a code outside its alphabet, a public point other
  than the key's, or a signature that doesn't verify with the key's public half (checked on
  every signature, before it leaves) is refused and logged. A key just made signs a probe
  before it is kept. A helper that dies, answers wrong (another key's point included, at
  start too) or stays silent past its deadline is killed and the job refused (`Failed`,
  `Timeout`); the next job starts a new helper. One deadline covers a request's write and its
  answer: a thread of the helper's writes the request, so a helper that stops reading its
  stdin (a request past the pipe's buffer: a large commit to sign) costs that deadline, not
  the caller for good (the review after M7.6, K-2). Its own refusal keeps it. Answers are held
  in buffers wiped when dropped (a shared secret moved once into the one returned), and the
  helper wipes its own once written (K-4). ([security inventory](../security.md#untrusted-inputs))
- **No blob reaches the device unless it is the one the device made for that key.** A
  malformed blob does more than crash the helper: corrupted ones sent to the real Secure
  Enclave made its firmware panic and the Mac with it (2026-11-12). So what `create_key`
  answers in `stored` is the blob **framed**: `writ-se-blob/1\n`, a SHA-256 over that header,
  the key's public point and the blob, then the blob. Wherever the daemon keeps it (sealed in
  the keystore, whose age encryption already refuses a changed file; or the boot tier, a
  plain file), the frame is checked against the key's kept public half before the helper
  sees the blob: corrupted, cut, bare, another key's, or a kept half that isn't P-256 never
  leaves the daemon. The digest guards against damage, not against someone who can write the
  daemon's files ([threat model](../threat-model.md#residual-risks-v1)).
- **Built from what the keystore holds:** `HelperSigner::new` takes each key's stored bytes
  and the public half the daemon kept, checks the frame, asks the helper for the point the
  blob holds (on the curve, checked, and the key's), then has it **sign a probe** (a fixed
  message, `writ-signer-probe/1`, checked against the kept public half and thrown away): a
  blob that opens can still be one its device won't sign with where the daemon runs (a key
  made outside the LaunchDaemon, found on the first real install, 2026-11-14). A key refused
  at any step (one the helper refuses or dies on, too) stays listed from the kept public half
  and refuses every signature (`SignerError::Unusable`); `refused()` says which and why, for
  the daemon's log and audit log, which name the command that replaces it (`writ admin key
  rotate <id>`, `writ admin ca rotate` for the CA, `writ admin tls rotate` for the TLS key).
  Every other key signs. The probe costs one signature per device key at each unseal (the
  TLS key's at each start), 10 to 40 ms on the Secure Enclave.

### Keys on the Secure Enclave in the daemon

`se-cryptokit` (M7.5, macOS) is a backend name like `software`: a key declared
`backend: se-cryptokit` (`p256`, signing in either format, or an `ssh` upstream credential)
is made by the Secure Enclave and never leaves it.

- **Which backends a daemon has** is `writd/src/platform.rs`'s `BACKENDS` (software
  everywhere, and `se-cryptokit` on macOS); a policy naming another is refused by name. At
  start, each device backend a key lives on is checked (`writ-se` runs, speaks `writ-se/1`,
  the Secure Enclave is there), refused naming the path (`signers.se_cryptokit.helper`) and
  why.
- **Each use's signer is a `Routed`** over every backend the daemon has, each on its own
  queue (`writ-sign-agent`, `writ-sign-agent-se-cryptokit`; `writ-upstream`,
  `writ-upstream-se-cryptokit`).
- **Making a key** goes through the keystore's `Makers`: a software key is generated by the
  daemon and handed over (`add_key`); a device key is made by the device (`create_key`): by
  the use's own backend in the running daemon (which then holds it), by a helper signer of
  its own at the daemon's start and in the development keystore. Its OpenPGP certificate,
  when there is one, is signed through the device too.
- **A device key is made only by `writd run`, never by a command run by hand.** A key made
  by `writd init` through `sudo -u _writd`, from a logged-in session, opens under the
  LaunchDaemon but never signs there ([found on the first real
  install](macos-secure-enclave.md#m0-results)): the device binds it to where it was made,
  which no command run by hand can be sure to match. So `writd init` and `writd recover`
  make every software key as before and leave each device key **owed**: written to
  `to-make.json` in `keystore.sealed.dir` (`writ-to-make/1`: the CA's backend, the TLS key's,
  and each declared key with its role and declaration as the command read them, and an
  OpenPGP key's user ids), printed as owed, never half made. `writd run` makes what is owed
  at its start, still sealed, before it reads a key or opens a listener: each key sealed to
  the keystore's recipient (a public file: no unseal needed), its public half written, one
  `key` audit line and one log line each with that public half, then the entry taken out
  (the file rewritten whole, removed when empty). A key whose files are there already (a
  start cut short after making it) is taken as made. The declaration comes from the file,
  not from the policy in force, which a sealed start reads but never acts on (the review
  after M7.6, S-1); the unseal then checks every key against the policy whose MAC it checked,
  as before. A file that doesn't parse, names a backend the daemon lacks, or an entry the
  device refuses stops the start, the entry kept for the next. While a key is owed,
  `writd host-key` still works, but `writd tls-fingerprint`, `writd signing-keys` and
  `writd upstream-keys` say it's owed (start the daemon once). `writd recover` adds its owed
  keys to the file, and refuses only an entry already owed under the same name with another
  declaration.
- **The key file** names the backend (`backend: se-cryptokit` in its `writ-key/1` header)
  and holds the framed blob in hex instead of a private key; the public half beside it (in
  the development keystore too, `<id>.pub`). A key held on another backend than declared is
  refused like one of another algorithm.
- **A blob refused at unseal** (its frame, its point, or its probe signature) leaves its key
  listed and refusing: one `admin` audit line ("key <id> is unusable: refused at unseal (…);
  writ admin key rotate <id> replaces it", the CA's naming `writ admin ca
  rotate`), and the agent's sign request denied with that reason. A refused TLS key no longer
  stops the start (it did before 2026-11-14): the daemon runs, every HTTPS handshake is
  refused, and one `admin` audit line names `writ admin tls rotate`, which the SSH approval
  API can send.

The daemon signs commits with `sshsig`, in git's namespace `git`, with the key the lease's
template names (`signing_key`) and the hash its declaration gives. Every key is
**declared** in the signed policy's `keys` (M6.2): a signing key with its format, algorithm,
optional hash and backend, an `ssh` upstream credential with its algorithm and backend
([operator reference](../operators/policy-yaml.md#keys-keysid)). A policy is refused, naming
the key and the reason, wherever the daemon reads one (at start, `writd init`, `writd
recover`, an admin change), on a combination its backend can't sign
(`writ_crypto::algorithm::check` against the backend's `pairs`), a backend the daemon lacks,
a template naming an undeclared key, or a key the keystore holds with another algorithm or
format (`writd`'s `declared` module). Every declared key is in the keystore: the change that
declares it makes it (`writd init` for the first policy, `writd recover`, or a signed admin
change, sealed to the keystore's recipient; its public half printed, logged; a device key by
the daemon's next start when the command was run by hand, [owed](#keys-on-the-secure-enclave-in-the-daemon)
until then), so a key missing at start, and not owed, stops it. Upstream credentials are made the same way, of any algorithm (some
remotes take only RSA keys), and served to ssh by the upstream signer.

**The key file** (`writ_crypto::keyfile`): an SSH key's sealed plaintext is an OpenSSH
private key (PKCS#8 for RSA), its public half an OpenSSH line, as before M5.5; a key made for
another format starts with a `writ-key/1` header (its format, and for OpenPGP its creation
time, part of its fingerprint), on both halves, checked against each other when opened. A
file without the header is an SSH key, so every key made before M5.5 reads as one.

The development keystore (`keystore: { dev: … }`, refused by release builds) makes each key a
template uses on first start, as declared, in `<keys>/signing/<id>` (0600), and hands them to
the software backend (likewise one Ed25519 key per `upstream_credential` of an `ssh://` repo,
in `<keys>/upstream/<id>`; an `https://` repo's credential is a token the operator writes
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
| **Secure Enclave** (`se-cryptokit`, M7.5) | P-256 with SHA-256 | No | On a Mac only: a CryptoKit key per key, through `writ-se` ([a helper process](#a-helper-process)); its framed blob sealed in the keystore. A keychain access group (`se-keychain`) is [parked](../backlog/parked/keychain-secure-enclave-signer.md). See [macOS Secure Enclave](macos-secure-enclave.md) |
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
(software by default, the Secure Enclave from M7.5; on a device, owed by `writd init` and
made with its certificate at the daemon's first start, so `writd tls-fingerprint` prints it
from then on); a new key means a new certificate, so approvers re-pin it once. A key its
device refuses at start (its probe) leaves the daemon running and every handshake refused
(`writ admin tls rotate` over the SSH approval API replaces it).

### OpenPGP keys

A key declared `format: openpgp` signs v4 OpenPGP signatures, written by `writ_crypto::openpgp`
(never parsed from an agent: OpenPGP adds no untrusted input to the daemon). Its public key
packet is made from its SSH public half and its **creation time**, kept in its key file since
the fingerprint depends on it (EdDSA, algorithm 22, for Ed25519; ECDSA for P-256 and P-384;
RSA). A signature is prepared there (`openpgp::detached`: the data, the hashed subpackets
with the signature's time and the issuer's fingerprint, the trailer), signed through the
`Signer` (Ed25519 signs the digest; ECDSA and RSA are asked for the preimage with the hash,
which they hash to the same digest), and wrapped (`ToSign::packet`: the MPIs, the issuer's key
id unhashed); `writ_signer::openpgp_signature` does the three. Armor with its CRC-24.

**The certificate** (`writ_signer::openpgp_certificate`): the public key packet, then each
user id the policy gives the key (the policy's `keys.<id>.uids`, a signed admin
change) with its positive self-certification: key flags certify and sign, SHA-512, SHA-384,
SHA-256 preferred, made **at the key's creation time**. Ed25519, RSA PKCS#1 v1.5 and the
software backend's ECDSA (RFC 6979) are deterministic, so the same key, time and user ids
give the same certificate. The service makes the certificates at unseal and on every policy
change (`service/openpgp.rs`; the change's `admin` line names each key whose user ids
changed, `certified OpenPGP key <id> (<fingerprint>): <uids>`), hands a lease its key's
certificate with the grant, and the daemon writes it beside the key
(`signing/<id>.asc`) for `writd signing-keys` to print; `writd init` makes it from the key
itself.

The sign request says the format git asked for (`writ-sign git <repo>` for SSH, `writ-sign
openpgp <repo>`); one that isn't the lease's key's is denied with `signature_format`
(logged, not a violation, no slot used): the daemon signs in the key's format only, so no
signature of one format can be read as the other. Both formats go in the same `gpgsig`
header, so the ledger is unchanged.

v1 ships the software backend; the others are in the [backlog](../backlog/README.md) (and
the Secure Enclave in local mode, `se-cryptokit`, in
[M7.5](../history/m7.5-secure-enclave-signer.md)).

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
  ways, `KeystoreUnwrap`, that may open a file), so a hardware recipient (M7.6) is one more
  way there, with no format change.
- **The boot tier** (`keystore.sealed.boot`, its own directory): the keys a sealed daemon
  authenticates itself with to the client that brings the passphrase, readable at start: the
  SSH host key and the HTTPS approval API's TLS key and certificate. Without hardware, what a
  daemon uses before any human input can be rebuilt from its disk; the
  [threat model](../threat-model.md#residual-risks-v1) says what that leaves.
- `writd init <writd.yaml>` makes the keystore once, as the daemon's user, into empty
  directories (a failure leaves them empty): the passphrase twice (at least 12 characters,
  one line of stdin when it isn't a terminal), the identity, the boot tier, the CA key and
  every key the policy names, those on a device owed to the daemon's first start
  ([owed keys](#keys-on-the-secure-enclave-in-the-daemon)). It never makes a token.
- **After unseal the identity stays open**, in memory wiped on drop, behind the same seam:
  a key a signed policy change creates is sealed to the recipient, and a token
  [`writ admin token`](approvals.md#writ-admin-token) brings is opened through it, as a
  start would, and the `https://` tokens and proxy passwords are unwrapped through it at each
  use (M7.6: the mirrors hold only a reference, [gateway](gateway.md#https-with-a-token)).
  Every key it opens is already in memory once unsealed; what holding it adds
  (a memory read opens the secrets added afterwards too) is a
  [residual risk](../threat-model.md#residual-risks-v1), closed by hardware recipients
  (M7.6).
- v1: `writ unseal` on the Mac asks for the keystore passphrase **and** signs an unseal
  approval with Secretive. From M7.6, `writ info` says what opens the sealed keystore
  (`unseal`: `passphrase` or `hardware`, read from `identity.age`'s header at start): with
  `hardware`, `writ unseal` asks for none and sends an empty one, never read; the daemon's
  hardware recipients unwrap the identity. `writd recover` takes the passphrase or the
  recovery key, never the hardware alone. Both travel over the authenticated channel; the daemon decrypts in
  memory only.
- Since M7.6 the data key can be wrapped to hardware recipients (the Secure Enclave's
  key-agreement keys, `piv-p256`), so unsealing needs no passphrase, and the tokens with
  them, each unwrapped only when used
  ([M7.6](../history/m7.6-hardware-wrapped-secrets.md)); each secret being its own age file
  (M5) is what made that a matter of recipients. Secretive can't do this part because SSH
  keys only sign; they can't decrypt.
- **The keystore's recipients** (M7.6, the policy's `recipients`): a hardware recipient (the
  Secure Enclave's key-agreement key, made by the change that declares it, its framed blob in
  `recipients/<name>.blob`, its `age1se1…` in `<name>.pub`) wraps `identity.age` instead of
  the passphrase (`piv-p256`), and the tokens with the recovery recipient; the recovery
  recipient (`age1…`) wraps the identity in `identity.recovery.age`, beside a challenge
  (`recovery-check.age`, `.sha256`) that `writ recovery check` opens. `keystore::recipients::reconcile`
  brings every file in line after each change and at each unseal (a change cut short is
  finished); age's own grease stanza is never read as a recipient. On a hardware keystore the
  identity is wiped once the unseal opened the keys: the tokens open through the devices, and
  a key made later is sealed to the public recipient. The recovery recipient in force is
  named by `identity.recovery.pub`, beside its files (M7.6 kept it as
  `recipients/recovery.pub`, where a hardware recipient named `recovery` collided: moved
  once at start, the review after M7.6, S-3).
- **The data key rotated when a way in is taken out** (the review after M7.6, S-8,
  `keystore::rotation`): a recovery recipient replaced or removed, a hardware recipient
  removed, the passphrase given up for hardware or the hardware for a passphrase. A new
  identity is made; the CA, `authority.age`, every signing and upstream key are opened with
  the old one and sealed to the new one; every token is sealed again (to the new identity on
  a passphrase keystore, to the hardware recipients and the recovery recipient on a hardware
  one); `identity.age` wraps the new identity to the ways that remain, the recovery files
  are made for the recovery recipient in force (or removed with it), `recipient` names the
  new identity, the removed hardware recipients' files go. Crash-safe: everything is staged
  in `rotation/` (each file whole, synced), then one record `rotation/commit` lists each file
  with its digest and each file removed; then each file is moved into place, then the record
  and `rotation/` go. A sealed start, an unseal and `writd recover` settle the keys directory
  first, from that record alone (never from the policy): staging without a record is
  removed, a record is finished (a file moved already is checked by its digest), so the
  keystore is exactly the old one or the new one, and a second start changes nothing; a
  `rotation` that isn't a directory, or a record that isn't well formed (its header, an entry
  out of the keystore's own files, a digest neither file has), refuses the start by name.
  On a hardware keystore the signed change rotates at once (the devices unwrap the old
  identity, the new one is wrapped to the hardware recipients' public halves) and the
  daemon's state is swapped whole on success. On a passphrase keystore the daemon holds no
  passphrase after unseal, so it can't wrap a new identity: the change is recorded as owed
  (`rotation-owed`, written before any attempt), the new recovery recipient takes its files
  at once, `writ info` (`rotation_owed`) and the change's answer (`keystore`) say what is
  owed, and the next unseal (or `writd recover`) rotates right after the MAC check, with the
  passphrase it brought. Until then the removed recipient, with a copy of the keys
  directory, still opens the keystore in force. **What it takes back:** after the rotation,
  what was taken out opens no copy of the keystore made from then on. A copy made before
  still opens what it held, with what was taken out: the keys that haven't changed since
  (rotate them, `writ admin key rotate`, `writ admin ca rotate`, and add the tokens again, if
  the recipient is thought compromised). The authority MAC's key is sealed again, not
  replaced: whoever held a copy and the removed recipient knows it, and could write a state
  the next unseal accepts (whole-state forgery needs the state's disk too); replacing it with
  the rotation is a [backlog](../backlog/README.md) item.
- Hardware signer backends (YubiKey, TPM) don't need the keystore; sealing then only gates the
  daemon.
- How a keystore file is opened is a `KeystoreUnwrap`: one way to unwrap an age file's file
  key from its header (the passphrase for the identity's file, the keystore's identity for
  every other secret in this build; hardware recipients and the recovery identity from M7.6),
  through `writ_platform::unlock::open`, the one place a keystore file is opened, which tries
  each way given in turn. New unseal methods plug in without touching the sealing logic
  ([Platform interfaces](platform.md)).

The unseal sequence is [Flows § 7](../flows.md#7-daemon-startup-sealed). Until unsealed, every
request fails closed with "daemon sealed".

How it is built: the approval service starts sealed (`writ_approval::Service`: no CA key, no
signer) and the gateway without mirrors; `writ info` names the boot to unseal (the host key's
fingerprint and a nonce drawn at start). `writ unseal` sends the passphrase with an approver's
SSHSIG over `writ-unseal/1` (`{daemon, nonce}`); the service checks it
(`Service::check_unseal`), then the daemon's `Unsealer` (`writd`'s `daemon::Opener`) unwraps
the identity through the ways the request brings (`KeystoreUnwrap`: the passphrase), opens the authority key and checks the versions in force
against its MAC (`InForce::check_mac`, in `keystore::open`) before anything is read or
written from the policy the daemon started with (read from the state, unchecked: the review
after M7.6, S-1), then opens every secret through the one seam, brings the keystore's files
in line with the policy's recipients, starts the signers and the mirrors (`Gateway::set_mirrors`), and hands the service its keys
(`Service::unseal`, which checks the CA is the one whose public half the daemon started with,
that the signer holds every template's key, and the MAC again with the same function, the
store still holding those versions, and logs `unseal` before anything is
served). The notifiers whose token is sealed (`notifiers[].telegram.token.sealed`) start
then; those whose token is in the boot tier (`token.boot`) were told of the sealed start.

**The SSH CA behind the `Signer` (M7.6):** the CA's key is read like any key file (an
OpenSSH key in software, or a device's framed blob behind its `writ-key/1` header), given to
its own signer (`writ-ca`, a queue per backend), and the certificate authority signs each
session certificate through it (`writ_crypto::ca::CaSigner`; ECDSA's hash for a P-256 key).
`writd init --ca-backend se-cryptokit` puts it in the Secure Enclave (P-256): owed by
`writd init`, made by the daemon at its first start ([owed keys](#keys-on-the-secure-enclave-in-the-daemon)).
A blob the device refuses at unseal (its probe signature included) leaves every grant
refused, the daemon running: the approver is told why (refusal `ca`, "the daemon's CA key is
unusable: …: writ admin ca rotate --backend <name> replaces it", the CA never asked to sign),
the ticket stays pending for a signature after the rotation, and the audit log says it once
at unseal. Moving an existing
daemon's CA is [`writ admin ca rotate`](approvals.md#writ-admin-ca-rotate).

Secrets held in memory (decrypted keys, the data key, tokens: `UpstreamToken`, `BotToken`) are zeroized on drop and never
printed through `Debug` or logs.
