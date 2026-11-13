# Hardware-wrapped secrets

**Status:** in progress as [M7.6](../roadmap.md#m76--hardware-wrapped-secrets).
**Area:** Sealing, Credentials. **Kind:** feature. **Size:** M.

## Problem

A signing key can live in hardware: whoever reaches the daemon host can use it while there,
never copy it. A token can't, since it doesn't sign: an `https://` upstream's token, later the
[HTTP credential proxy](http-credential-proxy.md)'s credentials, sit in the keystore, and once
the daemon is unsealed every one of them is plaintext in its memory for as long as it runs.
Unsealing itself needs a passphrase typed by a human after each restart.

## Proposal

A secret store backed by a hardware encryption key, remote-agnostic (nothing here knows what a
secret is for):

1. **Setup:** the daemon creates the encryption key in the hardware (or names a KMS key) and
   prints its **public** recipient.
2. **Adding a secret:** the operator encrypts it to that recipient, from any machine, with the
   public key alone, through M5's signed admin change; the plaintext is never written on the
   daemon host.
3. **Using it:** when an operation needs it (an HTTPS push or fetch, a proxied request), the
   daemon asks the hardware to unwrap its file key, decrypts it, hands it on as today (to git
   through pipes, [gateway](../architecture/gateway.md)) and zeroizes it.
4. **Rotating:** encrypt the new value to the same recipient and replace the file.
5. **Killing everything:** remove the hardware key or revoke the KMS key, and every secret
   wrapped only to it is unreadable at once.

The keystore's data key is one more wrapped secret, so unsealing needs the approver's signature
and no passphrase. A recovery recipient (an age X25519 identity kept offline) keeps one lost
device from losing everything.

**Auto-unseal (`unseal: auto`, opt-in):** decided with the user. The daemon starts open with
no human only when nothing on the host opens a secret without one: every signing key in
hardware (the CA key moved behind the `Signer`), every secret wrapped only to hardware
recipients or the offline recovery identity; the notification token and the boot tier's
transport keys exempt (the boot tier gets a hardware option). Anything else: refused at start,
naming it. `writd recover` then takes the recovery identity, never the hardware alone. The
operator guide gets a step-by-step section ([sealing](../operators/sealing.md)).

## Scope and non-goals

- In M7.6: the unwrap interface and its contract suite, the passphrase identity (M5's) and a
  recovery identity as implementations, the Secure Enclave recipient. No cache.
- Later, with their backlog backends: YubiKey PIV and TPM (P-256 key agreement), a cloud KMS
  or Vault Transit (their Decrypt, see the [cloud KMS signer](README.md#cloud-kms-signer-backend)).
  Each is an implementation of the same interface, beside its `Signer`; a backend implements
  whichever of the two its hardware can (a cloud KMS's signing and encryption keys are
  separate keys).
- Not in M7.6: the gateway's SSH host key behind the `Signer`. russh (0.65) signs its host
  key proofs with an in-memory private key and has no hook for another signer; the idea waits
  for one ([backlog](README.md#ssh-host-key-behind-the-signer)). The boot tier is exempt from
  auto-unseal, and its TLS key already has the Secure Enclave (M7.5).
- Not a generic secret store for agents ([non-goals](../product.md#non-goals)): only the
  daemon's own secrets.

## Design

Settled with the user at M7.6's start ([decision log](../decisions.md), 2026-11-13).

- **Keystore format (M5):** one age file per secret. M7.6 changes which recipients a file is
  encrypted to, never the format, and never a file's plaintext.
- **Two ways a keystore unseals, never both:**
  - **Passphrase** (M5, the only way without hardware: detached mode today): `identity.age`
    wrapped with the passphrase (age scrypt); every secret, tokens included, encrypted to the
    keystore identity's recipient.
  - **Hardware + recovery:** `identity.age` wrapped to the keystore's **recipients** (at least
    one hardware recipient and exactly one recovery recipient); the keys (the CA, the agent
    signing keys and their blobs, the upstream keys, the authority MAC key) encrypted to the
    keystore identity as before; the **tokens** encrypted to the recipients directly, never to
    the identity. No passphrase exists: moving to hardware removes the scrypt file, and the
    recovery identity takes its place wherever a passphrase was asked off the hardware path.
- **The recipients by signed admin change:** `writ admin keystore show` (the way in force, each
  recipient, `age1…`), `writ admin keystore recipient add se` (the daemon makes the Secure
  Enclave key itself, under its own user, and answers its recipient), `recipient add recovery
  <age1…>`, `recipient remove <name>`. Each change is a signed `writ-keystore/1` bound to the
  set in force (a replay or a stale change refused), applied live: the daemon re-encrypts
  `identity.age` and every token file to the new set (each written new, then moved over the
  old one; a start finishes a half-done change), one `admin` line. A set with a hardware
  recipient and no recovery recipient is refused (one lost device must not lose everything);
  removing the last hardware recipient goes back to a passphrase, typed with the change.
  `writd init --recipients se,recovery=<age1…>` makes a keystore that way from the start.
- **The interface:** `KeystoreUnlock` becomes `KeystoreUnwrap` in `writ-platform`: one
  implementation unwraps one file key from an age file's stanzas (or says it has no stanza
  there), with its contract suite and a fake ([platform interfaces](../architecture/platform.md)).
  Implementations: the passphrase (scrypt, `identity.age` only), an X25519 identity (the
  keystore's own, and the recovery identity), and the Secure Enclave in
  `writ-platform-macos`. `SecretFiles` (the one seam a secret is read through) holds a list of
  them. Later backends (YubiKey PIV, TPM, KMS Decrypt) are more implementations.
- **The Secure Enclave recipient:** a CryptoKit `SecureEnclave.P256.KeyAgreement` key, made
  and used through M7.5's `writ-se` helper: `writ-se/1` gains `create-agreement` and `agree
  <stored> <point>` (the ECDH shared secret, checked for its length; the point checked on the
  curve before it is sent). Its blob is framed like a signing key's, with its own kind, and
  kept in `recipients/` in the keys directory, beside its public half: it can't be sealed to
  the identity it unwraps, and is usable only by that Mac's Secure Enclave, under `_writd`.
  No prompt (no access-control flag needing a user).
- **The stanza: `piv-p256`**, as age-plugin-yubikey and age-plugin-se write it (an ephemeral
  P-256 point, compressed, and a 4-byte tag of the recipient; HKDF-SHA256 over the shared
  secret; ChaCha20-Poly1305 over the file key), implemented in Writ's own Rust
  (`writ-crypto`): no plugin binary is ever run. The recipient prints as age-plugin-se's
  `age1se1…`. Checked against the plugins' own test vectors. A YubiKey or TPM recipient later
  reuses the same code with its own ECDH.
- **The recovery identity:** `writ recovery new`, best run on an offline machine, prints an
  age X25519 secret key once (for paper; never written to disk) and its recipient; any
  `age-keygen` identity works too. The recipient is registered with `recipient add recovery`.
  With it the daemon writes a **recovery challenge** (`recovery-check.age`: a random value
  wrapped to the recovery recipient, and that value's SHA-256), read with a reader key;
  `writ recovery check` reads the secret key on stdin and proves it opens the challenge,
  sending nothing back. Recovered files open with stock `age -d -i`.
- **Per use, no cache:** a token is unwrapped when an operation needs it (an HTTPS push or
  fetch, a proxy's password), handed on, and wiped; a token that can't be unwrapped (its key
  removed, the device refusing) denies that operation with the reason, the daemon running.
  With a hardware keystore the identity itself is wiped once the unseal opened the keys: a key
  made later is sealed to the identity's recipient (public), so an idle daemon's memory holds
  no identity and no token (the software signing keys, outside auto-unseal, stay as M5 left
  them). The notification tokens stay opened at unseal (exempt: a notification grants
  nothing).
- **Unseal:** `writ info` says how the keystore unseals; `writ unseal` asks for the passphrase
  only for a passphrase keystore, and always for the approver's signature. `writd recover`
  takes the recovery identity (stdin), or the passphrase on a passphrase keystore, never the
  hardware alone.
- **The CA behind the `Signer`:** the CA's certificates are signed through a `Signer` adapter,
  so the CA key can live on any backend (P-256 on the Secure Enclave). `writd init
  --ca-backend`; `writ admin ca show` and `writ admin ca rotate [--backend]`, a signed
  `writ-ca/1` bound to the CA in force, live: new certificates come from the new CA, and the
  gateway keeps trusting the old CA's public key only until the last lease it certified ends
  (bounded by the longest TTL), then drops it, one `admin` line each way.
- **Auto-unseal:** `unseal: auto` in `writd.yaml` (default `approver`). At start, the daemon
  checks the keystore unseals by hardware + recovery, the CA and every declared key on a
  hardware backend, and no token encrypted to anything else; anything else refuses the start
  naming each one. The start is logged (`unseal`, "automatic") and notified.
- **Ruled out: keys derived from a signature** (sign a fixed challenge, hash it into a key).
  It needs a key that signs the same bytes the same way every time: Ed25519 does, but the
  Secure Enclave's, the TPM's and most KMS P-256 ECDSA signatures are randomized, so the same
  input never gives the same key. Decrypting keys (ECDH, KMS Decrypt) are made for this.
- **Ruled out: age 1.3's `p256tag`** (the newer tagged recipient): our age crate lacks it and
  its spec is newer; `piv-p256` is what both hardware plugins already write. **Writ's own
  stanza:** new crypto to review for no gain.

## Threat model impact

- A compromised agent gets nothing, as today.
- Disk theft, backups and images of the daemon host get only ciphertext; a memory dump of an
  idle daemon gets no secret.
- **Root on a live host is not stopped:** it can ask the hardware to unwrap as the daemon
  does, and unlike a signing key (whose use yields one signature, only while on the host) one
  unwrap yields the secret itself, usable from anywhere until it expires or is revoked. The
  [threat model](../threat-model.md) says so; secrets as narrow and short-lived as their
  remote allows ([narrower upstream credentials](README.md#narrower-upstream-credentials))
  limit what that leaves.
- The Secure Enclave key's blob is a plain file under `_writd`: a copy restored on the same
  Mac (a backup) unwraps again; removing the key means removing every copy.
- The recovery identity opens everything: it is kept offline, and checked without being
  typed on a networked machine if the operator follows the guide.
- With a cloud KMS: a trusted third party (the provider and the account holding the key), and
  a network call on each use, failing closed.

## Open questions

Answered at M7.6's start (the [decision log](../decisions.md), 2026-11-13): the `piv-p256`
stanza; no cache; the recovery identity made by `writ recovery new` (or `age-keygen`) and
checked by `writ recovery check` against the daemon's challenge.

## Acceptance

[M7.6's checklist](../roadmap.md#m76--hardware-wrapped-secrets).

## Plan

Each step leaves Writ working, `make ci` and `make e2e` passing, its docs and registries in
the same commit.

1. **The unwrap interface:** `KeystoreUnlock` → `KeystoreUnwrap` (`writ-platform`), its
   contract suite and fake; the passphrase and the X25519 identity as its first
   implementations; `SecretFiles` over a list of them; platform.md, AGENTS.md and the
   contract docs renamed.
2. **Secrets per use:** the upstream tokens and the proxies' passwords unwrapped per
   operation through `SecretFiles` and wiped after (`writ-mirror` takes a token source, not a
   token); a token that can't be unwrapped denies that operation with its reason; `writ admin
   token` checks the new token the same way.
3. **`piv-p256` and the recovery identity:** the stanza in `writ-crypto` (wrap to a point;
   unwrap from any ECDH), against the plugins' vectors and hostile stanzas; `writ recovery
   new` and `writ recovery check`.
4. **The Secure Enclave recipient:** `create-agreement` and `agree` in `writ-se/1` and the
   fake helper (every fault), the framed agreement blob, `KeystoreUnwrap` over the helper in
   `writ-platform-macos`, the contract on the real Secure Enclave. The graft test.
5. **The recipients by signed admin change:** `writ admin keystore show | recipient add |
   recipient remove`, `writ-keystore/1`, the live re-encryption and its recovery at start, the
   recovery challenge, `writd init --recipients`, the identity wiped after unseal.
6. **Unseal with no passphrase:** `writ info`'s unseal way, `writ unseal` asking only what the
   keystore needs, `writd recover` with the recovery identity.
7. **The CA behind the `Signer`:** the adapter, the CA key file naming its backend, `writd
   init --ca-backend`, `writ admin ca show | rotate [--backend]`, the old CA trusted until its
   last lease ends.
8. **Auto-unseal:** `unseal: auto`, the start check naming each software key or secret, the
   start logged and notified, `writd recover` needing the recovery identity.
9. **The operator guide and the checks:** the auto-unseal section; its commands that need no
   hardware (the recovery identity, `keystore show`, the refusal with a software key left) run
   in `make e2e` on Linux, those that need the Secure Enclave by an integration scenario on
   the Mac's real one, the whole section followed in the [manual checks](../guides/manual-checks.md)
   (for M7.7); the threat model and the security inventory gone over once more.
