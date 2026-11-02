# Hardware-wrapped secrets

**Status:** specified; picked as [M7.6](../roadmap.md#m76--hardware-wrapped-secrets).
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
- Not a generic secret store for agents ([non-goals](../product.md#non-goals)): only the
  daemon's own secrets.

## Design

- **Keystore format (M5):** one age file per secret, each encrypted to the recipient of an
  age X25519 identity that the passphrase unlocks at unseal. M7.6 changes which recipient a
  secret's file is encrypted to, not the format.
- **Interface (M7.6):** `KeystoreUnlock` generalized into a recipient that unwraps one
  secret's file key, in `writ-platform` with its contract suite and a fake
  ([platform interfaces](../architecture/platform.md)); implementations in `writ-platform-*`
  (the Secure Enclave in `writ-platform-macos`, through M7.5's Swift component) or
  `writ-signer` (portable hardware, behind Cargo features).
- **Recipients:** ECDH on P-256 in the Secure Enclave, a YubiKey PIV slot or a TPM (the age
  plugin format: `age-plugin-se`, `age-plugin-yubikey`, `age-plugin-tpm`), or a KMS's
  Decrypt.
- **Ruled out: keys derived from a signature** (sign a fixed challenge, hash it into a key).
  It needs a key that signs the same bytes the same way every time: Ed25519 does, but the
  Secure Enclave's, the TPM's and most KMS P-256 ECDSA signatures are randomized, so the same
  input never gives the same key. Decrypting keys (ECDH, KMS Decrypt) are made for this.

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
- With a cloud KMS: a trusted third party (the provider and the account holding the key), and
  a network call on each use, failing closed.

## Open questions

- The age plugin formats as they are (compatible with `age-plugin-se` and others), or Writ's
  own stanza?
- A short in-memory cache per secret (exposure traded for speed), once the HTTP proxy needs
  one unwrap per request?
- Where the recovery identity is made and checked, so it's known to work before it's needed.

## Acceptance

[M7.6's checklist](../roadmap.md#m76--hardware-wrapped-secrets).

## Plan

Written when M7.6 starts.
