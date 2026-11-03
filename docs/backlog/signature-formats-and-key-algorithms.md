# Signature formats and key algorithms

**Status:** in progress as [M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms).
**Area:** Signers, Clients. **Kind:** feature. **Size:** L.

## Problem

Writ signs commits in one format, SSH (`gpg.format = ssh`, an SSHSIG in namespace `git`), with
the one algorithm the development keystore generates (Ed25519), and nothing declares a key: a
template's `signing_key` is generated on first start. Many people keep an OpenPGP key for
their commits, separate from their SSH keys, and some tooling and remotes only know OpenPGP
signatures. And the operator can't choose a key's algorithm or hash, nor learn at start that
the backend they picked can't hold it (the Secure Enclave does P-256 only).

The goal is to support as many of git's signature formats as possible, starting with OpenPGP,
behind a seam where the next one (`x509`, [backlog](README.md#x509-commit-signatures)) plugs in
without touching the core.

## Proposal

Each agent signing key is **declared**, with its format, algorithm, hash and backend, checked
against the backend when the daemon starts, and created by an explicit command:

```yaml
# writd.yaml: deployment choices, checked against the signer at start
signing_keys:
  agent-gpg:
    format: openpgp          # ssh | openpgp
    algorithm: p256          # ed25519 | p256 | p384 | rsa3072 | rsa4096
    hash: sha512             # optional; the strongest the format, algorithm and backend allow
    backend: software        # software | se-cryptokit (M7.5) | …
  agent-ssh:
    format: ssh
    algorithm: ed25519
    backend: software

# policy.yaml: binding an identity to a key is a signed admin change (M5)
signing_keys:
  agent-gpg:
    uids: ["Your Name <user+agent@example.org>"]
```

- **One format per key.** The same key material could make both kinds of signature; a key id
  is one or the other, so its audit trail and its registrations on remotes stay simple, and no
  signature of one format can be read as the other.
- **The config is refused, never adjusted.** The daemon refuses to start, naming the key and
  the reason, on: a format × algorithm pair it doesn't support; an algorithm × hash pair the
  format doesn't allow; a backend that can't hold the algorithm or sign with that hash (the
  Secure Enclave with `ed25519`; an ssh-agent backend with `p256` and `sha512` in OpenPGP,
  since an ssh-agent hashes P-256 with SHA-256 itself); a declared key missing from the
  keystore, or held with another algorithm or format; an OpenPGP key whose templates allow a
  committer email that none of its UIDs carry (the remote would show those commits
  unverified); a template naming an undeclared key.
- **`hash` is optional:** left out, Writ takes the strongest the format, algorithm and backend
  allow; set, it is checked like the rest. Nothing below SHA-256 exists to choose.
- **Keys are created on purpose:** `writd keys create <writd.yaml> <id>` (run as the daemon's
  user, so in local mode under `_writd`) makes the key the declaration describes, writes it to
  the keystore (an age file to the keystore's recipient, which needs no unsealing), logs it,
  and prints what to register on remotes: the SSH public key, or the armored OpenPGP
  certificate. The development keystore keeps generating missing keys on first start (refused
  by release builds), now following the declaration.
- **Git on the agent host:** for an OpenPGP key, `writ init` writes `gpg.format = openpgp`,
  `gpg.openpgp.program = writ-sign` and `user.signingkey = <fingerprint>`; the session holds
  `signing_key.asc` beside `signing_key.pub`. The agent needs no `gpg` to sign.
- **Proving a key:** `writ prove-key` gains an OpenPGP variant, for Forgejo and Gitea's
  challenge (`/user/gpg_key_token`, `/user/gpg_key_verify`): a detached signature over the
  token, behind the approver's signature as today.

## Scope and non-goals

- In M5.5: the SSH and OpenPGP formats; Ed25519, P-256, P-384, RSA 3072 and RSA 4096 in the
  software backend; the hash per key; the startup checks; `writd keys create`.
- Not `x509` (gpgsm, S/MIME): the format is an open enum with one encoder per format, and
  `x509` is [its own idea](README.md#x509-commit-signatures).
- Not RSA 2048 (about 112-bit security, deprecated by NIST after 2030): refused with a reason.
- Not OpenPGP v6 keys (RFC 9580): GnuPG doesn't read them; keys are v4, Ed25519 as GnuPG's
  EdDSA (algorithm 22).
- Not tag signing, still a [non-goal](../product.md#non-goals) (Q11).
- Not the upstream credentials or the TLS key: their algorithm stays as M4 and M5 make them
  (an open question below).
- Never the user's own GnuPG keys or `~/.gnupg` (hard rule 8): tests use a throwaway
  `GNUPGHOME`, and `writ-sign` passes only `--verify` to the real `gpg`.

## Design

- **Formats and algorithms in `writ-crypto`** (pure, no I/O): one encoder per format behind a
  small seam (what to hash and sign for a payload, how to wrap the signature: armored SSHSIG,
  or an armored OpenPGP signature packet), and the table of what each format accepts:

  | Format | Algorithms | Hashes (default: the strongest) |
  |---|---|---|
  | `ssh` | Ed25519, P-256, P-384, RSA | The SSHSIG message hash: `sha256`, `sha512`. ECDSA's own hash is fixed by its SSH algorithm (P-256 → SHA-256, P-384 → SHA-384); RSA signs as `rsa-sha2-256` or `rsa-sha2-512` to match, never `ssh-rsa` (SHA-1) |
  | `openpgp` | Ed25519 (EdDSA, algorithm 22), P-256, P-384 (ECDSA), RSA | `sha256`, `sha384`, `sha512` (the digest signed; ECDSA truncates it to the curve's size) |

  The OpenPGP side builds v4 signature packets (hashed subpackets: creation time, issuer
  fingerprint) and the certificate (public key packet, its creation time stored for good since
  the fingerprint depends on it, a UID packet and self-signature per UID). Candidate crates:
  `pgp` (rPGP, MIT/Apache-2.0) if it signs through an external signer, else a minimal v4
  writer; `sequoia-openpgp` is LGPL, outside the license allow-list. The daemon only writes
  OpenPGP, never parses it from an agent: no new untrusted input on the daemon.
- **The `Signer` interface learns the hash** (hard rule 4: the trait, its contract tests and
  the docs first). `sign` takes what to sign and the hash to use (a message the backend
  hashes, or a digest already computed where the backend signs digests), and
  `Capabilities` lists what a backend *supports* (the (algorithm, hash) pairs it can create
  and sign with), not only the algorithms of the keys it holds. The startup check reads it.
  Signatures still come back in SSH encoding; a small adapter turns them into OpenPGP MPIs, as
  the M5 TLS adapter turns them into DER. The contract suite gains a section run by every
  backend: each declared pair signs and verifies (with the real `gpg` and `ssh-keygen` in
  integration tests), an undeclared one is refused by name.
- **RSA in the software backend through `aws-lc-rs`**: it generates and signs RSA in constant
  time. The `rsa` crate stays banned (`deny.toml`: the Marvin timing side channel, and agents
  can ask for signatures and time them). `ring` stays rustls' provider; Ed25519, P-256 and
  P-384 stay pure Rust (`ed25519-dalek`, `p256`, `p384`). `aws-lc-rs` brings C and assembly
  built by cargo: a C compiler in the Docker build, and its licenses checked against the
  allow-list.
- **The sign command carries the format** git asked for (`-Y sign` or `-bsau`); the daemon
  picks the format from the lease's key, never from the client, and a mismatch is a denial
  with its own code (`DenyCode::SignatureFormat`), logged. The ledger is unchanged: git puts
  either format in the same `gpgsig` / `gpgsig-sha256` header, and the ledger hashes the
  commit with whatever is in it.
- **`writ-sign` as `gpg.program`:** git runs `<program> --status-fd=2 -bsau <key id>` with the
  payload on stdin and wants the armored signature on stdout and `[GNUPG:] SIG_CREATED` on the
  status descriptor; `writ-sign` sends the payload to the daemon as in SSH mode (same repo
  checks, same trees) and writes both. `--verify` goes to the real `gpg` (its path a client
  setting); anything else is refused.
- **UIDs are policy:** they live in `policy.yaml`, so adding or changing one is a signed admin
  change (M5); the daemon then makes the new self-signatures through the `Signer` and logs
  them. `writd signing-keys` prints each key's certificate.
- Docs: [signer](../architecture/signer.md), [clients](../architecture/clients.md),
  [gateway](../architecture/gateway.md#signing), [flows](../flows.md#2-signed-commit), the
  operators' references for both files and the client settings, the
  [stack](../stack.md) (the OpenPGP crate, `aws-lc-rs`), the [threat model](../threat-model.md),
  the [product](../product.md) scope.

## Threat model impact

- **New asset: the OpenPGP certificate**, made by the daemon, binding an email to an agent key
  that remotes then trust as the user's, like an SSH signing key registered on the account
  today. Binding a UID is a signed admin change, never a config edit alone.
- **No cross-format confusion:** a key signs in one format only, and the daemon builds every
  signed byte (the commit payload checked as today, then the format's own framing).
- **No weak choice:** no SHA-1, no RSA under 3072, no `ssh-rsa`; the startup check refuses
  what the backend can't do instead of signing something else.
- **A new dependency in the signing path:** `aws-lc-rs` (C) for RSA keys only; the timing side
  channel the banned `rsa` crate has is why.
- **Agent hosts:** the operator's own GnuPG agent is to the agent what their ssh-agent is: out
  of its reach ([good practice](../operators/good-practice.md)); Writ never uses it.
- An OpenPGP signature carries the daemon's time: shown by remotes, never a guarantee.

## Open questions

Settled when M5.5 started ([decision log](../decisions.md), 2026-11-03):

- **`Signer::sign` takes the bytes and the hash, one method:** `sign(id, data, hash)`, where
  `hash` is `None` for an algorithm that signs the bytes themselves (Ed25519, pure EdDSA) and
  `Some(sha256 | sha384 | sha512)` for one that signs a digest (ECDSA, the digest truncated to
  the curve; RSA, PKCS#1 v1.5 with the hash's `DigestInfo`): the backend hashes. A backend
  that signs only digests hashes itself; one that signs only messages with a fixed hash (an
  ssh-agent's P-256) declares only that pair. It answers a `RawSignature` (the algorithm,
  the hash and the signature in one fixed encoding: Ed25519's 64 bytes, ECDSA's `r ‖ s`, RSA's
  `s`), which small adapters turn into SSH, DER (TLS) or OpenPGP MPIs: an SSH `Signature`
  can't say "RSA with SHA-384".
- **The upstream credentials stay as M4 makes them** (Ed25519, SSH, software), not declared.
- **A key a signed policy change names** is made from its declaration (format, algorithm,
  creation time) and handed over through `Signer::add_key(id, KeyPair)`: `KeyPair` is
  `writ-crypto`'s own private key type (Ed25519, P-256, P-384 through `ssh-key`, RSA through
  `aws-lc-rs`), since `ssh-key`'s `PrivateKey` signs RSA only with the banned `rsa` crate. A
  key the configuration doesn't declare is refused before anything is made.
- **No certificate expiry** in M5.5: a key is retired by taking it out of the configuration;
  an expiration renewed by admin changes stays a later idea.
- **OpenPGP ECDSA signs with its curve's hash only** (P-256 with SHA-256, P-384 with
  SHA-384: RFC 6637's pairing, which every implementation verifies); nothing larger is
  offered until a remote is checked to verify it.
- **Q28:** not `pgp` (rPGP depends on the banned `rsa` crate): a minimal v4 writer in
  `writ-crypto`; `aws-lc-rs` confirmed for RSA.
- **Certificates are deterministic:** every self-signature carries the key's creation time,
  and Ed25519, RSA PKCS#1 v1.5 and the software backend's ECDSA (RFC 6979) are deterministic,
  so the certificate is a function of the key, its creation time and its UIDs: the daemon
  makes it again at unseal and on each policy change, and no certificate is state to keep
  in step.
- **The key file:** an agent signing key's sealed plaintext stays an OpenSSH private key for
  an SSH key made before M5.5 (read as `format: ssh`); a key made from a declaration is a
  `writ-key/1` text (format, algorithm, creation time for OpenPGP, then the private key: an
  OpenSSH key, or PKCS#8 for RSA). Its public half beside it says the same, in clear, so
  the print commands need no unseal; the two are checked against each other at open.

## Acceptance

[M5.5's checklist](../roadmap.md#m55--signature-formats-and-key-algorithms).

## Plan

One commit per step, each with `make ci` (and `make e2e` when a binary changed):

1. **This plan** (docs).
2. **The `Signer` seam:** `writ_crypto::algorithm` (`KeyAlgorithm`, `Hash`, `SignatureFormat`,
   the table of what each format takes and its default hash), `KeyPair`, `RawSignature` and
   its SSH and DER adapters, `writ_crypto::verify` (a raw signature checked in Rust, for the
   contract); `Signer::sign(id, data, hash)`, `Capabilities::pairs`, `SignerError::Unsupported`
   naming the pair, `add_key(id, KeyPair)`; the contract suite signs and verifies every pair
   the backend declares for each key it holds and refuses an undeclared one by name; the
   software backend adds P-384; the SSHSIG hash a parameter. The signer page first.
3. **RSA through `aws-lc-rs`:** RSA 3072 and 4096 in `KeyPair` (generated, PKCS#8, signed in
   constant time), the software backend's RSA pairs, SSH's `rsa-sha2-256` and `rsa-sha2-512`;
   `deny.toml` still bans `rsa`; the stack page.
4. **Keys declared:** `signing_keys` in `writd.yaml`, `signing_keys.<id>.uids` in
   `policy.yaml`; every refusal at start (and on a policy change: a template naming an
   undeclared key, an email without a UID), each with its exact reason; `writ-key/1`; the
   development keystore, `writd init` and signed policy changes making keys from their
   declaration; `writd keys create`; the operator references, the configuration registry.
5. **OpenPGP signatures:** `writ_crypto::openpgp` (v4 public key, UID and certificate,
   detached binary signatures, armor); the service signs in the key's format; `writ-sign
   openpgp <repo>` beside `writ-sign git <repo>`, a mismatch denied with
   `DenyCode::SignatureFormat`; certificates made at unseal and on a policy change, the
   UIDs certified in the change's audit line; the grant carries the format and the
   certificate; `writd signing-keys` prints it; the real `gpg` verifies each algorithm.
6. **Clients:** `writ-sign` as `gpg.program` (`--status-fd=2 -bsau`, `SIG_CREATED`;
   `--verify` to the real `gpg`, `WRIT_GPG`), `signing_key.asc`, `writ init`'s OpenPGP
   settings, `writ prove-key` for an OpenPGP key; a hostile `GNUPGHOME` and agent socket
   never used.
7. **End to end:** an OpenPGP key proved on Forgejo, an agent's commit verified there; every
   new command, flag and key in its registry.
8. **Docs and history:** threat model, product, the history page.
