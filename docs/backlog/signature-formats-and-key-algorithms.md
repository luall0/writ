# Signature formats and key algorithms

**Status:** specified; picked as [M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms).
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

- The exact signature of the new `Signer::sign` (an enum of message or digest, or two
  methods), settled with the contract tests before any backend changes.
- Whether the upstream credentials (`ssh://` repos) get the same declaration (algorithm,
  backend), or stay as M4 makes them.
- Whether a key can also be created through the running daemon (a signed admin change), on
  top of `writd keys create`.
- Certificate expiry (an OpenPGP key expiration subpacket), renewed by a signed admin change:
  wanted, or left out?
- P-256 with SHA-384 or SHA-512 in OpenPGP: GnuPG accepts it; to be checked on GitHub and
  Forgejo before it is a default (otherwise the default for P-256 is SHA-256).

## Acceptance

[M5.5's checklist](../roadmap.md#m55--signature-formats-and-key-algorithms).

## Plan

Written when M5.5 starts.
