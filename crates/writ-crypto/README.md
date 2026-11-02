# writ-crypto

The cryptography Writ needs, on top of `ssh-key` and `rustls`.

## What it does

- **SSHSIG** (`sshsig`): signing and verifying in OpenSSH's format, for commit signatures
  (namespace `git`) and approvals (`writ-approval`); the bytes to sign are built separately
  from the signing, so a `Signer` can hold the key.
- **The SSH certificate authority** (`ca`): session certificates for leases, and their checks
  (authority, validity window, principal, deny list).
- **The approvers file** (`allowed_signers`): git's `allowed_signers` format; every option is
  honored or refused, never ignored.
- **The readers file** (`readers`): the Ed25519 keys that may use the approval API, over SSH
  and as HTTPS client certificates (mutual TLS, checked in `tls`).
- **Keys and randomness** (`keys`): key generation and random bytes that fail instead of
  panicking.
- **The approval API's TLS** (`tls`): the self-signed certificate, its pin, the server
  identity (`TlsIdentity`) and the client config that accepts only the pinned certificate.
- **A passphrase a person types** (`passphrase`): its bounds, read with the terminal's echo
  off, or one line of stdin, a byte at a time into memory wiped on drop (`writd init`,
  `writ unseal`).

## Scope

- Primitives and formats only: where keys live is the `Signer`'s business (`writ-signer`), who may sign
  is the approval service's.
- Usable by clients (the CLI signs approvals and pins TLS with it) and by the daemon.

## Depends on

No other crate of the workspace.

## Docs

[Approvals](../../docs/architecture/approvals.md),
[Identity](../../docs/architecture/identity.md),
[Signer](../../docs/architecture/signer.md).
