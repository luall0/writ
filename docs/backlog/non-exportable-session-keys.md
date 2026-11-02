# Non-exportable session keys

**Status:** specified; picked as [M8.5](../roadmap.md#m85--non-exportable-session-keys).
**Area:** Identity. **Kind:** hardening. **Size:** M.

## Problem

The session key is the lease holder's whole identity ([Identity](../architecture/identity.md)).
`writ request` creates it as an Ed25519 file, `~/.writ/sessions/<lease>/key`, before any
approval; the daemon certifies its public half when the lease is granted, and every later call
(push, fetch, `writ-sign`) proves possession of the private half. Malware on the agent host can
copy that file with its certificate and act as the lease holder from any address the gateway
admits, until the lease expires or is revoked. The certificate alone is worthless; the key is
what to protect.

```
 agent host                               daemon
 writ request ── creates the key (file today, hardware here)
              ── ticket + public key ───► stores the ticket ◄── writ sign (approver)
                                          lease granted: certificate for that public key
              ◄── certificate ──────────┘
 git push/fetch, writ-sign
   ssh: key + certificate ──────────────► gateway checks the certificate against the lease
```

## Proposal

The session key lives in hardware that can't export it, held by a Writ session agent on the
agent host: malware there can use it during the lease, never copy it.

- **On when the host can, off when it can't, never switched silently.** The first
  `writ request` with no recorded choice detects the hardware for real (a throwaway key made
  and used), records `hardware` or `file` in `~/.writ/`, and prints what it chose and how to
  change it.
- `writ session-key` shows the choice and what the host supports;
  `writ session-key hardware|file` changes it for later leases (current ones keep their key);
  `WRIT_SESSION_KEY` overrides it, for containers and scripts.
- A recorded `hardware` that stops working (a TPM disabled, an image moved) makes
  `writ request` refuse with a reason; re-detecting or switching is the user's explicit act.
- The ticket carries the session key's kind (`hardware: secure-enclave`, `hardware: tpm`,
  `file`) and `writ sign` shows it to the approver.

## Scope and non-goals

- In M8.5: the Secure Enclave (Mac) and a TPM 2.0 (Linux), one key per lease.
- Not a YubiKey: a few PIV slots, so a key would be reused across leases. Later, if wanted.
- Not enforced by the daemon: it can't tell where a key lives. Requiring it per template needs
  attestation (open questions).
- Never the user's own ssh-agent or keys (hard rule 8).

## Design

- **Why a client setting:** the private key is made and used only on the agent host; the
  daemon sees its public half, which reads the same from a file, the Secure Enclave or a TPM.
  Clients are untrusted (hard rule 1), so the setting is the agent host's hardening, and the
  ticket's kind is a claim shown as information (hard rule 6), checked only for consistency
  with the key (Ed25519 can't be `hardware`).
- **The session agent** speaks the ssh-agent protocol: git's `ssh` reaches it through
  `IdentityAgent` in the session's git config, `writ` through the same socket; it makes one key
  per lease (an agent extension message) and forgets it when the session goes.
- **A client-side platform seam:** `writ-platform*` is the daemon's today, and clients never
  depend on it. Where a session key lives becomes an interface with its contract suite and a
  fake, in client platform crates; the dependency directions and conventions change first.
- **The daemon:** already takes Ed25519 and P-256 session keys; it gains the ticket's kind,
  its validation and its display, nothing else.

## Threat model impact

- Malware on an agent host with a hardware session key can use the lease while it runs there,
  never from elsewhere; the residual risk "session key theft on an agent host" narrows to that.
- The agent itself can switch to `file` (same host, same user): it doesn't need to steal its
  own key, so the feature isn't against the agent; the ticket's kind makes a downgrade visible
  to the approver.
- Local mode gains little: the Unix socket and the process chain already refuse a copied key.

## Open questions

- The session agent's binary name (AGENTS.md's naming table).
- Attestation: a TPM can prove a key lives in it (a chain to the maker's certificate), so a
  template could require `attested`; the Secure Enclave can't without App Attest (a paid
  Apple account).
- The session agent's lifetime: per session, or one per host serving every session.

## Acceptance

[M8.5's checklist](../roadmap.md#m85--non-exportable-session-keys).

## Plan

Written when M8.5 starts.
