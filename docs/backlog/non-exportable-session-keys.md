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

- **The template decides the mode, never the ticket:** a template term
  `session_key: hardware | file` (default `file`), edited from the CLI like every template
  field (`writ admin template`). The ticket carries its key's kind (`hardware: secure-enclave`,
  `hardware: tpm`, `file`), which `writ sign` shows, and it must be the template's mode
  exactly, or the ticket is refused by policy; there is no `any`. Over several repositories
  their templates must name the same mode (one key per lease).
- **A client setting, `session_key: auto | hardware | file`** (the settings file, default
  `auto`): what this host may make, never what a lease gets. `auto` makes what the template
  asks for; `hardware` or `file` makes only that kind, and `writ request` refuses a template
  asking for the other. A hardware key the host can't make (no hardware, a TPM disabled, an
  image moved) is a refusal, never a fallback to a file.
- **Switched from the CLI:** `writ session-key` shows the setting and what the host supports;
  `writ session-key auto|hardware|file` writes it for later leases (current ones keep their
  key); `WRIT_SESSION_KEY` overrides it, for containers and scripts. The installer's agent
  host setups ask it.

## Scope and non-goals

- In M8.5: the Secure Enclave (Mac) and a TPM 2.0 (Linux), one key per lease.
- Not a YubiKey: a few PIV slots, so a key would be reused across leases. Later, if wanted.
- Not proven to the daemon: it can't tell where a key lives, so the template's mode is
  enforced on the client's claim. A mode the daemon proves needs attestation (open questions).
- Never the user's own ssh-agent or keys (hard rule 8).

## Design

- **Why a client setting:** the private key is made and used only on the agent host; the
  daemon sees its public half, which reads the same from a file, the Secure Enclave or a TPM.
  Clients are untrusted (hard rule 1), so the setting is the agent host's hardening, and the
  ticket's kind is a claim, checked for consistency with the key (Ed25519 can't be
  `hardware`).
- **Why the template decides:** the operator decides, in the policy, which kind of key a
  repository's leases get; a ticket choosing its own mode would let the agent pick the weaker
  one. It is part of the structured scope, enforced within a template (hard rule 6), but over
  a claim: it refuses a host set up wrong, or a switch to `file`, before the approver sees the
  ticket; an agent that lies about its key passes it. The trust row says so. The client
  setting only limits what a host makes, so a host can never be made to fall back.
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
  to the approver, and a template's `session_key: hardware` refuses it unless the agent also
  lies about the kind.
- New residual risk: the template's mode trusts the client's claim. It adds no new way in
  (without it the kind isn't checked at all), but must not read as a guarantee.
- Local mode gains little: the Unix socket and the process chain already refuse a copied key.

## Open questions

- The session agent's binary name (AGENTS.md's naming table).
- Attestation: a TPM can prove a key lives in it (a chain to the maker's certificate), so the
  template's mode could gain `attested`; the Secure Enclave can't without App Attest (a paid
  Apple account).
- The session agent's lifetime: per session, or one per host serving every session.

## Acceptance

[M8.5's checklist](../roadmap.md#m85--non-exportable-session-keys).

## Plan

Written when M8.5 starts.
