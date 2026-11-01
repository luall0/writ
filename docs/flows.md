# Flows

All flows are the same in detached and local mode, except where noted. The objects they move
(tickets, leases, templates) are defined in [Lease model](lease-model.md); the components in
[Architecture overview](architecture/overview.md).

## 1. Ticket: submit, review, sign or refuse

```mermaid
sequenceDiagram
  actor Me
  participant A as Agent (Writ skill + writ CLI)
  participant D as writd
  participant AP as writ sign (Mac)
  participant SC as Secretive
  Me->>A: "build feature X on omega-code"
  A->>A: think through scope, write ticket (task, plan, repos, branches, limits)
  A->>A: writ request → generates session key
  A->>D: submit ticket + session pubkey
  alt doesn't fit any template
    D-->>A: rejected_by_policy + reason
    A->>A: revise ticket, resubmit
  else fits a template
    D->>D: state = pending
    D-->>Me: notification: "ticket waiting" (also printed by the agent)
    Me->>AP: writ sign
    AP->>D: fetch canonical ticket
    AP->>Me: shows ticket: task, plan, scope, limits, template, diff vs previous revision
    alt I sign (optionally narrowing values first)
      AP->>SC: ssh-keygen -Y sign -n writ-approval (narrowed ticket)
      SC->>Me: Touch ID
      SC-->>AP: SSHSIG
      AP->>D: approval (SSHSIG)
      D->>D: verify signature + signed ticket ⊆ submitted, state = active, log GRANT
      D-->>A: final lease (narrowed values, if any) + SSH certificate (valid until lease expiry)
      A->>A: write key + cert, configure git
    else I refuse
      Me->>AP: reason ("don't touch billing")
      AP->>D: refusal + feedback
      D-->>A: refused + feedback
      A->>A: revise plan, resubmit as revision n+1
    end
  end
```

When a harness (e.g. Omega Code) requests the lease on the agent's behalf, it plays the
`writ request` part and writes the key, certificate and git config itself.

On the wire (M2): `writ request` connects to the agents' listener as user `writ` with the new
session key and runs `writ request` (the ticket file on stdin); the key it authenticated with
becomes `subject.session_key`. It then runs `writ wait <id>` on the same connection, which
returns once I decide: the lease (canonical bytes) and the certificate, the feedback, or
`expired` / `revoked`. Only that session key can wait on the ticket. The session lands in
`~/.writ/sessions/<lease>/` (`key`, `key.pub`, `key-cert.pub`, `ticket.json`, `lease.json`,
and `signing_key.pub`, the daemon's key for the lease's commits),
with `current` pointing at it. `writ request` exits 0 when granted, 3 when rejected by
policy, 4 when refused, 5 when the ticket expired or was withdrawn. `writ sign` and
`writ refuse` reach the approval listener ([Approvals](architecture/approvals.md#reaching-the-daemon)).

## 2. Signed commit

```mermaid
sequenceDiagram
  participant G as git
  participant S as writ-sign
  participant D as writd
  participant SG as Signer backend
  G->>S: -Y sign -n git -f key /tmp/obj
  S->>S: first parent commit + trees that differ (git cat-file, diff-tree)
  S->>D: writ-sign git <repo>: the commit + those objects, over SSH, session cert
  D->>D: objects read by the ids computed from their bytes → touched paths
  D->>D: cert → lease, object type, committer email,<br/>Writ trailer (if ticket_link = trailer), paths vs expected_paths, count, rate
  alt allowed
    D->>SG: sign(SSHSIG signed data), key = template's signing_key
    SG-->>D: signature
    D->>D: log SIGN, count it, ledger += id of the commit with its signature in it
    D-->>S: armored SSHSIG
    S-->>G: /tmp/obj.sig, exit 0
  else denied
    D->>D: log DENY (on_violation: revoke_lease → revoked)
    D-->>S: reason
    S-->>G: exit 1 (git prints the reason)
  end
```

Signing happens at **commit time** so commit hashes never change. The ledger links signing to
the later push: it records the id of the commit git writes once the signature is in it (git
puts it in a `gpgsig` header, `writ_git::signed`), so the same commit without its signature,
which has another id, never matches. Denial notifications come with M8.

## 3. Push

```mermaid
sequenceDiagram
  participant G as git (agent)
  participant D as writd gateway
  participant Q as Quarantine
  participant F as Remote (upstream)
  G->>D: git push writ agent/x (session cert)
  D->>Q: receive pack
  D->>D: checks: lease covers push + repo,<br/>ref matches agent/*, no force push,<br/>every new commit in ledger for this lease,<br/>size limits
  alt accepted
    D->>F: push agent/x with daemon credentials
    alt upstream ok
      D->>D: update mirror refs, log PUSH
      D-->>G: ok
    else upstream rejects (e.g. non-fast-forward)
      D-->>G: rejected + upstream reason
    end
  else denied
    D->>D: log DENY, notify
    D-->>G: rejected + reason
  end
```

If upstream moved, the agent fetches through the daemon, rebases, and the new commits are
signed again under the same lease.

### 3b. Push, `proxy` mode
The agent connects to the daemon (same URL rewrite).

1. The daemon reads `git-receive-pack '<path>'` and the ref update lines: checks repo, refs,
   protected refs and force push.
2. It buffers the pack into a temporary quarantine (bounded by `max_push_size`) and indexes it
   with `git index-pack`.
3. It walks the new commits and checks each one against the ledger for this lease.
4. Only then does it open its own SSH session to the remote and relay the ref updates and the
   pack.
5. The quarantine is deleted; the remote's answer goes back to the agent. Any rejection shows
   in the agent's terminal, as with `gateway`.

To find which commits are "new" without a mirror, the daemon first asks the remote for its
current refs (the advertisement at the start of the upstream session), relays them to the
agent, and uses them as the boundary.

The daemon advertises the `no-thin` capability to the agent, so the pack is self-contained: it
can be indexed and every commit object in it read without having the remote's objects locally.
Commits in the pack are exactly the new commits to check.

### 3c. Push, `direct_ssh` mode
At lease grant, the daemon also exposes a per-lease ssh-agent socket (reachable through the
session channel) holding only the repo's deploy key. Each signature request is checked for
host (`session-bind`), user, limits and TTL. The remote enforces the repo; nothing enforces
refs.

## 4. Fetch

`git fetch writ` → the daemon syncs its mirror from upstream if stale, then serves
`upload-pack`. Requires a lease with `fetch` (or a read-only template). Agents never hold remote
credentials, even read-only ones.

## 5. Revoke / expire

- `writ revoke <id>`, menu bar, phone → lease `revoked`, certificate added to the deny list,
  open sessions dropped (the gateway disconnects every SSH session of that certificate). With
  `decisions: signed`, the revocation is an SSHSIG over a `writ-revocation/1` document. On a
  pending ticket, `writ revoke` withdraws it.
- TTL reached → `expired`; every counted operation used up → `exhausted` (never with
  `fetch`, [lease model](lease-model.md#lifecycle)); notify. The daemon checks every second
  and before every request; the certificate itself ends at `expires_at`, and open sessions
  are dropped like on a revocation. A pending ticket not signed by `expires_at` expires too.
- Local mode: session root process exits → `revoked`
- Violation with `on_violation: revoke_lease` → revoked + notify

## 6. Out-of-ticket request

**Deny + notify.** The operation fails immediately with a reason the agent can read, plus a
hint: *"outside ticket wrt_…: branch main not allowed. If needed, submit an amendment."*

If the agent genuinely needs more, the skill tells it to submit an **amendment**
(`amends: <id>`) explaining why. I sign or refuse it like any ticket. The denied operation is
not replayed; the agent retries after the amendment is signed.

## 6b. Closing a ticket

When the work is done, the agent runs `writ close` with a short summary. The daemon:
- ends the lease and revokes the certificate
- produces an **activity report**: commits signed, pushes, branches, denials, time used vs
  granted, files touched vs `expected_paths`

I review the report alongside the branch before merging.

## 7. Daemon startup: sealed

```mermaid
sequenceDiagram
  participant D as writd
  participant U as writ unseal (Mac)
  participant SC as Secretive
  actor Me
  D->>D: start sealed (only unseal endpoint served)
  D-->>Me: notification: "writd restarted, sealed"
  Me->>U: writ unseal
  U->>Me: keystore passphrase prompt
  U->>SC: sign unseal request (namespace writ-approval)
  SC->>Me: Touch ID
  U->>D: passphrase + SSHSIG over the authenticated channel
  D->>D: verify approver, decrypt keystore in memory, log UNSEAL
  D->>D: reload active leases from SQLite
```

Until unsealed, every request fails closed with "daemon sealed". Later, hardware recipients
replace the passphrase.
