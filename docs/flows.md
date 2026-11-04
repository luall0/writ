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
  D->>D: cert → active lease, commit_sign, repo (before reading the body)
  D->>D: objects read by the ids computed from their bytes → touched paths
  D->>D: cert → lease, object type, committer and author emails,<br/>Writ trailer (if ticket_link = trailer), paths vs expected_paths, count, rate
  alt allowed
    D->>D: under the lock: count and rate slot taken (never given back)
    D->>SG: outside the lock, through the queue (deadline): sign(SSHSIG signed data), key = template's signing_key
    SG-->>D: signature
    D->>D: under the lock: lease still the same, active, not expired, cert not on the deny list
    D->>D: log SIGN, ledger += id of the commit with its signature in it
    D-->>S: armored SSHSIG
    S-->>G: /tmp/obj.sig, exit 0
  else denied, or the lease ended or changed while signing (signature discarded)
    D->>D: log DENY (on_violation: revoke_lease → revoked)
    D-->>S: reason
    S-->>G: exit 1 (git prints the reason)
  end
```

The signer never runs under the service's state lock: a revocation, an approval or a `writ
wait` never waits for a device, and a lease revoked, expired or amended while its commit is
being signed gets no signature ([Policy and state](architecture/policy-and-state.md#policy-engine)).

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
  D->>D: lease covers push + repo (may_push), mirror synced unless fresh
  D->>Q: receive-pack: the pack, fsck'd, in quarantine
  Q->>D: pre-receive hook: token, quarantine, ref updates
  D->>D: lease again, mirror held, read from the objects git verified:<br/>new commits, fast-forwards, case twins, size, paths again
  D->>D: under one lock: ledger, decide_push (refs, protected refs, force push,<br/>every new commit signed under this lease with the same paths, size),<br/>count and rate, log PUSH
  alt accepted
    D->>D: lease once more
    D->>F: push --atomic --force-with-lease from the quarantine, daemon credential
    alt upstream ok
      D-->>Q: ok: git moves the mirror's refs
      D-->>G: ok
      opt ticket_link: notes
        D->>D: the commits wait for their note; once git gave the mirror back,<br/>the notes job: notes commit, merged into the notes ref
        D->>F: push the notes ref, fast-forward (moved: fetch, merge, once more)
        D->>D: log NOTES (allowed, or denied: the notes wait for the next push)
      end
    else upstream rejects (moved, its hook, an error)
      D->>D: log DENY with the remote's reason
      D-->>G: rejected + upstream reason (the mirror unchanged)
    end
  else denied
    D->>D: log DENY (on_violation applied)
    D-->>G: rejected + reason
  end
```

If upstream moved, the agent fetches through the daemon, rebases, and the new commits are
signed again under the same lease. The notes of a `ticket_link: notes` repo
([Notes](architecture/gateway.md#notes)) follow the branch on their own: a notes push that
fails never undoes the branch's. A push already decided keeps its slot of the lease's count
and rate when the remote refuses it.

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

Notes (`ticket_link: notes`) go the same way as in `gateway` mode, from a small notes-only
repository per repo instead of the mirror: the notes job needs only the notes ref, never
the annotated commits.

### 3c. Push, `direct_ssh` mode
At lease grant, the daemon also exposes a per-lease ssh-agent socket (reachable through the
session channel) holding only the repo's deploy key. Each signature request is checked for
host (`session-bind`), user, limits and TTL. The remote enforces the repo; nothing enforces
refs.

## 4. Fetch

`git fetch writ` → `Service::fetch`: the certificate's single active lease, the policy's
`decide_fetch` (the lease allows `fetch` and names the repo, the rate) and one operation taken
from the rate window, under one lock, logged as one `fetch` line, so `max_ops_per_minute`
bounds fetches too (a fetch never uses up a lease). Then the daemon syncs its mirror from
upstream unless it is fresh (`mirrors.fresh_for`), outside the state lock, and serves
`upload-pack`; a sync that fails refuses the fetch with its reason (`cannot sync from
upstream: …`), logged. Requires a lease with `fetch` (or a read-only template). Agents never
hold remote credentials, even read-only ones.

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

If the agent runs out of time or counts, the skill tells it to submit a **renewal**
(`renews: <id>`, § 6c), never an amendment: an amendment changes scope, not time.

## 6b. Closing a ticket

When the work is done (or stops for good), the agent runs `writ close --summary "…"` with its
session key (as user `writ`, like `writ wait`; to another session the lease doesn't exist).
The daemon:

- ends an active lease (`closed`, its certificate on the deny list, its sessions dropped); a
  lease that already ended (expired, used up, renewed) keeps its state and gets the summary,
  so its report still comes back;
- writes one `close` line;
- builds the **activity report** of the lease and the leases it renews (`Service::close`),
  from its state (the chain, each lease's counters, the ledger) under the lock, then from its
  audit log read without the lock (the chain's lines): commits signed, pushes and branches,
  fetches, denials by code (counted ones included), the warnings of its signatures (files
  outside `expected_paths`), time used against time granted, the estimate, and the phases
  (submission to grant, grant to first signature, each push to the next signature, the last
  push to the end), labeled approximate.

`writ close` prints it, adds the agent's own phase marks (`writ mark`, kept on its host),
marks the session ended, and records the run in the skill's `timings.md` (compacted to its
limits). I read the same report with `writ report <lease>` before merging.

## 6c. Renewing a lease

```mermaid
sequenceDiagram
  participant A as Agent (skill + writ)
  participant D as writd
  participant AP as writ sign (Mac)
  A->>D: writ request: renews A (A's session key), a fresh ttl, the same scope or narrower
  D->>D: A active, or ended ≤ renew_grace ago; same template and subject; within A; max_renewals
  D-->>AP: shown with A's terms (diff), the chain's original ticket, time used, A's counts
  AP->>D: approval (SSHSIG)
  D->>D: checked again; under one change: B active (new certificate, same key), A renewed
  D->>D: A's certificate on the deny list, its sessions dropped; log grant (B) and renew (A)
  D-->>A: lease B + certificate
  A->>D: WRIT_SESSION=B: push the commits A signed (the ledger accepts B's chain)
```

## 7. Daemon startup: sealed

```mermaid
sequenceDiagram
  participant D as writd
  participant U as writ unseal (Mac)
  participant SC as Secretive
  actor Me
  D->>D: start sealed: the boot tier only (host key, TLS key), a boot nonce drawn
  D-->>Me: notification "writd started, sealed" (token in the boot tier only)
  Me->>U: writ unseal
  U->>D: writ info (over the pinned SSH or HTTPS channel, reader key)
  D-->>U: sealed: this daemon (host key fingerprint), this boot (nonce)
  U->>Me: keystore passphrase prompt
  U->>SC: sign writ-unseal/1 {daemon, nonce} (namespace writ-approval)
  SC->>Me: Touch ID
  U->>D: writ unseal: passphrase + the document + its SSHSIG
  D->>D: check the document is this daemon's and this boot's, the SSHSIG an approver's
  D->>D: unwrap the identity (scrypt), open every secret, start the signers and mirrors
  D->>D: the service gets the CA and the signer, logs UNSEAL; the active leases are served again
  D-->>Me: notification "writd unsealed"
```

Until unsealed, every request but `writ info` and `writ unseal` fails closed with "daemon
sealed" (`sealed`), logged and coalesced per source; the sealed start is one `seal` line. The
signature is checked before the passphrase is tried, so only an approver can make the daemon
spend scrypt's second; one unseal runs at a time. A wrong passphrase, a signature for another
boot or another daemon, a key not in `approvers`: each refused, logged, the daemon still
sealed. The development keystore opens at start (its `unseal` line names it). Later,
hardware recipients replace the passphrase (M7.6).
