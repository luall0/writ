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
  A->>D: writ policy <repo>…: what a ticket for each repo may ask
  D-->>A: templates (branches, emails, signing key id, limits), protected refs, ticket link
  A->>A: think through scope, write ticket (task, plan; per repo: branches, paths, counts)
  A->>D: writ request --dry-run: every submission check, nothing stored
  D-->>A: would be accepted, or rejected + reasons
  A->>A: writ request → generates session key
  A->>D: submit ticket + session pubkey
  alt a repo fits no template, or the templates disagree (key, time)
    D-->>A: rejected_by_policy + reason
    A->>A: revise ticket, resubmit
  else each repo fits a template
    D->>D: state = pending
    D-->>Me: notification: "ticket waiting" (also printed by the agent)
    Me->>AP: writ sign
    AP->>D: fetch canonical ticket
    AP->>Me: shows ticket: the lease's terms, a block per repo, task, plan, diff vs previous revision
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
`writ policy` and `writ request --dry-run` run on the agents' listener too, before any edit:
reads that grant nothing ([what the agent reads before it asks](architecture/clients.md#what-the-agent-reads-before-it-asks)).

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
  D->>D: cert → lease, object type, committer and author emails,<br/>Writ trailer (if ticket_link = trailer), paths vs the repo's expected_paths, the repo's count, rate
  alt allowed
    D->>D: under the lock: the repo's count and the rate slot taken (never given back)
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
  D->>D: under one lock: ledger, decide_push (refs, protected refs, force push,<br/>every new commit signed under this lease with the same paths, size),<br/>the repo's count and the rate, log PUSH
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
fails never undoes the branch's. A push already decided keeps its slot of the repo's count
and rate when the remote refuses it.

## 4. Fetch

`git fetch writ` → `Service::fetch`: the certificate's single active lease, the policy's
`decide_fetch` (the lease allows `fetch` and names the repo, the rate) and one operation taken
from the rate window, under one lock, logged as one `fetch` line, so `max_ops_per_minute`
bounds fetches too (a fetch never uses up a lease). Then the daemon syncs its mirror from
upstream unless it is fresh (`mirrors.fresh_for`), outside the state lock, and serves
`upload-pack`; a sync that fails refuses the fetch (`cannot sync from upstream: repo <name>:
…`, what failed and never upstream's address or words), its whole reason logged. Requires a lease with `fetch` (or a read-only template). Agents never
hold remote credentials, even read-only ones.

**A fetch with no signature** (M7.9.7): a new ticket whose every repository asks only
`fetch`, under a template whose `unsigned_fetch` is on, is granted when it is submitted, with
no pending state and no notification. `Service::submit` admits it as any ticket (the rates,
the templates, its time within their `unsigned_fetch`), logs its `submit` line, then grants it in phases as a signed
grant is: decided under the lock (`lease::activate_unsigned`), the certificate signed without
it, decided again against the policy in force, then recorded (`Store::insert_unsigned`) with
its `grant` line. `writ request`'s wait then finds it active. It takes no slot of
`max_active_per_source`, is never amended or renewed, and every fetch under it is denied once
its templates stop granting that, or grant it for less than its time (`config`). `writ git fetch` and `pull` with no lease ask for
one themselves ([clients](architecture/clients.md#fetching-with-no-lease)).

## 5. Revoke / expire

- `writ revoke <id>`, menu bar, phone → lease `revoked`, certificate added to the deny list,
  open sessions dropped (the gateway disconnects every SSH session of that certificate). With
  `decisions: signed`, the revocation is an SSHSIG over a `writ-revocation/1` document. On a
  pending ticket, `writ revoke` withdraws it.
- TTL reached → `expired`; every counted operation used up → `exhausted` (never with
  `fetch`, [lease model](lease-model.md#lifecycle)), once no signature or push of the lease
  is still in flight (the last one's own checks would refuse it otherwise); notify. The daemon checks every second
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

- counts the request against the submission rates, like a submission (any key can ask);
- ends an active lease (`closed`, its certificate on the deny list, its sessions dropped); a
  lease that already ended (expired, used up, renewed) keeps its state and gets the summary,
  so its report still comes back; a lease takes one summary: once it has one, a `close` gets
  the report as `writ report` gives it, the summary as first written, and writes no line;
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
  D->>D: A active, or ended ≤ renew_grace ago; each repo's template and the subject the same; within A; max_renewals
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
  D->>D: settle the keys directory: a rotation of the data key cut short finished or undone, from its own record
  D->>D: start sealed: the boot tier only (host key, TLS key), a boot nonce drawn
  D-->>Me: notification "writd started, sealed" (token in the boot tier only)
  Me->>U: writ unseal
  U->>D: writ info (over the pinned SSH or HTTPS channel, reader key)
  D-->>U: sealed: this daemon (host key fingerprint), this boot (nonce), what opens the keystore, a rotation owed
  U->>Me: keystore passphrase prompt (none when the hardware opens it)
  U->>SC: sign writ-unseal/1 {daemon, nonce} (namespace writ-approval)
  SC->>Me: Touch ID
  U->>D: writ unseal: passphrase + the document + its SSHSIG
  D->>D: check the document is this daemon's and this boot's, the SSHSIG an approver's
  D->>D: unwrap the identity (scrypt, or the hardware recipients' devices), open the authority key, check the versions in force against its MAC
  D->>D: then, and only then, rotate the data key if the keystore owes it, open every secret, bring the keystore in line with the policy's recipients, start the signers and mirrors
  D->>D: the service gets the CA and the signer, logs UNSEAL; the active leases are served again
  D-->>Me: notification "writd unsealed"
```

Until unsealed, every request but `writ info` and `writ unseal` fails closed with "daemon
sealed" (`sealed`), logged and coalesced per source; a daemon whose policy in force is of an
older format, once unsealed, refuses every request but those two and the migration until `writ
migrate` signs it (`migration_owed`, M7.9.6: [approvals](architecture/approvals.md#writ-migrate)); the sealed start is one `seal` line. The
signature is checked before the passphrase is tried, so only an approver can make the daemon
spend scrypt's second; one unseal runs at a time. A wrong passphrase, a signature for another
boot or another daemon, a key not in `approvers`: each refused, logged, the daemon still
sealed. The policy, approvers and readers the daemon started with were read from its state
with no MAC checked (the key is sealed): nothing is done from them before the authority key
opens and their MAC is checked, so versions altered at rest are refused ("altered at rest")
with nothing written; an `unseal: auto` read from them lets the devices unwrap the identity at
start, and the same check comes before anything else. The development keystore opens at start (its `unseal` line names it). On a
keystore its hardware recipients wrap (M7.6), `writ unseal` asks no passphrase and the
devices unwrap the identity; `unseal: auto` does it at start with no one. Before anything
reads the keys directory, a rotation of the data key cut short is finished or undone from the
keystore's own record, never from the policy; one a passphrase keystore owes (a recipient
removed or replaced while it ran) is done right after the MAC check, with the passphrase the
unseal brought, and `writ unseal` says so first
([signer](architecture/signer.md#startup-and-sealing)).

## 8. Daemon stop

```mermaid
sequenceDiagram
  participant S as launchd, systemd, docker stop, Ctrl-C
  participant D as writd run
  participant A as Agent git
  participant UP as Upstream
  S->>D: SIGTERM (or SIGINT)
  D->>D: log "stopping" (the signal named); the sweeper and the mirrors' sync end; the listeners closed
  D->>D: a lease holder's new git operation or signature refused ("the daemon is stopping"), logged, and nothing new sent upstream, both at once
  A->>D: a push already in flight goes on
  D->>UP: its upstream push, within mirrors.timeout
  D-->>A: its answer
  A->>D: hangs up (the stop waits for it: its answer never cut)
  D->>D: the notes in flight waited for, in the same wait
  D->>D: log "stopped"; the state's lock released as the process ends
```

Both signals stop the daemon the same way, and so does anything it can't run without: a
listener that ends, an open that fails once the gateway runs, a background task (the sweeper,
the mirrors' sync) that keeps ending after three restarts; then it logs `stopping` with the
reason and exits with an error once stopped (a service manager restarts it). The stop waits
once, for the lease holders' git operations and signatures (each until its client has hung up,
so the answer and the client's own disconnect are never cut) and the upstream operations left
together: at most `mirrors.timeout` and a 5 s margin, and never past 320 s, ahead of the
service managers' 330 s (the review after M7.6, D-5). An operation still running then is cut,
and the last line says how many (`stopped with operations still running past their
deadline`). A second SIGINT or SIGTERM while it waits is said (`a second signal while
stopping`) and the daemon exits at once, with an error, what is in flight cut. Sessions that
ran no git operation or signature and requests waiting for a decision (`writ request`) are
dropped: the ticket stays pending in the store. A client that keeps its connection open after
its answer is waited for to the same deadline, then cut.

`writd run` holds an exclusive lock on `<state_dir>/writd.lock` (its pid written in it) for
its whole life: a second `writd run` and `writd recover` on the same state are refused while
it is held, naming the holder. The kernel releases the lock when the process ends, so a
crashed daemon leaves none behind.
