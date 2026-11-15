# Multi-user daemon

**Status:** specified up to its open questions; after v1, not on the
[roadmap](../roadmap.md). **Area:** Identity, Approvals, Upstream.
**Kind:** feature. **Size:** L.

Multi-user is a [v1 non-goal](../product.md#non-goals); this page is its design, for when it is
picked after v1.

## Problem

One daemon serves one person today. Everything that grants or shows something is daemon-wide:

| What | Today |
|---|---|
| `approvers` | Any key in it may approve any ticket, under any template, for any repo |
| `readers` | Any reader sees every ticket (task, plan, repos) and every lease, and may refuse or revoke any (with `decisions: open`, without a signature) |
| `repos.<name>.upstream_credential` | One credential per repo: every push of every lease reaches the remote with it, so the remote shows every push as that one key's (an account or a deploy key) |
| Templates and their `signing_key` | Not owned by anyone: any approver can grant any of them |
| Admin changes, unsealing (M5) | Any approver |
| Notifications | One `Notifier`, one chat |
| The audit log, the ledger | Name leases and certificates, never a person |

So several people can't share one daemon (a homelab serving a household or a small team, each
with their own agents and their own remote accounts) without each being able to approve the
others' agents' tickets, read their tasks, revoke their leases, and push under their
credential.

## Proposal

**Users** are declared in the daemon's configuration, each with:

- their **approver keys** (who signs for them), and their **reader keys** (who reaches the
  approval API as them);
- the **templates** they own: they alone may approve a ticket under one;
- their **upstream credential per repo**: their pushes reach the remote as them;
- where their notifications go.

A lease belongs to one user. Everything the daemon decides for that lease uses that user's
authority: whose approval counts, whose credential pushes, who sees it, who is notified. The
audit log names the user on every line.

One or more users are **admins**: they make admin changes (users, templates, the repo
registry, the approvers and readers files) and unseal the daemon. An admin's approval key
signs those like it signs an approval today ([hard rule 5](../../AGENTS.md#hard-rules)), and
so are the signed requests of [M6.2](../history/m6.2-managing-the-daemon-from-the-cli-design.md) that make the daemon
reach the network (the host key scan): only an admin's key may sign one.

Repos can be shared: one registry entry, one mirror, several users each with their own
credential for it. The policy stays per lease, so sharing a repo shares only its content (which
every user with access fetches from the remote anyway).

A sketch (keys and names to settle with the open questions):

```yaml
users:
  ana:
    admin: true
    approvers: [ana-approval]         # entries of the approvers file
    readers: [ana-mac]                # entries of the readers file
    templates: [omega-work]
    credentials:
      omega-code: upstream-ana        # this user's key for that repo
  sam:
    approvers: [sam-approval]
    readers: [sam-laptop]
    templates: [sam-work]
    credentials:
      omega-code: upstream-sam
```

## Scope and non-goals

- One daemon host, run by one operator whom every user trusts: root on the daemon host sees
  every user's keys (software backend) and every mirror, as today. Users don't trust each
  other, nor each other's agents and approver keys.
- No accounts outside the daemon's configuration: no sign-up, no SSO or OIDC, no web UI, no
  passwords. A user is their keys.
- No team policy beyond ownership: no "two approvals needed", no review rules, no roles but
  `admin`. A quorum for admin changes is an open question, not a default.
- No per-user quotas beyond what templates and the submission rates already bound.
- The remote's own permissions stay the remote's: Writ picks which credential pushes, it
  doesn't manage accounts on the remote.

## Design

Rough, to be written up with the open questions settled.

- **`writ-core`:** users in the policy config; a lease's user; the policy checks that the
  approver (or the refusing or revoking key) belongs to the user owning the ticket's template,
  or is an admin where an admin may act. Pure, like the rest of the core.
- **Approval service (`writ-approval`):** the approval and admin paths take the user from the
  signing key; reads (`ls`, `show`, `info`) filtered to the reader's user (everything for an
  admin, if decided so); notifications routed per user.
- **Store (`writ-store`):** the user of each lease; the audit line's `user` field.
- **Mirrors and upstream (`writ-mirror`, `writ-gateway`):** the credential of a push is the
  lease's user's for that repo, never the repo's alone; a repo with no credential for that
  user refuses the push (fail closed). The mirror stays one per repo, its syncs made with any
  of the repo's credentials (or a daemon-owned read credential: open question).
- **Notes ([M4.7](../history/m4.7-ticket-link-in-git-notes.md)):** the notes ref is
  shared by every lease on a repo, so by several users. M4.7's notes job already takes the
  credential it pushes with as a parameter, and each pending note records the credential that
  pushed its commit, so this milestone only decides which credential pushes a batch of notes
  (an open question below).
- **Agent signing keys:** already per template; a user's templates name the keys the user
  registered on their own remote account (`writ prove-key`, for "Verified").
- **Migration:** a single-user configuration keeps working as one user who is an admin and
  owns every template and credential.

## Threat model impact

- **A new actor: another user**, with their agents and their approver key, possibly
  compromised. Design target: they can't approve, refuse, revoke, read, push or sign for a
  scope they don't own, and they can't make admin changes unless they are an admin.
- **New guarantees, each with a test that tries to break it:**
  - an approval signed by a user's key for another user's template is refused, logged;
  - a reader sees only their user's tickets and leases (`ls`, `show`, the HTTPS routes alike);
  - a push never reaches the remote with another user's credential, nor with the repo's when
    the lease's user has none;
  - an admin change or an unseal signed by a non-admin is refused.
- **Assets:** several users' upstream credentials and approver key lists on one host;
  the daemon host stays the crown jewel ([boundary 5](../threat-model.md#5-daemon-host-the-crown-jewel)).
- **Residual:** users sharing a repo share its mirror (its content, the notes ref); a remote
  account-wide key of one user still reaches that user's other repos
  ([residual risks](../threat-model.md#residual-risks-v1)).

## Open questions

To settle with the user before the plan.

1. **How a lease gets its user:** from the template's owner (a ticket names a template, so its
   user follows), from the approver who signs it, or both required to match.
2. **Credentials:** per repo and user (the sketch), per template, or both; what happens to a
   repo shared by users of whom only some have a credential for it.
3. **Who pushes the notes ref**, shared by every user of a repo:
   - the credential of the push that brought the notes (M4.7's choice): simple, but one
     user's key then pushes notes about other users' commits (a batch carries every pending
     note of the repo);
   - **a daemon-owned notes credential per repo**: the shared ref has one owner, each user's
     key pushes only their own branches, and removing a user never breaks the notes. It adds
     no security on GitHub, Codeberg, Forgejo or Gitea, which can't limit a key to
     `refs/notes/*` (a key that can push notes can push branches), and it is one more key to
     register and rotate; it is real least privilege only where the remote scopes keys by ref
     (Gerrit, or a server-side hook).
4. **Admins:** one admin, several, or a quorum of admin approvals for admin changes and
   unsealing; whether an admin sees and revokes every user's leases.
5. **Syncs:** which credential fetches a shared repo's mirror (any user's, or a daemon-owned
   read-only one, a deploy key).
6. **Notifications:** one `Notifier` per user (their own Telegram chat), or one with a user
   field.
7. **Submissions:** today a ticket comes from a session key, with no user. Whether a
   submission names its user (checked against the template), and per-user submission rates.
8. **Configuration:** users as a new file or a section of `policy.yaml`, and how the
   `approvers` and `readers` files name their user.
9. **A separate admin key:** whether an admin signs admin changes and unseals with a key
   distinct from the one that approves leases. A Touch ID prompt naming the admin key outside
   an admin task is then the alarm, where today one key's prompt looks the same for a lease
   and for a change to the templates themselves (found by the
   [M7.7 review](../roadmap.md#m77--review-after-m76), H2: in local mode an agent running
   as the approver's user can get an admin change signed that was never shown).

## Acceptance

Drafted; final with the plan.

- Two users on one daemon, each with their own agents, templates, approver and reader keys,
  push to the same repo at once under their own credentials: the remote shows each push as
  its user's, and both get their notes.
- Every cross-user attempt (approve, refuse, revoke, `ls`, `show`, push, an admin change by a
  non-admin) is refused with its exact code and logged with both users named.
- A single-user configuration from v1 starts unchanged and behaves as before.
- Every new command, flag and configuration key has its end-to-end scenario and its
  configuration test (hard rules 18 and 19).

## Plan

Written when it is picked, once the open questions are settled; each commit leaves Writ
working.
