# Product overview

> A trust broker for AI agents. The agent drafts a ticket for its task; I sign it, and the
> signed ticket (the writ) becomes a scoped, time-boxed **lease**. Writ holds the agent
> signing and push keys and is the only thing allowed to push.
>
> *A writ is a written order, issued under seal, that authorizes someone to act within stated
> limits.*

## Problem

Today every git signature and push goes through Secretive and needs one Touch ID approval
each time. That's fine at the keyboard. It breaks when an agent works autonomously for an
hour while I'm away: the work stalls on the first commit.

The opposite extreme isn't acceptable either: a key with no auth, or Secretive's global
"unlock for X minutes", which any process can use for any repo and any host.

## How I work with agents

Agents don't run on their own. I start one **for a specific feature or fix**. The point of
Writ is that, once we agree on the scope, the agent can do the whole job end to end without
waiting on me for every commit and push.

## Goal

**The agent plans its scope upfront as a ticket; I sign the ticket; the signed ticket becomes
its lease.**

A ticket says what the agent will do and what it needs:
- the task and its plan
- **repos**, **branches** (e.g. `agent/*`), **operations** (fetch, commit signing, push)
- **limits**: time, number of commits and pushes

If I refuse, I say why, and the agent revises its plan and submits a new ticket.
**Templates**, written by me in advance, cap what any ticket can ask for.

Agents can run anywhere (Mac, VMs, containers). They all talk to the same daemon. Agents
**never hold remote credentials**: the daemon is their git remote and pushes upstream itself,
to any remote (GitHub, Gitea, Forgejo…).

The full schema of tickets, templates and the repo registry is in
[Lease model](lease-model.md).

## User story

1. I ask an agent to build feature X on `omega-code`.
2. Following the Writ skill, it thinks through the scope and submits a ticket: *"Add OAuth
   login · omega-code · branch `agent/oauth-login` · sign + push · 3h · max 30 commits ·
   template feature-branch"*, with a short plan.
3. I run `writ sign`, read the ticket, and either:
   - **sign it** with Touch ID (Secretive), or
   - **refuse it with a reason** ("don't touch the billing module, split this in two"). The
     agent revises and resubmits.
4. I walk away. The agent implements, commits (signed by the daemon) and pushes. The daemon
   checks every push against the ticket and pushes upstream with its own credentials.
5. Anything outside the ticket is denied with a clear reason. If the agent genuinely needs
   more, it submits an **amendment** for me to sign.
6. When done, the agent closes the ticket with a summary. I review the branch and the
   ticket's activity report, then merge.

Each step is drawn in [Flows](flows.md).

## Deployment modes

| Mode | Where the daemon runs | Typical signer |
|---|---|---|
| **Detached** | Linux server, Docker (homelab) | Software keys (v1), YubiKey / TPM later |
| **Local** | My Mac, native | Secure Enclave |

Same daemon, same protocol. Details in [Architecture overview](architecture/overview.md#deployment-modes).

## Relationship with Secretive

Writ **coexists** with Secretive. Secretive keeps my personal keys (per-use Touch ID). Writ
owns only the agent keys and never touches Secretive's, so the worst case of any Writ
approval is bounded to what the agent keys can do.

## Scope v1

- Personal use (my own projects)
- Detached mode in Docker with a software signer; signer interface ready for YubiKey
- Local mode on the Mac
- SSH commit signing; push/fetch through the daemon's git gateway; upstream over SSH to any
  remote (GitHub, Codeberg, Forgejo, GitLab…)
- Approvals signed by my approver keys (Secretive first, own Secure Enclave signer later)
- Daemon starts sealed; unsealed with a passphrase + approver signature
- Agents on any host that can reach the daemon

The order in which this is built is the [Roadmap](roadmap.md).

## Non-goals

v1 does not do any of these; don't build them unless explicitly asked:

- GPG signing
- Generic secret-store proxying (API tokens, keychain items). An HTTP credential proxy is a
  v2 idea in the [backlog](backlog/http-credential-proxy.md).
- Multi-user / team policy (after v1: [M11](roadmap.md#m11--multi-user-daemon), designed in the
  [backlog](backlog/multi-user.md))
- Client-work compliance (not used for client projects for now)
- Tag signing ([Q11](decisions.md)): releases stay a human act

## Design principles

1. **Policy lives in the daemon.** Clients, shims and harnesses are untrusted.
2. **Agents never hold remote credentials.** Only the daemon pushes.
3. **Keys sit behind a signer interface.** The daemon doesn't care where they live.
4. **One human approval per ticket**, signed by a registered approver key (signer-agnostic),
   always within a template.
5. **Remote-agnostic.** No reliance on remote-specific protections; they're optional defense in
   depth.
6. **Everything is logged; every lease is revocable instantly.**
7. **Fail closed.** Daemon unreachable or lease unclear → deny.
