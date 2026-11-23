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

Agents run on the machine the daemon runs on (agents on other hosts, VMs or containers, need
the [detached deployment](backlog/detached-deployment.md), in the backlog). They all talk to
the same daemon. Agents **never hold remote credentials**: the daemon is their git remote and
pushes upstream itself, to any remote (GitHub, Gitea, Forgejo…).

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
| **Detached** (not built yet: [backlog](backlog/detached-deployment.md)) | Linux server, Docker (homelab) | Software keys, YubiKey / TPM later |
| **Local** | My Mac or a Linux workstation, native ([M7](history/m7-local-mode-on-the-mac.md), [M7.1](history/m7.1-local-mode-on-linux.md)) | Secure Enclave on the Mac, software keys on Linux |

Same daemon, same protocol. Details in [Architecture overview](architecture/overview.md#deployment-modes).

## Relationship with Secretive

Writ **coexists** with Secretive. Secretive keeps my personal keys (per-use Touch ID). Writ
owns only the agent keys and never touches Secretive's, so the worst case of any Writ
approval is bounded to what the agent keys can do.

## Scope v1

v1 is complete (1.0.0, 2026-11-23): what was built is in the [history](history/README.md).

- Personal use (my own projects)
- Local mode on the Mac and on Linux; the signer interface ready for other backends (the
  Secure Enclave on the Mac is one)
- One installer for every local setup, and an uninstall that leaves the machine as it was
- SSH and OpenPGP commit signing, each key declared with its algorithm and hash
  ([M5.5](history/m5.5-signature-formats-and-key-algorithms.md)); push/fetch through the daemon's git gateway; upstream over SSH to any
  remote (GitHub, Codeberg, Forgejo, GitLab…)
- Approvals signed by my approver keys (Secretive first, own Secure Enclave signer later)
- Daemon starts sealed; unsealed with a passphrase + approver signature
- Agents on the machine the daemon runs on

**Left out of v1**, after two weeks of real use: detached mode in Docker, with agents on other
hosts ([detached deployment](backlog/detached-deployment.md)), and session keys held by the
agent host's hardware ([non-exportable session keys](backlog/non-exportable-session-keys.md)).
An agent's attempts to use another lease were all refused on that lease's scope (another
repository), and in local mode a lease bound with `writ run` already serves only that agent's
processes. Both stay in the
[backlog](backlog/README.md), with everything else that could come next.

## Non-goals

v1 does not do any of these; don't build them unless explicitly asked:

- Generic secret-store proxying (API tokens, keychain items). An HTTP credential proxy is a
  v2 idea in the [backlog](backlog/http-credential-proxy.md).
- Multi-user / team policy (designed in the [backlog](backlog/multi-user.md), not picked)
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
