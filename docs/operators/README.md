# Running Writ

Writ sits between your AI agents and your git remotes. An agent asks for a **ticket**: which
repos, which branches, for how long. You sign it. The daemon `writd` turns it into a
**lease** and enforces it: it signs the agent's commits, checks every push, and is the only
thing that talks to the remote.

## Guides

| I want to… | Read |
|---|---|
| **Start here**: from `make install` on my Mac to an agent's first verified commit (the keys, a template, a repo, an agent) | [Quick start](quick-start.md) |
| Install Writ on my Mac or my Linux workstation in one command (local mode), upgrade it, or take it all back | [Installing on your machine](install.md) |
| Set a daemon up from nothing on any host, file by file (the detached path, or to see each piece) | [Setup](setup.md) |
| Unseal after a restart; add or change a repo, a template, a key or a host; add a token | [Daily operations](sealing.md) |
| Get access back after losing a key, a Mac or the passphrase | [Recovery](recovery.md) |
| Check that the daemon keeps its secrets out of core dumps, debuggers and swap | [Process hardening](hardening.md) |
| Let an agent work in my repo without handing it my own keys | [Working beside an agent](good-practice.md) |

## Reference

Every key, with its default and its limits.

| File | Every key | Template to copy |
|---|---|---|
| The daemon's configuration | [`writd.yaml`](writd-yaml.md) | [`writd.yaml`](templates/writd.yaml) |
| The keys, the remotes' host keys, the repos agents may use, and the templates that cap tickets (changed with `writ admin`) | [`policy.yaml`](policy-yaml.md) | [`policy.yaml`](templates/policy.yaml) |
| A ticket, as an agent writes it | [The ticket file](ticket.md) | [`ticket.yaml`](templates/ticket.yaml) |
| `writ`'s flags, environment variables and files | [Client settings](clients.md) | — |

In the templates, required keys are set and optional ones are commented out at their default.

## Words used in these pages

- **Approver**: you, signing with your approval key.
- **Approval key**: a dedicated SSH key held by an ssh-agent, the one on `SSH_AUTH_SOCK` or the
  one you name. Writ only sees its public half, and asks the agent for each signature. Any
  key and agent work; pick one that asks you every time
  ([choosing your approval key](good-practice.md#choosing-your-approval-key)).
- **An approval**: one signature with your approval key, confirmed the way your agent asks
  for it. The pages say "one approval" where you will be asked.
- **Upstream key**: the key the daemon reaches one repository on your remote with (a deploy
  key there). Agents never hold it.
- **Signing key**: the key the daemon signs your agents' commits with (`agent-01`). On your
  account on the remote, it makes those commits show as verified.
- **Template**: the most a ticket may ask for a repository (operations, branches, how long,
  how many commits and pushes).
- **Reader key**: the key `writ` uses to connect to the daemon's approval API. Connecting is
  not approving: signing still needs the approval key.
- **Authority file**: a file that decides who may do what (`writd.yaml`, `policy.yaml`,
  `approvers`, `readers`). It must be owned by the daemon's user and not
  writable by group or others, or the daemon refuses it.
- **Sealed**: the daemon is running but can't use any secret until you run `writ unseal`.
- **Not built yet**: a feature in the [backlog](../backlog/README.md), linked to its page.

## Going further

[Lease model](../lease-model.md): how the policy, templates and tickets combine ·
[Threat model](../threat-model.md): what Writ guarantees, and what it doesn't ·
[Deployment](../architecture/deployment.md) · [Backlog](../backlog/README.md)
