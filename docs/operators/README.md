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
- **Approval key**: a dedicated SSH key that an ssh-agent holds for you: on the Mac, a key in
  Secretive (it asks for Touch ID); or any agent on `SSH_AUTH_SOCK`, such as a key with a
  passphrase that your agent asks for through pin-entry, or a security key that asks for a
  touch. Writ only sees its public half, and asks the agent for each signature. Pick one that
  asks you every time (Touch ID, a touch, or `ssh-add -c` to confirm each use): your agents
  run as you, and could use a key that signs without asking.
- **An approval**: one signature with your approval key. Your agent asks you to confirm it
  (Touch ID with Secretive, your passphrase or a touch with others). The pages say "one
  approval" where you will be asked.
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
- **M7, M8…**: a feature that isn't built yet, and the [roadmap](../roadmap.md) milestone that
  brings it.

## Going further

[Lease model](../lease-model.md): how the policy, templates and tickets combine ·
[Threat model](../threat-model.md): what Writ guarantees, and what it doesn't ·
[Deployment](../architecture/deployment.md) · [Roadmap](../roadmap.md)
