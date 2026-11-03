# Running Writ

Writ sits between your AI agents and your git remotes. An agent asks for a **ticket**: which
repos, which branches, for how long. You sign it. The daemon `writd` turns it into a
**lease** and enforces it: it signs the agent's commits, checks every push, and is the only
thing that talks to the remote.

## Guides

| I want to… | Read |
|---|---|
| Install the daemon and start it for the first time | [Setup](setup.md) |
| Unseal after a restart, change the policy or the keys, add a token | [Daily operations](sealing.md) |
| Get access back after losing a key, a Mac or the passphrase | [Recovery](recovery.md) |
| Check that the daemon keeps its secrets out of core dumps, debuggers and swap | [Process hardening](hardening.md) |
| Let an agent work in my repo without handing it my own keys | [Working beside an agent](good-practice.md) |

## Reference

Every key, with its default and its limits.

| File | Every key | Template to copy |
|---|---|---|
| The daemon's configuration | [`writd.yaml`](writd-yaml.md) | [`writd.yaml`](templates/writd.yaml) |
| The repos agents may use, and the templates that cap tickets | [`policy.yaml`](policy-yaml.md) | [`policy.yaml`](templates/policy.yaml) |
| A ticket, as an agent writes it | [The ticket file](ticket.md) | [`ticket.yaml`](templates/ticket.yaml) |
| `writ`'s flags, environment variables and files | [Client settings](clients.md) | — |

In the templates, required keys are set and optional ones are commented out at their default.

## Words used in these pages

- **Approver**: you, signing with your approval key (a dedicated key in Secretive, with Touch ID).
- **Reader key**: the key `writ` uses to connect to the daemon's approval API. Connecting is
  not approving: signing still needs the approval key.
- **Authority file**: a file that decides who may do what (`writd.yaml`, `policy.yaml`,
  `approvers`, `readers`, the pinned host keys). It must be owned by the daemon's user and not
  writable by group or others, or the daemon refuses it.
- **Sealed**: the daemon is running but can't use any secret until you run `writ unseal`.
- **M7, M8…**: a feature that isn't built yet, and the [roadmap](../roadmap.md) milestone that
  brings it.

## Going further

[Lease model](../lease-model.md): how the policy, templates and tickets combine ·
[Threat model](../threat-model.md): what Writ guarantees, and what it doesn't ·
[Deployment](../architecture/deployment.md) · [Roadmap](../roadmap.md)
