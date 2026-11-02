# Running Writ

Writ is a trust broker for AI agents: an agent submits a **ticket** for its task, you sign it,
and the daemon `writd` turns it into a scoped, time-boxed **lease**. `writd` holds the signing
keys and the remote credentials, is the agents' git remote, checks every commit and push
against the lease, and is the only thing that pushes upstream.

## Start here

1. [Set the daemon up](setup.md): its files, upstream keys and tokens, host keys, the pins
   on every client.
2. Copy the templates and fill them in: [`writd.yaml`](templates/writd.yaml),
   [`policy.yaml`](templates/policy.yaml). Required keys are set; optional ones are commented
   out at their default.
3. [Work beside an agent](good-practice.md): wrapper or whole repo, keeping your own keys
   yours, guardrails, checking what landed.

## Reference

Every key, with its default, its bounds, and whether it works today (a feature not built yet
names its milestone):

| File | Reference | Template |
|---|---|---|
| The daemon's configuration | [`writd.yaml`](writd-yaml.md) | [`writd.yaml`](templates/writd.yaml) |
| The repo registry and the templates | [`policy.yaml`](policy-yaml.md) | [`policy.yaml`](templates/policy.yaml) |
| A ticket, as an agent writes it | [The ticket file](ticket.md) | [`ticket.yaml`](templates/ticket.yaml) |
| `writ`'s flags and environment, the client files | [Client settings](clients.md) | none |

## Further

[Lease model](../lease-model.md) (how registry, templates and tickets combine) ·
[Threat model](../threat-model.md) (what Writ guarantees, and what it doesn't) ·
[Deployment](../architecture/deployment.md) · [Roadmap](../roadmap.md)
