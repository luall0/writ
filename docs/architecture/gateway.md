# Gateway, mirrors and upstream

The daemon is the agents' git remote and the only thing that pushes upstream. That is what
makes repo, destination ref and pushed content strong, forge-agnostic checks
([threat model, boundary 2](../threat-model.md#2-policy-strong-because-the-daemon-is-the-git-server)).

Code: `crates/writ-gateway` (SSH server), `crates/writ-git` (mirrors, quarantine, upstream).

## Gateway (SSH server)

The single entry point for agents. Authenticates with **SSH user certificates** issued by the
daemon itself for each lease (see [Identity](identity.md#session-identity)). It exposes:
- **git** `upload-pack` (fetch) and `receive-pack` (push) for leased repos, so a plain
  `git fetch/push writ` works
- **sign** command used by the `writ-sign` shim (full commit/tag object in, armored SSHSIG out)
- **lease** commands (request, status, release) for the CLI and harness

Every request goes through the [policy engine](policy-and-state.md#policy-engine) before
anything else happens. Git itself is not reimplemented: the daemon shells out to
`git upload-pack` / `git receive-pack` / `git index-pack` against its own repositories.

## Repo mirrors

One bare mirror per registered repo. Used to serve fetches, receive pushes into a quarantine,
and validate packs. Synced from upstream on fetch, on push, and periodically (no webhooks,
[Q19](../decisions.md)).

## Upstream pusher

Pushes accepted refs to the real forge with the daemon's own credentials, over **SSH** (key
via the [signer](signer.md)) or **HTTPS** (token from the sealed keystore), depending on the
repo's `upstream` URL ([Q4](../decisions.md)). The mirror's refs are updated **only after**
upstream accepted the push.

## Push modes (per repo)

Each repo in the [registry](../lease-model.md#repo-registry-daemon-config-admin-approved)
chooses which push modes are allowed. Default: `gateway` only.

| Mode | How the agent pushes | What the daemon sees and checks | Needs |
|---|---|---|---|
| `gateway` (default) | To the daemon's mirror; the daemon pushes upstream | Repo, refs, force push, **every commit against the ledger**, size | Repo registered with a mirror |
| `proxy` | SSH to the daemon, which relays the stream to the forge with its own key | Repo path (from the `git-receive-pack '<path>'` command), ref updates (old → new, so force push too), size, and **every commit against the ledger** (pack buffered and indexed in a temporary quarantine before relaying) | No mirror; temporary disk for the pack |
| `direct_ssh` | The daemon lends a per-lease ssh-agent socket; the agent talks to the forge itself | Destination host (`session-bind`), user, limits, TTL. **Not** the repo, refs or content | Upstream key that the forge scopes to this repo (deploy key), or explicit `allow_account_wide: true` |

Why `direct_ssh` needs a repo-scoped key: the repo path is sent inside the encrypted SSH
session, after authentication. The agent socket only sees "sign this auth challenge for
github.com", so with an account-wide key the agent could push to any of my repos on that
forge. Only the forge can scope it, through a deploy key.

The step-by-step of each mode is in [Flows](../flows.md#3-push) (3, 3b, 3c).

## URL rewrite

`gateway` and `proxy` keep the plain `git push origin` habit with a URL rewrite written by
`writ init`:

```ini
[url "ssh://git@writ.home:2222/github.com/user/"]
    insteadOf = git@github.com:user/
```

The agent keeps `origin` pointing at GitHub; git transparently routes it through the daemon.
The full git config of an agent host is in [Clients](clients.md#repo-setup-on-an-agent-host).
