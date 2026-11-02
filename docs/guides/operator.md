# Working beside an agent: good practice for operators

How to wire a repository for an agent while keeping your own git workflow, and what protects
what. Writ guards what the agent does **through the daemon**; what an agent running as your
user could reach on your machine is yours to protect. See the
[threat model](../threat-model.md#what-writ-does-not-guarantee).

## Setting up the daemon

From nothing, on the daemon's host, in the directory that holds its files (`make e2e` runs
these steps, with these commands, before every scenario: [end-to-end](../end-to-end.md#commands-the-docs-show)).
The order matters only in that the daemon starts last: every command that prints a key works
before any approver or reader is listed.

1. **The configuration**: `writd.yaml`, with paths relative to it (`state_dir: data`,
   `policy: policy.yaml`, `approvers: approvers`, `readers: readers`,
   `mirrors.known_hosts: upstream_known_hosts`; the [development one](../../dev/writd.yaml)
   is a commented example), and `policy.yaml`, the repo registry and the templates
   ([lease model](../lease-model.md)). Both 0644 or stricter, owned by the daemon's user.
2. **The upstream credentials**, each added on its remote (below: a deploy key with write
   access on its repository):

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writd upstream-keys writd.yaml
   ```
3. **Each remote's host key**, pinned, then checked against the fingerprints the remote
   publishes (below):

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   ssh-keyscan -t ed25519 <host> >> upstream_known_hosts
   ssh-keygen -lf upstream_known_hosts
   ```
4. **The agent signing keys**, to add on the account as signing keys if the remote should
   show the commits as verified ([proving a key](../architecture/approvals.md#proving-a-signing-key-to-a-remote)
   when the remote asks for it, as Forgejo and Gitea do):

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writd signing-keys writd.yaml
   ```
5. **The daemon's identity, pinned on every client**: its host key in `~/.writ/known_hosts`
   (`[<daemon>]:2222 <key>` for agents, `[<daemon>]:2223 <key>` for the approver), its TLS
   certificate's fingerprint in the approver's `~/.writ/tls_pins` (`[<daemon>]:8443 SHA256:…`):

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writd host-key writd.yaml
   writd tls-fingerprint writd.yaml
   ```
6. **The approver's machine**: its reader key (the approval API lets only readers in), whose
   printed line goes into the daemon's `readers` file; and the approval key's public half
   (Secretive's dedicated key) into `approvers`, as `<name> <key>`:

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writ reader <name>
   ```
7. **Start it**, from its directory:

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writd run writd.yaml
   ```

   It logs its host key, TLS fingerprint, each approver's and reader's fingerprint, and its
   listeners; check the fingerprints against what you pinned and listed.

## Upstream keys and host keys

The daemon pushes to and fetches from each repo's `upstream` with that repo's
`upstream_credential`, a key in its signer ([gateway](../architecture/gateway.md#upstream)).

1. **Add each credential on its remote.** `writd upstream-keys writd.yaml` prints each key
   and the repos that use it. Prefer a **deploy key** with write access on that one repository
   (GitHub, Codeberg, Forgejo and GitLab all have them): the remote then scopes the key to the
   repo. A key added on your account reaches every repository you can push to; the daemon's
   registry is then the only per-repo boundary.
2. **Pin each remote's host key** in the file `mirrors.known_hosts` names, one line per host:
   `github.com ssh-ed25519 AAAA…`, or `[forgejo.home]:2222 ssh-ed25519 AAAA…` off port 22.
   Take the key from the remote's published fingerprints (GitHub, Codeberg and GitLab publish
   theirs) or from `ssh-keyscan -t ed25519 <host>` checked against them; never trust a scan
   alone. The daemon refuses to start when a repo's host has no pin, and refuses a sync when
   the host shows another key. Wildcards, hashed names and `@cert-authority` lines are refused.
3. **Mind the bounds** (`mirrors` in `writd.yaml`): `max_fetch` (1 GiB) caps what one sync
   takes from upstream, `timeout` (5 min) how long it may take; a first sync of a large
   repository may need more.

## Wrapper or whole repo

`writ init <repo>` ([repo setup](../architecture/clients.md#repo-setup-on-an-agent-host)):

| Mode | Use it for | What changes |
|---|---|---|
| **Wrapper** (default) | Your own clone, shared with an agent | Nothing in the repo's git config. The agent runs every git command through `writ git …` (rebase, cherry-pick, `commit --amend` and push included) or a program that runs git through `writ exec -- …`; your plain `git` keeps your key, email and remotes |
| **Whole repo** (`--whole-repo`) | A clone dedicated to an agent (a VM, a container, a separate directory) | The repo's git config: plain `git` there is the agent's git, and `origin` goes through the daemon |

`writ init --undo` takes either back exactly. One wiring per clone: a repo already wired must
be undone first. In both modes the clone's `origin` URL is rewritten to the daemon under the
wiring (only that URL, never in your global config), so the agent pushes to `origin` as usual;
in wrapper mode your own `git push origin` still goes straight to the remote.

In wrapper mode, keep the agent working in its own branch (`agent/…`) and don't work in the
same files at the same time: you share a working tree.

The wiring lives in the environment of what `writ git` and `writ exec` start, so **every git
that process runs gets it**, in any repository: a build script or a tool that commits in
another clone has that commit refused by `writ-sign` (the settings name the wired
repository's git directory, `writ.gitdir`), and its SSH remotes are reached with the
session's key (and fail on the daemon's pinned host key). Run only the work for the wired
repo under `writ exec`.

## Protect your own credentials

On a machine you share with an agent as the same user, the agent can run anything you can:
your `git`, `ssh-keygen`, `ssh`, your tools. What keeps your keys yours is that using them
needs **you**:

- **Your commit signing key** behind user presence: Secretive with "Require authentication"
  (Touch ID), or a security key (`sk-ssh-ed25519`, a touch per signature).
- **Your push credential** the same way: the SSH key your remotes (GitHub, Codeberg,
  Forgejo, GitLab…) accept, in Secretive with Touch ID or on a security key.
- **No credential that answers silently**: no HTTPS credential helper that hands out a token
  without asking (`osxkeychain`, `gh auth setup-git`), no remote token in the environment
  (`GH_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`), no logged-in CLI the agent can drive.

Checks:

```sh
git config --show-origin --get-all credential.helper   # expect nothing, or a helper that prompts
ssh-add -l                                              # every key here should need a touch
env | grep -iE 'token|secret'                           # nothing a remote accepts
```

With both keys behind Touch ID, an agent that runs plain `git commit -S` or `git push origin`
gets a prompt you won't approve, or nothing.

## Guardrails in the agent's configuration

Agent harnesses let you deny commands. Deny the plain ones and allow the wrapper, so a sloppy
agent is stopped and told to use `writ git`. For example, Claude Code's
`.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(writ git:*)", "Bash(writ exec:*)"],
    "deny": ["Bash(git commit:*)", "Bash(git push:*)", "Bash(git tag:*)", "Bash(gh:*)"]
  }
}
```

These are **guardrails, not a boundary**: a determined or prompt-injected agent can go around
a deny list (`/usr/bin/git commit`, `git -C . commit`, `sh -c "git push"`, a script it writes,
an alias, a tool that runs git). The boundaries are your keys needing your touch, and the
daemon's checks on everything that goes through Writ.

## Check what landed

- `git verify-commit <rev>` with the agent's key in an allowed-signers file
  (`<WRIT_HOME>/sessions/<lease>/signing_key.pub`); `git log --show-signature`.
- The `Writ: wrt_…` trailer names the lease each commit was signed under; the daemon's ledger
  and audit log hold every signature, with its lease and key.
- Agent commits carry the agent's email (`user+agent@…`), yours carry yours.

## More isolation

- A clone dedicated to the agent, in a VM or a container, against a daemon on another host
  (detached mode, [M8](../roadmap.md#m8--detached-deployment)): the agent host holds no key
  and no remote credential at all.
- Local mode's daemon runs as its own user ([M7](../roadmap.md#m7--local-mode-on-the-mac)):
  the agent can't read its keys, though it still runs as you.
