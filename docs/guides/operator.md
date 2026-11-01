# Working beside an agent: good practice for operators

How to wire a repository for an agent while keeping your own git workflow, and what protects
what. Writ guards what the agent does **through the daemon**; what an agent running as your
user could reach on your machine is yours to protect. See the
[threat model](../threat-model.md#what-writ-does-not-guarantee).

## Wrapper or whole repo

`writ init <repo>` ([repo setup](../architecture/clients.md#repo-setup-on-an-agent-host)):

| Mode | Use it for | What changes |
|---|---|---|
| **Wrapper** (default) | Your own clone, shared with an agent | Nothing in the repo's git config. The agent runs every git command through `writ git …` (rebase, cherry-pick, `commit --amend` and push included) or a program that runs git through `writ exec -- …`; your plain `git` keeps your key, email and remotes |
| **Whole repo** (`--whole-repo`) | A clone dedicated to an agent (a VM, a container, a separate directory) | The repo's git config: plain `git` there is the agent's git |

`writ init --undo` takes either back exactly. One wiring per clone: a repo already wired must
be undone first.

In wrapper mode, keep the agent working in its own branch (`agent/…`) and don't work in the
same files at the same time: you share a working tree.

The wiring lives in the environment of what `writ git` and `writ exec` start, so **every git
that process runs gets it**, in any repository: a build script or a tool that commits in
another clone sends that commit to the daemon as if it were for the wired repo, and its SSH
remotes are reached with the session's key (and fail on the daemon's pinned host key). Run
only the work for the wired repo under `writ exec`.

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
