# Working beside an agent

Writ controls what an agent does **through the daemon**. It can't stop an agent running as your
user from using what is on your machine: that part is up to you. This page covers both
([threat model](../threat-model.md#what-writ-does-not-guarantee)).

## Wiring a repo: wrapper or whole repo

`writ init <repo>` wires a clone for an agent, in one of two modes
([details](../architecture/clients.md#repo-setup-on-an-agent-host)):

| | Wrapper (default) | Whole repo (`--whole-repo`) |
|---|---|---|
| For | Your own clone, shared with an agent | A clone only the agent uses: a VM, a container, a separate directory |
| The agent runs | `writ git …` (every git command, rebase and push included), or `writ exec -- <program>` for a tool that runs git | Plain `git` |
| Your own `git` | Unchanged: your key, your email, your remotes | — |
| The repo's git config | Untouched | Changed |

In both modes, the agent's `origin` goes through the daemon, so it pushes to `origin` as
usual. In wrapper mode, your own `git push origin` still goes straight to the remote.

- `writ init --undo` reverts either mode exactly.
- One wiring per clone: undo it before switching modes.
- For one agent at a folder of repositories, run `writ init` in the folder, with no repo
  name: it wires every repository in it, in the mode you pick
  ([a folder of repositories](clients.md#a-folder-of-repositories)).

**In wrapper mode:**

- Keep the agent on its own branch (`agent/…`), and don't edit the same files at the same
  time: you share one working tree.
- Everything started under `writ git` or `writ exec` is wired, in any repository. A build
  script that commits in another clone gets refused, and its SSH remotes fail. Run only the
  work on the wired repo under `writ exec`.

## Protect your own credentials

An agent running as your user can run anything you can: `git`, `ssh`, `ssh-keygen`, your
tools. Your keys stay yours only if using them needs **you**:

- **Your commit signing key** requires your presence: Secretive with "Require
  authentication" (Touch ID), or a security key (`sk-ssh-ed25519`, a touch per signature).
- **Your push key** too, the same way.
- **No credential that answers silently:**
  - no credential helper that hands out a token without asking (`osxkeychain`,
    `gh auth setup-git`);
  - no remote token in the environment (`GH_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`);
  - no logged-in CLI the agent could drive.

Check:

```sh
git config --show-origin --get-all credential.helper   # expect nothing, or a helper that prompts
ssh-add -l                                              # every key here should need a touch
env | grep -iE 'token|secret'                           # nothing a remote accepts
```

Then an agent running plain `git commit -S` or `git push origin` gets a Touch ID prompt you
won't approve, or nothing.

## Guardrails in the agent's configuration

Most agent harnesses can deny commands. Deny the plain ones and allow the wrapper, so a sloppy
agent is told to use `writ git`. For Claude Code, in `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Bash(writ git:*)", "Bash(writ exec:*)"],
    "deny": ["Bash(git commit:*)", "Bash(git push:*)", "Bash(git tag:*)", "Bash(gh:*)"]
  }
}
```

**This is a guardrail, not a boundary.** A determined agent gets around a deny list easily:
`/usr/bin/git commit`, `git -C . commit`, `sh -c "git push"`, a script it writes. The real
boundaries are your keys needing your touch, and the daemon checking everything that goes
through Writ.

## Check what landed

- **Signatures:** `git verify-commit <rev>` with the agent's key in an allowed-signers file
  (the key is `<WRIT_HOME>/sessions/<lease>/signing_key.pub`), or `git log --show-signature`.
- **Which lease:** a `Writ: wrt_…` trailer or git note, if the repo's `ticket_link` asks for one. The
  daemon's ledger and audit log record every signature with its lease and key either way.
- **Who:** agent commits carry the agent's email (`user+agent@…`), yours carry yours.

## More isolation

- **The agent on another machine** (a VM, a container) against a daemon on another host:
  detached mode ([M8](../roadmap.md#m8--detached-deployment)). The agent host then holds no
  key and no remote credential at all.
- **A daemon running as its own user** on your Mac: local mode
  ([M7](../roadmap.md#m7--local-mode-on-the-mac)). The agent can't read the daemon's keys,
  though it still runs as you.
- **One agent per OS user, container or VM** when several agents share a host. Under one user,
  each could read the others' session files and use their leases
  ([threat model](../threat-model.md#1-agent--daemon-session-certificate)). Each gets its own
  `~/.writ` (0700). Set `max_active_per_source: 1` in `writd.yaml` to limit a host to one
  active lease.
- **Agents sharing one Writ home** each keep their own lease with `WRIT_SESSION` (the line
  `writ request` prints) or a clone pinned with `writ init --lease`: a convenience against
  mix-ups, not against an agent that wants another's lease
  ([several agents](clients.md#several-agents-on-one-host)).
