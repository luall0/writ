# Client settings: `writ` and `writ-sign`

What `writ` reads, on an agent host and on your machine. Nothing here grants anything: the
daemon checks everything again. The clients never read `~/.ssh` and never use your own
ssh-agent to connect (it would offer your personal keys to the daemon).

## `writ`: flags and environment

Each setting is a flag or an environment variable; the flag wins. `writ <command> --help`
lists them.

| Flag | Variable | Default | What it is |
|---|---|---|---|
| `--home` | `WRIT_HOME` | `~/.writ` | Writ's directory on this host: sessions, pins, the reader key |
| `--known-hosts` | `WRIT_KNOWN_HOSTS` | `<home>/known_hosts` | The daemon's pinned SSH host key ([setup, step 7](setup.md#steps)) |
| `--tls-pins` | `WRIT_TLS_PINS` | `<home>/tls_pins` | The daemon's pinned TLS certificate, for an `https://` approval URL |
| `--reader` | `WRIT_READER` | `<home>/reader` | Your reader key. `writ reader <name>` creates it and prints the line for the daemon's `readers` |
| `--url` | `WRIT_URL` | none | The agents' listener, `ssh://host:port`. Used by `request`, `wait`, `close`, `policy`, `init` |
| `--approval-url` | `WRIT_APPROVAL_URL` | none | The approval listener, `https://host:port` or `ssh://host:port`. Used by `ls`, `sign`, `refuse`, `revoke`, `report`, `prove-key` |
| none | `WRIT_SESSION` | none | The lease an agent works under: `writ git`, `writ exec`, `writ close`, `writ mark` and `writ-sign` use its session, whatever `current` points at. Set it to the line `writ request` prints. A lease this host doesn't have, or that ended, is refused, never replaced by `current`. [Several agents](#several-agents-on-one-host) |
| `--key` | `WRIT_APPROVAL_KEY` | `<home>/approver.pub` | Your approval key's **public** half (a private key file is refused) |
| `--agent` | `WRIT_APPROVAL_AGENT` | `$SSH_AUTH_SOCK` | The ssh-agent holding your approval key: Secretive's socket |
| none | `WRIT_SSH_KEYGEN` | `/usr/bin/ssh-keygen` | The `ssh-keygen` that signs your approvals: an absolute path, OpenSSH 8.9 or newer. Never looked up in `PATH`, where anything could sit first and change what gets signed |
| none | `WRIT_GPG` | `/usr/bin/gpg` | `writ-sign`: the `gpg` it hands git's OpenPGP `--verify` calls to, an absolute path. It never runs gpg to sign: the key is the daemon's |

Every command and its arguments: [clients](../architecture/clients.md). `writ sign`'s
narrowing flags: [approvals](../architecture/approvals.md).

Approve from a terminal at least 80 columns wide. `writ sign` keeps every row within that
width, so the terminal never wraps one; a narrower terminal would wrap rows again, and a
wrapped row loses the `│` mark that shows text the agent wrote.

## Files

| Path | Where | What it is |
|---|---|---|
| `<home>/known_hosts` | Both | The daemon's host key: `[<daemon>]:2222 <key>` on agent hosts, `[<daemon>]:2223 <key>` on your machine. A plain file, yours (or root's) and writable by nobody else, or `writ` refuses it |
| `<home>/tls_pins` | Your machine | The daemon's TLS certificate: `[<daemon>]:8443 SHA256:…`. A plain file, yours (or root's) and writable by nobody else, or `writ` refuses it |
| `<home>/approver.pub` | Your machine | Your approval key's public half |
| `<home>/reader` | Your machine | Your reader key, mode 0600 |
| `<home>/sessions/<lease>/` | Agent host | One per ticket: its session key, its certificate once signed, the lease's terms, and the agent signing key's public half (`signing_key.pub`, for `git verify-commit`), and for an OpenPGP key its certificate (`signing_key.asc`: import it into a GnuPG home to verify). `ended` once it was closed or renewed; `marks`, the agent's `writ mark` lines |
| `<home>/sessions/current` | Agent host | A link to the latest granted session: what wired repos use when neither `WRIT_SESSION` nor a pinned lease says otherwise |
| `<skills folder>/writ/SKILL.md`, `timings.md` | Agent host | The agent skill `writ init` installs, and beside the first one what the agent learns about sizing tickets. [The skill](#the-agent-skill) |

## `writ init` and `writ-sign`

`writ init <repo>` writes the git settings a wired repo needs: in the environment of
`writ git` and `writ exec` (wrapper mode), or in the repo's config (`--whole-repo`). It
records them in `<git common dir>/writ/config`. Never set them by hand: `writ init --undo`
removes exactly what `writ init` wrote.

`writ-sign` (git's `gpg.ssh.program`) reads only those settings: `writ.url`, `writ.repo`,
`writ.gitdir`, `writ.session`, and the SSH command git uses. Each one:
[repo setup on an agent host](../architecture/clients.md#repo-setup-on-an-agent-host).

`writ init`'s flags:

- **`--whole-repo`** writes the settings in the repo's config, for a clone dedicated to an
  agent.
- **`--email`** is the committer email (default: the lease's, when it allows one). The name
  is the lease's when its template sets `committer_name`: `writ git` sets git's `user.name`
  to it, whatever your own git says.
- **`--lease`** pins the repo to a lease: its session, never `current` (`WRIT_SESSION` still
  comes first).
- **`--agents`** says who gets the skill, without asking: `claude`, `agents`, `opencode`,
  `cursor`, comma-separated, or `none`.
- **`--skill-dir`** also installs the skill in that folder (`<folder>/writ/SKILL.md`).
- **`--global`** installs the skill in your own folders (`~/.claude/skills`…) instead of the
  repo's.
- **`--agents-md`** adds a line pointing at the skill to `AGENTS.md` and `CLAUDE.md`.
- **`--undo`** takes back what `writ init` did. The timings file stays.

## Several agents on one host

Each `writ request` that is granted moves `<home>/sessions/current`. Two agents sharing a home
would follow it and swap leases. Give each agent its own lease:

- `writ request` prints `export WRIT_SESSION=<lease>`: run the agent with it. It warns when it
  moves `current` while another lease of the home still runs.
- Or pin a clone to a lease with `writ init --lease <lease>`.
- Or give each agent its own home (`WRIT_HOME`), or its own OS user: see
  [good practice](good-practice.md#more-isolation).

## The agent skill

`writ init` installs the skill where each agent looks for it. On a terminal it asks which
agents, with the ones it detects marked; `--agents` or `--skill-dir` answer for it. Without a
terminal and without them, it refuses and wires nothing.

| Agent | Folder in the repo | With `--global` |
|---|---|---|
| Claude Code | `.claude/skills` | `~/.claude/skills` |
| Codex, Gemini CLI, GitHub Copilot, Amp (`agents`) | `.agents/skills` | `~/.agents/skills` |
| OpenCode | `.opencode/skills`, only when neither of the two above is picked: it reads them too | `~/.config/opencode/skills` |
| Cursor | `.cursor/skills` | `~/.cursor/skills` |

- In the repo, each `writ/` folder installed goes in `.git/info/exclude`: never committed.
- `SKILL.md` is Writ's: a new `writ init` replaces it. A `SKILL.md` that isn't Writ's is never
  written over.
- The skill has the agent start each task that changes files, before any edit, with
  `writ policy` (what a ticket for the repo may ask: run it yourself to see what your agents
  see) and the ticket, checked with `writ request --dry-run` before it is submitted.
- `timings.md` beside the first one is what the agent learns. `writ close` records each run in
  it and keeps it within its limits; `writ timings` changes them; `writ check timings.md`
  says what `writ close` would drop or rewrite. `writ init --undo` keeps it.
