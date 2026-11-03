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
| `--url` | `WRIT_URL` | none | The agents' listener, `ssh://host:port`. Used by `request`, `wait`, `init` |
| `--approval-url` | `WRIT_APPROVAL_URL` | none | The approval listener, `https://host:port` or `ssh://host:port`. Used by `ls`, `sign`, `refuse`, `revoke`, `prove-key` |
| `--key` | `WRIT_APPROVAL_KEY` | `<home>/approver.pub` | Your approval key's **public** half (a private key file is refused) |
| `--agent` | `WRIT_APPROVAL_AGENT` | `$SSH_AUTH_SOCK` | The ssh-agent holding your approval key: Secretive's socket |
| none | `WRIT_SSH_KEYGEN` | `/usr/bin/ssh-keygen` | The `ssh-keygen` that signs your approvals: an absolute path, OpenSSH 8.9 or newer. Never looked up in `PATH`, where anything could sit first and change what gets signed |
| none | `WRIT_GPG` | `/usr/bin/gpg` | `writ-sign`: the `gpg` it hands git's OpenPGP `--verify` calls to, an absolute path. It never runs gpg to sign: the key is the daemon's |

Every command and its arguments: [clients](../architecture/clients.md). `writ sign`'s
narrowing flags: [approvals](../architecture/approvals.md).

## Files

| Path | Where | What it is |
|---|---|---|
| `<home>/known_hosts` | Both | The daemon's host key: `[<daemon>]:2222 <key>` on agent hosts, `[<daemon>]:2223 <key>` on your machine |
| `<home>/tls_pins` | Your machine | The daemon's TLS certificate: `[<daemon>]:8443 SHA256:…` |
| `<home>/approver.pub` | Your machine | Your approval key's public half |
| `<home>/reader` | Your machine | Your reader key, mode 0600 |
| `<home>/sessions/<lease>/` | Agent host | One per ticket: its session key, its certificate once signed, the lease's terms, and the agent signing key's public half (`signing_key.pub`, for `git verify-commit`), and for an OpenPGP key its certificate (`signing_key.asc`: import it into a GnuPG home to verify) |
| `<home>/sessions/current` | Agent host | A link to the session wired repos use |

## `writ init` and `writ-sign`

`writ init <repo>` writes the git settings a wired repo needs: in the environment of
`writ git` and `writ exec` (wrapper mode), or in the repo's config (`--whole-repo`). It
records them in `<git common dir>/writ/config`. Never set them by hand: `writ init --undo`
removes exactly what `writ init` wrote.

`writ-sign` (git's `gpg.ssh.program`) reads only those settings: `writ.url`, `writ.repo`,
`writ.gitdir`, and the SSH command git uses. Each one:
[repo setup on an agent host](../architecture/clients.md#repo-setup-on-an-agent-host).
