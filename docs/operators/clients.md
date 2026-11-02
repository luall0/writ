# Client settings: `writ` and `writ-sign`

What the clients on an agent host and on the approver's machine read. Clients are untrusted
conveniences: nothing here grants anything, the daemon checks everything again. They never read
`~/.ssh` or use your own ssh-agent for connections (they would offer personal keys to the
daemon).

## `writ`: flags and environment

Each setting is a flag or its environment variable (the flag wins); `writ --help` and
`writ <command> --help` list them.

| Flag | Variable | Default | What it is |
|---|---|---|---|
| `--home` | `WRIT_HOME` | `~/.writ` | Writ's directory on this host: sessions, pins, the reader key |
| `--known-hosts` | `WRIT_KNOWN_HOSTS` | `<home>/known_hosts` | The daemon's SSH host key, pinned: `[<daemon>]:2222 <key>` (agents), `[<daemon>]:2223 <key>` (approvals); `writd host-key` prints it |
| `--tls-pins` | `WRIT_TLS_PINS` | `<home>/tls_pins` | The daemon's TLS certificate, pinned for an `https://` approval URL: `[<daemon>]:8443 SHA256:…`; `writd tls-fingerprint` prints it |
| `--reader` | `WRIT_READER` | `<home>/reader` | The key the approval API lets in; `writ reader <name>` makes it on first use and prints the line for the daemon's `readers` |
| `--url` | `WRIT_URL` | none | The agents' listener: `ssh://host:port` (`request`, `wait`, `init`) |
| `--approval-url` | `WRIT_APPROVAL_URL` | none | The approval listener: `https://host:port` or `ssh://host:port` (`ls`, `sign`, `refuse`, `revoke`, `prove-key`) |
| `--key` | `WRIT_APPROVAL_KEY` | `<home>/approver.pub` | The approval key's **public** half (a private key file is refused) |
| `--agent` | `WRIT_APPROVAL_AGENT` | `$SSH_AUTH_SOCK` | The ssh-agent holding the approval key (Secretive's socket) |
| none | `WRIT_SSH_KEYGEN` | `/usr/bin/ssh-keygen` | The `ssh-keygen` `writ sign`, `refuse`, `revoke` and `prove-key` sign with: an absolute path (OpenSSH 8.9 or newer), never looked up in `PATH` (whatever sat first in `PATH` would see the approval and choose what gets signed) |

Every command and flag, with its arguments: [clients](../architecture/clients.md);
`writ sign`'s narrowing flags: [approvals](../architecture/approvals.md).

## Files on the agent host

| Path | What it is |
|---|---|
| `<home>/known_hosts` | The daemon's host key (above) |
| `<home>/sessions/<lease>/` | One session per ticket: its key, its certificate once signed, the lease's terms and its agent signing key's public half (`signing_key.pub`, for `git verify-commit`) |
| `<home>/sessions/current` | The session a wired repo uses (a link to the active one) |

## Files on the approver's machine

| Path | What it is |
|---|---|
| `<home>/known_hosts`, `<home>/tls_pins` | The daemon's pinned identities (above) |
| `<home>/approver.pub` | The approval key's public half |
| `<home>/reader` | The reader key (above), mode 0600 |

## `writ init` and `writ-sign`

`writ init <repo>` writes the wiring a repository needs: git settings in the environment of
`writ git` and `writ exec` (wrapper mode) or in the repo's config (`--whole-repo`), recorded
in `<git common dir>/writ/config`. They are `writ init`'s to write and `--undo`'s to remove:
never set by hand. `writ-sign` (git's `gpg.ssh.program`) reads only them: `writ.url`,
`writ.repo`, `writ.gitdir`, and the SSH command git uses. The settings, one by one:
[repo setup on an agent host](../architecture/clients.md#repo-setup-on-an-agent-host).
