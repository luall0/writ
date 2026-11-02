# Setting up the daemon

From nothing to a running `writd`: its files, the upstream credentials and host keys, the
pins on every client. Every key of the files it reads:
[`writd.yaml`](writd-yaml.md) and [`policy.yaml`](policy-yaml.md). Once it runs, wiring repos
for agents and keeping your own keys yours: [good practice](good-practice.md).

## The steps

On the daemon's host, in the directory that holds its files (`make e2e` runs
these steps, with these commands, before every scenario: [end-to-end](../end-to-end.md#commands-the-docs-show)).
The order matters only in that the daemon starts last: every command that prints a key works
before any approver or reader is listed.

1. **The configuration**: `writd.yaml`, with paths relative to it (`state_dir: data`,
   `policy: policy.yaml`, `approvers: approvers`, `readers: readers`,
   `mirrors.known_hosts: upstream_known_hosts`; the [development one](../../dev/writd.yaml)
   is a commented example; [every key](writd-yaml.md), a [template](templates/writd.yaml) to
   start from), and `policy.yaml`, the repo registry and the templates ([every key](policy-yaml.md),
   a [template](templates/policy.yaml)). Both 0644 or stricter, owned by
   the daemon's user.
2. **The upstream credentials**, each added on its remote (below: a deploy key with write
   access on its repository):

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   writd upstream-keys writd.yaml
   ```

   An `https://` upstream's credential is a token instead ([below](#https-upstreams-and-tokens)):
   paste it alone (then Enter, Ctrl-D) into its file in the keystore, readable by the daemon's
   user only:

   <!-- e2e: crates/writ-e2e/src/setup.rs -->
   ```sh
   (umask 077 && mkdir -p data/keys/tokens && cat > data/keys/tokens/<id>)
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
3. **Mind the bounds** ([`mirrors`](writd-yaml.md#mirrors-and-upstream) in `writd.yaml`): `max_fetch` (1 GiB) caps what one sync
   takes from upstream, `timeout` (5 min) how long it may take; a first sync of a large
   repository may need more.

## HTTPS upstreams and tokens

Where a remote is reachable over HTTPS only, a repo's `upstream` is `https://host[:port]/path`
and its `upstream_credential` names a **token** ([gateway](../architecture/gateway.md#upstream)):

1. **Make the token as narrow as the remote allows**: on GitHub a fine-grained token for that
   one repository with "Contents: read and write"; on GitLab a project access token with
   `write_repository`; on Forgejo or Gitea a token with `write:repository`. A token reaches
   whatever its scope covers: the daemon's registry is the only per-repo boundary beyond it.
2. **Put it in the keystore**: alone in `data/keys/tokens/<id>` (the development keystore,
   until the sealed keystore of M5), mode 0600, with the command above. The daemon refuses to
   start without it, or with anything but one word of printable ASCII in it. One id is a key
   or a token, never both.
3. **The user name**: most remotes take any name with a token (GitHub, GitLab, Forgejo,
   Gitea); the daemon sends `writ`. A remote that wants a given one has it in the URL
   (`https://x-token-auth@bitbucket.org/…`). Never a password in the URL: refused.
4. **The server's certificate** is checked against the system's CAs, or, when the remote's
   certificate comes from your own CA (a self-hosted Forgejo), against the PEM file
   `mirrors.ca_certs` names (an authority file, like `known_hosts`: it then replaces the
   system's). git 2.47 or newer on the daemon's host.

The token stays in the daemon: git gets it for one operation from the daemon's own helper,
through a socket only the daemon's user reaches; it is never in a command line, an
environment variable, a URL, the mirror's config or a log. A redirect is refused, and git
reaches only the registry's host, through a proxy that caps what upstream sends like
`max_fetch` does for SSH.

## Notes on the remote

A repo with `ticket_link: notes` ([reference](policy-yaml.md#the-repo-registry-reposname))
gets a git note per pushed commit, `Writ: <lease id>`, written and pushed by the daemon after
each push ([how](../architecture/gateway.md#notes)), under `refs/notes/commits` (git's own
notes ref) unless `notes_ref: writ` says `refs/notes/writ`:

1. **The credential pushes one more ref.** The repo's upstream key or token must be allowed to
   push the notes ref, not only branches: write access does it on GitHub, Codeberg,
   Forgejo and Gitea; a rule that limits which refs may be pushed must let it through. A
   refused notes push leaves the branch pushed, writes a denied `notes` line in the audit log
   with the remote's reason, and the next push of the repo writes the missing notes.
2. **Reading them.** Forgejo and Gitea show the notes under `refs/notes/commits` on a
   commit's page. GitHub's web interface shows none; from a clone, `git log` shows them once
   fetched:

   <!-- e2e: crates/writ-e2e/tests/scenarios/notes.rs -->
   ```sh
   git fetch origin refs/notes/commits:refs/notes/commits
   git log
   ```

   With `notes_ref: writ`, fetch `refs/notes/writ` and read them with
   `git log --notes=writ`. Under `refs/notes/commits`, notes a person wrote there stay: the
   daemon adds its lines to theirs.

3. **What a note is worth.** Notes commits are unsigned (`writd <writd@writ.invalid>`), and
   anyone who can push to the remote can write one: a note is a readable copy of the link,
   the daemon's ledger is the reference.
