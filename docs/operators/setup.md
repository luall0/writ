# Setup

From nothing to a running, unsealed `writd`. Two machines are involved (they can be the same):

- **The daemon host**, where `writd` runs and keeps its files.
- **Your machine**, the approver's: `writ`, and your approval key in Secretive.

These are the exact commands `make e2e` runs before every scenario, so they are known to work
([end-to-end](../end-to-end.md#commands-the-docs-show)).

## What you end up with

One directory on the daemon host, owned by the daemon's user:

| Path | What it is | Made by |
|---|---|---|
| `writd.yaml` | The daemon's configuration: the host's settings only | You, from the [template](templates/writd.yaml) |
| `policy.yaml` | The policy's first version: the keys, the remotes' host keys, the repos agents may use, and the templates that cap tickets | You, from the [template](templates/policy.yaml) (it can start with no entry) |
| `approvers` | The keys that may sign tickets and changes | You (step 2) |
| `readers` | The keys that may use the approval API | You (step 2) |
| `data/keys/` | Every secret, encrypted | `writd init` (step 4) |
| `data/boot/` | The keys the daemon needs before it is unsealed | `writd init` (step 4) |
| `data/` | Leases, ledger, audit log, mirrors | `writd run` (step 8) |

`data/boot/` may live on another volume ([why](sealing.md#how-the-keystore-works)).

After `writd init`, the host's files no longer change the policy: you change it from your
machine with `writ admin`, one signed change at a time (steps 10 to 14).

## On the daemon host

1. **Write `writd.yaml` and `policy.yaml`**, from the templates. The paths in `writd.yaml`
   are relative to it, for example:

   ```yaml
   state_dir: data
   policy: policy.yaml
   approvers: approvers
   readers: readers
   keystore: { sealed: { dir: data/keys, boot: data/boot } }
   ```

   `policy.yaml` can start with no entry, everything added from your machine once the daemon
   runs:

   ```yaml
   keys: {}
   repos: {}
   templates: {}
   ```

   Or write your entries now: every key the policy names declared in
   its `keys` section, every `ssh://` repo's host pinned (step 3)
   ([every key](policy-yaml.md)).

   Both files mode 0644 or stricter. Every setting: [`writd.yaml`](writd-yaml.md),
   [`policy.yaml`](policy-yaml.md). A commented example: the
   [development configuration](../../dev/writd.yaml).

2. **List your keys** in two files. On your machine, make your reader key:

   ```sh
   writ reader <name>
   ```

   - Put the line it prints into `readers`.
   - Put your approval key's public half into `approvers`, as `<name> <public key>`.

   If you can, add a second approval key (a YubiKey) and a second reader on another machine
   now. Losing your only one is painful ([recovery](recovery.md)).

3. **Pin the hosts of the repos you wrote** into `policy.yaml` (skip this with a policy of
   no entry: step 10 does it from your machine):

   ```sh
   ssh-keyscan -t ed25519 <host> > <host>.keys
   ssh-keygen -lf <host>.keys
   ```

   Compare the fingerprint with the one the remote publishes. Never trust a scan alone. Then
   put the key (the line's last two fields) under `upstream_hosts`, as
   `<host>: ["ssh-ed25519 AAAA…"]` (`"[<host>]:<port>"` off port 22).

4. **Create the keystore**, as the daemon's user:

   ```sh
   writd init writd.yaml
   ```

   It asks for a passphrase twice (12 characters or more; one line of stdin when it isn't a
   terminal). Keep it in a password manager: you type it at every unseal, and nothing
   recovers a lost one. It makes every key the policy declares, and prints what to
   register. A key declared later is made by the signed change that declares it.

5. **Register the upstream keys** the policy declares (none with a policy of no entry):

   ```sh
   writd upstream-keys writd.yaml
   ```

   It prints each key and the repos that use it. Add each one as a **deploy key with write
   access** on its repository ([why](#upstream-keys-and-host-keys)).

6. **Register the agent signing keys** on your remote account, so agent commits show as
   verified (optional):

   ```sh
   writd signing-keys writd.yaml
   ```

   Forgejo and Gitea ask you to prove the key: [proving a signing key](../architecture/approvals.md#proving-a-signing-key-to-a-remote).
   A key added later: `writ admin key show <id> --public` prints its public half.

7. **Pin the daemon's identity** on every client. Print it:

   ```sh
   writd host-key writd.yaml
   writd tls-fingerprint writd.yaml
   ```

   Then add these lines:

   | Where | File | Line |
   |---|---|---|
   | Each agent host | `~/.writ/known_hosts` | `[<daemon>]:2222 <key>` |
   | Your machine | `~/.writ/known_hosts` | `[<daemon>]:2223 <key>` |
   | Your machine | `~/.writ/tls_pins` | `[<daemon>]:8443 SHA256:…` |

   Steps 5 to 7 only read public keys: no passphrase needed.

8. **Start the daemon**, from its directory:

   ```sh
   writd run writd.yaml
   ```

   It starts sealed and [hardened](hardening.md). Its log shows its host key, its TLS
   fingerprint, the fingerprint of each approver and reader, and its listeners. Check them
   against what you pinned and listed.

## From your machine

9. **Unseal it**. You'll do this after every restart:

   ```sh
   writ unseal
   ```

   It asks for the passphrase, then one Touch ID.

10. **Pin a remote's host**, on a terminal:

    ```sh
    writ admin host add <host>
    ```

    The daemon scans the host (one Touch ID) and shows its keys with their fingerprints.
    Compare them with the ones the remote publishes, answer `y`, then sign the change that
    pins them. `<host>:<port>` for another port than 22. A host whose keys changed later:
    `writ admin host rescan <host>`.

11. **Make a template**, the most a ticket for its repos may ask:

    ```sh
    writ admin template add <template>
    ```

    Each field is asked with its bounds and default ([what each means](policy-yaml.md#templates-templatesname)).
    `--from <other>` starts from another template's values.

12. **Declare the repo's upstream key**:

    ```sh
    writ admin key add <id> use=upstream kind=ssh algorithm=ed25519
    ```

    It prints the key's public half once the change applies: add it as a **deploy key with
    write access** on the repository. Some remotes take only RSA: `algorithm=rsa3072`.

13. **Add the repo**:

    ```sh
    writ admin repo add <repo> upstream=ssh://git@<host>/<path>.git upstream_credential=<id> templates=<template>
    ```

    On a terminal, `writ admin repo add <repo>` alone asks each field instead, can declare a
    new key in the same change, scans a host with no pin, and checks the repo once you press
    Enter.

14. **Check it**, once its key is registered on the remote:

    ```sh
    writ admin repo check <repo>
    ```

    The daemon reads, syncs its mirror, and tries a push that sends nothing, with the repo's
    key: `<repo> is ready` once all three pass. A step that fails says what the remote said.

15. **Add the tokens** of `https://` repos ([details](#https-upstreams-and-tokens)):

    ```sh
    writ admin token <id>
    ```

    Paste the token (it isn't shown), then sign.

Done. `writ admin repo|template|key|host list` and `show` read what is in force; `set`
changes one field ([changing the policy](sealing.md#changing-the-policy-the-approvers-or-the-readers)).
Next: [wire a repo for an agent](good-practice.md).

## Upstream keys and host keys

The daemon fetches from and pushes to each repo's `upstream` with that repo's
`upstream_credential`, a key it holds ([gateway](../architecture/gateway.md#upstream)).

**Use deploy keys.** GitHub, Codeberg, Forgejo and GitLab all have them. A deploy key reaches
one repository. A key added to your account reaches every repository you can push to, and
then only the daemon's policy stops an agent from reaching the others.

**Pin host keys in the policy.** One entry per host in `upstream_hosts`, signed like the rest
of the policy, added with `writ admin host add` (step 10):

```yaml
upstream_hosts:
  github.com: ["ssh-ed25519 AAAA…"]
  "[forgejo.home]:2222": ["ssh-ed25519 AAAA…"]
```

- A policy whose `ssh://` repo's host has no pin is refused.
- It refuses a sync if the host shows a different key. If the remote really changed its
  keys, `writ admin host rescan <host>` shows the new ones beside the pin, and replaces it
  once you compared them.
- Wildcards, hashed names and `@cert-authority` lines are refused.

**Large repositories.** One sync may take at most `mirrors.max_fetch` (1 GiB) and
`mirrors.timeout` (5 min). A first sync of a big repository may need more
([`mirrors`](writd-yaml.md#mirrors-and-upstream)).

## HTTPS upstreams and tokens

For a remote reachable only over HTTPS: set `upstream: https://host[:port]/path`, and
`upstream_credential` names a token, declared like any key, with the host it is sent to:
`writ admin key add <id> use=upstream kind=token host=<host>`.

**Make the token as narrow as the remote allows:**

| Remote | Token |
|---|---|
| GitHub | Fine-grained, for that one repository, "Contents: read and write" |
| GitLab | Project access token with `write_repository` |
| Forgejo, Gitea | Token with `write:repository` |

**Add it**, once the daemon is unsealed: `writ admin token <id>`. Run it again to rotate the
token. Until it is added, that repo's syncs and pushes are refused (with the command to run);
everything else works.

**Good to know:**

- The token is encrypted on your machine before it is sent. The daemon stores it as
  `tokens/<id>.age`.
- It must be one word of printable ASCII. An id is either a key or a token, never both.
- The daemon sends the user name `writ`, which most remotes accept. If yours wants a specific
  one, put it in the URL (`https://x-token-auth@bitbucket.org/…`). A password in the URL is
  refused.
- The server's certificate is checked against the system's CAs. For a self-hosted remote
  behind your own CA, point `mirrors.ca_certs` at its PEM file (it then replaces the system's
  CAs).
- Needs git 2.47 or newer on the daemon host.
- The development keystore (tests only) reads the token from the file `<keys>/tokens/<id>`
  (0600) instead.

**How the token is protected:** git gets it for one operation at a time, from the daemon's own
credential helper, through a socket only the daemon's user can reach. It never appears in a
command line, an environment variable, a URL, a config file or a log. Redirects are refused,
and git can only reach the policy's host, through a proxy that caps how much it downloads.

## Notes on the remote

With `ticket_link: notes` ([reference](policy-yaml.md#linking-commits-to-leases-ticket_link)),
the daemon adds a git note `Writ: <lease id>` to each commit it pushes, under
`refs/notes/commits` (or `refs/notes/writ` with `notes_ref: writ`).

**The upstream credential must be allowed to push the notes ref.** Write access does it on
GitHub, Codeberg, Forgejo and Gitea. A rule limiting which refs may be pushed must let it
through. If the remote refuses a note:

- the branch is still pushed;
- the audit log gets a denied `notes` line with the remote's reason;
- the note is retried at the next push or background sync, until it goes through.

**Turning notes on later** is fine: commits the daemon pushed before get their notes at the
next background sync (or the next start).

**Reading them.** Forgejo and Gitea show them on a commit's page. GitHub's web interface
doesn't. From a clone:

```sh
git fetch origin refs/notes/commits:refs/notes/commits
git log
```

With `notes_ref: writ`, fetch `refs/notes/writ` instead and read with `git log --notes=writ`.
Notes someone else wrote under `refs/notes/commits` are kept: the daemon adds its line to
theirs.

**A note is not proof.** Notes are unsigned (`writd <writd@writ.invalid>`), and anyone who can
push to the remote can write one. They are a readable copy. The daemon's ledger is the
reference.
