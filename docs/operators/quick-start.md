# Quick start

From a finished `make install` on your Mac to an agent's first commit, signed by the daemon
and shown as verified on your remote. Each step says what it is for in a line; the other pages
say more.

Before you start: Writ installed with `make install` ([install](install.md)), your
[approval key](README.md#words-used-in-these-pages) in its agent, and a repository on GitHub, Codeberg, Forgejo or Gitea that you can change the
settings of. A throwaway one is best the first time.

## The keys, and who signs what

Three kinds of signature are involved. Knowing which is which makes every step below clear:

| Signature | Made by | With | Proves |
|---|---|---|---|
| An **approval** | You, confirmed in your ssh-agent | Your approval key | You agreed to a ticket, a change of the policy, or a proof. Its SSH namespace is `writ-approval`, so it can never pass for a commit signature or a login |
| A **commit signature** | The daemon, when the agent commits | An agent signing key (`agent-01`, made by the install) | The commit was made under a lease you signed. The remote shows it as verified |
| The **upstream login** | The daemon, when it fetches or pushes | An upstream key, one per repository | The daemon may read and push that repository on the remote. The agent never holds it |

Agents hold none of these keys. They ask the daemon, and the daemon checks every request
against what you signed.

## 1. Unseal the daemon

**After the install, and after every restart:**

```sh
writ unseal
```

It asks for the keystore passphrase, if you chose one, then one approval. Until then the
daemon runs but uses no key.

## 2. The signing key

`agent-01` was made by the install. It signs your agents' commits. Your remote shows those
commits as **verified** when the key is on your account and the commit's email is one of your
account's verified emails.

**Print its public half:**

```sh
writ admin key show <key> --public
```

with `agent-01` for `<key>`. On the remote, add it to **your account** as an SSH **signing**
key (GitHub: Settings, SSH and GPG keys, New SSH key, key type "Signing Key").

**Prove it**, on Forgejo, Gitea and Codeberg. GitHub asks for no proof: skip this. The remote
shows a challenge, a token of 64 characters, next to the key. Sign it through the daemon:

```sh
printf %s <token> | writ prove-key <key> --namespace gitea
```

It shows the key, the namespace and the token, then asks before it signs (one approval). Paste
the signature it prints back into the remote. The namespace says what the signature is for:
`gitea` is the one these remotes check a proof with. Writ refuses `git`: a proof must never
pass for a commit signature.

## 3. The upstream key

The key the daemon uses to reach your repository on the remote: one per repository, the
agent never holds it.

**Make it:**

```sh
writ admin key add <id> use=upstream kind=ssh algorithm=ed25519
```

`<id>` is a name you choose, like `upstream-myrepo`. It asks for one approval, then prints the
key's public half. On the remote, add it to the repository as a **deploy key with write
access**. A deploy key reaches that one repository only; a key added to your account would
reach every repository you can push to. Some remotes take only RSA: use `algorithm=rsa3072`
instead.

## 4. A template

A template is the most a ticket may ask for a repository: the operations, the branches, how
long a lease lasts, how many commits and pushes. Each repository names the templates its
tickets may use, so make one first.

**Make one**, on a terminal:

```sh
writ admin template add <template>
```

It asks each field in turn. Where there is a choice, use the arrow keys and Enter. In a list
where several can be picked, space ticks. For a first template:

- **operations**: tick `fetch`, `commit_sign` and `push`.
- **branches**: `agent/*`, so agents push only to their own branches.
- **committer_emails**: one of your account's verified emails, for the verified badge.
- **signing_key**: `agent-01`.
- Enter keeps the default of every other field.

It then shows the change in full and asks you to sign it.

## 5. The repository

**Add it**, on a terminal:

```sh
writ admin repo add <repo>
```

`<repo>` is the name agents and tickets use for it, like `myrepo`. It asks, in turn:

1. **upstream**: the repository's SSH URL on the remote, like
   `ssh://git@github.com/you/myrepo.git`.
2. When the remote's host is new to the daemon, it reads the host's keys (one approval) and
   shows their fingerprints. Compare them with the ones the remote publishes on its website,
   then answer `y`. From then on the daemon refuses that host if its key ever changes.
3. **upstream_credential**: the key of step 3, picked in the list. (`new`, the first
   option, would make one in the same change instead.)
4. **templates**: tick the one you made.
5. Enter keeps the default of every other field. It then shows the change in full and asks
   you to sign it.

Then press Enter: the daemon reads the repository, copies it, and tries a push that sends
nothing, with the key of step 3. `<repo> is ready` once all three pass. A step that fails says
what the remote said.

A big repository takes a while the first time; `writ admin repo status` shows how far the copy
is:

```sh
writ admin repo status
```

Pressed Esc before the check, or added the deploy key later? Check it then:

```sh
writ admin repo check <repo>
```

## 6. A first agent

**Wire your clone of the repository**, in its folder:

```sh
writ init demo --agents claude
```

with your `<repo>` in place of `demo`, and the agent you use (`claude`, `agents` for Codex and
others, `opencode`, `cursor`). It routes the clone's git through the daemon and installs the
Writ skill, which tells the agent how to ask for a ticket. Your own git setup is not touched.

**Start the agent under Writ**, in the same folder:

```text
writ run -- claude
```

Give it a task. It writes a ticket and asks for it. The approval popup comes up: read what
you sign in the middle, and the agent's plan on the right. Sign, then confirm it in your agent. The
agent commits and pushes through the daemon. On the remote, its commit shows as verified.
When the agent quits, its lease is revoked.

## Next

- [Working beside an agent](good-practice.md): what the agent can and can't do, and the
  wrapper or whole-repository wiring.
- [Daily operations](sealing.md): unsealing, changing a template or a repository, adding a
  token for an `https://` remote.
- [The approval popup](clients.md#the-approval-popup-on-the-mac) and every client setting.
- [`policy.yaml`](policy-yaml.md): every field a template and a repository take.
