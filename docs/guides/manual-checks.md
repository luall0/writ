# Manual checks

Checks that need a person: a Touch ID, a hardware key. `make test` covers everything else
with generated keys and throwaway agents; these run the same code with your real approver.
They only use the development daemon (`make run`), test keys and the throwaway `demo` repo.

## Approving with Secretive (Touch ID)

[M2](../history/m2-ticket-flow.md)'s acceptance item "signed with Secretive". `writ sign`,
`writ refuse` and `writ revoke` sign through Secretive's agent with your dedicated approval
key, and nothing else. Each signature is one Touch ID.

You need Secretive with a dedicated approval key ("Require authentication" on), and three
terminals at the repo root.

**1. Your approval public key.** In Secretive, select the approval key and copy its public
key (the files are also in
`~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/PublicKeys/`). Save it as
the client's approval key, and list it as the daemon's approver:

```sh
mkdir -p dev/data/client
pbpaste > dev/data/client/approver.pub          # the copied public key line
echo "me $(cat dev/data/client/approver.pub)" > dev/approvers
```

Both stay out of git (`dev/data/` and `dev/approvers` are ignored). Never put a private key
there: only the public line.

**2. Pin the daemon** (host key for SSH, certificate fingerprint for HTTPS):

```sh
make dev-client
```

**3. Terminal 1: the daemon.**

```sh
make run
```

It prints its host key, TLS fingerprint, your approver's fingerprint (check it matches the
key in Secretive) and its listeners: agents on 2222, approvals on 2223 (SSH) and 8443
(HTTPS).

**4. Terminal 2: the agent side.** Submit `dev/ticket.yaml` and wait for the decision:

```sh
source dev/client.env
cargo run -q -p writ-cli -- request dev/ticket.yaml
```

It prints the ticket id and waits.

**5. Terminal 3: the approver side.** Review and sign:

```sh
source dev/client.env
cargo run -q -p writ-cli -- sign
```

The ticket is shown first (agent text behind `│`). Answer `y`: Secretive asks for Touch ID.
Terminal 2 then prints `Lease wrt_… granted until …` and exits 0; the session is in
`dev/data/client/sessions/<id>/` (`key`, `key-cert.pub`, `lease.json`).

`dev/client.env` uses HTTPS for the approval API. To check SSH too, run step 5 again with
`WRIT_APPROVAL_URL=ssh://127.0.0.1:2223`.

**6. Refuse and revoke** (also signed: `decisions: signed` in `dev/writd.yaml`):

```sh
# terminal 2: submit again
cargo run -q -p writ-cli -- request dev/ticket.yaml
# terminal 3: refuse it (Touch ID); terminal 2 prints the feedback and exits 4
cargo run -q -p writ-cli -- ls
cargo run -q -p writ-cli -- refuse <pending id> -m "Manual check: refused on purpose"
# terminal 3: revoke the lease from step 5 (Touch ID)
cargo run -q -p writ-cli -- revoke <active lease id>
```

**7. What to check.**

- Every signature asked for Touch ID, and Secretive named the approval key, never another.
- Answering `n` at the prompt signs nothing (`Nothing signed.`, exit 6).
- Cancelling Touch ID fails the command (`ssh-keygen could not sign`), and the ticket stays
  pending (`writ ls`).
- `dev/data/audit.jsonl` has `grant allowed`, `refuse done` and `revoke done` lines whose
  `approver` is your key's fingerprint, and no key material.

**8. Clean up.** Stop `make run` (Ctrl-C), then:

```sh
rm -rf dev/data dev/approvers
```

When it passes, note it under the acceptance item in
[the M2 history page](../history/m2-ticket-flow.md).

## Approval key through your own agent (any key)

`make test-agent KEY=<public key .pub> [AGENT=<socket>]` signs a random message with a key in
your agent and verifies it in Rust (checked in [M0](../history/m0-protocol-spike.md) with a
Secure Enclave key). It doesn't need the daemon.
