# Process hardening

Once unsealed, the daemon holds its secrets in memory: the agent signing keys, the upstream
credentials and tokens, the CA key, the keystore's identity. Each `writd` process that holds a
secret first closes the ways the operating system could let them out: a core dump when it
crashes, a debugger attached to it, its memory written to swap.

Every step is per process (a limit, a flag, a call): Writ never changes a setting of the whole
system, and never asks you to, so a development Mac or a shared host runs it as it is.

- **Required:** no core dump and no debugger, which only the process decides. If one can't be
  applied, the process stops before it reads a secret, with the reason.
- **Best effort:** memory locked out of swap, which the host's lock limit decides. If it isn't
  allowed, a warning at start names the fix, which is up to you; the daemon runs either way.

## Which processes

| Process | Holds | Says what it couldn't apply |
|---|---|---|
| `writd run` | every secret, once unsealed | yes, in its log at start |
| `writd init` | the passphrase, every key it makes | yes, on stderr |
| `writd recover` | the passphrase, the authority key | yes, on stderr |
| `writd upstream-credential` (git's credential helper, one per HTTPS operation) | one token, for one operation | only a refusal (then git's operation fails): it runs for each git operation, so a warning would repeat each time |

## The steps

| Step | Linux | macOS |
|---|---|---|
| No core dump | `RLIMIT_CORE` 0 (soft and hard), and not dumpable (`PR_SET_DUMPABLE` 0) | `RLIMIT_CORE` 0 (soft and hard) |
| No debugger | not dumpable: a process of the same user can't attach (`ptrace`) nor read `/proc/<pid>/mem`; root still can | `PT_DENY_ATTACH`: an attach is refused, root's too. A process already traced (started under a debugger) would be killed by it, so it is checked first: a release build refuses to start traced; a debug build (developing writd) skips it with a warning |
| Memory out of swap | `mlockall(MCL_CURRENT \| MCL_FUTURE \| MCL_ONFAULT)`, only when the lock limit is unlimited or the process has `CAP_IPC_LOCK`: under a smaller limit, an allocation would fail once it is reached and the daemon abort | no call locks a whole process: one info line; macOS encrypts swap |

## When a step isn't applied

What each warning says, and its fix, optional:

- **Memory not locked (Linux): the lock limit is not unlimited.** Raise it for the daemon
  only: `ulimit -l unlimited` in the shell that starts it, `LimitMEMLOCK=infinity` in its
  systemd unit, `ulimits: { memlock: -1 }` for its service in a compose file, or the
  `CAP_IPC_LOCK` capability. Without it, a page of a secret can reach swap: encrypt swap, or
  run without it.

What stops the process (required steps):

- **Not dumpable, the core limit or `PT_DENY_ATTACH`: the call failed.** Rare (a sandbox
  forbidding it); the error is named.
- **Traced (macOS, release build).** Start it without a debugger.
- **This build has no hardening for this OS (`NoHardening`).** Only Linux and macOS have one.

## Checking it on the host

**Linux**, with the daemon's pid (`pid=$(pgrep -u <daemon user> -n writd)`):

```sh
stat -c %U /proc/$pid/status            # root: not dumpable (the daemon runs as its own user)
grep 'Max core file size' /proc/$pid/limits   # 0 0
grep VmLck /proc/$pid/status             # more than 0 kB: memory locked (with an unlimited lock limit)
head -c1 /proc/$pid/mem                  # as the daemon's user: Permission denied
```

**macOS**:

```sh
lldb -p "$(pgrep -n writd)" --batch -o detach    # attach failed: Operation not permitted
```

`writd run`'s log says, at start, each step applied, not applied (a warning, with the fix) or
unavailable.

## What is left

Root, or whoever controls the daemon's user before it starts, can still read its memory; memory
not locked can reach swap. The [threat model](../threat-model.md#residual-risks-v1)
lists it; hardware keys (M7.5, M7.6) take the secrets out of the process's memory.
