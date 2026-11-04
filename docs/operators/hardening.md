# Process hardening

Once unsealed, `writd` holds its secrets in memory. Before it reads any secret, each `writd`
process shuts the three usual ways memory leaks out:

| Protection | If it can't be applied |
|---|---|
| No core dump when it crashes | The process stops, and says why |
| No debugger attaching to it | The process stops, and says why |
| Its memory kept out of swap | A warning at start, with the fix. The daemon runs anyway |

Writ only changes settings of its own process. It never changes a system-wide setting, and
never asks you to.

## Which processes

| Process | Holds | Reports what it couldn't apply |
|---|---|---|
| `writd run` | Every secret, once unsealed | In its log, at start |
| `writd init` | The passphrase, every key it makes | On stderr |
| `writd recover` | The passphrase, the key protecting the authority files | On stderr |
| `writd keys create` | The passphrase, the key it makes | On stderr |
| `writd upstream-credential` (git's credential helper, one per HTTPS operation) | One token, for one operation | Only when it refuses (git's operation then fails), so the warning doesn't repeat at every operation |

## How, on each OS

| Protection | Linux | macOS |
|---|---|---|
| No core dump | `RLIMIT_CORE` 0, and the process marked not dumpable (`PR_SET_DUMPABLE` 0) | `RLIMIT_CORE` 0 |
| No debugger | Not dumpable: another process of the same user can't attach (`ptrace`) or read `/proc/<pid>/mem`. Root still can. Started under a tracer already (`strace`, `gdb`), the daemon refuses to run | `PT_DENY_ATTACH`: every attach is refused, root's too. A release build refuses to start under a debugger; a debug build skips this step, with a warning |
| Out of swap | `mlockall`, only when the lock limit is unlimited or the process has `CAP_IPC_LOCK`. Under a smaller limit, the daemon would crash once it reached it | Not possible for a whole process (an info line). macOS encrypts swap |

## The swap warning on Linux

The lock limit isn't unlimited. Raise it **for the daemon only**, one of:

- `ulimit -l unlimited` in the shell that starts it;
- `LimitMEMLOCK=infinity` in its systemd unit;
- `ulimits: { memlock: -1 }` for its service in a compose file;
- the `CAP_IPC_LOCK` capability.

Or leave it: a page holding a secret could then reach swap, so encrypt swap.

## When the process refuses to start

- **A call failed** (not dumpable, the core limit, `PT_DENY_ATTACH`). Rare, usually a sandbox
  forbidding it. The error names the call.
- **Started under a debugger** (macOS, release build). Start it without one.
- **`NoHardening`**: this build has no hardening for this OS. Only Linux and macOS have one.

## Checking it

**Linux**, with the daemon's pid (`pid=$(pgrep -u <daemon user> -n writd)`):

```sh
stat -c %U /proc/$pid/status            # root: not dumpable (the daemon runs as its own user)
grep 'Max core file size' /proc/$pid/limits   # 0 0
grep VmLck /proc/$pid/status             # more than 0 kB: memory locked (with an unlimited lock limit)
head -c1 /proc/$pid/mem                  # as the daemon's user: Permission denied
```

**macOS**:

```sh
lldb -p "$(pgrep -n writd)" --batch -o detach    # attach failed: lost connection
```

`writd run`'s log also lists, at start, each protection: applied, not applied (with the fix),
or unavailable.

## What it doesn't cover

Root, or whoever controls the daemon's user before it starts, can still read its memory. And
memory that isn't locked can reach swap. Hardware keys (M7.5, M7.6) take the secrets out of the
process entirely ([threat model](../threat-model.md#residual-risks-v1)).
