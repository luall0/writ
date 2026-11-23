# `direct_ssh` push mode

**Status:** parked (2026-11-15). **Area:** Gateway, Upstream. **Kind:** feature.

This page explains why we are not building it, and what would make us reconsider. It was M10
on the roadmap (gone since v1 closed); its keys (`push_modes`, `direct_ssh.hosts`, `direct_ssh.allow_account_wide`)
leave the policy in [M7.9.6](../../history/m7.9.6-upgrades.md)'s format 2.

## The idea

The daemon lends each lease an ssh-agent socket holding only the repo's deploy key, and the
agent pushes to the remote itself. Each signature request is checked for the host
(`session-bind`), the user, the limits and the time ([Q22](../../decisions.md)). A key that
isn't limited to the repo needed `allow_account_wide: true`, and the approver saw a warning.

## Why it is a no-go

The daemon would see only the SSH authentication, never what is pushed: not the repo (the
path travels inside the encrypted session, so only a deploy key scopes it), not the refs or
protected refs, not force pushes, and not the commits. Every pushed commit signed under the
lease, the guarantee Writ exists for, would be unchecked. A mode the docs would advise against
adds a weaker path, a residual risk and an exception (`allow_account_wide`) to keep correct.

## What would make us reconsider

Nothing in this shape: no change to the lent socket lets the daemon see the push. A remote
that enforces Writ's checks itself (refs, signatures against a published ledger) would be a
different idea.
