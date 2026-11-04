# writ-alloc

The global allocator of every binary that handles a secret (`writd`, `writ`, `writ-sign`):
each block is zeroed before it goes back to the system, so no copy of a secret a library made
and freed stays in memory.

## What it does

- **The allocator** (`wipe`): `Wiping`, over the system's allocator. `dealloc` zeroes the
  block, through a compiler barrier so the zeroes are never removed as dead stores, then frees
  it; `realloc` is a new block, a copy and a wiped free, never the system's own `realloc`
  (which may move a block and free the old one unwiped). Allocation is the system's.
- With the `testing` feature: `testing::Checking`, an allocator that checks every block it
  gets back holds only zeros (the tests run the wiping allocator over it);
  `testing::wiped_blocks`, the blocks wiped in this process (each binary's test proves its
  global allocator is the wiping one); `testing::Switch`, the system allocator wiping or not,
  for the benchmark.

## Scope

- Wiping freed memory only. Not here: ending a secret's life when its owner is done
  (`Zeroizing`, in each crate), live copies, the stack, other processes.
- The crate's `unsafe` code is in `wipe` and, with `testing`, `testing`: nowhere else.

## Depends on

Nothing (the standard library).

## Docs

[Security conventions, secrets](../../docs/security.md#secrets),
[Code conventions, secrets](../../docs/conventions.md#secrets),
[M5.7](../../docs/history/m5.7-memory-wiped-on-free.md) (the benchmark and the decision).
