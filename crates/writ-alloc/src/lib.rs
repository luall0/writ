//! [`Wiping`]: the global allocator of every binary that handles a secret (`writd`, `writ`,
//! `writ-sign`). Each block is zeroed before it goes back to the allocator underneath, whatever
//! code freed it: Writ's own, or a library's copy of a secret Writ can't reach (age's
//! encryption buffer, bech32's checksum work), or the smaller buffer a growing `Vec` left
//! behind (docs/security.md#secrets).
//!
//! It wraps another allocator (the system's, in every binary) and changes only the way back:
//!
//! - `alloc` and `alloc_zeroed` are the inner allocator's;
//! - `dealloc` zeroes the block (its whole requested size, which is all Rust code may have
//!   written), then hands it to the inner allocator;
//! - `realloc` is a new block, a copy, and the old block wiped and freed: never the inner
//!   allocator's own `realloc`, which may move a block and free the old one unwiped.
//!
//! What it doesn't cover: a block still in use (a library's live copy, while its call runs),
//! the stack and registers, other processes (git), the kernel's buffers. `Zeroizing` stays
//! where it is: it ends a secret's life when its owner is done with it, not when its memory
//! happens to be freed.
//!
//! The crate's `unsafe` code is in two modules: [`wipe`] (the allocator), and with the
//! `testing` feature, [`testing`] (allocators for the tests and the benchmark).

// The allocator: `GlobalAlloc` is an unsafe trait, and a block is written through a raw
// pointer. Each `unsafe` has its SAFETY.
#[allow(unsafe_code)]
mod wipe;

// Test support, and the benchmark's switchable allocator: more `GlobalAlloc`s, each `unsafe`
// with its SAFETY.
#[cfg(feature = "testing")]
#[allow(unsafe_code)]
pub mod testing;

pub use wipe::Wiping;

/// The unit tests run on the wiping allocator over one that checks every block it gets back
/// is zero: every block this test binary frees, the harness's own included.
#[cfg(test)]
#[global_allocator]
static TESTED: Wiping<testing::Checking> = Wiping::new(testing::Checking::new());
