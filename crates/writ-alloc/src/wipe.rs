//! [`Wiping`], the allocator, and [`wipe`], the zeroing it does on every free. The crate's
//! production `unsafe` code, all of it here.

use std::alloc::{GlobalAlloc, Layout, System};

/// A global allocator that zeroes every block before handing it back to `A` (the system's
/// allocator by default). See the crate's documentation for what it covers.
pub struct Wiping<A = System> {
    inner: A,
}

impl Wiping<System> {
    /// The wiping allocator over the system's: what each binary sets as its
    /// `#[global_allocator]`.
    pub const fn system() -> Self {
        Self::new(System)
    }
}

impl<A> Wiping<A> {
    /// The wiping allocator over `inner`.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }

    /// The allocator underneath.
    #[cfg(test)]
    pub(crate) const fn inner(&self) -> &A {
        &self.inner
    }
}

/// Zeroes `len` bytes at `ptr`, in a way the compiler can't remove even though the block is
/// freed right after (a store to memory about to be freed is dead to the optimizer).
///
/// # Safety
///
/// `ptr` is valid for writes of `len` bytes.
#[inline]
pub(crate) unsafe fn wipe(ptr: *mut u8, len: usize) {
    // SAFETY: the caller guarantees `ptr` is valid for writes of `len` bytes; `u8` has no
    // alignment requirement.
    unsafe { ptr.write_bytes(0, len) };
    // SAFETY: an empty template runs no instruction. Without `nomem` or `readonly`, the
    // compiler must assume the block reads memory reachable from its operands (the block, by
    // `ptr`), so the zeroes above are read and can't be removed as dead stores before the
    // free (`tests/barrier.rs` reads the optimized code: without this line, they are gone).
    // glibc's `explicit_bzero` and Linux's `memzero_explicit` do the same.
    unsafe { core::arch::asm!("/* {0} */", in(reg) ptr, options(nostack, preserves_flags)) };
}

// SAFETY: every block comes from `inner` and goes back to it with the layout it was made with;
// `realloc` is the trait's own (a new block from `self.alloc`, the old one through
// `self.dealloc`), so no block skips the wipe.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Wiping<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is the inner allocator's.
        unsafe { self.inner.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live block of this allocator made with `layout`, so it is valid
        // for writes of `layout.size()` bytes.
        unsafe { wipe(ptr, layout.size()) };
        #[cfg(feature = "testing")]
        crate::testing::count_wiped();
        // SAFETY: the block and layout the caller gave, from `inner`.
        unsafe { self.inner.dealloc(ptr, layout) }
    }

    // `realloc` is deliberately the trait's default: `self.alloc`, a copy, `self.dealloc`
    // (which wipes the old block).
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout};
    use std::hint::black_box;

    use crate::testing::Checking;

    /// The test binary's allocator (`crate::TESTED`): the wiping one over the checker.
    fn checker() -> &'static Checking {
        crate::TESTED.inner()
    }

    /// Runs `work`, then checks that the blocks freed meanwhile were all zero, and that at
    /// least `freed` were checked (other threads of the harness may free some too).
    fn freed_zeroed(freed: usize, work: impl FnOnce()) {
        let before = checker().checked();
        work();
        let checked = checker().checked().saturating_sub(before);
        assert!(
            checked >= freed,
            "{checked} blocks checked, {freed} expected"
        );
        assert_eq!(checker().dirty(), 0, "a block came back with its bytes");
    }

    /// Sizes in every class the system allocators use: each one up to a page, then around
    /// each power of two up to 64 MiB (blocks the system maps on their own, past glibc's
    /// 128 KiB threshold and macOS's large blocks).
    fn sizes() -> Vec<usize> {
        let mut sizes: Vec<usize> = (1..=4096).collect();
        for shift in 13..=26 {
            let power = 1usize << shift;
            sizes.extend([power - 1, power, power + 1]);
        }
        sizes
    }

    #[test]
    fn every_block_freed_is_zero_whatever_its_size() {
        let sizes = sizes();
        freed_zeroed(sizes.len(), || {
            for &size in &sizes {
                drop(black_box(vec![0xa5u8; size]));
            }
        });
    }

    #[test]
    fn every_block_freed_is_zero_whatever_its_alignment() {
        let mut freed = 0;
        freed_zeroed(4 * 13, || {
            for align in [16, 64, 4096, 1 << 16] {
                for size in [
                    1,
                    7,
                    64,
                    100,
                    4095,
                    4096,
                    4097,
                    65_536,
                    65_537,
                    1 << 20,
                    3 << 20,
                    1 << 22,
                    1 << 24,
                ] {
                    let layout = Layout::from_size_align(size, align).unwrap();
                    // SAFETY: a layout of non-zero size.
                    let block = unsafe { std::alloc::alloc(layout) };
                    assert!(!block.is_null());
                    // SAFETY: the block is valid for `size` bytes.
                    unsafe { block.write_bytes(0x5a, size) };
                    // SAFETY: the block and layout from `alloc` above.
                    unsafe { std::alloc::dealloc(black_box(block), layout) };
                    freed += 1;
                }
            }
        });
        assert_eq!(freed, 4 * 13);
    }

    #[test]
    fn a_vec_grown_many_times_leaves_no_copy_behind() {
        // A secret read a byte at a time: each growth moves it and frees the smaller copy.
        let before = checker().reallocs();
        // 8 bytes doubled to 1 MiB: 17 old blocks freed, then the shrink's and the drop's.
        freed_zeroed(19, || {
            let mut secret = Vec::new();
            for i in 0..(1usize << 20) {
                secret.push(black_box(u8::try_from(i % 251).unwrap() | 1));
            }
            secret.truncate(1000);
            secret.shrink_to_fit();
            drop(black_box(secret));
        });
        // Never the inner allocator's own realloc: it could free the old block unwiped.
        assert_eq!(checker().reallocs(), before);
    }

    #[test]
    fn strings_and_zeroed_blocks_too() {
        freed_zeroed(3, || {
            let mut text = String::with_capacity(10);
            for _ in 0..1000 {
                text.push_str(black_box("secret-key-text-"));
            }
            drop(black_box(text));
            let mut zeroed = vec![0u8; 1 << 20];
            zeroed.fill(0xff);
            drop(black_box(zeroed));
        });
    }

    #[test]
    fn blocks_freed_from_many_threads_are_all_zero() {
        freed_zeroed(8 * 1000, || {
            std::thread::scope(|scope| {
                for t in 0..8u8 {
                    scope.spawn(move || {
                        for i in 0..1000usize {
                            drop(black_box(vec![t | 1; 1 + i % 3000]));
                        }
                    });
                }
            });
        });
    }

    #[test]
    fn the_checker_sees_a_block_left_unwiped() {
        // The checks above are only worth something if the checker catches a block that
        // still holds its bytes: one checker of its own, the block handed back unwiped.
        let checker = Checking::new();
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: a layout of non-zero size.
        let block = unsafe { checker.alloc(layout) };
        assert!(!block.is_null());
        // SAFETY: the block is valid for 64 bytes; every byte zero but the last.
        unsafe { block.write_bytes(0, 64) };
        // SAFETY: as above, the last byte.
        unsafe { block.add(63).write(1) };
        // SAFETY: the block and layout from this checker.
        unsafe { checker.dealloc(block, layout) };
        assert_eq!((checker.checked(), checker.dirty()), (1, 1));

        // The same through the wiping allocator: zero when it gets back.
        let wiping = super::Wiping::new(Checking::new());
        // SAFETY: as above.
        let block = unsafe { wiping.alloc(layout) };
        assert!(!block.is_null());
        // SAFETY: as above.
        unsafe { block.write_bytes(0xff, 64) };
        // SAFETY: the block and layout from this allocator.
        unsafe { wiping.dealloc(block, layout) };
        assert_eq!((wiping.inner().checked(), wiping.inner().dirty()), (1, 0));
    }

    #[test]
    fn realloc_moves_through_a_wiped_free() {
        let wiping = super::Wiping::new(Checking::new());
        let layout = Layout::from_size_align(32, 8).unwrap();
        // SAFETY: a layout of non-zero size.
        let block = unsafe { wiping.alloc(layout) };
        assert!(!block.is_null());
        // SAFETY: the block is valid for 32 bytes.
        unsafe { block.write_bytes(0x42, 32) };
        // SAFETY: the block and layout from this allocator; a non-zero new size.
        let grown = unsafe { wiping.realloc(block, layout, 4096) };
        assert!(!grown.is_null());
        // SAFETY: the new block holds the 32 bytes copied.
        let kept = unsafe { std::slice::from_raw_parts(grown, 32) };
        assert!(kept.iter().all(|b| *b == 0x42));
        // The old block came back wiped; the inner allocator's realloc was never asked.
        let inner = wiping.inner();
        assert_eq!(
            (inner.checked(), inner.dirty(), inner.reallocs()),
            (1, 0, 0)
        );
        let grown_layout = Layout::from_size_align(4096, 8).unwrap();
        // SAFETY: the first 32 bytes are written; the rest is written here before the free.
        unsafe { grown.add(32).write_bytes(0x42, 4096 - 32) };
        // SAFETY: the block and layout from `realloc` above.
        unsafe { wiping.dealloc(grown, grown_layout) };
        assert_eq!((inner.checked(), inner.dirty()), (2, 0));
    }
}
