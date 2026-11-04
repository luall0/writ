//! Test support (feature `testing`):
//!
//! - [`Checking`]: an allocator that checks every block it gets back holds only zeros, for the
//!   tests of [`Wiping`](crate::Wiping) (it sits under it);
//! - [`wiped_blocks`]: how many blocks a [`Wiping`](crate::Wiping) allocator wiped in this
//!   process, so a binary's test proves its global allocator is the wiping one;
//! - [`Switch`]: the system allocator, wiping or not as the benchmark asks, so one process
//!   measures the same work both ways (docs/history/m5.7-memory-wiped-on-free.md).
//!
//! Never in a shipped binary (`tool/check-features.py`).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::wipe::wipe;

/// Blocks wiped by every [`Wiping`](crate::Wiping) allocator of this process.
static WIPED: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn count_wiped() {
    WIPED.fetch_add(1, Ordering::Relaxed);
}

/// How many blocks the [`Wiping`](crate::Wiping) allocators of this process wiped so far.
pub fn wiped_blocks() -> usize {
    WIPED.load(Ordering::Relaxed)
}

/// The system allocator, checking every block it gets back: one holding a byte other than
/// zero is counted ([`Checking::dirty`]). It reads each block before freeing it, so it only
/// sits under an allocator that wrote every byte of a block before handing it back (the
/// wiping one), or gets blocks written whole: reading a byte never written is undefined.
pub struct Checking {
    checked: AtomicUsize,
    dirty: AtomicUsize,
    reallocs: AtomicUsize,
}

impl Checking {
    pub const fn new() -> Self {
        Self {
            checked: AtomicUsize::new(0),
            dirty: AtomicUsize::new(0),
            reallocs: AtomicUsize::new(0),
        }
    }

    /// Blocks checked so far.
    pub fn checked(&self) -> usize {
        self.checked.load(Ordering::SeqCst)
    }

    /// Blocks that came back holding a byte other than zero.
    pub fn dirty(&self) -> usize {
        self.dirty.load(Ordering::SeqCst)
    }

    /// Calls of this allocator's own `realloc` (the wiping one never makes any).
    pub fn reallocs(&self) -> usize {
        self.reallocs.load(Ordering::SeqCst)
    }
}

impl Default for Checking {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every call is the system allocator's, with the caller's arguments; `dealloc` only
// reads the block before handing it back, while it is still allocated.
unsafe impl GlobalAlloc for Checking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live block of `layout.size()` bytes, every one of them written
        // (this type's contract, above).
        let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
        if block.iter().any(|byte| *byte != 0) {
            self.dirty.fetch_add(1, Ordering::SeqCst);
        }
        self.checked.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the block and layout the caller gave, from the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.reallocs.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// The system allocator, wiping or not ([`Switch::set_wiping`]): wiping, it does what
/// [`Wiping`](crate::Wiping) does (each block zeroed on free, `realloc` as a new block and a
/// wiped free) without counting; not wiping, it is the system's, `realloc` included. The
/// benchmark's global allocator, so the same work is measured both ways in one process.
pub struct Switch {
    wiping: AtomicBool,
}

impl Switch {
    /// Not wiping until [`Switch::set_wiping`] says so.
    pub const fn new() -> Self {
        Self {
            wiping: AtomicBool::new(false),
        }
    }

    pub fn set_wiping(&self, on: bool) {
        self.wiping.store(on, Ordering::SeqCst);
    }

    fn wiping(&self) -> bool {
        self.wiping.load(Ordering::Relaxed)
    }
}

impl Default for Switch {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every block comes from the system allocator and goes back to it with its layout;
// wiping, a block is zeroed while still allocated, and `realloc` copies at most the smaller of
// the two sizes into a new block of the new size.
unsafe impl GlobalAlloc for Switch {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.wiping() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            unsafe { wipe(ptr, layout.size()) };
        }
        // SAFETY: the block and layout the caller gave, from the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !self.wiping() {
            // SAFETY: the caller's contract is the system allocator's.
            return unsafe { System.realloc(ptr, layout, new_size) };
        }
        // SAFETY: the caller guarantees `new_size`, rounded up to the alignment, fits an
        // `isize` (`GlobalAlloc::realloc`'s contract).
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: a layout of non-zero size (`new_size` is non-zero by the same contract).
        let new = unsafe { System.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: both blocks are live, distinct, and valid for the smaller size.
            unsafe { std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size)) };
            // SAFETY: the old block and its layout, wiped then freed.
            unsafe { self.dealloc(ptr, layout) };
        }
        new
    }
}
