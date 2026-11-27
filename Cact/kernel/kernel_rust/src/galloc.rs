// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The kernel's `#[global_allocator]`.
//!
//! A crate graph may define exactly one global allocator, and it is an `unsafe`
//! lang-item, so it belongs here — in the graph's one `unsafe` crate — rather
//! than beside the heap it wraps in `cact_mm`, which then stays free of
//! `unsafe`.  It bridges Rust's `alloc` crate to `cact_mm`'s heap over the C
//! ABI: `kmalloc_aligned`/`krealloc_aligned`/`kfree` are `#[no_mangle]` exports
//! of `cact_mm`.

use core::alloc::{GlobalAlloc, Layout};

use crate::sys;

/// The kernel's global allocator: `cact_mm`'s heap, with alignment support.
struct CactAllocator;

// SAFETY: every method upholds `GlobalAlloc`'s contract; `kmalloc_aligned`
// returns either null or a block of exactly `layout.size()` bytes aligned to
// `layout.align()`, and `kfree` releases exactly such a block.
unsafe impl GlobalAlloc for CactAllocator {
    /// # Safety
    ///
    /// See [`GlobalAlloc::alloc`]: `layout` must have a non-zero size.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `kmalloc_aligned` has no preconditions beyond the non-zero
        // size and power-of-two alignment the `GlobalAlloc` contract guarantees;
        // the returned block belongs to the caller.
        unsafe { sys::kmalloc_aligned(layout.size(), layout.align()) }
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::dealloc`]: `ptr` must come from `alloc` on this
    /// allocator, with the same `layout`, and must not have been freed already.
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract, so `ptr`
        // is a live block from `kmalloc_aligned` that `kfree` may release.
        unsafe { sys::kfree(ptr) };
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::realloc`]: `ptr` must come from `alloc`/`realloc` on
    /// this allocator with `layout`, and `new_size` must be non-zero.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract, so `ptr`
        // is a live block from this allocator; `realloc` keeps it in place when it
        // fits and otherwise allocates a fresh `new_size` block and copies.
        unsafe { sys::krealloc_aligned(ptr, new_size, layout.align()) }
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::alloc_zeroed`]: `layout` must have a non-zero size.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as in `alloc`; the returned block is the caller's.
        let ptr = unsafe { sys::kmalloc_aligned(layout.size(), layout.align()) };
        if !ptr.is_null() {
            // SAFETY: `ptr` is a fresh block of at least `layout.size()` bytes, so
            // zeroing exactly that many is in bounds; the block holds no typed
            // contents yet.
            unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        }
        ptr
    }
}

#[global_allocator]
static ALLOCATOR: CactAllocator = CactAllocator;
