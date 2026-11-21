// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The kernel's Rust link crate.
//!
//! Every kernel Rust crate is an `rlib` so that Rust code can call Rust code
//! with plain `use` (`cact_mm::kfree`, `sched::task_fork`, …) — `extern "C"`
//! is reserved for the real C kernel (`printk`, VFS, ELF loader, APIC, …).
//!
//! Something still has to be a `staticlib`, because meson links one archive
//! into `kernel.bin`.  That is this crate: it depends on the whole Rust graph
//! and pulls every crate into a single archive, so each symbol — and each
//! `#[no_mangle]` C-ABI entry point — exists exactly once in the final image.
//!
//! The graph's `#[panic_handler]` and `#[global_allocator]` live in `cact_mm`
//! and `cact_net` respectively; a crate graph may define each exactly once.

#![no_std]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

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
        // The `GlobalAlloc` contract makes `layout.size()` non-zero and
        // `layout.align()` a power of two, which is what `kmalloc_aligned`
        // requires; the returned block belongs to the caller.  The call itself
        // is safe (allocation has no preconditions).
        cact_mm::kmalloc_aligned(layout.size(), layout.align())
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::dealloc`]: `ptr` must come from `alloc` on this
    /// allocator, with the same `layout`, and must not have been freed already.
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract, so `ptr`
        // is a live block from `kmalloc_aligned` that `kfree` may release.
        unsafe { cact_mm::kfree(ptr) };
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::realloc`]: `ptr` must come from `alloc`/`realloc` on
    /// this allocator with `layout`, and `new_size` must be non-zero.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract, so `ptr`
        // is a live block from this allocator; `realloc` keeps it in place when it
        // fits and otherwise allocates a fresh `new_size` block and copies.
        unsafe { cact_mm::krealloc_aligned(ptr, new_size, layout.align()) }
    }

    /// # Safety
    ///
    /// See [`GlobalAlloc::alloc_zeroed`]: `layout` must have a non-zero size.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = cact_mm::kmalloc_aligned(layout.size(), layout.align());
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

pub use cact_drm as drm;
pub use cact_hmac_ffi as hmac;
pub use cact_hv as hv;
pub use cact_mm as mm;
pub use cact_net as net;
pub use cact80211 as wireless;
pub use cact_vfs as vfs;
pub use sched as sched;
