// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe memory access: owned 4 KiB kernel pages, host/guest address
//! translation, and frame pinning.  Callers get a [`Page`] handle and typed
//! accessors instead of raw `*mut u8` and `write_volatile`.

use crate::sys;

const PAGE_SIZE: usize = 4096;

/// An owned, zeroed 4 KiB kernel page (`kalloc`), freed on [`Page::free`].
pub struct Page {
    ptr: *mut u8,
}

impl Page {
    /// Allocate a zeroed page, or `None` when the heap is exhausted.
    pub fn alloc() -> Option<Page> {
        // SAFETY: allocation has no preconditions; `kalloc` returns a 4 KiB
        // direct-mapped frame or null.
        let ptr = unsafe { sys::kalloc() };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: `ptr` is a fresh frame of `PAGE_SIZE` bytes, so zeroing that
        // many is in bounds and the frame holds no typed contents yet.
        unsafe { core::ptr::write_bytes(ptr, 0, PAGE_SIZE) };
        Some(Page { ptr })
    }

    /// The page's host-physical address (`vmm_v2p`).
    pub fn phys(&self) -> u64 {
        // SAFETY: `ptr` is a live frame this `Page` owns.
        unsafe { sys::vmm_v2p(self.ptr) }
    }

    /// Raw pointer to the page base (for handing to the C side).
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Write a `u8` at `off` (bounds checked).
    pub fn write_u8(&self, off: usize, value: u8) {
        assert!(off + 1 <= PAGE_SIZE);
        // SAFETY: `off` is in bounds of a live frame this `Page` owns.
        unsafe { core::ptr::write_volatile(self.ptr.add(off), value) };
    }

    /// Write a `u16` at `off` (bounds checked).
    pub fn write_u16(&self, off: usize, value: u16) {
        assert!(off + 2 <= PAGE_SIZE);
        // SAFETY: in bounds; `off` need not be aligned (write_volatile to a
        // packed address is what the original code did via `as *mut u16`).
        unsafe { core::ptr::write_volatile(self.ptr.add(off) as *mut u16, value) };
    }

    /// Write a `u32` at `off` (bounds checked).
    pub fn write_u32(&self, off: usize, value: u32) {
        assert!(off + 4 <= PAGE_SIZE);
        // SAFETY: in bounds of a live frame.
        unsafe { core::ptr::write_volatile(self.ptr.add(off) as *mut u32, value) };
    }

    /// Write a `u64` at `off` (bounds checked).
    pub fn write_u64(&self, off: usize, value: u64) {
        assert!(off + 8 <= PAGE_SIZE);
        // SAFETY: in bounds of a live frame.
        unsafe { core::ptr::write_volatile(self.ptr.add(off) as *mut u64, value) };
    }

    /// Read a `u16` at `off` (bounds checked).
    pub fn read_u16(&self, off: usize) -> u16 {
        assert!(off + 2 <= PAGE_SIZE);
        // SAFETY: in bounds of a live frame.
        unsafe { core::ptr::read_volatile(self.ptr.add(off) as *const u16) }
    }

    /// Read a `u32` at `off` (bounds checked).
    pub fn read_u32(&self, off: usize) -> u32 {
        assert!(off + 4 <= PAGE_SIZE);
        // SAFETY: in bounds of a live frame.
        unsafe { core::ptr::read_volatile(self.ptr.add(off) as *const u32) }
    }

    /// Hand the frame back to the allocator.
    pub fn free(self) {
        // SAFETY: `ptr` is a live frame this `Page` owns and has not freed.
        unsafe { sys::free_page(self.ptr) };
    }
}

/// Pin the frames backing `[va, va+size)` into `frames` (one `u64` per page).
/// Returns the number of pages pinned `== frames.len()` on success.
pub fn pin_range(pd: *mut u64, va: u64, size: u64, frames: &mut [u64]) -> i64 {
    // SAFETY: `frames` is a live slice of at least the page count; `pd` is the
    // caller's live page map.
    unsafe { sys::vmm_pin_range(pd, va, size, frames.as_mut_ptr()) }
}

/// Hand a `kmalloc` block back to the heap (`ptr` must come from `kmalloc`).
pub fn kfree(ptr: *mut u8) {
    // SAFETY: the caller passes a live `kmalloc` block.
    unsafe { sys::kfree(ptr) };
}

/// Unpin frames previously pinned by [`pin_range`].
pub fn unpin_frames(frames: &[u64]) {
    // SAFETY: `frames` holds `phys` values from a prior `vmm_pin_range`.
    unsafe { sys::vmm_unpin_frames(frames.as_ptr(), frames.len() as u64) };
}

/// Translate kernel virtual `va` to its physical address in page directory
/// `pd`; a null `pd` selects the kernel's own directory.  Returns 0 when `va`
/// is not mapped.
pub fn get_phys(pd: *mut u64, va: u64) -> u64 {
    // SAFETY: `pd` is the caller's live page map (or null for the kernel's) and
    // `va` a virtual address in it.
    unsafe { sys::vmm_get_phys(pd, va) }
}
