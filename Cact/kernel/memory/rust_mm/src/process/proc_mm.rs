// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Growable array of per-process physical pages (`ProcPageTracker`) and teardown helpers.

use crate::ffi::*;
use crate::alloc::heap::{kmalloc, kfree};
use crate::vmm::paging::vmm_free_address_space;

#[unsafe(no_mangle)]
pub extern "C" fn proc_tracker_add(t: *mut ProcPageTracker, frame: *mut u8) -> i32 {
    if t.is_null() || frame.is_null() {
        return -1;
    }

    // `t` is non-null (checked above) and points to a valid `ProcPageTracker`
    // owned by the caller; this borrow is exclusive for the whole call, and the
    // allocator/logging calls in between never touch it.
    let t = kernel_rust::ptr::as_mut(t);
    if t.pages.is_null() {
        t.pages = kmalloc(PROC_INITIAL_PAGES as usize * core::mem::size_of::<*mut u8>())
            as *mut *mut u8;
        if t.pages.is_null() {
            printk(c"proc-mm: ERR: initial alloc failed\n".as_ptr() as *const u8);
            return -1;
        }
        // `t.pages` is the fresh `kmalloc` block of `PROC_INITIAL_PAGES` slots
        // (just checked non-null); the slice spans exactly that allocation and
        // this borrow is exclusive.
        let slots =
            kernel_rust::ptr::slice_mut(t.pages, PROC_INITIAL_PAGES as usize);
        slots.fill(core::ptr::null_mut());
        t.capacity = PROC_INITIAL_PAGES;
    }

    if t.count >= t.capacity {
        let new_cap = t.capacity + PROC_GROW_STEP;
        let new_arr = kmalloc(new_cap as usize * core::mem::size_of::<*mut u8>()) as *mut *mut u8;
        if new_arr.is_null() {
            printk(c"proc-mm: ERR: grow alloc failed\n".as_ptr() as *const u8);
            return -1;
        }
        // `new_arr` is the fresh `kmalloc` block of `new_cap` slots (just
        // checked non-null); the slice spans exactly that allocation and this
        // borrow is exclusive for the rest of the branch.
        let new_slots = kernel_rust::ptr::slice_mut(new_arr, new_cap as usize);
        // `t.pages` holds `t.count` valid slots and `t.count <= new_cap`, so
        // copying that many elements into the new block is in bounds; the two
        // allocations are distinct.
        kernel_rust::ptr::copy_nonoverlapping(t.pages, new_slots.as_mut_ptr(), t.count as usize);
        new_slots[t.count as usize..].fill(core::ptr::null_mut());
        // `t.pages` is the old `kmalloc`'d array that this call owns and is
        // replacing, so it is freed exactly once here.
        kfree(t.pages as *mut u8);
        t.pages = new_arr;
        t.capacity = new_cap;
    }

    // `t.count < t.capacity` holds (the branch above guarantees it) and
    // `t.pages` is a valid `t.capacity`-slot array; the slice spans exactly that
    // allocation and this borrow is exclusive.
    let slots = kernel_rust::ptr::slice_mut(t.pages, t.capacity as usize);
    slots[t.count as usize] = frame;
    t.count += 1;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn proc_free_pages(t: *mut ProcPageTracker) {
    if t.is_null() {
        return;
    }

    // `t` is non-null (checked above) and points to a valid `ProcPageTracker`;
    // this borrow is exclusive for the whole call, and the release helpers below
    // only touch the allocations its fields point at.
    let t = kernel_rust::ptr::as_mut(t);
    if !t.pages.is_null() {
        // `t.pages` is an owned `kmalloc`'d allocation (per the caller contract)
        // that this destructor is allowed to release.
        kfree(t.pages as *mut u8);
    }

    t.pages = core::ptr::null_mut();
    t.count = 0;
    t.capacity = 0;

    if !t.page_dir.is_null() {
        // `t.page_dir` is the process's page directory, which this teardown is
        // allowed to free; the borrow of `t` ends at this statement.
        vmm_free_address_space(t.page_dir);
        t.page_dir = core::ptr::null_mut();
    }
}
