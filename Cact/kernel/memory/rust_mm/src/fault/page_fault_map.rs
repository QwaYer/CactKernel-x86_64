// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Demand/zero/COW mapping helpers exposed to C. Split out of `page_fault.rs`.

use crate::ffi::*;
use crate::pmm::{kalloc, free_page, page_ref_inc, page_ref_get_locked, PAGE_LOCK};
use crate::vmm::paging::{vmm_map, p2v, v2p};
use crate::fault::page_fault::{ensure_private_pte, pte_get};
use crate::safe::{zero_page, flush_tlb, lock_acquire, lock_release};
use kernel_rust::ptr;

/// `pd` is null or a valid page directory that the caller owns and may mutate;
/// the caller must serialise concurrent page-table changes.
pub extern "C" fn vmm_map_demand(
    pd: *mut u64,
    virtual_addr: u64,
    size: u32,
    flags: i32,
) -> i32 {
    if pd.is_null() || size == 0 {
        return -1;
    }
    let flags = flags as u32;
    let start = virtual_addr & !0xFFF;
    let end = virtual_addr
        .saturating_add(size as u64)
        .saturating_add(0xFFF)
        & !0xFFF;

    if start >= USER_STACK_TOP as u64 || end > USER_STACK_TOP as u64 {
        return -1;
    }

    let mut va = start;
    while va < end {
        // `pd` is the caller's live page map; the walk creates the private
        // tables this entry needs.
        let entry = ensure_private_pte(pd, va, flags);
        if entry.is_null() {
            return -1;
        }
        // `entry` is an in-bounds page-table entry.
        ptr::write(entry, (PAGE_DEMAND | (flags & (PAGE_USER | PAGE_RW))) as u64);
        va += PAGE_SIZE as u64;
    }
    0
}

/// `pd` is null or a valid page directory that the caller owns and may mutate;
/// the caller must serialise concurrent page-table changes.
pub extern "C" fn vmm_map_zero(
    pd: *mut u64,
    virtual_addr: u64,
    size: u32,
    flags: i32,
) -> i32 {
    if pd.is_null() || size == 0 {
        return -1;
    }
    let flags = flags as u32;
    let start = virtual_addr & !0xFFF;
    // Use saturating arithmetic so an overflowing range is caught by the
    // kernel-space boundary check below rather than wrapping to a low address.
    let end = virtual_addr
        .saturating_add(size as u64)
        .saturating_add(0xFFF)
        & !0xFFF;
    // C-08: never install demand entries inside kernel space (≥ 0xC000_0000).
    // A saturated end will be ≥ USER_STACK_TOP and is therefore also rejected.
    if start >= USER_STACK_TOP as u64 || end > USER_STACK_TOP as u64 {
        return -1;
    }

    let mut va = start;
    while va < end {
        // `pd` is the caller's live page map; the walk creates the private
        // tables this entry needs.
        let entry = ensure_private_pte(pd, va, flags);
        if entry.is_null() {
            return -1;
        }
        // `entry` is an in-bounds page-table entry.
        ptr::write(entry, (PAGE_DEMAND | PAGE_ZERO | (flags & (PAGE_USER | PAGE_RW))) as u64);
        // The entry replaces whatever the VA was mapped to before (an identity
        // entry, a previous mapping): the old translation lives on in the TLB
        // and would keep serving stores until an unrelated CR3 load drops it.
        crate::safe::flush_tlb(va);
        va += PAGE_SIZE as u64;
    }
    0
}

pub extern "C" fn vmm_map_cow(pd: *mut u64, virtual_addr: u64) -> i32 {
    let pte = pte_get(pd, virtual_addr);
    // `pte` is the result of `pte_get` and is non-null on the left of `||`, so
    // the present-bit test reads a valid PTE.
    if pte.is_null() || ptr::read(pte) & PAGE_PRESENT as u64 == 0 {
        return -1;
    }
    // `pte` is the non-null live PTE returned by `pte_get`.
    let val = ptr::read(pte);
    // `pte` is non-null (checked above), so storing the COW-marked value back is
    // in bounds.
    ptr::write(pte, (val & !(PAGE_RW as u64)) | PAGE_COW as u64);
    flush_tlb(virtual_addr & !0xFFF);
    0
}

pub extern "C" fn vmm_is_cow_page(pd: *mut u64, virtual_addr: u64) -> i32 {
    let pte = pte_get(pd, virtual_addr);
    // `pte` is non-null on the left of `&&`; its COW bit is read from a live PTE.
    if !pte.is_null() && ptr::read(pte) & PAGE_COW as u64 != 0 {
        1
    } else {
        0
    }
}

pub extern "C" fn vmm_handle_cow(pd: *mut u64, virtual_addr: u64) -> i32 {
    let pte = pte_get(pd, virtual_addr);
    // `pte` is non-null on the left of `||`; a live PTE's COW bit is read.
    if pte.is_null() || ptr::read(pte) & PAGE_COW as u64 == 0 {
        return -1;
    }

    // `pte` is valid and has the COW flag; the low bits masked off give the
    // page-aligned physical frame it names.
    let old_phys = ptr::read(pte) & !0xFFF;
    // `pte` is non-null and COW-flagged; reading its value is valid.
    let pte_val = ptr::read(pte);
    let flags = ((pte_val & 0xFFF) & !(PAGE_COW as u64)) | PAGE_RW as u64 | PAGE_PRESENT as u64;

    // ── Sole-owner fast path ─────────────────────────────────────────────────
    // Hold PAGE_LOCK for the entire check + PTE-update so that no other CPU
    // can observe rc == 1 and also promote its own PTE to RW for the same
    // physical frame (C-01: two processes writing to one physical frame).
    lock_acquire(PAGE_LOCK.as_ptr());
    if page_ref_get_locked(p2v(old_phys) as *const u8) == 1 {
        // Writing the private copy's frame into the live COW PTE addressed by
        // `pte`; the entry takes the frame's physical address.
        ptr::write(pte, (old_phys & !0xFFF) | flags);
        lock_release(PAGE_LOCK.as_ptr());
        flush_tlb(virtual_addr & !0xFFF);
        return 0;
    }
    lock_release(PAGE_LOCK.as_ptr());

    // ── Multi-owner copy path ────────────────────────────────────────────────
    // Allocate the new frame outside the lock (kalloc takes PAGE_LOCK itself).
    let new_phys = kalloc();
    if new_phys.is_null() {
        return -1;
    }

    // `old_phys` is the shared frame named by the live COW PTE (reached through
    // the direct map) and `new_phys` a fresh `kalloc` page, so the 4 KiB copy is
    // in bounds.
    ptr::copy_nonoverlapping(p2v(old_phys) as *const u8, new_phys, PAGE_SIZE as usize);
    // `pte` is non-null (checked above), so storing the private copy's frame's
    // physical address back is in bounds.
    ptr::write(pte, (v2p(new_phys) & !0xFFF) | flags);

    // Release our reference to the shared frame.
    // The frame is live and PMM-managed; this call releases exactly one reference to it.
    // The PTE names a physical address, which `free_page` wants as a VA.
    free_page(p2v(old_phys) as *mut u8);

    flush_tlb(virtual_addr & !0xFFF);
    0
}

/// `pd` is a valid page directory for the current address space; the function
/// writes PTEs into it and allocates frames for the user stack window.
pub extern "C" fn vmm_setup_user_stack(pd: *mut u64, initial_size: u32) -> u32 {
    if pd.is_null() {
        return 0;
    }

    let mut initial_size = (initial_size + 0xFFF) & !0xFFF;
    if initial_size == 0 {
        initial_size = PAGE_SIZE;
    }

    let bottom = USER_STACK_TOP as u64 - initial_size as u64;

    let mut va = bottom;
    while va < USER_STACK_TOP as u64 {
        let phys = kalloc();
        if phys.is_null() {
            return 0;
        }
        zero_page(phys);
        // `pd` is valid (checked at entry), `va` lies in the user stack window
        // and `phys` is the zeroed frame just allocated for it; the mapping takes
        // the frame's physical address.
        vmm_map(
            pd,
            va,
            v2p(phys),
            (PAGE_PRESENT | PAGE_RW | PAGE_USER) as i32,
        );
        va += PAGE_SIZE as u64;
    }

    USER_STACK_TOP
}

/// Pin the user pages covering `[va, va+size)` in `pd`, so the hypervisor can
/// back guest memory with userspace frames (the `/dev/chv` memory-slot uAPI).
///
/// For each 4 KiB page: walk to its PTE.  A present page is used as is; a
/// lazily-mapped anonymous page (`PAGE_DEMAND`, as a fresh `mmap` installs) is
/// materialised here — a zeroed frame installed exactly as the demand fault
/// path would on first touch.  A page that is neither present nor a demand page
/// fails the whole call.  Each frame takes one extra reference, so the swap
/// reclaim path (`swap_evict_page`, which skips frames with a reference count
/// above 1) leaves the guest's memory alone.  The frames' physical addresses are
/// written into `out_phys[0..n]`.
///
/// Returns the number of pages pinned, or -1 (nothing left pinned) when a page
/// cannot be backed.
///
/// `pd` is a live page map the caller owns and may mutate, and no other CPU may
/// race a walk of it; `out_phys` must have room for `ceil(size/4096)` `u64`s.
pub extern "C" fn vmm_pin_range(
    pd: *mut u64,
    va: u64,
    size: u64,
    out_phys: *mut u64,
) -> i64 {
    if pd.is_null() || out_phys.is_null() || size == 0 {
        return -1;
    }
    let start = va & !0xFFF;
    // A saturated end is rejected by the boundary test below (it is >= the top).
    let end = va.saturating_add(size).saturating_add(0xFFF) & !0xFFF;
    if end <= start || start < USER_SPACE_START as u64 || end > USER_STACK_TOP as u64 {
        return -1;
    }

    let mut n: i64 = 0;
    let mut cur = start;
    while cur < end {
        let pte = pte_get(pd, cur);
        if pte.is_null() {
            // `out_phys[0..n]` holds frames pinned in this call.
            return unpin_prefix(out_phys, n);
        }
        // `pte` is a live in-bounds page-table entry.
        let mut val = ptr::read(pte);
        if val & PAGE_PRESENT as u64 == 0 {
            // Lazy anonymous page: install a zeroed frame (the demand fault path
            // would do the same on first touch).  Anything else is unmapped.
            if val & PAGE_DEMAND as u64 == 0 {
                // As above.
                return unpin_prefix(out_phys, n);
            }
            let frame = kalloc();
            if frame.is_null() {
                // As above.
                return unpin_prefix(out_phys, n);
            }
            zero_page(frame);
            val = (v2p(frame) & !0xFFF) | (PAGE_PRESENT | PAGE_USER | PAGE_RW) as u64;
            // `pte` is the live entry for this address; the store publishes the
            // materialised mapping.
            ptr::write(pte, val);
            flush_tlb(cur);
        }
        let phys = val & !0xFFF;
        page_ref_inc(p2v(phys) as *const u8);
        // `n` stays below the caller's page count while `cur < end`.
        ptr::write(out_phys.wrapping_add(n as usize), phys);
        n += 1;
        cur += PAGE_SIZE as u64;
    }
    n
}

/// Release the references taken by `vmm_pin_range()`, unpinning the frames.
///
/// `phys` must hold `count` frames previously pinned by `vmm_pin_range()` and
/// not already unpinned.
pub extern "C" fn vmm_unpin_frames(phys: *const u64, count: u64) {
    if phys.is_null() {
        return;
    }
    let mut i = 0u64;
    while i < count {
        // Each entry is a frame pinned by `vmm_pin_range`.
        let p = ptr::read(phys.wrapping_add(i as usize));
        if p != 0 {
            // `p` is a live PMM-managed frame; this releases exactly the
            // reference the matching pin took.
            free_page(p2v(p) as *mut u8);
        }
        i += 1;
    }
}

/// Unpin the first `n` frames of `out_phys` (the failure path of
/// `vmm_pin_range`).  Returns -1 so callers can `return` it directly.
fn unpin_prefix(out_phys: *mut u64, n: i64) -> i64 {
    // `out_phys[0..n]` holds frames pinned in this call.
    vmm_unpin_frames(out_phys as *const u64, n as u64);
    -1
}
