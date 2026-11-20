// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Per-address-space page accounting for /proc/meminfo.
//!
//! Walks a process page map the same way `vmm_free_address_space` does and
//! counts (a) resident user pages, split anonymous vs file-backed from the
//! process's mmap table and shm attachments, and (b) the private page-table
//! pages the address space owns.  This is a diagnostic read: it walks page
//! tables a task may be mutating on another CPU, so a torn read only makes a
//! figure momentarily inexact — it never corrupts anything.

use crate::ffi::*;
use crate::process::shm::shm_attached_ranges;
use crate::vmm::mmap::mmap_find_region;
use crate::vmm::paging::{entry_val, get_kernel_pd, p2v, PD_KERNEL_ENTRIES};

/// Entries per page table (the module-private `TABLE_ENTRIES` in `paging`).
const TABLE_ENTRIES: usize = 512;

/// Resident user pages and page-table pages of one address space, in 4 KiB
/// pages.
#[repr(C)]
pub struct VmmUserStats {
    pub anon_pages:   u32,  // private pages: brk, stack, anon mmap, image
    pub file_pages:   u32,  // pages inside a file-backed mmap region
    pub ptable_pages: u32,  // page-table pages owned by this address space
}

/// Classify one resident user page by virtual address:
/// `None` for a shared-memory page (reported separately as `Shmem`),
/// `Some(true)` for a file-backed mapping, `Some(false)` for an anonymous page.
///
/// # Safety
///
/// `tbl` must be the live mmap table of the address space (or null).
unsafe fn classify(tbl: *mut MmapTable, shm_ranges: &[(u32, u32)], va: u32) -> Option<bool> {
    for &(base, end) in shm_ranges {
        if va >= base && va < end {
            return None;
        }
    }
    // SAFETY: `tbl` is the process's live mmap table, or null.
    let r = unsafe { mmap_find_region(tbl, va) };
    if r.is_null() {
        return Some(false);
    }
    // SAFETY: `r` is a live region returned by `mmap_find_region`.
    let (fd, shobj) = unsafe { ((*r).fd, (*r).shobj) };
    Some(fd >= 0 || shobj > 0)
}

/// Walk `pd` (a process PML4) and report its user pages and private page-table
/// pages.  `proc` is the owning `ProcMeta` (mmap table + shm attachments), or
/// null for a bare address space.  A null/kernel `pd` yields all-zero counts.
///
/// # Safety
///
/// `pd` must be null or a live page map; `proc` must be null or the live
/// `ProcMeta` that owns `pd`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_user_stats(pd: *mut u64, proc: *const ProcMeta) -> VmmUserStats {
    let mut out = VmmUserStats { anon_pages: 0, file_pages: 0, ptable_pages: 0 };
    if pd.is_null() {
        return out;
    }

    // shm VA windows for this process (empty when `proc` is null or has none).
    let mut shm_ranges = [(0u32, 0u32); TASK_SHM_MAX];
    let n_shm = shm_attached_ranges(proc, &mut shm_ranges);
    let shm_ranges = &shm_ranges[..n_shm];

    let tbl = if proc.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: `proc` is the caller's live `ProcMeta`.
        unsafe { (*proc).mmap_table }
    };

    // SAFETY: `pd` is a live PML4 root; `entry_val` reads its entry 0.
    let low = unsafe { entry_val(pd, 0) };
    if low & PAGE_PRESENT as u64 == 0 || low & PDE_PRIVATE as u64 == 0 {
        // The kernel's own map, or an address space whose low half is not
        // private — nothing here belongs to this process.
        return out;
    }
    // The PML4 and its private low PDPT are both this address space's.
    out.ptable_pages = 2;

    let pdpt = p2v(low & !0xFFF) as *const u64;
    for i in 0..PD_KERNEL_ENTRIES as u32 {
        // SAFETY: `pdpt` is this map's live low PDPT and `i` is in bounds.
        let pd_val = unsafe { entry_val(pdpt, i) };
        if pd_val & PAGE_PRESENT as u64 == 0 || pd_val & PDE_PRIVATE as u64 == 0 {
            continue;
        }
        if pd_val & PAGE_PS as u64 != 0 {
            continue;
        }
        let pdt = p2v(pd_val & !0xFFF) as *const u64;
        out.ptable_pages += 1;
        for j in 0..TABLE_ENTRIES as u32 {
            // SAFETY: `pdt` is a live page directory and `j` is in bounds.
            let pd_entry = unsafe { entry_val(pdt, j) };
            if pd_entry & PAGE_PRESENT as u64 == 0
                || pd_entry & PAGE_PS as u64 != 0
                || pd_entry & PDE_PRIVATE as u64 == 0
            {
                continue;
            }
            let pt = p2v(pd_entry & !0xFFF) as *const u64;
            out.ptable_pages += 1;
            for k in 0..TABLE_ENTRIES as u32 {
                // SAFETY: `pt` is a live page table and `k` is in bounds.
                let pte = unsafe { entry_val(pt, k) };
                if pte & PAGE_PRESENT as u64 == 0 || pte & PAGE_USER as u64 == 0 {
                    continue;
                }
                let va = (i << 30) | (j << 21) | (k << 12);
                // SAFETY: `tbl` is this process's live mmap table or null.
                match unsafe { classify(tbl, shm_ranges, va) } {
                    Some(true)  => out.file_pages += 1,
                    Some(false) => out.anon_pages += 1,
                    None        => {}   // shm; counted as Shmem
                }
            }
        }
    }
    out
}

/// Page-table pages the kernel's own address space holds: every present table
/// below the PML4, at each level.  Reported by /proc/meminfo as part of
/// `PageTables`; the figure is fixed after boot apart from MMIO windows.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_kernel_ptable_pages() -> u32 {
    let pml4 = get_kernel_pd() as *const u64;
    let mut n = 1u32; // the PML4 itself
    for l4 in 0..TABLE_ENTRIES as u32 {
        // SAFETY: `pml4` is the live kernel PML4 and `l4` is in bounds.
        let e4 = unsafe { entry_val(pml4, l4) };
        if e4 & PAGE_PRESENT as u64 == 0 || e4 & PAGE_PS as u64 != 0 {
            continue;
        }
        let pdpt = p2v(e4 & !0xFFF) as *const u64;
        n += 1;
        for l3 in 0..TABLE_ENTRIES as u32 {
            // SAFETY: `pdpt` is a live PDPT and `l3` is in bounds.
            let e3 = unsafe { entry_val(pdpt, l3) };
            if e3 & PAGE_PRESENT as u64 == 0 || e3 & PAGE_PS as u64 != 0 {
                continue;
            }
            let pdt = p2v(e3 & !0xFFF) as *const u64;
            n += 1;
            for l2 in 0..TABLE_ENTRIES as u32 {
                // SAFETY: `pdt` is a live page directory and `l2` is in bounds.
                let e2 = unsafe { entry_val(pdt, l2) };
                if e2 & PAGE_PRESENT as u64 == 0 || e2 & PAGE_PS as u64 != 0 {
                    continue;
                }
                n += 1; // a page table
            }
        }
    }
    n
}
