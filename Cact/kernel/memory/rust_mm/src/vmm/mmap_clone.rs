// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! mmap table cloning (fork) and teardown. Split out of `mmap.rs` so the
//! COW/private-PDE machinery stays together with its two main users.

use crate::ffi::*;
use crate::pmm::page_ref_inc;
use crate::process::memfd::memfd_map_inc;
use crate::safe::flush_tlb_all;
use crate::vmm::mmap::do_munmap;
use crate::vmm::paging::p2v;
use kernel_rust::ptr;

/// `src` and `dst` are live, distinct `MmapTable`s and `src_pd`/`dst_pd`
/// valid page directories owned by the caller; none of them may be mutated
/// concurrently for the duration of the call.
pub extern "C" fn mmap_table_clone(
    src: *mut MmapTable,
    dst: *mut MmapTable,
    src_pd: *mut u64,
    dst_pd: *mut u64,
) {
    if src.is_null() || dst.is_null() {
        return;
    }

    // `src`/`dst` are valid `MmapTable`s (the caller checked them), so
    // this bump-pointer read is in bounds.
    let next_base = ptr::as_ref(src).next_base;
    // As above, for the destination table.
    ptr::as_mut(dst).next_base = next_base;

    for i in 0..MMAP_MAX_REGIONS {
        // `src` is a valid `MmapTable` and `i < MMAP_MAX_REGIONS`, so the region
        // reference is in bounds.
        let sr = &ptr::as_ref(src).regions[i];
        // `dst` is a valid `MmapTable`, distinct from `src`, and `i` is in
        // bounds of its region array.
        let dr = &mut ptr::as_mut(dst).regions[i];

        if sr.is_used == 0 {
            dr.is_used = 0;
            continue;
        }

        // `sr` is an in-bounds region slot of the source table, and `dr` the
        // corresponding one of the distinct destination table: copy the region
        // field by field (`MmapRegion` is not `Copy`, and the slots do not
        // overlap).
        dr.base = sr.base;
        dr.length = sr.length;
        dr.flags = sr.flags;
        dr.prot = sr.prot;
        dr.fd = sr.fd;
        dr.file_off = sr.file_off;
        dr.is_used = sr.is_used;
        dr.shobj = sr.shobj;

        let pages = sr.length / PAGE_SIZE;

        if sr.flags & MAP_SHARED as u32 != 0 {
            // A memfd-backed region stays alive for the child as well.
            if sr.shobj > 0 {
                memfd_map_inc(sr.shobj);
            }
            for p in 0..pages {
                let va = sr.base + p * PAGE_SIZE;

                // `src_pd` is the caller's live page map and the walk
                // only reads it, so nothing is allocated or mutated.
                let src_w = crate::vmm::paging::walk(src_pd, va as u64, false, false);
                if src_w.pte_entry.is_null() {
                    continue;
                }
                // `src_w.pte_entry` is an in-bounds page-table entry.
                let pte = ptr::read(src_w.pte_entry);
                if pte == 0 {
                    continue;
                }

                // `dst_pd` is the child's live page map; the walk creates
                // the private tables this shared page needs.
                let dst_w = crate::vmm::paging::walk(dst_pd, va as u64, true, true);
                if dst_w.pte_entry.is_null() {
                    continue;
                }
                // `dst_w.pte_entry` points at one PTE, which receives the
                // mapping shared with the parent.
                ptr::write(dst_w.pte_entry, pte);

                if pte & PAGE_PRESENT as u64 != 0 {
                    page_ref_inc(p2v(pte & !0xFFF) as *const u8);
                }
            }
        } else {
            for p in 0..pages {
                let va = sr.base + p * PAGE_SIZE;

                // `src_pd` is the caller's live page map and the walk
                // only reads it.
                let src_w = crate::vmm::paging::walk(src_pd, va as u64, false, false);
                if src_w.pte_entry.is_null() {
                    continue;
                }
                // `src_w.pte_entry` is an in-bounds page-table entry.
                let pte = ptr::read(src_w.pte_entry);

                // `dst_pd` is the child's live page map; the walk creates
                // the private tables this page needs.
                let dst_w = crate::vmm::paging::walk(dst_pd, va as u64, true, true);
                if dst_w.pte_entry.is_null() {
                    continue;
                }

                if pte & PAGE_PRESENT as u64 == 0 {
                    // Demand/swapped PTEs have no frame: copy the marker across.
                    // `dst_w.pte_entry` points at one PTE.
                    ptr::write(dst_w.pte_entry, pte);
                    continue;
                }

                // User page: both maps point at the frame, read-only and marked
                // COW, with one more reference on it.
                let cow_pte = (pte & !(PAGE_RW as u64)) | PAGE_COW as u64;
                // Both entry pointers are in bounds and hold one PTE each.
                ptr::write(src_w.pte_entry, cow_pte);
                ptr::write(dst_w.pte_entry, cow_pte);

                page_ref_inc(p2v(pte & !0xFFF) as *const u8);
            }

            flush_tlb_all();
        }
    }
}

/// `tbl` may be null; otherwise it is a live `MmapTable` whose regions are
/// mapped into `pd`, and `pd` is a valid page directory owned by the caller.
pub extern "C" fn mmap_table_free(tbl: *mut MmapTable, pd: *mut u64) {
    if tbl.is_null() || pd.is_null() {
        return;
    }
    // tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = &ptr::as_ref(tbl).regions[i];
        if r.is_used == 0 {
            continue;
        }
        // `tbl`/`pd` are valid (checked at entry) and `r.base`/`r.length`
        // describe the live region being torn down.
        do_munmap(pd, tbl, r.base, r.length);
    }
}
