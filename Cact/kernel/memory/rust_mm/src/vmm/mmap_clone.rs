//! mmap table cloning (fork) and teardown. Split out of `mmap.rs` so the
//! COW/private-PDE machinery stays together with its two main users.

use crate::ffi::*;
use crate::pmm::page_ref_inc;
use crate::process::memfd::memfd_map_inc;
use crate::safe::flush_tlb_all;
use crate::vmm::mmap::do_munmap;
use crate::vmm::paging::p2v;

/// # Safety
///
/// `src` and `dst` must be live, distinct `MmapTable`s and `src_pd`/`dst_pd`
/// valid page directories owned by the caller; none of them may be mutated
/// concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap_table_clone(
    src: *mut MmapTable,
    dst: *mut MmapTable,
    src_pd: *mut u64,
    dst_pd: *mut u64,
) {
    if src.is_null() || dst.is_null() {
        return;
    }

    // SAFETY: `src`/`dst` are valid `MmapTable`s (the caller checked them), so
    // this bump-pointer read is in bounds.
    let next_base = unsafe { (*src).next_base };
    // SAFETY: as above, for the destination table.
    unsafe { (*dst).next_base = next_base };

    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `src` is a valid `MmapTable` and `i < MMAP_MAX_REGIONS`, so the region
        // reference is in bounds.
        let sr = unsafe { &(*src).regions[i] };
        // SAFETY: `dst` is a valid `MmapTable`, distinct from `src`, and `i` is in
        // bounds of its region array.
        let dr = unsafe { &mut (*dst).regions[i] };

        if sr.is_used == 0 {
            dr.is_used = 0;
            continue;
        }

        // SAFETY: `sr` is an in-bounds region slot of the source table.
        let src_region = unsafe { core::ptr::read(sr) };
        // SAFETY: `dr` is the corresponding in-bounds slot of the distinct
        // destination table, so the places do not overlap.
        unsafe { core::ptr::write(dr, src_region) };

        let pages = sr.length / PAGE_SIZE;

        if sr.flags & MAP_SHARED as u32 != 0 {
            // A memfd-backed region stays alive for the child as well.
            if sr.shobj > 0 {
                memfd_map_inc(sr.shobj);
            }
            for p in 0..pages {
                let va = sr.base + p * PAGE_SIZE;

                // SAFETY: `src_pd` is the caller's live page map and the walk
                // only reads it, so nothing is allocated or mutated.
                let src_w = unsafe { crate::vmm::paging::walk(src_pd, va as u64, false, false) };
                if src_w.pte_entry.is_null() {
                    continue;
                }
                // SAFETY: `src_w.pte_entry` is an in-bounds page-table entry.
                let pte = unsafe { *src_w.pte_entry };
                if pte == 0 {
                    continue;
                }

                // SAFETY: `dst_pd` is the child's live page map; the walk creates
                // the private tables this shared page needs.
                let dst_w = unsafe { crate::vmm::paging::walk(dst_pd, va as u64, true, true) };
                if dst_w.pte_entry.is_null() {
                    continue;
                }
                // SAFETY: `dst_w.pte_entry` points at one PTE, which receives the
                // mapping shared with the parent.
                unsafe { *dst_w.pte_entry = pte };

                if pte & PAGE_PRESENT as u64 != 0 {
                    page_ref_inc(p2v(pte & !0xFFF) as *const u8);
                }
            }
        } else {
            for p in 0..pages {
                let va = sr.base + p * PAGE_SIZE;

                // SAFETY: `src_pd` is the caller's live page map and the walk
                // only reads it.
                let src_w = unsafe { crate::vmm::paging::walk(src_pd, va as u64, false, false) };
                if src_w.pte_entry.is_null() {
                    continue;
                }
                // SAFETY: `src_w.pte_entry` is an in-bounds page-table entry.
                let pte = unsafe { *src_w.pte_entry };

                // SAFETY: `dst_pd` is the child's live page map; the walk creates
                // the private tables this page needs.
                let dst_w = unsafe { crate::vmm::paging::walk(dst_pd, va as u64, true, true) };
                if dst_w.pte_entry.is_null() {
                    continue;
                }

                if pte & PAGE_PRESENT as u64 == 0 {
                    // Demand/swapped PTEs have no frame: copy the marker across.
                    // SAFETY: `dst_w.pte_entry` points at one PTE.
                    unsafe { *dst_w.pte_entry = pte };
                    continue;
                }

                // User page: both maps point at the frame, read-only and marked
                // COW, with one more reference on it.
                let cow_pte = (pte & !(PAGE_RW as u64)) | PAGE_COW as u64;
                // SAFETY: both entry pointers are in bounds and hold one PTE each.
                unsafe {
                    *src_w.pte_entry = cow_pte;
                    *dst_w.pte_entry = cow_pte;
                }

                page_ref_inc(p2v(pte & !0xFFF) as *const u8);
            }

            flush_tlb_all();
        }
    }
}

/// # Safety
///
/// `tbl` must be null or a live `MmapTable` whose regions are mapped into `pd`,
/// and `pd` must be a valid page directory owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap_table_free(tbl: *mut MmapTable, pd: *mut u64) {
    if tbl.is_null() || pd.is_null() {
        return;
    }
    // SAFETY: tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = unsafe { &(*tbl).regions[i] };
        if r.is_used == 0 {
            continue;
        }
        // SAFETY: `tbl`/`pd` are valid (checked at entry) and `r.base`/`r.length`
        // describe the live region being torn down.
        unsafe { do_munmap(pd, tbl, r.base, r.length); }
    }
}
