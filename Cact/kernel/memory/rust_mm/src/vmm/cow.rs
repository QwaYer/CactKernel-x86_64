//! Copy-on-write fork of a process address space.
//!
//! Skips the mmap window (mmap_table_clone handles those) and shares the
//! kernel's entries read-only.  Four-level walk: the kernel's window is the last
//! PDPT entry of the low half and is copied by reference; everything below it is
//! the process's own page directories and page tables.

use crate::ffi::*;
use crate::pmm::{kalloc, page_ref_inc};
use crate::safe::{zero_page, flush_tlb_all};
use crate::vmm::paging::PD_KERNEL_ENTRIES;

/// Number of entries in each level.
const TABLE_ENTRIES: usize = 512;

/// # Safety
///
/// `src_pd` and `dst_pd` must be null or valid, distinct page maps owned by the
/// caller, and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_fork_address_space(src_pd: *mut u32, dst_pd: *mut u32) {
    if src_pd.is_null() || dst_pd.is_null() {
        return;
    }

    // The mmap window lives inside one 1 GiB window; its page-directory entries
    // are cloned by mmap_table_clone, not here.
    let mmap_window = pdpt_index(MMAP_BASE) as usize;
    let mmap_pd_start = pd_index(MMAP_BASE) as usize;
    let mmap_pd_end = pd_index(MMAP_LIMIT) as usize;

    // SAFETY: `src_pd`/`dst_pd` are the caller's valid, distinct page maps (one
    // 512-entry table each), so these slices span exactly one map each and do not
    // overlap.
    let src_root = unsafe { core::slice::from_raw_parts(src_pd, TABLE_ENTRIES) };
    // SAFETY: as above, for the child map, which this call writes.
    let dst_root = unsafe { core::slice::from_raw_parts_mut(dst_pd, TABLE_ENTRIES) };

    // The kernel's own image is shared outright.
    dst_root[511] = src_root[511];

    let src_low = src_root[0];
    let dst_low = dst_root[0];
    if src_low & PAGE_PRESENT == 0 || dst_low & PAGE_PRESENT == 0 {
        return;
    }
    // SAFETY: both are live 512-entry page-directory-pointer tables.
    let src_pdpt =
        unsafe { core::slice::from_raw_parts((src_low & !0xFFF) as *const u32, TABLE_ENTRIES) };
    // SAFETY: as above, for the child's table.
    let dst_pdpt =
        unsafe { core::slice::from_raw_parts_mut((dst_low & !0xFFF) as *mut u32, TABLE_ENTRIES) };

    for i in 0..PD_KERNEL_ENTRIES {
        let src_pdpt_val = src_pdpt[i];
        if src_pdpt_val & PAGE_PRESENT == 0 || src_pdpt_val & PDE_PRIVATE == 0 {
            // Absent, or the kernel's own window (mapped with 2 MiB pages):
            // share the reference.  The child inherits the kernel's view.
            dst_pdpt[i] = src_pdpt_val;
            continue;
        }

        let src_pdt_ptr = (src_pdpt_val & !0xFFF) as *const u32;
        // SAFETY: the source PDPT entry names a live page directory; so does the
        // destination's when it is private already.
        let src_pdt = unsafe { core::slice::from_raw_parts(src_pdt_ptr, TABLE_ENTRIES) };

        // The child needs a page directory of its own: `vmm_create_address_space`
        // leaves the low windows pointing at the kernel's shared directories.
        let dst_pdpt_val = dst_pdpt[i];
        if dst_pdpt_val & PAGE_PRESENT == 0 || dst_pdpt_val & PDE_PRIVATE == 0 {
            let new_pd = kalloc() as *mut u32;
            if new_pd.is_null() {
                continue;
            }
            // SAFETY: `new_pd` is a fresh 4 KiB frame, so the 512-entry copy is
            // in bounds; copying the source first keeps every entry the loop
            // below does not rewrite (large pages, shared kernel tables).
            unsafe {
                core::ptr::copy_nonoverlapping(src_pdt_ptr, new_pd, TABLE_ENTRIES);
            }
            dst_pdpt[i] = (new_pd as u32 & !0xFFF) | (src_pdpt_val & 0xFFF) | PDE_PRIVATE;
        }
        // SAFETY: the destination PDPT entry is present and names a private page
        // directory.
        let dst_pdt =
            unsafe { core::slice::from_raw_parts_mut((dst_pdpt[i] & !0xFFF) as *mut u32, TABLE_ENTRIES) };

        for j in 0..TABLE_ENTRIES {
            if i == mmap_window && j >= mmap_pd_start && j < mmap_pd_end {
                continue;
            }

            let src_pde = src_pdt[j];
            if src_pde & PAGE_PRESENT == 0 {
                dst_pdt[j] = src_pde;
                continue;
            }
            if src_pde & PAGE_PS != 0 || src_pde & PDE_PRIVATE == 0 {
                // A 2 MiB page or a shared kernel table: not this process's to
                // copy, so both maps keep pointing at it.
                dst_pdt[j] = src_pde;
                continue;
            }

            let src_pt = (src_pde & !0xFFF) as *mut u32;
            let dst_pt = kalloc() as *mut u32;
            if dst_pt.is_null() {
                continue;
            }
            zero_page(dst_pt as *mut u8);

            for k in 0..TABLE_ENTRIES {
                // SAFETY: `src_pt` is the live page table of the present private
                // source entry and `k` is in bounds.
                let src_entry = unsafe { src_pt.add(k) };
                // SAFETY: `src_entry` points at one initialised PTE.
                let pte = unsafe { *src_entry };

                // SAFETY: `dst_pt` is a live 512-entry page table and `k` is in
                // bounds.
                let dst_entry = unsafe { dst_pt.add(k) };

                if pte & PAGE_PRESENT == 0 {
                    // Demand/swapped PTEs have no frame yet: copy verbatim.
                    // SAFETY: `dst_entry` points at one PTE.
                    unsafe { *dst_entry = pte };
                    continue;
                }

                if pte & PAGE_USER == 0 {
                    // Kernel identity-map PTE: share it without a refcount — the
                    // kernel PMM owns the frame, not this process.
                    // SAFETY: `dst_entry` points at one PTE, sharing the kernel's
                    // mapping with the child.
                    unsafe { *dst_entry = pte };
                    continue;
                }

                let va = ((i as u32) << 30) | ((j as u32) << 21) | ((k as u32) << 12);
                if (USER_STACK_LIMIT..USER_STACK_TOP).contains(&va) {
                    // User stack pages are cloned eagerly: copy-on-write there
                    // faults on the first prologue/store after returning to user
                    // mode, which is both slow and hard to reason about.
                    let new_page = kalloc();
                    if !new_page.is_null() {
                        let phys = pte & !0xFFFu32;
                        let mut flags = pte & 0xFFFu32;
                        flags &= !PAGE_COW;
                        flags |= PAGE_RW;
                        // SAFETY: `phys` is a page-aligned frame named by the
                        // parent PTE and `new_page` is a fresh kalloc page, so the
                        // 4 KiB copy is in bounds.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                phys as *const u8,
                                new_page,
                                PAGE_SIZE as usize,
                            );
                        }
                        // SAFETY: `dst_entry` points at one PTE, which receives
                        // the cloned child frame.
                        unsafe { *dst_entry = (new_page as u32 & !0xFFFu32) | flags };
                        continue;
                    }
                    // Out of frames: fall through to plain copy-on-write.
                }

                // User page: both maps point at the frame, read-only and marked
                // COW, with one more reference on it.
                let phys = pte & !0xFFFu32;
                let cow_flags = ((pte & 0xFFFu32) & !PAGE_RW) | PAGE_COW;
                // SAFETY: `src_entry` points at one PTE, which receives the COW
                // flags.
                unsafe { *src_entry = phys | cow_flags };
                // SAFETY: `dst_entry` points at one PTE, which receives the same
                // flags.
                unsafe { *dst_entry = phys | cow_flags };
                page_ref_inc(phys as *const u8);
            }

            dst_pdt[j] = (dst_pt as u32 & !0xFFFu32) | (src_pde & 0xFFFu32);
        }

        flush_tlb_all();
    }
}
