// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Copy-on-write fork of a process address space.
//!
//! Skips the mmap window (mmap_table_clone handles those) and shares the
//! kernel's entries read-only.  Four-level walk: the kernel's window is the last
//! PDPT entry of the low half and is copied by reference; everything below it is
//! the process's own page directories and page tables.

use crate::ffi::*;
use crate::pmm::{kalloc, page_ref_inc};
use crate::safe::{zero_page, flush_tlb_all};
use crate::vmm::paging::{p2v, v2p, PD_KERNEL_ENTRIES};
use kernel_rust::ptr;

/// Number of entries in each level.
const TABLE_ENTRIES: usize = 512;

/// `src_pd` and `dst_pd` are the caller's valid, distinct page maps; neither may
/// be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_fork_address_space(src_pd: *mut u64, dst_pd: *mut u64) {
    if src_pd.is_null() || dst_pd.is_null() {
        return;
    }

    // The mmap window lives inside one 1 GiB window; its page-directory entries
    // are cloned by mmap_table_clone, not here.
    let mmap_window = pdpt_index(MMAP_BASE as u64) as usize;
    let mmap_pd_start = pd_index(MMAP_BASE as u64) as usize;
    let mmap_pd_end = pd_index(MMAP_LIMIT as u64) as usize;

    // `src_pd`/`dst_pd` are the caller's valid, distinct page maps (one
    // 512-entry table each), so these slices span exactly one map each and do not
    // overlap.
    let src_root = ptr::slice(src_pd, TABLE_ENTRIES);
    // As above, for the child map, which this call writes.
    let dst_root = ptr::slice_mut(dst_pd, TABLE_ENTRIES);

    // The kernel's own image (511) and the direct map of physical memory (256)
    // are shared outright: every address space needs both to reach the kernel.
    dst_root[511] = src_root[511];
    dst_root[256] = src_root[256];

    let src_low = src_root[0];
    let dst_low = dst_root[0];
    if src_low & PAGE_PRESENT as u64 == 0 || dst_low & PAGE_PRESENT as u64 == 0 {
        return;
    }
    // Both are live 512-entry page-directory-pointer tables, reached
    // through the direct map (the physical address in each PML4 entry).
    let src_pdpt =
        ptr::slice(p2v(src_low & !0xFFF) as *const u64, TABLE_ENTRIES);
    // As above, for the child's table.
    let dst_pdpt =
        ptr::slice_mut(p2v(dst_low & !0xFFF) as *mut u64, TABLE_ENTRIES);

    for i in 0..PD_KERNEL_ENTRIES {
        let src_pdpt_val = src_pdpt[i];
        if src_pdpt_val & PAGE_PRESENT as u64 == 0 || src_pdpt_val & PDE_PRIVATE as u64 == 0 {
            // Absent, or the kernel's own window (mapped with 2 MiB pages):
            // share the reference.  The child inherits the kernel's view.
            dst_pdpt[i] = src_pdpt_val;
            continue;
        }

        // The entry names a physical address; the kernel dereferences the table
        // through the direct map.
        let src_pdt_ptr = p2v(src_pdpt_val & !0xFFF) as *const u64;
        // The source PDPT entry names a live page directory; so does the
        // destination's when it is private already.
        let src_pdt = ptr::slice(src_pdt_ptr, TABLE_ENTRIES);

        // The child needs a page directory of its own: `vmm_create_address_space`
        // leaves the low windows pointing at the kernel's shared directories.
        let dst_pdpt_val = dst_pdpt[i];
        if dst_pdpt_val & PAGE_PRESENT as u64 == 0 || dst_pdpt_val & PDE_PRIVATE as u64 == 0 {
            let new_pd = kalloc() as *mut u64;
            if new_pd.is_null() {
                continue;
            }
            // `new_pd` is a fresh 4 KiB frame, so the 512-entry copy is
            // in bounds; copying the source first keeps every entry the loop
            // below does not rewrite (large pages, shared kernel tables).
            ptr::copy_nonoverlapping(src_pdt_ptr, new_pd, TABLE_ENTRIES);
            // The entry takes the new table's physical address.
            dst_pdpt[i] = (v2p(new_pd) & !0xFFF) | (src_pdpt_val & 0xFFF) | PDE_PRIVATE as u64;
        }
        // The destination PDPT entry is present and names a private page
        // directory, which the kernel reaches through the direct map.
        let dst_pdt =
            ptr::slice_mut(p2v(dst_pdpt[i] & !0xFFF) as *mut u64, TABLE_ENTRIES);

        for j in 0..TABLE_ENTRIES {
            if i == mmap_window && j >= mmap_pd_start && j < mmap_pd_end {
                // The mmap window's page-table entries are (re)built by
                // `mmap_table_clone`, and the non-region pages that live in the
                // same address range (the per-process sigreturn trampoline) by
                // their own mappers, once this call returns.  The entry the
                // verbatim copy above left here names the *parent's* page table:
                // the child would write through it and, when its address space is
                // torn down (at exec), free that table and its frames — pulling
                // the mapping out from under the parent.  Drop it so those
                // mappers build private tables instead.
                dst_pdt[j] = 0;
                continue;
            }

            let src_pde = src_pdt[j];
            if src_pde & PAGE_PRESENT as u64 == 0 {
                dst_pdt[j] = src_pde;
                continue;
            }
            if src_pde & PAGE_PS as u64 != 0 || src_pde & PDE_PRIVATE as u64 == 0 {
                // A 2 MiB page or a shared kernel table: not this process's to
                // copy, so both maps keep pointing at it.
                dst_pdt[j] = src_pde;
                continue;
            }

            // The entry names a physical address; the walk uses the direct map.
            let src_pt = p2v(src_pde & !0xFFF) as *mut u64;
            let dst_pt = kalloc() as *mut u64;
            if dst_pt.is_null() {
                continue;
            }
            zero_page(dst_pt as *mut u8);

            for k in 0..TABLE_ENTRIES {
                // `src_pt` is the live page table of the present private
                // source entry and `k` is in bounds.
                let src_entry = src_pt.wrapping_add(k);
                let pte = ptr::read(src_entry);

                // `dst_pt` is a live 512-entry page table and `k` is in
                // bounds.
                let dst_entry = dst_pt.wrapping_add(k);

                if pte & PAGE_PRESENT as u64 == 0 {
                    // Demand/swapped PTEs have no frame yet: copy verbatim.
                    ptr::write(dst_entry, pte);
                    continue;
                }

                if pte & PAGE_USER as u64 == 0 {
                    // Kernel identity-map PTE: share it without a refcount — the
                    // kernel PMM owns the frame, not this process.
                    ptr::write(dst_entry, pte);
                    continue;
                }

                let va = ((i as u64) << 30) | ((j as u64) << 21) | ((k as u64) << 12);
                if (USER_STACK_LIMIT as u64..USER_STACK_TOP as u64).contains(&va) {
                    // User stack pages are cloned eagerly: copy-on-write there
                    // faults on the first prologue/store after returning to user
                    // mode, which is both slow and hard to reason about.
                    let new_page = kalloc();
                    if !new_page.is_null() {
                        let phys = pte & !0xFFF;
                        let mut flags = pte & 0xFFF;
                        flags &= !(PAGE_COW as u64);
                        flags |= PAGE_RW as u64;
                        // `phys` is a page-aligned frame named by the
                        // parent PTE (read through the direct map) and `new_page`
                        // is a fresh kalloc page (a direct-map VA), so the 4 KiB
                        // copy is in bounds.
                        ptr::copy_nonoverlapping(
                            p2v(phys) as *const u8,
                            new_page,
                            PAGE_SIZE as usize,
                        );
                        // `dst_entry` points at one PTE, which receives
                        // the cloned child frame by its physical address.
                        ptr::write(dst_entry, (v2p(new_page) & !0xFFF) | flags);
                        continue;
                    }
                    // Out of frames: fall through to plain copy-on-write.
                }

                // User page: both maps point at the frame, read-only and marked
                // COW, with one more reference on it.
                let phys = pte & !0xFFF;
                let cow_flags = ((pte & 0xFFF) & !(PAGE_RW as u64)) | PAGE_COW as u64;
                // `src_entry` points at one PTE, which receives the COW
                // flags.
                ptr::write(src_entry, phys | cow_flags);
                // `dst_entry` points at one PTE, which receives the same
                // flags.
                ptr::write(dst_entry, phys | cow_flags);
                page_ref_inc(p2v(phys) as *const u8);
            }

            dst_pdt[j] = (v2p(dst_pt) & !0xFFF) | (src_pde & 0xFFF);
        }

        flush_tlb_all();
    }
}
