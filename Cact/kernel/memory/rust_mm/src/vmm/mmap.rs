// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! `mmap` / `munmap` implementation: private PDEs, file-backed mappings, and COW with the VMM.

use crate::ffi::*;
use crate::munmap_plan::{clip_region, MunmapClip};
use crate::pmm::{kalloc, page_ref_inc};
use crate::vmm::paging::{vmm_map, p2v, v2p, walk};
use crate::fault::page_fault::vmm_map_zero;
use crate::process::memfd::{
    memfd_get_page, memfd_get_seals, memfd_grow_to, memfd_map_dec, memfd_map_inc,
    F_SEAL_FUTURE_WRITE, F_SEAL_WRITE,
};

use crate::safe::{zero_page, flush_tlb, kprint_str, klog_msg};
use kernel_rust::mem::free_page;
use kernel_rust::ptr;

fn fd_to_node(fd: i32) -> *mut VfsNode {
    let t = cact_current_task_get();
    if t.is_null() {
        return core::ptr::null_mut();
    }
    if fd < 0 || fd as usize >= MAX_FD {
        return core::ptr::null_mut();
    }
    // `t` is a live task (the caller checked it); this shared borrow is
    // consumed by the checks below.
    let t = ptr::as_ref(t);
    if t.proc.is_null() {
        return core::ptr::null_mut();
    }
    // `t.proc` is non-null (checked above) and points at the task's live
    // `ProcMeta`, so this field read is in bounds.
    let fds = ptr::as_ref(t.proc).fds;
    if fds.is_null() {
        return core::ptr::null_mut();
    }
    // `fds` is non-null (checked above) and `fd < MAX_FD`, so this fd-table
    // slot is in bounds.
    ptr::as_ref(fds).fd_table[fd as usize]
}

// Making a page table private before writing to it — copying the kernel's shared
// entry into a per-process one — used to be a helper of its own here.  It is now
// part of `crate::vmm::paging::walk(pd, va, true, true)`, which copies a shared
// page directory (and, further down, splits a 2 MiB page) on the way to the
// entry a caller wants to change.

fn prot_to_page_flags(prot: i32, user: bool) -> i32 {
    let mut f = PAGE_PRESENT as i32;
    if prot & PROT_WRITE != 0 {
        f |= PAGE_RW as i32;
    }
    if user {
        f |= PAGE_USER as i32;
    }
    f
}

fn find_free_va(tbl: *mut MmapTable, length: u32) -> u32 {
    // tbl is a valid MmapTable (checked by callers).
    let mut candidate = ptr::as_ref(tbl).next_base;
    candidate = (candidate + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    loop {
        if candidate.wrapping_add(length) > MMAP_LIMIT
            || candidate.wrapping_add(length) < candidate
        {
            return 0;
        }

        let mut clash = false;
        // tbl is valid, regions array is within bounds.
        for i in 0..MMAP_MAX_REGIONS {
            // `tbl` is a valid `MmapTable` (its callers guarantee it) and
            // `i < MMAP_MAX_REGIONS`, so the region reference is in bounds.
            let r = &ptr::as_ref(tbl).regions[i];
            if r.is_used == 0 {
                continue;
            }
            let r_end = r.base.saturating_add(r.length);
            let c_end = candidate.saturating_add(length);
            if candidate < r_end && c_end > r.base {
                candidate = r_end;
                candidate = (candidate + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                clash = true;
                break;
            }
        }
        if !clash {
            return candidate;
        }
    }
}

fn alloc_region_slot(tbl: *mut MmapTable) -> *mut MmapRegion {
    // tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is valid and `i < MMAP_MAX_REGIONS`; the returned slot may be
        // mutated by the caller while it holds the table.
        let r = &mut ptr::as_mut(tbl).regions[i];
        if r.is_used == 0 {
            return r;
        }
    }
    core::ptr::null_mut()
}

/// Present physical frame backing `va` in `pd`, or 0 if absent.
fn pte_phys(pd: *mut u64, va: u32) -> u64 {
    // `pd` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    let w = walk(pd, va as u64, false, false);
    if !w.pd_entry.is_null() {
        // `w.pd_entry` is an in-bounds PD entry.
        let pde = ptr::read(w.pd_entry);
        if pde & PAGE_PRESENT as u64 != 0 && pde & PAGE_PS as u64 != 0 {
            return large_page_phys(pde, va as u64) & !0xFFF;
        }
    }
    if w.pte_entry.is_null() {
        return 0;
    }
    // `w.pte_entry` is an in-bounds page-table entry.
    let pte = ptr::read(w.pte_entry);
    if pte & PAGE_PRESENT as u64 == 0 {
        return 0;
    }
    pte & !0xFFF
}

/// Drop the PTE for a user virtual address, releasing its frame reference.
fn clear_user_pte(pd: *mut u64, va: u32) {
    // `pd` is a live page map and the walk only reads it.
    let w = walk(pd, va as u64, false, false);
    if w.pte_entry.is_null() {
        return;
    }
    // `w.pte_entry` is an in-bounds page-table entry.
    let pte = ptr::read(w.pte_entry);
    if pte & PAGE_PRESENT as u64 != 0 && pte & PAGE_USER as u64 != 0 {
        // The frame is live and PMM-managed; this call releases exactly one reference to it.
        // The entry names a physical address, which `free_page` wants as a VA.
        free_page(p2v(pte & !0xFFF) as *mut u8);
    }
    // `w.pte_entry` points at one PTE, which this unmap clears.
    ptr::write(w.pte_entry, 0);
    flush_tlb(va as u64);
}

/// `tbl` may be null; otherwise it points to a live, writable `MmapTable` with
/// room for `MMAP_MAX_REGIONS` regions.
#[unsafe(no_mangle)]
pub extern "C" fn mmap_table_init(tbl: *mut MmapTable) {
    if tbl.is_null() {
        return;
    }
    // `tbl` is a live, writable `MmapTable` (per the caller contract); this
    // borrow is exclusive for the whole initialisation.
    let tbl = ptr::as_mut(tbl);
    for r in tbl.regions.iter_mut() {
        r.is_used = 0;
        r.fd = -1;
        r.shobj = 0;
    }
    tbl.next_base = MMAP_BASE;
}

/// `tbl` may be null; otherwise it points to a live, initialised `MmapTable`
/// that stays valid for the call.
#[unsafe(no_mangle)]
pub extern "C" fn mmap_find_region(tbl: *mut MmapTable, addr: u32) -> *mut MmapRegion {
    if tbl.is_null() {
        return core::ptr::null_mut();
    }
    // tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is a valid `MmapTable` (checked at entry) and `i` is in bounds
        // of the region array.
        let r = &mut ptr::as_mut(tbl).regions[i];
        if r.is_used == 0 {
            continue;
        }
        if addr >= r.base && addr < r.base + r.length {
            return r;
        }
    }
    core::ptr::null_mut()
}

/// `pd` is a valid page directory and `tbl` a live `MmapTable`, both owned
/// by the caller; they must stay valid and un-mutated by another thread for the
/// duration of the call.
#[unsafe(no_mangle)]
pub extern "C" fn do_mmap(
    pd: *mut u64,
    tbl: *mut MmapTable,
    hint: u32,
    mut length: u32,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: u32,
) -> *mut u8 {
    if pd.is_null() || tbl.is_null() || length == 0 {
        return MAP_FAILED as *mut u8;
    }
    if (flags & MAP_SHARED == 0) && (flags & MAP_PRIVATE == 0) {
        return MAP_FAILED as *mut u8;
    }

    length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let va;
    if (flags & MAP_FIXED != 0) && hint != 0 {
        if !hint.is_multiple_of(PAGE_SIZE) {
            return MAP_FAILED as *mut u8;
        }
        // A fixed mapping must stay in the user half.  With the identity map
        // confined to the boot reservation and every frame reached through the
        // direct map, no user VA can shadow a kernel frame any more, so the
        // whole user range is fair game.
        if hint < USER_SPACE_START
            || hint >= USER_STACK_TOP
            || hint.saturating_add(length) > USER_STACK_TOP
        {
            return MAP_FAILED as *mut u8;
        }
        // A fixed mapping must not silently land on top of a live region: the
        // demand-zero PTE it installs would replace a PRESENT entry, discarding
        // the mapping's contents and leaking the frame it named.  Linux unmaps
        // the overlap instead, but this region table cannot split a region in
        // the middle, so the safe answer is to fail loudly rather than corrupt.
        // tbl is a valid MmapTable (checked at entry).
        for i in 0..MMAP_MAX_REGIONS {
            // `tbl` is valid and `i < MMAP_MAX_REGIONS`.
            let r = &ptr::as_ref(tbl).regions[i];
            if r.is_used == 0 {
                continue;
            }
            if hint < r.base.saturating_add(r.length) && r.base < hint.saturating_add(length) {
                klog_msg(
                    LOG_ERROR,
                    c"[MMAP] do_mmap: MAP_FIXED overlaps an existing region".as_ptr() as *const u8,
                );
                return MAP_FAILED as *mut u8;
            }
        }
        va = hint;
    } else {
        va = find_free_va(tbl, length);
        if va == 0 {
            klog_msg(LOG_ERROR, c"[MMAP] do_mmap: no free virtual address space".as_ptr() as *const u8);
            return MAP_FAILED as *mut u8;
        }
    }

    let region = alloc_region_slot(tbl);
    if region.is_null() {
        klog_msg(LOG_ERROR, c"[MMAP] do_mmap: region table full".as_ptr() as *const u8);
        return MAP_FAILED as *mut u8;
    }

    let page_flags = prot_to_page_flags(prot, true);
    let pages = length / PAGE_SIZE;

    // Shared backing object for the mapped fd (0 = no shared backing) and the
    // byte offset of this mapping inside it.  The C helper resolves both: a
    // memfd answers with its own handle at the file offset, a DRM card node
    // answers with the GEM buffer's handle at a driver-chosen object offset.
    let mut shobj: i32 = 0;
    let mut obj_off: u32 = 0;

    if flags & MAP_ANON != 0 {
        // `pd` is valid (checked at entry), `va` was chosen inside the mmap
        // window and `length` is a whole number of pages.
        if vmm_map_zero(pd, va as u64, length, page_flags) != 0 {
            klog_msg(LOG_ERROR, c"[MMAP] do_mmap: vmm_map_zero failed".as_ptr() as *const u8);
            return MAP_FAILED as *mut u8;
        }
    } else {
        if fd < 0 {
            return MAP_FAILED as *mut u8;
        }
        // vfs_mmap_resolve only inspects the fd table and the node's
        // ops table; it never dereferences user memory.
        if flags & MAP_SHARED != 0 {
            let mut backing: i32 = 0;
            let mut backing_off: u32 = 0;
            let rc = vfs_mmap_resolve(fd, offset, length, &mut backing, &mut backing_off);
            if rc == 0 && backing > 0 {
                shobj = backing;
                obj_off = backing_off;
            }
        }

        if shobj > 0 && flags & MAP_SHARED != 0 {
            // Shared backing: map the object's own frames so that fd I/O,
            // truncate, fork, and other MAP_SHARED mappings see one storage.
            if !offset.is_multiple_of(PAGE_SIZE) || !obj_off.is_multiple_of(PAGE_SIZE) {
                return MAP_FAILED as *mut u8;
            }
            // F_SEAL_WRITE / F_SEAL_FUTURE_WRITE: a sealed object refuses a *new*
            // writable shared mapping — this is the mmap half of the seal, the
            // other half being the refuse-write in memfd_write.  Mappings that
            // already exist are not revoked: this region table cannot split a
            // region, so that half of Linux's semantics is documented, not
            // emulated.  `memfd_get_seals` is -1 when the backing object is not
            // a memfd, which must not count as sealed.
            let seals = memfd_get_seals(shobj);
            let write_sealed = seals >= 0 && seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) as i32 != 0;
            if prot & PROT_WRITE != 0 && write_sealed {
                return MAP_FAILED as *mut u8;
            }
            if memfd_map_inc(shobj) != 0 {
                return MAP_FAILED as *mut u8;
            }
            let first_page = obj_off / PAGE_SIZE;
            if memfd_grow_to(shobj, obj_off + length) != 0 {
                memfd_map_dec(shobj);
                return MAP_FAILED as *mut u8;
            }
            let mut installed = 0u32;
            while installed < pages {
                let page = memfd_get_page(shobj, first_page + installed);
                if page.is_null() {
                    break;
                }
                let va_i = va + installed * PAGE_SIZE;
                // `pd` is valid, `va_i` lies inside the region reserved
                // above, and `page` is a live memfd frame (a direct-map VA), so
                // the mapping takes its physical address.
                vmm_map(pd, va_i as u64, v2p(page), page_flags);
                if pte_phys(pd, va_i) != v2p(page) {
                    break;
                }
                page_ref_inc(page);
                installed += 1;
            }
            if installed < pages {
                for m in 0..installed {
                    clear_user_pte(pd, va + m * PAGE_SIZE);
                }
                memfd_map_dec(shobj);
                klog_msg(LOG_ERROR, c"[MMAP] do_mmap: memfd shared map failed".as_ptr() as *const u8);
                return MAP_FAILED as *mut u8;
            }
        } else if shobj > 0 {
            // MAP_PRIVATE over a backed object: take a private snapshot copy.
            if !offset.is_multiple_of(PAGE_SIZE) || !obj_off.is_multiple_of(PAGE_SIZE) {
                return MAP_FAILED as *mut u8;
            }
            for i in 0..pages {
                let phys = kalloc();
                if phys.is_null() {
                    for m in 0..i {
                        clear_user_pte(pd, va + m * PAGE_SIZE);
                    }
                    return MAP_FAILED as *mut u8;
                }
                zero_page(phys);
                let src = memfd_get_page(shobj, obj_off / PAGE_SIZE + i);
                if !src.is_null() {
                    // Both page pointers are valid 4 KiB frames (the
                    // destination is a direct-map VA from `kalloc`).
                    ptr::copy_nonoverlapping(src, phys, PAGE_SIZE as usize);
                }
                // `pd` is valid, `va + i * PAGE_SIZE` is inside the region
                // reserved above, and `phys` is the frame just allocated for it;
                // the mapping takes its physical address.
                vmm_map(pd, (va + i * PAGE_SIZE) as u64, v2p(phys), page_flags);
            }
        } else {
            let node = fd_to_node(fd);
            let mut file_off = offset;

            for i in 0..pages {
                let phys = kalloc();
                if phys.is_null() {
                    // The region is registered only once every page is mapped, so
                    // do_munmap() would find nothing here yet; drop the partial
                    // mapping's PTEs directly, as the snapshot path above does.
                    for m in 0..i {
                        clear_user_pte(pd, va + m * PAGE_SIZE);
                    }
                    return MAP_FAILED as *mut u8;
                }
                zero_page(phys);
                if !node.is_null() {
                    read_vfs(node, file_off as u64, PAGE_SIZE, phys);
                }
                // `pd` is valid, `va + i * PAGE_SIZE` is inside the region
                // reserved above, and `phys` is the frame just allocated for it;
                // the mapping takes its physical address.
                vmm_map(pd, (va + i * PAGE_SIZE) as u64, v2p(phys), page_flags);
                file_off += PAGE_SIZE;
            }
        }
    }

    let shared_backed = shobj > 0 && flags & MAP_SHARED != 0;

    // `region` is the valid slot allocated just above and not used again
    // after this fill, so this borrow is exclusive.
    let region = ptr::as_mut(region);
    region.base = va;
    region.length = length;
    region.flags = flags as u32;
    region.prot = prot as u32;
    region.fd = if flags & MAP_ANON != 0 { -1 } else { fd };
    region.file_off = offset;
    region.is_used = 1;
    region.shobj = if shared_backed { shobj } else { 0 };

    // tbl is valid.
    if va + length > ptr::as_ref(tbl).next_base {
        // `tbl` is a valid `MmapTable` (checked at entry); this only moves its
        // bump pointer forward.
        ptr::as_mut(tbl).next_base = va + length;
    }

    va as *mut u8
}

/// `pd` is a valid page directory and `tbl` a live `MmapTable` owned by the
/// caller, and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub extern "C" fn do_munmap(
    pd: *mut u64,
    tbl: *mut MmapTable,
    addr: u32,
    mut length: u32,
) -> i32 {
    if pd.is_null() || tbl.is_null() || length == 0 {
        return -1;
    }
    if !addr.is_multiple_of(PAGE_SIZE) {
        return -1;
    }

    length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // `end` is exclusive; a range that wraps the 32-bit space is malformed.
    let end = match addr.checked_add(length) {
        Some(e) => e,
        None => return -1,
    };

    // Pass 1: how many regions the request touches, and how many of them need a
    // second slot to keep their tail (a slice cut out of the middle).  Every
    // slot is reserved here, before a single page is unmapped, so the call fails
    // whole when the table cannot hold the split.
    let mut used = 0usize;
    let mut splits = 0usize;
    let mut touched = 0usize;
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = &ptr::as_ref(tbl).regions[i];
        if r.is_used == 0 {
            continue;
        }
        used += 1;
        if let Some(s) = clip_region(r.base, r.length, addr, end) {
            touched += 1;
            if s.kind.needs_slot() {
                splits += 1;
            }
        }
    }
    if touched == 0 {
        return -1;
    }
    if MMAP_MAX_REGIONS - used < splits {
        klog_msg(
            LOG_ERROR,
            c"[MMAP] do_munmap: region table full, cannot split".as_ptr() as *const u8,
        );
        return -1;
    }

    // Pass 2: unmap the overlapping slice of each region and reshape it in place.
    // Regions are disjoint, so a tail written into a free slot never lies inside
    // the request range and is skipped if the loop reaches its index.
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is valid and `i < MMAP_MAX_REGIONS`, so this names a slot
        // of the caller's table.  A raw pointer (not a reference) is held so that
        // `alloc_region_slot` may hand out another slot below.
        let region: *mut MmapRegion = &mut ptr::as_mut(tbl).regions[i];
        // `region` names a live slot of the caller's table, not mutated
        // concurrently for the duration of the call.
        let (r_base, r_len, r_flags, r_prot, r_fd, r_off, r_shobj, r_used) = {
            let r = ptr::as_ref(region);
            (
                r.base,
                r.length,
                r.flags,
                r.prot,
                r.fd,
                r.file_off,
                r.shobj,
                r.is_used,
            )
        };
        if r_used == 0 {
            continue;
        }
        let slice = match clip_region(r_base, r_len, addr, end) {
            Some(s) => s,
            None => continue,
        };
        let (lo, hi) = (slice.lo, slice.hi);

        // Drop the frames the slice covers.  Supervisor identity PTEs (present,
        // no PAGE_USER) are left alone; only user frames go back to the PMM.
        let mut va = lo;
        while va < hi {
            // `pd` is the caller's live page map and the walk only reads it.
            let w = walk(pd, va as u64, false, false);
            if !w.pte_entry.is_null() {
                // `w.pte_entry` is an in-bounds page-table entry.
                let pte = ptr::read(w.pte_entry);
                if pte & PAGE_PRESENT as u64 != 0 && pte & PAGE_USER as u64 != 0 {
                    // The frame is live and PMM-managed; this releases
                    // exactly one reference to it.
                    free_page(p2v(pte & !0xFFF) as *mut u8);
                }
                // `w.pte_entry` points at one PTE, which this unmap clears.
                ptr::write(w.pte_entry, 0);
                flush_tlb(va as u64);
            }
            va += PAGE_SIZE;
        }

        // Write the file-backed dirty range this slice covers back to disk before
        // the mapping goes away (mmap writes bypass write()).
        if r_fd >= 0 && r_shobj > 0 {
            // The fd is the one that backs this mapping; the VFS resolves it to
            // its inode's address space and flushes (a no-op when there is none).
            kernel_rust::vfs::as_flush_fd(r_fd, r_off + (lo - r_base), hi - lo);
        }

        match slice.kind {
            MunmapClip::Whole => {
                // `region` is this iteration's live slot; the mapping is
                // being torn down.
                let r = ptr::as_mut(region);
                r.is_used = 0;
                r.fd = -1;
                r.shobj = 0;
                if r_shobj > 0 {
                    memfd_map_dec(r_shobj);
                }
            }
            MunmapClip::Front => {
                // Drop the front: the region becomes its own tail.
                // As above; the region stays live with trimmed bounds.
                let r = ptr::as_mut(region);
                r.base = hi;
                r.length = r_base + r_len - hi;
                r.file_off = r_off + (hi - r_base);
            }
            MunmapClip::Back => {
                // Drop the back: the region becomes its own head.
                // As above; only its length shrinks.
                ptr::as_mut(region).length = lo - r_base;
            }
            MunmapClip::Middle => {
                // Drop the middle: keep the head here and move the tail into a
                // free slot (pass 1 guaranteed one).  Both halves still name the
                // shared backing object, so the tail takes its own reference.
                // `tbl` is valid; `alloc_region_slot` only reads it.
                let tail = alloc_region_slot(tbl);
                // `tail` is a distinct free slot and `region` a live one,
                // so the writes do not alias; the slot was reserved in pass 1.
                {
                    let t = ptr::as_mut(tail);
                    t.base = hi;
                    t.length = r_base + r_len - hi;
                    t.flags = r_flags;
                    t.prot = r_prot;
                    t.fd = r_fd;
                    t.file_off = r_off + (hi - r_base);
                    t.shobj = r_shobj;
                    t.is_used = 1;
                }
                ptr::as_mut(region).length = lo - r_base;
                if r_shobj > 0 {
                    memfd_map_inc(r_shobj);
                }
            }
        }
    }

    0
}

/// `pd` is a valid page directory and `tbl` a live `MmapTable` owned by the
/// caller, and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub extern "C" fn do_mprotect(
    pd: *mut u64,
    tbl: *mut MmapTable,
    addr: u32,
    mut length: u32,
    prot: i32,
    brk_start: u64,
    brk_end: u64,
) -> i32 {
    if pd.is_null() || tbl.is_null() || length == 0 {
        return -1;
    }
    if !addr.is_multiple_of(PAGE_SIZE) {
        return -1;
    }

    length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let in_brk = (addr as u64) >= brk_start && (addr as u64) < brk_end;

    // `tbl` was checked non-null above and is the caller's live table.
    let region = mmap_find_region(tbl, addr);
    if region.is_null() && !in_brk {
        return -1;
    }

    let page_flags = prot_to_page_flags(prot, true) as u32;
    let pages = length / PAGE_SIZE;

    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;

        // `pd` is the caller's live page map; the walk creates the
        // private tables this entry needs.
        let w = walk(pd, va as u64, true, true);
        if w.pte_entry.is_null() {
            return -1;
        }
        let pte_entry = w.pte_entry;
        // `pte_entry` points at one initialised PTE.
        let pte = ptr::read(pte_entry);
        if pte & PAGE_PRESENT as u64 == 0 {
            continue;
        }
        // `pte_entry` points at one PTE, which receives the new flags.
        ptr::write(pte_entry, (pte & !0xFFF) | page_flags as u64);
        flush_tlb(va as u64);
    }

    if !in_brk {
        // region is valid (non-brk path).
        ptr::as_mut(region).prot = prot as u32;
    }
    0
}

/// `tbl` may be null; otherwise it points to a live, initialised `MmapTable`
/// that stays valid for the call.
#[unsafe(no_mangle)]
pub extern "C" fn mmap_print_regions(tbl: *const MmapTable) {
    if tbl.is_null() {
        return;
    }
    let mut buf = [0u8; 16];
    kprint_str(c"[MMAP] === Memory Regions ===\n".as_ptr() as *const u8);
    // tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = &ptr::as_ref(tbl).regions[i];
        if r.is_used == 0 {
            continue;
        }
        kprint_str(c"  [".as_ptr() as *const u8);
        itoa(i as i32, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c"] base=0x".as_ptr() as *const u8);
        hex_to_ascii(r.base, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c" len=0x".as_ptr() as *const u8);
        hex_to_ascii(r.length, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c" prot=".as_ptr() as *const u8);
        itoa(r.prot as i32, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c" flags=".as_ptr() as *const u8);
        itoa(r.flags as i32, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c" fd=".as_ptr() as *const u8);
        itoa(r.fd, buf.as_mut_ptr());
        printk(buf.as_ptr());
        kprint_str(c"\n".as_ptr() as *const u8);
    }
}
#[path = "mmap_clone.rs"]
mod mmap_clone;
pub use mmap_clone::*;
