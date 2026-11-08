// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! `mmap` / `munmap` implementation: private PDEs, file-backed mappings, and COW with the VMM.

use crate::ffi::*;
use crate::pmm::{kalloc, free_page, page_ref_inc};
use crate::vmm::paging::{vmm_map, p2v, v2p, walk};
use crate::fault::page_fault::vmm_map_zero;
use crate::process::memfd::{memfd_get_page, memfd_grow_to, memfd_map_dec, memfd_map_inc};

unsafe extern "C" {
    /// Flush a file-backed mapping's page-cache range back to its filesystem.
    fn vfs_as_flush_fd(fd: i32, off: u32, size: u32);
}
use crate::safe::{zero_page, flush_tlb, kprint_str};

fn fd_to_node(fd: i32) -> *mut VfsNode {
    // SAFETY: `cact_current_task_get` is the scheduler's per-CPU accessor; it may return null,
    // which the test below handles.
    let t = unsafe { cact_current_task_get() };
    if t.is_null() {
        return core::ptr::null_mut();
    }
    if fd < 0 || fd as usize >= MAX_FD {
        return core::ptr::null_mut();
    }
    // SAFETY: `t` is a live task (the caller checked it); this shared borrow is
    // consumed by the checks below.
    let t = unsafe { &*t };
    if t.proc.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `t.proc` is non-null (checked above) and points at the task's live
    // `ProcMeta`, so this field read is in bounds.
    let fds = unsafe { (*t.proc).fds };
    if fds.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `fds` is non-null (checked above) and `fd < MAX_FD`, so this fd-table
    // slot is in bounds.
    unsafe { (*fds).fd_table[fd as usize] }
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
    // SAFETY: tbl is a valid MmapTable (checked by callers).
    let mut candidate = unsafe { (*tbl).next_base };
    candidate = (candidate + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    loop {
        if candidate.wrapping_add(length) > MMAP_LIMIT
            || candidate.wrapping_add(length) < candidate
        {
            return 0;
        }

        let mut clash = false;
        // SAFETY: tbl is valid, regions array is within bounds.
        for i in 0..MMAP_MAX_REGIONS {
            // SAFETY: `tbl` is a valid `MmapTable` (its callers guarantee it) and
            // `i < MMAP_MAX_REGIONS`, so the region reference is in bounds.
            let r = unsafe { &(*tbl).regions[i] };
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
    // SAFETY: tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `tbl` is valid and `i < MMAP_MAX_REGIONS`; the returned slot may be
        // mutated by the caller while it holds the table.
        let r = unsafe { &mut (*tbl).regions[i] };
        if r.is_used == 0 {
            return r;
        }
    }
    core::ptr::null_mut()
}

/// Present physical frame backing `va` in `pd`, or 0 if absent.
fn pte_phys(pd: *mut u64, va: u32) -> u64 {
    // SAFETY: `pd` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    let w = unsafe { walk(pd, va as u64, false, false) };
    if !w.pd_entry.is_null() {
        // SAFETY: `w.pd_entry` is an in-bounds PD entry.
        let pde = unsafe { *w.pd_entry };
        if pde & PAGE_PRESENT as u64 != 0 && pde & PAGE_PS as u64 != 0 {
            return large_page_phys(pde, va as u64) & !0xFFF;
        }
    }
    if w.pte_entry.is_null() {
        return 0;
    }
    // SAFETY: `w.pte_entry` is an in-bounds page-table entry.
    let pte = unsafe { *w.pte_entry };
    if pte & PAGE_PRESENT as u64 == 0 {
        return 0;
    }
    pte & !0xFFF
}

/// Drop the PTE for a user virtual address, releasing its frame reference.
fn clear_user_pte(pd: *mut u64, va: u32) {
    // SAFETY: `pd` is a live page map and the walk only reads it.
    let w = unsafe { walk(pd, va as u64, false, false) };
    if w.pte_entry.is_null() {
        return;
    }
    // SAFETY: `w.pte_entry` is an in-bounds page-table entry.
    let pte = unsafe { *w.pte_entry };
    if pte & PAGE_PRESENT as u64 != 0 && pte & PAGE_USER as u64 != 0 {
        // SAFETY: the frame is live and PMM-managed; this call releases exactly one reference to it.
        // The entry names a physical address, which `free_page` wants as a VA.
        unsafe { free_page(p2v(pte & !0xFFF) as *mut u8) };
    }
    // SAFETY: `w.pte_entry` points at one PTE, which this unmap clears.
    unsafe { *w.pte_entry = 0 };
    flush_tlb(va as u64);
}

/// # Safety
///
/// `tbl` must be null or point to a live, writable `MmapTable` with room for
/// `MMAP_MAX_REGIONS` regions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap_table_init(tbl: *mut MmapTable) {
    if tbl.is_null() {
        return;
    }
    // SAFETY: `tbl` is a live, writable `MmapTable` (per the caller contract); this
    // borrow is exclusive for the whole initialisation.
    let tbl = unsafe { &mut *tbl };
    for r in tbl.regions.iter_mut() {
        r.is_used = 0;
        r.fd = -1;
        r.shobj = 0;
    }
    tbl.next_base = MMAP_BASE;
}

/// # Safety
///
/// `tbl` must be null or point to a live, initialised `MmapTable` that stays
/// valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap_find_region(tbl: *mut MmapTable, addr: u32) -> *mut MmapRegion {
    if tbl.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `tbl` is a valid `MmapTable` (checked at entry) and `i` is in bounds
        // of the region array.
        let r = unsafe { &mut (*tbl).regions[i] };
        if r.is_used == 0 {
            continue;
        }
        if addr >= r.base && addr < r.base + r.length {
            return r;
        }
    }
    core::ptr::null_mut()
}

/// # Safety
///
/// `pd` must be a valid page directory and `tbl` a live `MmapTable`, both owned
/// by the caller; they must stay valid and un-mutated by another thread for the
/// duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_mmap(
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
        // SAFETY: tbl is a valid MmapTable (checked at entry).
        for i in 0..MMAP_MAX_REGIONS {
            // SAFETY: `tbl` is valid and `i < MMAP_MAX_REGIONS`.
            let r = unsafe { &(*tbl).regions[i] };
            if r.is_used == 0 {
                continue;
            }
            if hint < r.base.saturating_add(r.length) && r.base < hint.saturating_add(length) {
                kprint_str(
                    c"[MMAP] do_mmap: MAP_FIXED overlaps an existing region\n".as_ptr() as *const u8,
                );
                return MAP_FAILED as *mut u8;
            }
        }
        va = hint;
    } else {
        va = find_free_va(tbl, length);
        if va == 0 {
            kprint_str(c"[MMAP] do_mmap: no free virtual address space\n".as_ptr() as *const u8);
            return MAP_FAILED as *mut u8;
        }
    }

    let region = alloc_region_slot(tbl);
    if region.is_null() {
        kprint_str(c"[MMAP] do_mmap: region table full\n".as_ptr() as *const u8);
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
        // SAFETY: `pd` is valid (checked at entry), `va` was chosen inside the mmap
        // window and `length` is a whole number of pages.
        if unsafe { vmm_map_zero(pd, va as u64, length, page_flags) } != 0 {
            kprint_str(c"[MMAP] do_mmap: vmm_map_zero failed\n".as_ptr() as *const u8);
            return MAP_FAILED as *mut u8;
        }
    } else {
        if fd < 0 {
            return MAP_FAILED as *mut u8;
        }
        // SAFETY: vfs_mmap_resolve only inspects the fd table and the node's
        // ops table; it never dereferences user memory.
        if flags & MAP_SHARED != 0 {
            let mut backing: i32 = 0;
            let mut backing_off: u32 = 0;
            // SAFETY: `vfs_mmap_resolve` only reads the fd table and the node's ops table
            // (never user memory) and the caller supplied valid out-pointers.
            let rc = unsafe {
                vfs_mmap_resolve(fd, offset, length, &mut backing, &mut backing_off)
            };
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
                // SAFETY: `pd` is valid, `va_i` lies inside the region reserved
                // above, and `page` is a live memfd frame (a direct-map VA), so
                // the mapping takes its physical address.
                unsafe { vmm_map(pd, va_i as u64, v2p(page), page_flags); }
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
                kprint_str(c"[MMAP] do_mmap: memfd shared map failed\n".as_ptr() as *const u8);
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
                    // SAFETY: both page pointers are valid 4 KiB frames (the
                    // destination is a direct-map VA from `kalloc`).
                    unsafe { core::ptr::copy_nonoverlapping(src, phys, PAGE_SIZE as usize); }
                }
                // SAFETY: `pd` is valid, `va + i * PAGE_SIZE` is inside the region
                // reserved above, and `phys` is the frame just allocated for it;
                // the mapping takes its physical address.
                unsafe { vmm_map(pd, (va + i * PAGE_SIZE) as u64, v2p(phys), page_flags); }
            }
        } else {
            let node = fd_to_node(fd);
            let mut file_off = offset;

            for i in 0..pages {
                let phys = kalloc();
                if phys.is_null() {
                    // SAFETY: `pd`/`tbl` are this function's own validated
                    // arguments; this rolls back the partial mapping installed so far.
                    unsafe { do_munmap(pd, tbl, va, i * PAGE_SIZE); }
                    return MAP_FAILED as *mut u8;
                }
                zero_page(phys);
                if !node.is_null() {
                    // SAFETY: node is a valid VfsNode; `phys` is the kalloc'd
                    // frame (a direct-map VA) the read fills.
                    unsafe { read_vfs(node, file_off as u64, PAGE_SIZE, phys); }
                }
                // SAFETY: `pd` is valid, `va + i * PAGE_SIZE` is inside the region
                // reserved above, and `phys` is the frame just allocated for it;
                // the mapping takes its physical address.
                unsafe { vmm_map(pd, (va + i * PAGE_SIZE) as u64, v2p(phys), page_flags); }
                file_off += PAGE_SIZE;
            }
        }
    }

    let shared_backed = shobj > 0 && flags & MAP_SHARED != 0;

    // SAFETY: `region` is the valid slot allocated just above and not used again
    // after this fill, so this borrow is exclusive.
    let region = unsafe { &mut *region };
    region.base = va;
    region.length = length;
    region.flags = flags as u32;
    region.prot = prot as u32;
    region.fd = if flags & MAP_ANON != 0 { -1 } else { fd };
    region.file_off = offset;
    region.is_used = 1;
    region.shobj = if shared_backed { shobj } else { 0 };

    // SAFETY: tbl is valid.
    if va + length > unsafe { (*tbl).next_base } {
        // SAFETY: `tbl` is a valid `MmapTable` (checked at entry); this only moves its
        // bump pointer forward.
        unsafe { (*tbl).next_base = va + length; }
    }

    va as *mut u8
}

/// # Safety
///
/// `pd` must be a valid page directory and `tbl` a live `MmapTable` owned by the
/// caller, and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_munmap(
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

    let mut region: *mut MmapRegion = core::ptr::null_mut();
    // SAFETY: tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = unsafe { &mut (*tbl).regions[i] };
        if r.is_used == 0 {
            continue;
        }
        if r.base == addr && r.length == length {
            region = r;
            break;
        }
        if r.base <= addr && addr + length <= r.base + r.length {
            region = r;
            break;
        }
    }

    if region.is_null() {
        return -1;
    }

    // Classify the request against the region the address falls in.  A request
    // that cuts a slice out of the *middle* has to leave two regions behind, so
    // it needs a second slot — reserve it now, before a single page is unmapped,
    // so the call can still fail cleanly when the table is full.
    // SAFETY: `region` is the live slot located by the scan above; the table is
    // not mutated concurrently.
    let (r_base, r_len) = unsafe { ((*region).base, (*region).length) };
    let front = addr == r_base;                 // unmap starts at the region's base
    let back = addr + length >= r_base + r_len; // ... and reaches its end
    let whole = front && back;

    let mut tail: *mut MmapRegion = core::ptr::null_mut();
    if !front && !back {
        // SAFETY: `tbl` is a valid `MmapTable` (checked at entry).
        tail = alloc_region_slot(tbl);
        if tail.is_null() {
            kprint_str(
                c"[MMAP] do_munmap: region table full, cannot split\n".as_ptr() as *const u8,
            );
            return -1;
        }
    }

    let pages = length / PAGE_SIZE;
    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;

        // SAFETY: `pd` is the caller's live page map and the walk only reads it.
        let w = unsafe { walk(pd, va as u64, false, false) };
        if w.pte_entry.is_null() {
            continue;
        }
        // SAFETY: `w.pte_entry` is an in-bounds page-table entry.
        let pte = unsafe { *w.pte_entry };

        // Only release frames that were allocated for user mappings. Supervisor
        // identity PTEs (present, no PAGE_USER) must not be passed to free_page.
        if pte & PAGE_PRESENT as u64 != 0 && pte & PAGE_USER as u64 != 0 {
            // SAFETY: the frame is live and PMM-managed; this call releases exactly one reference to it.
            // The entry names a physical address, which `free_page` wants as a VA.
            unsafe { free_page(p2v(pte & !0xFFF) as *mut u8) };
        }
        // SAFETY: `w.pte_entry` points at one PTE, which this unmap clears.
        unsafe { *w.pte_entry = 0 };
        flush_tlb(va as u64);
    }

    // SAFETY: `region` is the live region slot located by the scan above and it is
    // not used again after this update, so this borrow is exclusive; the
    // `memfd_map_*` calls do not touch the region.
    let region = unsafe { &mut *region };

    // Write the file-backed dirty page-cache range this call unmaps — exactly
    // [addr, addr + length), whichever slice of the region that is — back to
    // disk before the mapping goes away (mmap writes bypass write()).
    if region.fd >= 0 && region.shobj > 0 {
        // SAFETY: the fd is the one that backs this mapping; the VFS resolves
        // it to its inode's address space and flushes (a no-op when there is
        // none).
        unsafe { vfs_as_flush_fd(region.fd, region.file_off + (addr - r_base), length) };
    }

    if whole {
        let obj = region.shobj;
        region.is_used = 0;
        region.fd = -1;
        region.shobj = 0;
        if obj > 0 {
            memfd_map_dec(obj);
        }
    } else if front {
        // Drop the front: the region becomes its own tail.
        region.base = r_base + length;
        region.length = r_len - length;
        region.file_off += length;
    } else if back {
        // Drop the back: the region becomes its own head.
        region.length = addr - r_base;
    } else {
        // Drop the middle: keep the head here and move the tail into the slot
        // reserved above.  Both halves still name the shared backing object, so
        // the new tail takes its own MAP_SHARED reference.
        // SAFETY: `tail` is the unused slot reserved above, distinct from the
        // live `region`, so the two writes do not alias.
        unsafe {
            (*tail).base = addr + length;
            (*tail).length = (r_base + r_len) - (addr + length);
            (*tail).flags = region.flags;
            (*tail).prot = region.prot;
            (*tail).fd = region.fd;
            (*tail).file_off = region.file_off + (addr + length - r_base);
            (*tail).shobj = region.shobj;
            (*tail).is_used = 1;
        }
        if region.shobj > 0 {
            memfd_map_inc(region.shobj);
        }
        region.length = addr - r_base;
    }

    0
}

/// # Safety
///
/// `pd` must be a valid page directory and `tbl` a live `MmapTable` owned by the
/// caller, and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_mprotect(
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

    // SAFETY: `tbl` was checked non-null above and is the caller's live table.
    let region = unsafe { mmap_find_region(tbl, addr) };
    if region.is_null() && !in_brk {
        return -1;
    }

    let page_flags = prot_to_page_flags(prot, true) as u32;
    let pages = length / PAGE_SIZE;

    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;

        // SAFETY: `pd` is the caller's live page map; the walk creates the
        // private tables this entry needs.
        let w = unsafe { walk(pd, va as u64, true, true) };
        if w.pte_entry.is_null() {
            return -1;
        }
        let pte_entry = w.pte_entry;
        // SAFETY: `pte_entry` points at one initialised PTE.
        let pte = unsafe { *pte_entry };
        if pte & PAGE_PRESENT as u64 == 0 {
            continue;
        }
        // SAFETY: `pte_entry` points at one PTE, which receives the new flags.
        unsafe { *pte_entry = (pte & !0xFFF) | page_flags as u64 };
        flush_tlb(va as u64);
    }

    if !in_brk {
        // SAFETY: region is valid (non-brk path).
        unsafe { (*region).prot = prot as u32; }
    }
    0
}

/// # Safety
///
/// `tbl` must be null or point to a live, initialised `MmapTable` that stays
/// valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap_print_regions(tbl: *const MmapTable) {
    if tbl.is_null() {
        return;
    }
    let mut buf = [0u8; 16];
    kprint_str(c"[MMAP] === Memory Regions ===\n".as_ptr() as *const u8);
    // SAFETY: tbl is valid.
    for i in 0..MMAP_MAX_REGIONS {
        // SAFETY: `tbl` is valid (checked at entry) and `i < MMAP_MAX_REGIONS`.
        let r = unsafe { &(*tbl).regions[i] };
        if r.is_used == 0 {
            continue;
        }
        kprint_str(c"  [".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `itoa` writes within it.
        unsafe { itoa(i as i32, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `itoa`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c"] base=0x".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `hex_to_ascii` writes within it.
        unsafe { hex_to_ascii(r.base, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `hex_to_ascii`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c" len=0x".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `hex_to_ascii` writes within it.
        unsafe { hex_to_ascii(r.length, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `hex_to_ascii`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c" prot=".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `itoa` writes within it.
        unsafe { itoa(r.prot as i32, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `itoa`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c" flags=".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `itoa` writes within it.
        unsafe { itoa(r.flags as i32, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `itoa`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c" fd=".as_ptr() as *const u8);
        // SAFETY: `buf` is a live 16-byte stack array, so `itoa` writes within it.
        unsafe { itoa(r.fd, buf.as_mut_ptr()) };
        // SAFETY: `buf` was just made a NUL-terminated string by `itoa`.
        unsafe { printk(buf.as_ptr()) };
        kprint_str(c"\n".as_ptr() as *const u8);
    }
}
#[path = "mmap_clone.rs"]
mod mmap_clone;
pub use mmap_clone::*;
