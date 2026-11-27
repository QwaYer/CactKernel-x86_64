// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Shared-memory attach/detach/ctl syscall entry points. Split out of `shm.rs`.

use crate::ffi::*;
use crate::vmm::paging::{vmm_map, v2p};
use crate::safe::{lock_acquire, lock_release};
use crate::process::shm::{
    find_shm_va, seg_free, seg_valid, shm_ensure_init, shm_unmap_from, ShmSeg, SHM_LOCK, SHM_TABLE,
};

pub extern "C" fn shm_at(shmid: i32, shmaddr: u32, flags: i32) -> u32 {
    shm_ensure_init();

    let t = cact_current_task_get();
    // `t` is the live current task, checked non-null; `is_kernel` and `proc`
    // are plain fields of that `TaskStruct`.
    if t.is_null()
        || kernel_rust::ptr::as_ref(t).is_kernel != 0
        || kernel_rust::ptr::as_ref(t).proc.is_null()
    {
        return u32::MAX;
    }
    // `t` is the live current task (non-null) and its `proc` is non-null (both
    // checked above), so this `ProcMeta` pointer is valid for the call.
    let proc_meta = kernel_rust::ptr::as_ref(t).proc;

    lock_acquire(SHM_LOCK.as_ptr());

    if !seg_valid(shmid) {
        lock_release(SHM_LOCK.as_ptr());
        return u32::MAX;
    }

    let mut slot: i32 = -1;
    for i in 0..TASK_SHM_MAX {
        // `proc_meta` is the live `ProcMeta` and `i < TASK_SHM_MAX`, so the
        // attachment slot is in bounds.
        if kernel_rust::ptr::as_ref(proc_meta).shm_attachments[i].shm_id == 0 {
            slot = i as i32;
            break;
        }
    }
    if slot < 0 {
        lock_release(SHM_LOCK.as_ptr());
        return u32::MAX;
    }

    let va;
    if shmaddr != 0 {
        let mut addr = shmaddr;
        if flags & SHM_RND != 0 {
            addr &= !(PAGE_SIZE - 1);
        }
        if !addr.is_multiple_of(PAGE_SIZE) {
            lock_release(SHM_LOCK.as_ptr());
            return u32::MAX;
        }
        va = addr;
    } else {
        // `SHM_TABLE[shmid-1]` read under `SHM_LOCK`, after `seg_valid`.
        let num_pages = SHM_TABLE.with(|table| table[(shmid - 1) as usize].num_pages);
        va = find_shm_va(num_pages);
        if va == 0 {
            lock_release(SHM_LOCK.as_ptr());
            return u32::MAX;
        }
    }

    let mut page_flags = (PAGE_PRESENT | PAGE_USER) as i32;
    if flags & SHM_RDONLY == 0 {
        page_flags |= PAGE_RW as i32;
    }

    // `SHM_TABLE[shmid-1]` mutated under `SHM_LOCK`, after `seg_valid`.
    SHM_TABLE.with(|table| {
        let seg = &mut table[(shmid - 1) as usize];
        for i in 0..seg.num_pages {
            // `t` is the live current task, so this `page_directory` field read
            // is in bounds.
            let pd = kernel_rust::ptr::as_ref(t).page_directory;
            // `pd` is the CR3 root of the live current task, `va + i *
            // PAGE_SIZE` is inside the SHM window chosen above, and the
            // segment's frames stay live while `SHM_LOCK` is held.  `seg.pages[i]`
            // is the `kalloc` VA of the frame, so the entry takes its physical
            // address.
            vmm_map(pd, (va + i * PAGE_SIZE) as u64, v2p(seg.pages[i as usize]), page_flags);
        }

        // `proc_meta` is the live `ProcMeta` and `slot` is in bounds
        // (`0 <= slot < TASK_SHM_MAX`), so this exclusive borrow of the slot is
        // valid while `SHM_LOCK` is held.
        let att = &mut kernel_rust::ptr::as_mut(proc_meta).shm_attachments[slot as usize];
        att.shm_id = shmid;
        att.shm_vaddr = va;
        seg.nattch += 1;
        // `(*t).pid` of the live task whose attach slot was just filled.
        seg.lpid = kernel_rust::ptr::as_ref(t).pid;
    });

    lock_release(SHM_LOCK.as_ptr());
    va
}

pub extern "C" fn shm_dt(shmaddr: u32) -> i32 {
    shm_ensure_init();

    let t = cact_current_task_get();
    // `t` is the live current task, checked non-null; `is_kernel`/`proc` are
    // plain fields of it.
    if t.is_null()
        || kernel_rust::ptr::as_ref(t).is_kernel != 0
        || kernel_rust::ptr::as_ref(t).proc.is_null()
    {
        return -1;
    }
    // `t` is the live current task (non-null) and its `proc` is non-null (both
    // checked above), so this `ProcMeta` pointer is valid for the call.
    let proc_meta = kernel_rust::ptr::as_ref(t).proc;

    lock_acquire(SHM_LOCK.as_ptr());

    let mut slot: i32 = -1;
    for i in 0..TASK_SHM_MAX {
        // `proc_meta` is the live `ProcMeta` and `i < TASK_SHM_MAX`, so the
        // attachment reference is in bounds.
        let att = &kernel_rust::ptr::as_ref(proc_meta).shm_attachments[i];
        if att.shm_vaddr == shmaddr && att.shm_id != 0 {
            slot = i as i32;
            break;
        }
    }
    if slot < 0 {
        lock_release(SHM_LOCK.as_ptr());
        return -1;
    }

    // `proc_meta` is the live `ProcMeta` and `slot` is in bounds.
    let id = kernel_rust::ptr::as_ref(proc_meta).shm_attachments[slot as usize].shm_id;
    if !seg_valid(id) {
        // Clearing the attach slot of the live task under `SHM_LOCK`.
        let att = &mut kernel_rust::ptr::as_mut(proc_meta).shm_attachments[slot as usize];
        att.shm_id = 0;
        att.shm_vaddr = 0;
        lock_release(SHM_LOCK.as_ptr());
        return -1;
    }

    // `SHM_TABLE[id-1]` mutated under `SHM_LOCK`, after `seg_valid`.
    SHM_TABLE.with(|table| {
        let seg = &mut table[(id - 1) as usize];
        // `(*t).page_directory` of the live task being detached.
        shm_unmap_from(kernel_rust::ptr::as_ref(t).page_directory, shmaddr, seg.num_pages);

        // Clearing the same live task's attach slot; still under `SHM_LOCK`.
        let att = &mut kernel_rust::ptr::as_mut(proc_meta).shm_attachments[slot as usize];
        att.shm_id = 0;
        att.shm_vaddr = 0;
        if seg.nattch > 0 {
            seg.nattch -= 1;
        }
        // `(*t).pid` of the live task.
        seg.lpid = kernel_rust::ptr::as_ref(t).pid;

        if seg.destroy != 0 && seg.nattch == 0 {
            seg_free(seg as *mut ShmSeg);
        }
    });

    lock_release(SHM_LOCK.as_ptr());
    0
}

pub extern "C" fn shm_ctl(shmid: i32, cmd: i32, buf: *mut u8) -> i32 {
    shm_ensure_init();
    lock_acquire(SHM_LOCK.as_ptr());

    if !seg_valid(shmid) {
        lock_release(SHM_LOCK.as_ptr());
        return -1;
    }

    // `SHM_TABLE[shmid-1]` mutated under `SHM_LOCK`, after `seg_valid`.
    SHM_TABLE.with(|table| {
        let seg = &mut table[(shmid - 1) as usize];

        if cmd == IPC_RMID {
            seg.destroy = 1;
            if seg.nattch == 0 {
                seg_free(seg as *mut ShmSeg);
            }
            lock_release(SHM_LOCK.as_ptr());
            return 0;
        }

        if cmd == IPC_STAT {
            if buf.is_null() {
                lock_release(SHM_LOCK.as_ptr());
                return -1;
            }
            // `buf` was null-checked above and the caller passes a
            // `ShmInfo`-sized C buffer, so this exclusive borrow of the whole
            // struct is valid; the segment stays live under `SHM_LOCK`.
            let info = kernel_rust::ptr::as_mut(buf as *mut ShmInfo);
            info.shm_segsz = seg.size;
            info.shm_cpid = seg.cpid;
            info.shm_lpid = seg.lpid;
            info.shm_nattch = seg.nattch;
            lock_release(SHM_LOCK.as_ptr());
            return 0;
        }

        lock_release(SHM_LOCK.as_ptr());
        -1
    })
}

pub extern "C" fn shm_detach_all(pid: u32, page_directory: *mut u64) {
    shm_ensure_init();
    if page_directory.is_null() {
        return;
    }

    // `task_list_head` is a valid kernel global.
    let mut found: *mut TaskStruct = core::ptr::null_mut();
    let mut cur = task_list_head();
    if cur.is_null() {
        return;
    }
    loop {
        // Walking the circular task list.
        if kernel_rust::ptr::as_ref(cur).pid == pid {
            found = cur;
            break;
        }
        // `cur` walks the task list; it is non-null at this point and the node
        // remains live for the duration of the walk.
        cur = kernel_rust::ptr::as_ref(cur).next;
        if cur.is_null() || cur == task_list_head() {
            break;
        }
    }

    if found.is_null() {
        return;
    }

    lock_acquire(SHM_LOCK.as_ptr());

    // `found` is the live `TaskStruct` located by the walk above, so this `proc`
    // field read is in bounds.
    let proc_meta = kernel_rust::ptr::as_ref(found).proc;
    for i in 0..TASK_SHM_MAX {
        // `proc_meta` is the live `ProcMeta` and `i` is in bounds of the
        // attachment array.
        let id = kernel_rust::ptr::as_ref(proc_meta).shm_attachments[i].shm_id;
        if id == 0 {
            continue;
        }
        if !seg_valid(id) {
            // Clearing the attach slot of the task being torn down, under
            // `SHM_LOCK`.
            let att = &mut kernel_rust::ptr::as_mut(proc_meta).shm_attachments[i];
            att.shm_id = 0;
            att.shm_vaddr = 0;
            continue;
        }
        // `SHM_TABLE[id-1]` mutated under `SHM_LOCK`, after `seg_valid`.
        SHM_TABLE.with(|table| {
            let seg = &mut table[(id - 1) as usize];
            shm_unmap_from(
                page_directory,
                // `shm_vaddr` of the live task's attachment slot.
                kernel_rust::ptr::as_ref(proc_meta).shm_attachments[i].shm_vaddr,
                seg.num_pages,
            );
            // Clearing the same attachment slot; still under `SHM_LOCK`.
            let att = &mut kernel_rust::ptr::as_mut(proc_meta).shm_attachments[i];
            att.shm_id = 0;
            att.shm_vaddr = 0;
            if seg.nattch > 0 {
                seg.nattch -= 1;
            }
            seg.lpid = pid;
            if seg.destroy != 0 && seg.nattch == 0 {
                seg_free(seg as *mut ShmSeg);
            }
        });
    }

    lock_release(SHM_LOCK.as_ptr());
}
