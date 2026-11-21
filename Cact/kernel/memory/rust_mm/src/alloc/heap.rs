// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Intrusive free-list heap in the `[HEAP_START, HEAP_START+HEAP_SIZE)` window,
//! which starts where the PMM's boot reservation ends (see
//! `pmm::heap_start()` — the reservation covers the bootloader's module images).
//!
//! `kmalloc` / `kfree` are IRQ-spinlocked and back much of the kernel and Rust MM code.

use crate::alloc::heap_stats::HeapAggregate;
use crate::alloc::realloc_plan::{plan, should_split, Realloc};
use crate::ffi::*;
use crate::pmm::{heap_end, heap_start};
use crate::safe::{KStatic, lock_acquire, lock_release, kprint_int, kprint_str, klog_msg};
use crate::vmm::paging::{p2v, v2p};

#[repr(C)]
struct HeapBlock {
    magic: u32,
    size: u32,
    is_free: u32,
    next: *mut HeapBlock,
}

static HEAP_START_PTR: KStatic<*mut HeapBlock> = KStatic::new(HEAP_START as *mut HeapBlock);
static HEAP_LOCK: KStatic<IrqSpinlock> = KStatic::new(IrqSpinlock { spin_locked: 0, saved_flags: 0 });
const HEAP_TAIL_MAGIC: u32 = 0xC0DEC0DE;

/// True when `ptr` — a pointer the heap list holds, i.e. a direct-map VA — names
/// a byte inside the heap window.  The window is a *physical* range, so the
/// check translates through the direct map first.
#[inline(always)]
fn heap_addr_in_range(ptr: *const u8) -> bool {
    let phys = v2p(ptr);
    phys >= heap_start() as u64 && phys < heap_end() as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn init_heap() {
    let start = heap_start();
    let end = heap_end();
    let window = end.saturating_sub(start);
    if window <= core::mem::size_of::<HeapBlock>() as u32 {
        klog_msg(LOG_FAIL, c"heap layout invalid".as_ptr() as *const u8);
        return;
    }

    // SAFETY: boot-time initialisation of `HEAP_LOCK` before any kernel thread or
    // SMP AP exists; single-threaded.
    unsafe { irq_spinlock_init(HEAP_LOCK.as_ptr()) };
    // SAFETY: `HEAP_START_PTR` is seeded with the direct-map VA of the start of
    // the dedicated heap window during single-threaded boot; no concurrent
    // allocator call yet.
    *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) } = p2v(start as u64) as *mut HeapBlock;

    // SAFETY: `HEAP_START_PTR` read during the same single-threaded init.
    let head = *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) };
    // SAFETY: `head` is the freshly seeded first `HeapBlock` at the window start,
    // reached through the direct map; it is large enough for the header it is
    // being initialised with and this is its only reference during
    // single-threaded init.
    let head = unsafe { &mut *head };
    head.magic = HEAP_MAGIC;
    head.size = window - core::mem::size_of::<HeapBlock>() as u32;
    head.is_free = 1;
    head.next = core::ptr::null_mut();

}

/// Allocate `size` bytes from the heap window.
///
/// The heap window is reached through the **direct map**, so the free list and
/// every `HeapBlock` link hold direct-map VAs: the whole allocator works in one
/// address space, and `kmalloc` hands the caller exactly the block address.
#[unsafe(no_mangle)]
pub extern "C" fn kmalloc(size: usize) -> *mut u8 {
    // A `HeapBlock` keeps its size in a `u32` and the window is a few MiB, so a
    // request the header cannot represent is unservable.  `MAX_BLOCK` leaves room
    // for the header and the rounding below to stay within `u32`.
    const MAX_BLOCK: usize = u32::MAX as usize - 64;
    if size == 0 || size > MAX_BLOCK {
        return core::ptr::null_mut();
    }
    let size = size as u32;
    let user_size = (size + 7) & !7;
    let mut size = user_size + 4;
    size = (size + 7) & !7;
    let hdr_size = core::mem::size_of::<HeapBlock>() as u32;
    lock_acquire(HEAP_LOCK.as_ptr());

    // SAFETY: `HEAP_START_PTR` read under `HEAP_LOCK`, acquired above, so the list
    // head cannot be swapped by a concurrent allocation.
    let mut current = *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) };
    if v2p(current) < heap_start() as u64 {
        lock_release(HEAP_LOCK.as_ptr());
        kprint_str(c"[FATAL] kmalloc: heap pointer below reserved boundary\n".as_ptr() as *const u8);
        return core::ptr::null_mut();
    }
    let mut best_fit: *mut HeapBlock = core::ptr::null_mut();

    while !current.is_null() {
        // SAFETY: `current` walks the heap list under `HEAP_LOCK`; every node was
        // range-checked when the list was built.
        let magic = unsafe { (*current).magic };
        if magic != HEAP_MAGIC {
            kprint_str(c"[FATAL] Heap corruption detected!\n".as_ptr() as *const u8);
            klog_msg(LOG_FAIL, c"heap corruption in allocation walk".as_ptr() as *const u8);
            lock_release(HEAP_LOCK.as_ptr());
            return core::ptr::null_mut();
        }
        // SAFETY: `(*current).is_free` of the same locked heap-list node.
        let is_free = unsafe { (*current).is_free };
        // SAFETY: `(*current).size` of the same locked heap-list node.
        let cur_size = unsafe { (*current).size };
        if is_free != 0 && cur_size >= size {
            // SAFETY: `best_fit` is a heap-list node found by this same locked walk.
            let best_size = if best_fit.is_null() { u32::MAX } else { unsafe { (*best_fit).size } };
            if cur_size < best_size {
                best_fit = current;
            }
        }
        // SAFETY: following the `next` link of a locked heap-list node.
        current = unsafe { (*current).next };
    }

    if !best_fit.is_null() {
        // SAFETY: `(*best_fit).size` of a locked heap-list node.
        let bf_size = unsafe { (*best_fit).size };
        if bf_size >= size + hdr_size + 8 {
            // SAFETY: splitting `best_fit` under `HEAP_LOCK`: `next_block` lies
            // `hdr_size + size` bytes into the block, which the size check above
            // proved is still inside that block's own extent in the heap window.
            let next_block = unsafe {
                (best_fit as *mut u8).add(hdr_size as usize + size as usize) as *mut HeapBlock
            };
            // SAFETY: `next_block` is the freshly-carved sub-block inside
            // `best_fit`'s extent and no reference to it exists yet.
            let next_block_ref = unsafe { &mut *next_block };
            // SAFETY: `best_fit` is the chosen free block and this call owns it
            // under `HEAP_LOCK`; the borrow ends at the end of this block, before
            // the tail canary below.
            let best_fit_ref = unsafe { &mut *best_fit };
            next_block_ref.magic = HEAP_MAGIC;
            next_block_ref.size = best_fit_ref.size - size - hdr_size;
            next_block_ref.is_free = 1;
            next_block_ref.next = best_fit_ref.next;
            best_fit_ref.size = size;
            best_fit_ref.next = next_block;
        }
        // SAFETY: marking the chosen block in-use, under `HEAP_LOCK`.
        unsafe { (*best_fit).is_free = 0; }
        lock_release(HEAP_LOCK.as_ptr());
        // SAFETY: `user_ptr` is `best_fit + hdr_size`, still inside the block whose
        // size was validated above (every block is at least `hdr_size + 4` bytes).
        let user_ptr = unsafe { (best_fit as *mut u8).add(hdr_size as usize) };
        // SAFETY: `(*best_fit).size` of the block this call owns under `HEAP_LOCK`.
        let block_size = unsafe { (*best_fit).size };
        // SAFETY: the tail canary lives at `user_ptr + block_size - 4`, i.e. 4 bytes
        // before the end of the block whose size was reserved by `kmalloc`.
        let tail = unsafe { user_ptr.add(block_size as usize - 4) as *mut u32 };
        // SAFETY: writing the tail canary into the reserved slot computed above.
        unsafe { *tail = HEAP_TAIL_MAGIC; }
        // The list lives in direct-map VAs, so `user_ptr` is already the address
        // the caller must see.
        return user_ptr;
    }

    lock_release(HEAP_LOCK.as_ptr());
    klog_msg(LOG_WARN, c"heap out of memory".as_ptr() as *const u8);
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn kmalloc_aligned(size: usize, align: usize) -> *mut u8 {
    let align = if align < 4 { 4 } else { align };
    let raw = kmalloc(size + align + 4);
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Align in the direct-map VA the caller will use; the direct map is far
    // coarser (2 MiB) than any heap alignment, so the frame is aligned too.  The
    // four bytes below `aligned` hold the *physical* address of the raw block —
    // `kfree` reads it back and re-derives the VA through the direct map.
    let raw_phys = v2p(raw) as u32;
    let addr = (raw as usize) + 4;
    let aligned = (addr + align - 1) & !(align - 1);
    // SAFETY: `kmalloc_aligned` reserved four extra bytes below `aligned` for
    // exactly this back-pointer; `aligned` is inside the block just returned by
    // `kmalloc`, which lives in the heap window.
    unsafe { *((aligned - 4) as *mut u32) = raw_phys; }
    aligned as *mut u8
}

/// # Safety
///
/// `ptr` must be null or a **virtual** address (direct-map, as `kmalloc` /
/// `kmalloc_aligned` hand out) of a block previously returned by those and not
/// already freed, and it must stay valid for the duration of the call.
///
/// The free list is held in direct-map VAs, so the walk below works on the
/// pointer itself; only the `kmalloc_aligned` back-pointer is stored physically
/// and has to be translated on the way in.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kfree(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let hdr_size = core::mem::size_of::<HeapBlock>() as usize;

    // Normal heap block?
    // SAFETY: `kfree` may only be called with a pointer from `kmalloc`, so
    // stepping back by the header size stays inside the same heap block; the
    // result is range-checked before any dereference.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    // SAFETY: `block` is inside the heap window and correctly aligned (checked
    // by `heap_addr_in_range` before the dereference).
    if heap_addr_in_range(block as *const u8) && unsafe { (*block).magic } == HEAP_MAGIC {
        kfree_impl(ptr);
        return;
    }

    // Linux-style fallback: kmalloc_aligned stores the raw block's *physical*
    // address 4 bytes below the aligned VA (see `kmalloc_aligned`); the VA of
    // that slot is `p2v(v2p(ptr) - 4)`.
    // SAFETY: aligned-allocation fallback — the slot holds the raw block's
    // physical address, recorded at allocation time; the VA is validated by
    // `heap_addr_in_range` before any dereference of the block itself.
    let raw_phys = unsafe { *(p2v(v2p(ptr) - 4) as *const u32) };
    let raw = p2v(raw_phys as u64) as *mut u8;
    if heap_addr_in_range(raw as *const u8) {
        // SAFETY: `raw` is only dereferenced after `heap_addr_in_range` proved it
        // lies in the heap window, so stepping back by the header size stays within
        // that window.
        let rblock = unsafe { raw.sub(hdr_size) } as *mut HeapBlock;
        // SAFETY: `rblock` is inside the heap window, verified by the check above.
        if unsafe { (*rblock).magic } == HEAP_MAGIC {
            kfree_impl(raw);
        }
    }
}

fn kfree_impl(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let hdr_size = core::mem::size_of::<HeapBlock>() as usize;
    lock_acquire(HEAP_LOCK.as_ptr());

    // SAFETY: `kfree_impl` is called from `kfree` with a direct-map VA of a
    // block returned by `kmalloc` (the free list's own terms); the header
    // step-back stays in the same block and `HEAP_LOCK` is already held, so the
    // list cannot move under us.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    if !heap_addr_in_range(block as *const u8) {
        klog_msg(LOG_WARN, c"kfree pointer outside heap range".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // Accept free() only for blocks that are still linked in the heap list.
    // SAFETY: `HEAP_START_PTR` read under `HEAP_LOCK`.
    let mut walk = *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) };
    let mut found = false;
    while !walk.is_null() {
        if !heap_addr_in_range(walk as *const u8) {
            kprint_str(c"[FATAL] kfree: walk pointer left heap range\n".as_ptr() as *const u8);
            klog_msg(LOG_FAIL, c"heap list pointer out of range".as_ptr() as *const u8);
            lock_release(HEAP_LOCK.as_ptr());
            return;
        }
        // SAFETY: `walk` is a node of the locked heap list, range-checked at the top
        // of every iteration before the dereference.
        let walk_magic = unsafe { (*walk).magic };
        if walk_magic != HEAP_MAGIC {
            kprint_str(c"[FATAL] kfree: list magic corrupted during lookup\n".as_ptr() as *const u8);
            klog_msg(LOG_FAIL, c"heap list magic corrupted".as_ptr() as *const u8);
            lock_release(HEAP_LOCK.as_ptr());
            return;
        }
        if walk == block {
            found = true;
            break;
        }
        // SAFETY: `(*walk).next` of a node proven to be in the heap range.
        walk = unsafe { (*walk).next };
    }
    if !found {
        klog_msg(LOG_WARN, c"kfree ignored for unknown block".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // SAFETY: `block` was just found to be a linked node of the heap list, so it
    // is a live `HeapBlock`; still under `HEAP_LOCK`.
    let magic = unsafe { (*block).magic };
    if magic != HEAP_MAGIC {
        klog_msg(LOG_WARN, c"kfree bad block magic".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // SAFETY: `(*block).size` of the validated heap block.
    let bsize = unsafe { (*block).size } as usize;
    if bsize < 4 {
        kprint_str(c"[FATAL] kfree: block too small for tail canary\n".as_ptr() as *const u8);
        klog_msg(LOG_FAIL, c"heap block too small for canary".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }
    // SAFETY: `bsize >= 4` is checked above and the block was validated as a live
    // heap block, so `ptr + bsize - 4` is the tail canary slot.
    let tail = unsafe { ptr.add(bsize - 4) as *mut u32 };
    // SAFETY: reading the tail canary slot computed above, inside the block.
    let tail_magic = unsafe { *tail };
    if tail_magic != HEAP_TAIL_MAGIC {
        kprint_str(c"[FATAL] kfree: tail canary corrupted (buffer overflow)\n".as_ptr() as *const u8);
        klog_msg(LOG_FAIL, c"heap tail canary corrupted".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // SAFETY: `(*block).is_free` of the validated heap block, under `HEAP_LOCK`.
    if unsafe { (*block).is_free } != 0 {
        klog_msg(LOG_WARN, c"double free ignored".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // SAFETY: releasing `block` back to the heap list, under `HEAP_LOCK`.
    unsafe { (*block).is_free = 1; }

    // SAFETY: `HEAP_START_PTR` re-read under `HEAP_LOCK` for the coalescing walk.
    let mut curr = *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) };
    while !curr.is_null() {
        // SAFETY: `curr` walks the locked heap list; each node is range/ magic checked
        // before use.
        let curr_magic = unsafe { (*curr).magic };
        if curr_magic != HEAP_MAGIC {
            kprint_str(c"[FATAL] kfree: heap corruption at curr\n".as_ptr() as *const u8);
            klog_msg(LOG_FAIL, c"heap corruption during coalesce".as_ptr() as *const u8);
            break;
        }
        // SAFETY: `(*curr).is_free` of the validated list node.
        let curr_free = unsafe { (*curr).is_free };
        // SAFETY: `(*curr).next` of the validated list node.
        let next = unsafe { (*curr).next };
        if curr_free != 0 && !next.is_null() {
            // SAFETY: `(*next).magic` of a node checked non-null and in heap range.
            let next_magic = unsafe { (*next).magic };
            if next_magic != HEAP_MAGIC {
                kprint_str(c"[FATAL] kfree: next header corrupted, stopping coalesce\n".as_ptr() as *const u8);
                klog_msg(LOG_FAIL, c"next heap header corrupted".as_ptr() as *const u8);
                break;
            }
            // SAFETY: `(*next).is_free` of the magic-checked node.
            let next_free = unsafe { (*next).is_free };
            if next_free != 0 {
                // SAFETY: `(*next).size` of the magic-checked node.
                let next_size = unsafe { (*next).size };
                // SAFETY: `(*next).next` of the magic-checked node.
                let next_next = unsafe { (*next).next };
                {
                    // SAFETY: `next` is the adjacent node being absorbed, and this
                    // call owns the locked heap list.
                    let next_ref = unsafe { &mut *next };
                    // SAFETY: `curr` is the node being widened; it is distinct from
                    // `next` (adjacent list nodes) and this call owns it under
                    // `HEAP_LOCK`.
                    let curr_ref = unsafe { &mut *curr };
                    next_ref.magic = 0;
                    curr_ref.size += next_size + hdr_size as u32;
                    curr_ref.next = next_next;
                }
                continue;
            }
        }
        curr = next;
    }
    lock_release(HEAP_LOCK.as_ptr());
}

/// Kernel-heap fragmentation summary, reported by `/proc/meminfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HeapStats {
    /// Sum of the sizes of the free blocks.
    pub free_bytes: u32,
    /// Sum of the sizes of the in-use blocks.
    pub used_bytes: u32,
    /// Number of free blocks.
    pub free_blocks: u32,
    /// Number of blocks of any kind.
    pub total_blocks: u32,
    /// Size of the largest free block (0 when the list holds no free block).
    pub largest_free: u32,
}

/// Walk the heap list once and fold it into a [`HeapStats`].  The list is
/// address-ordered and every block carries its own size, so one pass gives both
/// the totals and the fragmentation shape (free-block count, largest free).
#[unsafe(no_mangle)]
pub extern "C" fn heap_get_stats() -> HeapStats {
    let mut agg = HeapAggregate::new();
    lock_acquire(HEAP_LOCK.as_ptr());
    // SAFETY: `HEAP_START_PTR` read under `HEAP_LOCK`.
    let mut current = *unsafe { KStatic::get_mut(HEAP_START_PTR.as_ptr()) };
    while !current.is_null() {
        // SAFETY: `(*current).size` of a heap-list node, under `HEAP_LOCK`.
        let size = unsafe { (*current).size };
        // SAFETY: `(*current).is_free` of the same node.
        let is_free = unsafe { (*current).is_free } != 0;
        agg.add(size, is_free);
        // SAFETY: following `(*current).next` in the locked heap list.
        current = unsafe { (*current).next };
    }
    lock_release(HEAP_LOCK.as_ptr());
    HeapStats {
        free_bytes: agg.free_bytes,
        used_bytes: agg.used_bytes,
        free_blocks: agg.free_blocks,
        total_blocks: agg.total_blocks,
        largest_free: agg.largest_free,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn get_free_heap_memory() -> u32 {
    heap_get_stats().free_bytes
}

/// One-line heap summary for the boot log and manual debugging; the same
/// numbers `/proc/meminfo` reports, without the kB scaling.
#[unsafe(no_mangle)]
pub extern "C" fn kmalloc_print_stats() {
    let s = heap_get_stats();
    kprint_str(c"heap: free=".as_ptr() as *const u8);
    kprint_int(s.free_bytes as i32);
    kprint_str(c" used=".as_ptr() as *const u8);
    kprint_int(s.used_bytes as i32);
    kprint_str(c" free_blocks=".as_ptr() as *const u8);
    kprint_int(s.free_blocks as i32);
    kprint_str(c" total_blocks=".as_ptr() as *const u8);
    kprint_int(s.total_blocks as i32);
    kprint_str(c" largest_free=".as_ptr() as *const u8);
    kprint_int(s.largest_free as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
}

/// Resolve a live block pointer to its raw `HeapBlock` and the pointer's byte
/// offset inside it (`off >= header size`; larger for a `kmalloc_aligned` block).
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `kmalloc` /
/// `kmalloc_aligned` and not yet freed.
unsafe fn raw_block(ptr: *mut u8) -> Option<(*mut HeapBlock, u32)> {
    if ptr.is_null() {
        return None;
    }
    let hdr_size = core::mem::size_of::<HeapBlock>();
    // Plain block: the header sits exactly `hdr_size` below the pointer.
    // SAFETY: `ptr` is a caller-guaranteed live heap pointer, so stepping back by
    // the header size stays inside the same block; the result is range-checked
    // before the header is read.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    // SAFETY: `block` was range-checked by `heap_addr_in_range` before this read.
    if heap_addr_in_range(block as *const u8) && unsafe { (*block).magic } == HEAP_MAGIC {
        return Some((block, hdr_size as u32));
    }
    // Aligned block: `kmalloc_aligned` recorded the raw block's *physical*
    // address four bytes below the aligned pointer.
    // SAFETY: aligned-allocation fallback — the slot is read at the VA the
    // allocator wrote at allocation time, translated back through the direct map.
    let raw_phys = unsafe { *(p2v(v2p(ptr) - 4) as *const u32) };
    let raw = p2v(raw_phys as u64) as *mut u8;
    if heap_addr_in_range(raw as *const u8) {
        // SAFETY: `raw` is inside the heap window (checked above), so stepping
        // back by the header size stays within that window.
        let rblock = unsafe { raw.sub(hdr_size) } as *mut HeapBlock;
        // SAFETY: `rblock` is inside the heap window, verified by the check above.
        if unsafe { (*rblock).magic } == HEAP_MAGIC {
            return Some((rblock, (ptr as usize - raw as usize) as u32));
        }
    }
    None
}

/// Shrink `block` in place to `new_size`, splitting the slack off as a free
/// block when a whole header still fits after it, and always refreshing the
/// trailing tail canary.
///
/// # Safety
///
/// `block` must be a live heap block held under `HEAP_LOCK`, and `new_size` must
/// be at least `realloc_plan::required_block_size` for the caller's pointer.
unsafe fn resize_block(block: *mut HeapBlock, new_size: u32, hdr_size: u32) {
    // SAFETY: `block` is a live locked block.
    let cur_size = unsafe { (*block).size };
    if should_split(cur_size, new_size, hdr_size) {
        // SAFETY: `should_split` proved the split point lies inside `block`'s own
        // extent, so this is the freshly carved sub-block.
        let tail = unsafe {
            (block as *mut u8).add(hdr_size as usize + new_size as usize) as *mut HeapBlock
        };
        // SAFETY: `(*block).next` of the locked live block.
        let tail_next = unsafe { (*block).next };
        // SAFETY: `tail` is the freshly carved sub-block inside `block`; no
        // reference to it exists yet.
        let tail_ref = unsafe { &mut *tail };
        tail_ref.magic = HEAP_MAGIC;
        tail_ref.size = cur_size - new_size - hdr_size;
        tail_ref.is_free = 1;
        tail_ref.next = tail_next;
        // SAFETY: sizing `block` down to its leading part, under `HEAP_LOCK`.
        unsafe { (*block).size = new_size };
        // SAFETY: linking the just-carved free tail after `block`.
        unsafe { (*block).next = tail };
    }
    // SAFETY: `(*block).size` of the live locked block, after any split.
    let bsize = unsafe { (*block).size };
    // SAFETY: the tail canary lives in the last four bytes of the block, which the
    // size accounting above reserved.
    let canary = unsafe { (block as *mut u8).add(hdr_size as usize + bsize as usize - 4) as *mut u32 };
    // SAFETY: writing the canary into the reserved slot computed above.
    unsafe { *canary = HEAP_TAIL_MAGIC };
}

/// Merge the physically next free block `next` into `block`.
///
/// # Safety
///
/// `block` and `next` must be live adjacent heap blocks under `HEAP_LOCK`, with
/// `next` free and `(*block).next == next`.
unsafe fn absorb_next(block: *mut HeapBlock, next: *mut HeapBlock, hdr_size: u32) {
    // SAFETY: `next` is a live free block under `HEAP_LOCK`.
    let next_size = unsafe { (*next).size };
    // SAFETY: `(*next).next` of the same locked node.
    let next_next = unsafe { (*next).next };
    // SAFETY: `(*block).size` of the locked live block.
    let block_size = unsafe { (*block).size };
    // SAFETY: clearing the absorbed node's magic retires it as a list node.
    unsafe { (*next).magic = 0 };
    // SAFETY: widening `block` over `next`'s whole extent.
    unsafe { (*block).size = block_size + hdr_size + next_size };
    // SAFETY: relinking `block` past the absorbed `next`.
    unsafe { (*block).next = next_next };
}

/// Usable payload bytes of a live block: everything from `ptr` up to (but not
/// including) the trailing tail canary.
///
/// # Safety
///
/// `ptr` must be null or a live block pointer previously returned by `kmalloc` /
/// `kmalloc_aligned` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmalloc_usable_size(ptr: *mut u8) -> usize {
    // SAFETY: `raw_block` requires a live block pointer, which is this function's
    // caller contract.
    let Some((block, _off)) = (unsafe { raw_block(ptr) }) else {
        return 0;
    };
    // SAFETY: `block` is a live `HeapBlock` resolved by `raw_block`.
    let bsize = unsafe { (*block).size } as usize;
    let end = block as usize + core::mem::size_of::<HeapBlock>() + bsize;
    end.saturating_sub(ptr as usize).saturating_sub(4)
}

/// Grow or shrink a live block, keeping the same pointer whenever the block
/// already fits on its own or after absorbing its physically next free block.
///
/// # Safety
///
/// `ptr` must be null or a live block pointer from `kmalloc_aligned` (or
/// `kmalloc`) that has not been freed, and `align` a power of two — the same
/// alignment the block was allocated with.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krealloc_aligned(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    if ptr.is_null() {
        return kmalloc_aligned(new_size, align);
    }
    if new_size == 0 {
        // SAFETY: `ptr` is a live block (caller contract), so it may be freed.
        unsafe { kfree(ptr) };
        return core::ptr::null_mut();
    }
    // Same ceiling `kmalloc` enforces: a request the header cannot represent is
    // unservable.
    const MAX_BLOCK: usize = u32::MAX as usize - 64;
    if new_size > MAX_BLOCK {
        return core::ptr::null_mut();
    }
    let hdr_size = core::mem::size_of::<HeapBlock>() as u32;
    // SAFETY: `ptr` is a live block pointer (caller contract).
    let Some((block, off)) = (unsafe { raw_block(ptr) }) else {
        klog_msg(LOG_WARN, c"krealloc: pointer not in heap".as_ptr() as *const u8);
        return core::ptr::null_mut();
    };

    lock_acquire(HEAP_LOCK.as_ptr());
    // SAFETY: `block` is a live heap block and `HEAP_LOCK` is held, so its fields
    // are exclusive for the decision below.
    let cur_size = unsafe { (*block).size };
    // The free list is address-ordered and covers the window contiguously, so the
    // block's list `next` is its physical neighbour; only trust it when the
    // addresses really abut.
    // SAFETY: `(*block).next` of the locked live block.
    let next = unsafe { (*block).next };
    let mut next_free_size = None;
    if !next.is_null() && next as usize == block as usize + cur_size as usize {
        // SAFETY: `next` is the adjacent list node, under `HEAP_LOCK`.
        if unsafe { (*next).is_free } != 0 {
            // SAFETY: the adjacent free block's size, under `HEAP_LOCK`.
            next_free_size = Some(unsafe { (*next).size });
        }
    }
    // An in-place resize keeps the pointer, so it may only be used when the
    // pointer already satisfies the requested alignment.
    let decision = if (ptr as usize) % align.max(1) == 0 {
        plan(cur_size, off, hdr_size, next_free_size, new_size as u32)
    } else {
        Realloc::Move
    };
    match decision {
        Realloc::InPlace { block_size } => {
            // SAFETY: `block` is the locked live block and `block_size` is its
            // `required_block_size`, so the split and canary stay in bounds.
            unsafe { resize_block(block, block_size, hdr_size) };
            lock_release(HEAP_LOCK.as_ptr());
            ptr
        }
        Realloc::MergeNext { block_size } => {
            // SAFETY: `next` is the adjacent free block verified above; absorbing
            // it cannot race a concurrent free while `HEAP_LOCK` is held.
            unsafe { absorb_next(block, next, hdr_size) };
            // SAFETY: `block` is live and now spans `next`; `block_size` is its
            // `required_block_size`.
            unsafe { resize_block(block, block_size, hdr_size) };
            lock_release(HEAP_LOCK.as_ptr());
            ptr
        }
        Realloc::Move => {
            lock_release(HEAP_LOCK.as_ptr());
            let new = kmalloc_aligned(new_size, align);
            if new.is_null() {
                return core::ptr::null_mut();
            }
            // SAFETY: `ptr` is a live block (caller contract), so its usable size
            // is well-defined.
            let copy = (unsafe { kmalloc_usable_size(ptr) }).min(new_size);
            // SAFETY: `new` is a fresh block of at least `new_size` bytes and `ptr`
            // a live block of at least `copy`; the two do not overlap because `new`
            // was just carved from the same heap.
            unsafe { core::ptr::copy_nonoverlapping(ptr, new, copy) };
            // SAFETY: `ptr` is the caller's live block, now superseded by `new`.
            unsafe { kfree(ptr) };
            new
        }
    }
}