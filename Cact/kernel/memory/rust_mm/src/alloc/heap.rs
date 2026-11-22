// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Intrusive free-list heap in the `[HEAP_START, HEAP_START+HEAP_SIZE)` window,
//! which starts where the PMM's boot reservation ends (see
//! `pmm::heap_start()` — the reservation covers the bootloader's module images).
//!
//! `kmalloc` / `kfree` are IRQ-spinlocked and back much of the kernel and Rust MM code.

use crate::alloc::heap_class::{class_of, CLASS_COUNT};
use crate::alloc::heap_stats::HeapAggregate;
use crate::alloc::realloc_plan::{plan, should_split, Realloc, MIN_FREE};
use crate::ffi::*;
use crate::pmm::{heap_end, heap_start};
use crate::safe::{KStatic, lock_acquire, lock_release, kprint_int, kprint_str, klog_msg};
use crate::vmm::paging::{p2v, v2p};

#[repr(C)]
struct HeapBlock {
    magic: u32,
    size: u32,
    is_free: u32,
    /// Address-order links within the block's region (doubly linked, so a block
    /// can prove it is a real list node in O(1) — see `is_block_start`).
    next: *mut HeapBlock,
    prev: *mut HeapBlock,
    /// Segregated-free-list links, meaningful only while the block is free.
    cprev: *mut HeapBlock,
    cnext: *mut HeapBlock,
}

static HEAP_LOCK: KStatic<IrqSpinlock> = KStatic::new(IrqSpinlock { spin_locked: 0, saved_flags: 0 });
const HEAP_TAIL_MAGIC: u32 = 0xC0DEC0DE;

/// Header size, i.e. the offset of a block's payload.
const HEAP_HDR: usize = core::mem::size_of::<HeapBlock>();

/// Segregated free lists — one head per power-of-two size class, indexed by
/// `class_of(size)`.  `kmalloc` takes a block off the smallest non-empty class
/// that fits (O(1) instead of a whole-heap best-fit scan), and `kfree` puts it
/// back through the block's own `cprev`/`cnext` header links.
static FREE_CLASSES: KStatic<[*mut HeapBlock; CLASS_COUNT]> =
    KStatic::new([core::ptr::null_mut(); CLASS_COUNT]);

/// Push a free `block` onto the head of its size class list.  O(1).
///
/// # Safety
///
/// `block` must be a live free block that is not already on a class list.
unsafe fn class_push(block: *mut HeapBlock) {
    // SAFETY: `block` is a live free block, so reading its size is in bounds.
    let size = unsafe { (*block).size };
    let c = class_of(size);
    // SAFETY: `FREE_CLASSES` head array, mutated under `HEAP_LOCK`.
    let classes = unsafe { KStatic::get_mut(FREE_CLASSES.as_ptr()) };
    let head = classes[c];
    {
        // SAFETY: the block's own header fields; `block` is a live free block.
        let b = unsafe { &mut *block };
        b.cprev = core::ptr::null_mut();
        b.cnext = head;
    }
    if !head.is_null() {
        // SAFETY: `head` is a live free block of the same class; relink it back.
        unsafe { (*head).cprev = block };
    }
    classes[c] = block;
}

/// Unlink a free `block` from its size class list.  O(1).
///
/// # Safety
///
/// `block` must be a live free block that is currently on its class list.
unsafe fn class_remove(block: *mut HeapBlock) {
    // SAFETY: reading the live free block's size.
    let c = class_of(unsafe { (*block).size });
    // SAFETY: the block's own header link fields.
    let prev = unsafe { (*block).cprev };
    // SAFETY: the block's own header link fields.
    let next = unsafe { (*block).cnext };
    if prev.is_null() {
        // SAFETY: `block` was the class head; make its successor the new head.
        (unsafe { KStatic::get_mut(FREE_CLASSES.as_ptr()) })[c] = next;
    } else {
        // SAFETY: `prev` is a live free block of the same class; relink it forward.
        unsafe { (*prev).cnext = next };
    }
    if !next.is_null() {
        // SAFETY: `next` is a live free block of the same class; fix its prev link.
        unsafe { (*next).cprev = prev };
    }
}

/// One heap region: a contiguous physical range with its own address-ordered
/// block list.  Regions are independent, so a block's physical successor is
/// always inside the same region — the last block of a region has `next == null`
/// and never coalesces into the next region.
#[repr(C)]
#[derive(Clone, Copy)]
struct HeapRegion {
    base: u32,
    end: u32,
    head: *mut HeapBlock,
    next: *mut HeapRegion,
}

/// Maximum number of regions: the boot window (region 0) plus the ones
/// `grow_heap` adds on demand.
const MAX_REGIONS: usize = 8;

/// Region descriptors, handed out in order by `grow_heap` and never freed (the
/// heap does not shrink).  A descriptor is fully filled in before it is linked.
static REGION_DESCS: KStatic<[HeapRegion; MAX_REGIONS]> = KStatic::new(
    [HeapRegion {
        base: 0,
        end: 0,
        head: core::ptr::null_mut(),
        next: core::ptr::null_mut(),
    };
        MAX_REGIONS],
);
/// Head of the region list (region 0 first).
static REGIONS: KStatic<*mut HeapRegion> = KStatic::new(core::ptr::null_mut());
/// How many descriptors have been handed out.
static REGION_USED: KStatic<usize> = KStatic::new(0);

/// VA of the first block of the region containing `ptr`, or null when `ptr` lies
/// outside every region.  Regions are *physical* ranges, so the check translates
/// through the direct map first.
///
/// Safe to call without `HEAP_LOCK`: the list only grows, and a region is fully
/// initialised before it is linked, so a concurrent `grow_heap` cannot hide an
/// existing region or expose a half-built one.
fn region_head_of(ptr: *const u8) -> *mut HeapBlock {
    let phys = v2p(ptr);
    // SAFETY: `REGIONS` is the published list head.
    let mut r = unsafe { *KStatic::get_mut(REGIONS.as_ptr()) };
    while !r.is_null() {
        // SAFETY: `r` is a published region descriptor.
        let (base, end) = unsafe { ((*r).base as u64, (*r).end as u64) };
        if phys >= base && phys < end {
            // SAFETY: `(*r).head` of a published descriptor.
            return unsafe { (*r).head };
        }
        // SAFETY: `(*r).next` of a published descriptor.
        r = unsafe { (*r).next };
    }
    core::ptr::null_mut()
}

/// True when `block` is exactly the start of a live heap block: it lies in a
/// region, carries the header magic, and is a real node of that region's
/// address-ordered list — its predecessor links back to it.
///
/// The predecessor round-trip is the membership test `free` uses now that the
/// list is not walked.  For a pointer into the middle of a block, or one from
/// another allocator, the header bytes are unrelated data and an 8-byte
/// `prev.next == block` match does not hold.  It is O(1) and self-contained: it
/// never depends on a *neighbour's* payload or canary.
fn is_block_start(block: *const HeapBlock) -> bool {
    let head = region_head_of(block as *const u8);
    if head.is_null() {
        return false;
    }
    // SAFETY: `block` is inside a published region; read its header magic.
    if unsafe { (*block).magic } != HEAP_MAGIC {
        return false;
    }
    if block == head {
        // The region's first block has no predecessor.
        // SAFETY: `(*block).prev` of a block inside a region.
        return unsafe { (*block).prev.is_null() };
    }
    // SAFETY: `(*block).prev` of a block inside a region.
    let prev = unsafe { (*block).prev };
    if prev.is_null() {
        return false;
    }
    // SAFETY: `prev` is a candidate predecessor; only its `next` field is read.
    unsafe { (*prev).next == block as *mut HeapBlock }
}

/// Pop the smallest free block that can hold `size`, or null.
///
/// The `FREE_CLASSES` borrow is taken and released here, so a caller never holds
/// it across a call that also touches the array.
///
/// A class is a power-of-two *upper* bound (`class_of` is `ceil(log2)`), so the
/// request's own class can hold blocks smaller than the request: a 40-byte block
/// and a 56-byte request both map to class 6, and the head may be the smaller of
/// the two.  A block that does not fit is left on its list and walked past; the
/// first block that fits is unlinked in O(1).  Only the request's starting class
/// can need that scan — every later class holds sizes strictly above the request.
fn take_block(size: u32) -> *mut HeapBlock {
    // SAFETY: `FREE_CLASSES` head array, mutated under `HEAP_LOCK` (held by the
    // caller).
    let classes = unsafe { KStatic::get_mut(FREE_CLASSES.as_ptr()) };
    let mut i = class_of(size);
    while i < CLASS_COUNT {
        let mut block = classes[i];
        while !block.is_null() {
            // SAFETY: `block` is a node of class `i`, so its header is live.
            let next = unsafe { (*block).cnext };
            // SAFETY: `(*block).size` of that same live free block.
            if unsafe { (*block).size } >= size {
                // Unlink the chosen block, which need not be the class head.
                // SAFETY: `(*block).cprev` of the live free block being removed.
                let prev = unsafe { (*block).cprev };
                if prev.is_null() {
                    classes[i] = next;
                } else {
                    // SAFETY: `prev` is the live block before `block` in class `i`.
                    unsafe { (*prev).cnext = next };
                }
                if !next.is_null() {
                    // SAFETY: `next` is the live block after `block` in class `i`.
                    unsafe { (*next).cprev = prev };
                }
                return block;
            }
            // Too small for this request: leave it on its list for a smaller one.
            block = next;
        }
        i += 1;
    }
    core::ptr::null_mut()
}

/// Add a region so the heap can serve `need` bytes: allocate a contiguous run of
/// frames from the PMM and link it as a region with one free block.
///
/// Called with `HEAP_LOCK` held.  `kalloc_contig` only takes `PAGE_LOCK`, and
/// nothing takes those two the other way, so the nesting is safe.  Returns false
/// when no run is free or the region budget is exhausted; the caller then fails
/// the allocation exactly as before.
fn grow_heap(need: usize) -> bool {
    /// Smallest region to add, so one growth covers more than the one request.
    const MIN_REGION_FRAMES: usize = 256; // 1 MiB
    /// Largest region to add; a request beyond this cannot be served in one region.
    const MAX_REGION_FRAMES: usize = 1 << 14; // 64 MiB

    // SAFETY: `REGION_USED` read under `HEAP_LOCK`.
    let idx = unsafe { *KStatic::get_mut(REGION_USED.as_ptr()) };
    if idx >= MAX_REGIONS {
        return false;
    }
    let want = (HEAP_HDR + need).div_ceil(PAGE_SIZE as usize);
    let frames = want.clamp(MIN_REGION_FRAMES, MAX_REGION_FRAMES);
    if want > MAX_REGION_FRAMES {
        return false;
    }
    // SAFETY: called under `HEAP_LOCK`; `kalloc_contig` takes only `PAGE_LOCK`.
    let base_va = crate::pmm::kalloc_contig(frames as u32);
    if base_va.is_null() {
        return false;
    }
    let phys = v2p(base_va) as u32;
    let end = phys + (frames as u32) * PAGE_SIZE;

    // SAFETY: `REGION_DESCS` is only written under `HEAP_LOCK` (held here).
    let descs = unsafe { KStatic::get_mut(REGION_DESCS.as_ptr()) };
    let r = &mut descs[idx];
    r.base = phys;
    r.end = end;
    let head = base_va as *mut HeapBlock;
    r.head = head;
    // SAFETY: `REGIONS` list head read under `HEAP_LOCK`; the new region is pushed
    // at the head.
    r.next = unsafe { *KStatic::get_mut(REGIONS.as_ptr()) };

    // SAFETY: `head` is the start of the fresh run; its single block covers the
    // whole region.
    let head_ref = unsafe { &mut *head };
    head_ref.magic = HEAP_MAGIC;
    head_ref.size = (frames as u32) * PAGE_SIZE - HEAP_HDR as u32;
    head_ref.is_free = 1;
    head_ref.next = core::ptr::null_mut();
    head_ref.prev = core::ptr::null_mut();
    // SAFETY: publishing the fully initialised region as the new list head.
    unsafe { *KStatic::get_mut(REGIONS.as_ptr()) = r as *mut HeapRegion };
    // SAFETY: the descriptor is now in use.
    unsafe { *KStatic::get_mut(REGION_USED.as_ptr()) = idx + 1 };
    // SAFETY: the new block is a live free block, not yet on a class list.
    unsafe { class_push(head) };
    true
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

    // Region 0 is the boot window; later regions are added by `grow_heap`.
    // SAFETY: single-threaded boot; `REGION_DESCS` is untouched before this.
    let descs = unsafe { KStatic::get_mut(REGION_DESCS.as_ptr()) };
    let r0 = &mut descs[0];
    r0.base = start;
    r0.end = end;
    r0.next = core::ptr::null_mut();
    // SAFETY: the window start is reached through the direct map during
    // single-threaded boot; this is its only reference yet.
    let head = p2v(start as u64) as *mut HeapBlock;
    r0.head = head;
    // SAFETY: `head` is the freshly seeded first `HeapBlock` of the region, large
    // enough for the header being written.
    let head_ref = unsafe { &mut *head };
    head_ref.magic = HEAP_MAGIC;
    head_ref.size = window - core::mem::size_of::<HeapBlock>() as u32;
    head_ref.is_free = 1;
    head_ref.next = core::ptr::null_mut();
    head_ref.prev = core::ptr::null_mut();
    // SAFETY: publishing region 0 as the list head, during single-threaded boot.
    unsafe { *KStatic::get_mut(REGIONS.as_ptr()) = r0 as *mut HeapRegion };
    // SAFETY: one descriptor is now in use.
    unsafe { *KStatic::get_mut(REGION_USED.as_ptr()) = 1 };
    // SAFETY: the initial block is the whole window and free; nothing can race
    // this single-threaded init.
    unsafe { class_push(head) };
}

/// Allocate `size` bytes from the heap window.
///
/// The heap window is reached through the **direct map**, so the free list and
/// every `HeapBlock` link hold direct-map VAs: the whole allocator works in one
/// address space, and the caller gets exactly the block address.
///
/// This is the **heap-only** entry point.  The C-visible `kmalloc` is the
/// dispatcher in this module, which serves small requests from the slab caches.
pub extern "C" fn kmalloc_raw(size: usize) -> *mut u8 {
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

    // Take the head of the smallest non-empty class that can hold the request,
    // instead of scanning every block for a best fit.  If nothing fits, try to
    // add a region and look once more.
    let mut block = take_block(size);
    if block.is_null() && grow_heap(size as usize) {
        block = take_block(size);
    }
    if block.is_null() {
        lock_release(HEAP_LOCK.as_ptr());
        klog_msg(LOG_WARN, c"heap out of memory".as_ptr() as *const u8);
        return core::ptr::null_mut();
    }

    // SAFETY: `block` is the live free block popped from its class list.
    let block_size = unsafe { (*block).size };
    // SAFETY: marking the chosen block in use, under `HEAP_LOCK`.
    unsafe { (*block).is_free = 0 };

    // Split off the remainder, which goes back on its own class list.
    if block_size >= size + hdr_size + MIN_FREE {
        // SAFETY: the remainder lies `hdr_size + size` bytes into `block`, which the
        // size check above proved is still inside `block`'s own extent.
        let next_block =
            unsafe { (block as *mut u8).add(hdr_size as usize + size as usize) as *mut HeapBlock };
        // SAFETY: `(*block).next` is the block's address-list link, under `HEAP_LOCK`.
        let next_next = unsafe { (*block).next };
        // SAFETY: `next_block` is the freshly-carved sub-block inside `block`.
        let next_ref = unsafe { &mut *next_block };
        next_ref.magic = HEAP_MAGIC;
        next_ref.size = block_size - size - hdr_size;
        next_ref.is_free = 1;
        next_ref.next = next_next;
        next_ref.prev = block;
        if !next_next.is_null() {
            // SAFETY: `next_next` is the block that followed `block`; keep its back
            // link pointing at the remainder now inserted before it.
            unsafe { (*next_next).prev = next_block };
        }
        // SAFETY: sizing `block` down to the request, under `HEAP_LOCK`.
        unsafe { (*block).size = size };
        // SAFETY: linking the free remainder right after `block` in the address list.
        unsafe { (*block).next = next_block };
        // SAFETY: `next_block` is a live free block, not yet on a class list.
        unsafe { class_push(next_block) };
    }

    // SAFETY: `user_ptr` is `block + hdr_size`, inside the block whose size was just
    // fixed (every block is at least `hdr_size + 4` bytes).
    let user_ptr = unsafe { (block as *mut u8).add(hdr_size as usize) };
    // SAFETY: `(*block).size` of the block this call owns under `HEAP_LOCK`.
    let block_size = unsafe { (*block).size };
    // SAFETY: the tail canary lives in the last four bytes of the block.
    let tail = unsafe { user_ptr.add(block_size as usize - 4) as *mut u32 };
    // SAFETY: writing the tail canary into the reserved slot.
    unsafe { *tail = HEAP_TAIL_MAGIC };
    lock_release(HEAP_LOCK.as_ptr());
    // The heap lives in direct-map VAs, so `user_ptr` is already the caller's address.
    user_ptr
}

/// Heap-only aligned allocation: `kmalloc_raw` plus the back-pointer scheme
/// `kfree_raw` reverses.  Used for alignments the slab objects cannot give.
pub extern "C" fn kmalloc_aligned_raw(size: usize, align: usize) -> *mut u8 {
    let align = if align < 4 { 4 } else { align };
    let raw = kmalloc_raw(size + align + 4);
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Align in the direct-map VA the caller will use; the direct map is far
    // coarser (2 MiB) than any heap alignment, so the frame is aligned too.  The
    // four bytes below `aligned` hold the *physical* address of the raw block —
    // `kfree_raw` reads it back and re-derives the VA through the direct map.
    let raw_phys = v2p(raw) as u32;
    let addr = (raw as usize) + 4;
    let aligned = (addr + align - 1) & !(align - 1);
    // SAFETY: `kmalloc_aligned_raw` reserved four extra bytes below `aligned` for
    // exactly this back-pointer; `aligned` is inside the block just returned by
    // `kmalloc_raw`, which lives in the heap window.
    unsafe { *((aligned - 4) as *mut u32) = raw_phys; }
    aligned as *mut u8
}

/// # Safety
///
/// `ptr` must be null or a **virtual** address (direct-map, as the heap
/// allocators hand out) of a block previously returned by them and not already
/// freed, and it must stay valid for the duration of the call.
///
/// The free list is held in direct-map VAs, so the walk below works on the
/// pointer itself; only the `kmalloc_aligned_raw` back-pointer is stored
/// physically and has to be translated on the way in.
pub unsafe extern "C" fn kfree_raw(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let hdr_size = core::mem::size_of::<HeapBlock>() as usize;

    // Normal heap block?
    // SAFETY: `kfree` may only be called with a pointer from `kmalloc`, so
    // stepping back by the header size stays inside the same heap block; the
    // result is validated before any dereference of the block's payload.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    if is_block_start(block) {
        kfree_impl(ptr);
        return;
    }

    // Linux-style fallback: kmalloc_aligned stores the raw block's *physical*
    // address 4 bytes below the aligned VA (see `kmalloc_aligned`); the VA of
    // that slot is `p2v(v2p(ptr) - 4)`.
    // SAFETY: aligned-allocation fallback — the slot holds the raw block's
    // physical address, recorded at allocation time; the VA is validated by
    // `is_block_start` before any dereference of the block itself.
    let raw_phys = unsafe { *(p2v(v2p(ptr) - 4) as *const u32) };
    let raw = p2v(raw_phys as u64) as *mut u8;
    // SAFETY: stepping back by the header size from the raw VA recorded at
    // allocation time.
    let rblock = unsafe { raw.sub(hdr_size) } as *mut HeapBlock;
    if is_block_start(rblock) {
        kfree_impl(raw);
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
    // step-back stays in the same block and `HEAP_LOCK` is already held.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    // Re-validate under the lock: `block` must be a real block start, so a stray
    // pointer (middle of a block, another allocator, garbage) is rejected.
    if !is_block_start(block) {
        klog_msg(LOG_WARN, c"kfree ignored for unknown block".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // The double-free guard is what catches a second free: a freed block's own
    // tail canary is stale (only allocations refresh it), so the canary test below
    // would not screen a double free.
    // SAFETY: `(*block).is_free` of the live locked block.
    if unsafe { (*block).is_free } != 0 {
        klog_msg(LOG_WARN, c"double free ignored".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // SAFETY: `(*block).size` of the live locked block.
    let bsize = unsafe { (*block).size } as usize;
    if bsize < 4 {
        kprint_str(c"[FATAL] kfree: block too small for tail canary\n".as_ptr() as *const u8);
        klog_msg(LOG_FAIL, c"heap block too small for canary".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }
    // SAFETY: `bsize >= 4`, so `ptr + bsize - 4` is the block's tail canary slot.
    let tail = unsafe { ptr.add(bsize - 4) as *mut u32 };
    // SAFETY: reading the tail canary slot computed above, inside the block.
    if unsafe { *tail } != HEAP_TAIL_MAGIC {
        kprint_str(c"[FATAL] kfree: tail canary corrupted (buffer overflow)\n".as_ptr() as *const u8);
        klog_msg(LOG_FAIL, c"heap tail canary corrupted".as_ptr() as *const u8);
        lock_release(HEAP_LOCK.as_ptr());
        return;
    }

    // Coalesce forward with the physically next block.  The address-ordered list
    // names it as `(*block).next`, and the window is contiguous, so it lies exactly
    // one header plus `bsize` later; that check also keeps a corrupted size from
    // reading past the window.  (Backward coalescing would need a predecessor link
    // the design does not carry; a freed block merges only into its successor.)
    // SAFETY: `(*block).next` of the live locked block.
    let succ = unsafe { (*block).next };
    if !succ.is_null() && succ as usize == block as usize + hdr_size + bsize {
        // SAFETY: `succ` is the adjacent live block, read under `HEAP_LOCK`.
        let succ_magic = unsafe { (*succ).magic };
        // SAFETY: `(*succ).is_free` of the adjacent live block.
        let succ_free = unsafe { (*succ).is_free };
        if succ_magic == HEAP_MAGIC && succ_free != 0 {
            // SAFETY: `succ` is a live free block, so it is on its class list.
            unsafe { class_remove(succ) };
            // SAFETY: `(*succ).size` of the live free block.
            let succ_size = unsafe { (*succ).size };
            // SAFETY: `(*succ).next` of the live free block.
            let succ_next = unsafe { (*succ).next };
            // SAFETY: absorbing `succ` into `block`, under `HEAP_LOCK`.
            unsafe { (*block).size = bsize as u32 + hdr_size as u32 + succ_size };
            // SAFETY: relinking `block` past the absorbed `succ`.
            unsafe { (*block).next = succ_next };
            if !succ_next.is_null() {
                // SAFETY: `succ_next` followed `succ`; its back link now points at
                // `block`, which absorbed `succ`.
                unsafe { (*succ_next).prev = block };
            }
            // SAFETY: retiring the absorbed node's magic.
            unsafe { (*succ).magic = 0 };
        }
    }

    // SAFETY: releasing `block` back to the heap, under `HEAP_LOCK`.
    unsafe { (*block).is_free = 1 };
    // SAFETY: `block` is a live free block that is not on any class list yet.
    unsafe { class_push(block) };
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
    /// Number of heap regions (the boot window plus any `grow_heap` added).
    pub regions: u32,
}

/// Walk every region's block list once and fold it into a [`HeapStats`].  Each
/// region's list is address-ordered and every block carries its own size, so one
/// pass gives both the totals and the fragmentation shape.
#[unsafe(no_mangle)]
pub extern "C" fn heap_get_stats() -> HeapStats {
    let mut agg = HeapAggregate::new();
    let mut regions: u32 = 0;
    lock_acquire(HEAP_LOCK.as_ptr());
    // SAFETY: `REGIONS` list head read under `HEAP_LOCK`.
    let mut r = unsafe { *KStatic::get_mut(REGIONS.as_ptr()) };
    while !r.is_null() {
        regions = regions.saturating_add(1);
        // SAFETY: `(*r).head` of a live region descriptor, under `HEAP_LOCK`.
        let mut current = unsafe { (*r).head };
        while !current.is_null() {
            // SAFETY: `(*current).size` of a heap-list node, under `HEAP_LOCK`.
            let size = unsafe { (*current).size };
            // SAFETY: `(*current).is_free` of the same node.
            let is_free = unsafe { (*current).is_free } != 0;
            agg.add(size, is_free);
            // SAFETY: following `(*current).next` in the locked region list.
            current = unsafe { (*current).next };
        }
        // SAFETY: `(*r).next` of a live region descriptor, under `HEAP_LOCK`.
        r = unsafe { (*r).next };
    }
    lock_release(HEAP_LOCK.as_ptr());
    HeapStats {
        free_bytes: agg.free_bytes,
        used_bytes: agg.used_bytes,
        free_blocks: agg.free_blocks,
        total_blocks: agg.total_blocks,
        largest_free: agg.largest_free,
        regions,
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
    kprint_str(c" regions=".as_ptr() as *const u8);
    kprint_int(s.regions as i32);
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
    // the header size stays inside the same block; the result is validated
    // before the header is read.
    let block = unsafe { ptr.sub(hdr_size) } as *mut HeapBlock;
    if is_block_start(block) {
        return Some((block, hdr_size as u32));
    }
    // Aligned block: `kmalloc_aligned` recorded the raw block's *physical*
    // address four bytes below the aligned pointer.
    // SAFETY: aligned-allocation fallback — the slot is read at the VA the
    // allocator wrote at allocation time, translated back through the direct map.
    let raw_phys = unsafe { *(p2v(v2p(ptr) - 4) as *const u32) };
    let raw = p2v(raw_phys as u64) as *mut u8;
    // SAFETY: stepping back by the header size from the raw VA recorded at
    // allocation time.
    let rblock = unsafe { raw.sub(hdr_size) } as *mut HeapBlock;
    if is_block_start(rblock) {
        return Some((rblock, (ptr as usize - raw as usize) as u32));
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
        tail_ref.prev = block;
        if !tail_next.is_null() {
            // SAFETY: `tail_next` followed `block`; its back link now points at the
            // tail inserted before it.
            unsafe { (*tail_next).prev = tail };
        }
        // SAFETY: sizing `block` down to its leading part, under `HEAP_LOCK`.
        unsafe { (*block).size = new_size };
        // SAFETY: linking the just-carved free tail after `block`.
        unsafe { (*block).next = tail };
        // SAFETY: `tail` is a live free block, not yet on a class list.
        unsafe { class_push(tail) };
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
    // SAFETY: `next` is a live free block, so it is on its class list.
    unsafe { class_remove(next) };
    // SAFETY: clearing the absorbed node's magic retires it as a list node.
    unsafe { (*next).magic = 0 };
    // SAFETY: widening `block` over `next`'s whole extent.
    unsafe { (*block).size = block_size + hdr_size + next_size };
    // SAFETY: relinking `block` past the absorbed `next`.
    unsafe { (*block).next = next_next };
    if !next_next.is_null() {
        // SAFETY: `next_next` followed `next`; its back link now points at `block`,
        // which absorbed `next`.
        unsafe { (*next_next).prev = block };
    }
}

/// Usable payload bytes of a live block: everything from `ptr` up to (but not
/// including) the trailing tail canary.
///
/// # Safety
///
/// `ptr` must be null or a live **heap** block pointer previously returned by the
/// heap allocators (`kmalloc_raw` / `kmalloc_aligned_raw`) and not yet freed.
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

/// Grow or shrink a live **heap** block, keeping the same pointer whenever the
/// block already fits on its own or after absorbing its physically next free
/// block.  Slab objects are handled by the `krealloc_aligned` dispatcher above.
///
/// # Safety
///
/// `ptr` must be null or a live heap block from the heap allocators that has not
/// been freed, and `align` a power of two — the same alignment the block was
/// allocated with.
pub unsafe extern "C" fn krealloc_aligned_raw(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    if ptr.is_null() {
        return kmalloc_aligned_raw(new_size, align);
    }
    if new_size == 0 {
        // SAFETY: `ptr` is a live block (caller contract), so it may be freed.
        unsafe { kfree_raw(ptr) };
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
            let new = kmalloc_aligned_raw(new_size, align);
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
            unsafe { kfree_raw(ptr) };
            new
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatchers — the allocator the rest of the kernel (and C) calls.
//
// Small, 8-aligned requests come from the slab size caches; everything else
// comes from the heap.  Freeing is uniform: `kfree` asks the slab allocator
// first (a page header magic tells a slab object from a heap block) and falls
// back to the heap, so a block is freed correctly whatever allocated it.
// ---------------------------------------------------------------------------

/// Allocate `size` bytes: from a slab size cache when the request fits one, from
/// the heap otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    if size <= SLAB_MAX_OBJ_SIZE as usize {
        crate::alloc::slab::slab_kmalloc(size)
    } else {
        kmalloc_raw(size)
    }
}

/// Allocate `size` bytes aligned to `align`: the slab caches and heap blocks are
/// all 8-aligned, so a request at or below that goes through `kmalloc`; a larger
/// alignment needs the heap's back-pointer scheme.
#[unsafe(no_mangle)]
pub extern "C" fn kmalloc_aligned(size: usize, align: usize) -> *mut u8 {
    if align <= 8 {
        kmalloc(size)
    } else {
        kmalloc_aligned_raw(size, align)
    }
}

/// Free a block from `kmalloc` / `kmalloc_aligned` (any size or alignment).
///
/// # Safety
///
/// `ptr` must be null or a live block from those and not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kfree(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    // A slab object's page carries `SLAB_MAGIC` at its base; anything else is a
    // heap block, aligned or not.
    if crate::alloc::slab::slab_try_free(ptr) {
        return;
    }
    // SAFETY: `ptr` is a live block (caller contract) and not a slab object.
    unsafe { kfree_raw(ptr) };
}

/// Grow or shrink a live block, keeping the same pointer whenever the block
/// already fits — on its own, after absorbing the heap's next free block, or (for
/// a slab object) while it still fits its size class.
///
/// # Safety
///
/// `ptr` must be null or a live block from `kmalloc` / `kmalloc_aligned` that has
/// not been freed, and `align` a power of two — the alignment it was allocated
/// with.
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
    // SAFETY: `ptr` is a live block (caller contract).
    let obj_size = crate::alloc::slab::slab_object_size(ptr);
    if obj_size > 0 {
        // Slab object: a same-or-smaller 8-aligned request stays put; anything
        // else needs a fresh block and a copy of the live bytes.
        if new_size <= obj_size as usize && align <= 8 {
            return ptr;
        }
        let new = kmalloc_aligned(new_size, align);
        if new.is_null() {
            return core::ptr::null_mut();
        }
        let copy = (obj_size as usize).min(new_size);
        // SAFETY: `new` is a fresh block of at least `new_size` bytes and `ptr` a
        // live `obj_size`-byte object; the two do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(ptr, new, copy) };
        // SAFETY: `ptr` is the caller's live block, now superseded by `new`.
        unsafe { kfree(ptr) };
        return new;
    }
    // Heap block: the heap resize handles in-place grow/shrink itself.
    // SAFETY: `ptr` is a live heap block (caller contract).
    unsafe { krealloc_aligned_raw(ptr, new_size, align) }
}