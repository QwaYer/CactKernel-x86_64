// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Compressed-page pool: the store behind both zram and zswap.
//!
//! One pool owns a heap slot table; each slot holds one 4 KiB page compressed
//! with the kernel zstd (`cact_zstd_compress`), or the page verbatim when
//! compression did not shrink it (measured: a random page compresses to 4106 B,
//! i.e. larger than the 4096 it came from).  Slot bookkeeping and the byte
//! budget live in [`super::zpool_alloc`] and are host-tested; this module adds
//! the blobs, the compression calls and the C ABI that zram (C) links against.
//!
//! Payload length is charged to the budget as stored, so a caller may set a
//! page capacity above `budget / PAGE_SIZE` to let compression hold more pages
//! than the raw budget would.

use core::ffi::c_void;

use crate::alloc::heap::{kfree, kmalloc};
use crate::ffi::{IrqSpinlock, PAGE_SIZE, ZpoolStats};
use crate::safe::{lock_acquire, lock_release};

use super::zpool_alloc::SlotAlloc;

const PAGE: usize = PAGE_SIZE as usize;

/// One pool slot: a compressed blob, or the raw page when it did not shrink.
#[repr(C)]
struct Slot {
    blob: *mut u8,
    /// Payload length in bytes.  `blob == null` marks a free slot; a live slot
    /// has `0 < len <= PAGE_SIZE`, with `len == PAGE_SIZE` meaning "stored raw".
    len: u32,
}

/// A compressed-page pool.  Handed to C as an opaque pointer; every field but
/// the lock is only ever touched under it.
struct Zpool {
    lock: IrqSpinlock,
    alloc: SlotAlloc,
    links: *mut u32,
    slots: *mut Slot,
    level: i32,
    pages_stored: u32,
    pages_loaded: u32,
    stored_bytes: u64,
}

unsafe extern "C" {
    fn cact_zstd_compress(
        level: i32,
        src: *const u8,
        src_size: usize,
        dst: *mut u8,
        dst_capacity: usize,
    ) -> usize;
    fn cact_zstd_compress_bound(src_size: usize) -> usize;
    fn cact_zstd_decompress(
        src: *const u8,
        src_size: usize,
        dst: *mut u8,
        dst_capacity: usize,
    ) -> usize;
}

/// Worst-case compressed size of one page.
fn zstd_bound() -> usize {
    // SAFETY: `cact_zstd_compress_bound` only computes a size from its argument.
    unsafe { cact_zstd_compress_bound(PAGE) }
}

/// Compress one page into `dst`; returns the compressed length, 0 on failure.
fn zstd_compress(level: i32, src: *const u8, dst: *mut u8, dst_cap: usize) -> usize {
    // SAFETY: the caller guarantees `src` is a live PAGE_SIZE page and `dst` is
    // writable for `dst_cap` bytes; the glue touches only those.
    unsafe { cact_zstd_compress(level, src, PAGE, dst, dst_cap) }
}

/// Decompress a `len`-byte frame into a full page; returns the length written.
fn zstd_decompress(src: *const u8, len: usize, dst: *mut u8) -> usize {
    // SAFETY: the caller guarantees `src` is readable for `len` bytes and `dst`
    // is writable for a full page.
    unsafe { cact_zstd_decompress(src, len, dst, PAGE) }
}

/// Allocate a pool with `capacity_pages` slots and a `budget_bytes` payload
/// budget; every page is compressed at `level`.  Returns null on any failure.
///
/// # Safety
///
/// The returned pointer must be treated as opaque and only passed back to the
/// `zpool_*` entry points; the caller must call [`zpool_destroy`] exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_create(
    capacity_pages: u32,
    budget_bytes: u64,
    level: i32,
) -> *mut c_void {
    if capacity_pages == 0 {
        return core::ptr::null_mut();
    }
    let cap = capacity_pages as usize;

    let pool_mem = kmalloc(core::mem::size_of::<Zpool>()) as *mut Zpool;
    if pool_mem.is_null() {
        return core::ptr::null_mut();
    }
    let links = kmalloc(cap * core::mem::size_of::<u32>()) as *mut u32;
    if links.is_null() {
        // SAFETY: `pool_mem` is a live heap block from kmalloc above.
        unsafe { kfree(pool_mem as *mut u8) };
        return core::ptr::null_mut();
    }
    let slots = kmalloc(cap * core::mem::size_of::<Slot>()) as *mut Slot;
    if slots.is_null() {
        // SAFETY: `links` is a live heap block from kmalloc above.
        unsafe { kfree(links as *mut u8) };
        // SAFETY: `pool_mem` is a live heap block from kmalloc above.
        unsafe { kfree(pool_mem as *mut u8) };
        return core::ptr::null_mut();
    }

    // A null blob marks a free slot, so the table starts zeroed.
    // SAFETY: `slots` is a fresh `cap`-entry block, so this writes it in bounds.
    unsafe { core::ptr::write_bytes(slots, 0, cap) };

    // SAFETY: `links` is a fresh `cap`-entry u32 block, so the slice is in bounds.
    let links_slice = unsafe { core::slice::from_raw_parts_mut(links, cap) };
    let mut alloc = SlotAlloc::new();
    alloc.init(links_slice, budget_bytes);

    // SAFETY: `pool_mem` is a fresh, still-uninitialised `Zpool` block and the
    // value written is self-contained (no aliasing to other live objects).
    unsafe {
        core::ptr::write(
            pool_mem,
            Zpool {
                lock: IrqSpinlock {
                    spin_locked: 0,
                    saved_flags: 0,
                },
                alloc,
                links,
                slots,
                level,
                pages_stored: 0,
                pages_loaded: 0,
                stored_bytes: 0,
            },
        )
    };
    // SAFETY: `pool_mem` now holds a live `Zpool`, so the address of its lock
    // field is valid; `addr_of_mut!` forms that pointer without a reference.
    let lock_ptr = unsafe { core::ptr::addr_of_mut!((*pool_mem).lock) };
    // SAFETY: `lock_ptr` is the pool's own lock field, and this is its only
    // initialisation.
    unsafe { crate::ffi::irq_spinlock_init(lock_ptr) };

    pool_mem as *mut c_void
}

/// Free a pool and every blob it still holds.
///
/// # Safety
///
/// `p` must be a pointer from [`zpool_create`] that has not been destroyed, and
/// no other user (zram device, zswap) may still hold it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_destroy(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live pool (non-null, and the caller owns its lifetime).
    let pool = unsafe { &mut *(p as *mut Zpool) };
    let cap = pool.alloc.capacity() as usize;

    // SAFETY: `pool.slots` points at `cap` slots, allocated in `zpool_create`.
    let slots = unsafe { core::slice::from_raw_parts_mut(pool.slots, cap) };
    for s in slots.iter_mut() {
        if !s.blob.is_null() {
            // SAFETY: a non-null `blob` is a live heap block from `zpool_store`.
            unsafe { kfree(s.blob) };
            s.blob = core::ptr::null_mut();
        }
    }

    // SAFETY: `links` was handed out by kmalloc in `zpool_create`.
    unsafe { kfree(pool.links as *mut u8) };
    // SAFETY: `slots` was handed out by kmalloc in `zpool_create`.
    unsafe { kfree(pool.slots as *mut u8) };
    // SAFETY: `p` was handed out by kmalloc in `zpool_create`.
    unsafe { kfree(p as *mut u8) };
}

/// Compress `page` into a new slot.  Returns 0 and writes the handle, or -1
/// when the pool is full, out of memory, or has no free budget.
///
/// # Safety
///
/// `p` must be a live pool pointer; `page` must point at a readable 4 KiB page;
/// `out_handle` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_store(p: *mut c_void, page: *const u8, out_handle: *mut u32) -> i32 {
    if p.is_null() || page.is_null() || out_handle.is_null() {
        return -1;
    }
    // SAFETY: `p` is a live pool (non-null checked) and no other reference to it
    // is held for this call, per the C ABI contract.
    let pool = unsafe { &mut *(p as *mut Zpool) };

    // Compress into a scratch first: the compressed length decides both the
    // blob size and whether we fall back to storing the page raw.
    let bound = zstd_bound();
    if bound == 0 {
        return -1;
    }
    let scratch = kmalloc(bound);
    if scratch.is_null() {
        return -1;
    }
    let clen = zstd_compress(pool.level, page, scratch, bound);
    let (payload, src) = if clen != 0 && clen < PAGE {
        (clen, scratch)
    } else {
        // Incompressible: store the page verbatim (the measured 1.00x case).
        (PAGE, page as *mut u8)
    };

    let blob = kmalloc(payload);
    if blob.is_null() {
        // SAFETY: `scratch` is a live heap block from kmalloc above.
        unsafe { kfree(scratch) };
        return -1;
    }
    // SAFETY: `blob` is a fresh `payload`-byte block and `src` is readable for
    // `payload` bytes (the scratch frame, or the caller's page).
    unsafe { core::ptr::copy_nonoverlapping(src, blob, payload) };
    // SAFETY: `scratch` is a live heap block from kmalloc above.
    unsafe { kfree(scratch) };

    // Reserve the slot.  The lock is taken only now: compression above is the
    // slow part and must not hold the pool spinlock.
    lock_acquire(core::ptr::addr_of_mut!(pool.lock));
    let cap = pool.alloc.capacity() as usize;
    // SAFETY: `pool.links` points at `cap` u32s (allocated in `zpool_create`).
    let links = unsafe { core::slice::from_raw_parts_mut(pool.links, cap) };
    let handle = match pool.alloc.alloc(links, payload as u64) {
        Ok(h) => h,
        Err(_) => {
            lock_release(core::ptr::addr_of_mut!(pool.lock));
            // SAFETY: `blob` is a live heap block from kmalloc above.
            unsafe { kfree(blob) };
            return -1;
        }
    };
    // SAFETY: `pool.slots` points at `cap` slots (allocated in `zpool_create`).
    let slots = unsafe { core::slice::from_raw_parts_mut(pool.slots, cap) };
    slots[handle as usize] = Slot {
        blob,
        len: payload as u32,
    };
    pool.pages_stored += 1;
    pool.stored_bytes += payload as u64;
    lock_release(core::ptr::addr_of_mut!(pool.lock));

    // SAFETY: `out_handle` is a valid writable u32 (checked non-null).
    unsafe { *out_handle = handle };
    0
}

/// Decompress the page behind `handle` into `page`.  Returns 0 or -1.  The slot
/// stays allocated; the caller must release it with [`zpool_free`].
///
/// # Safety
///
/// `p` must be a live pool pointer; `page` must point at a writable 4 KiB page.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_load(p: *mut c_void, handle: u32, page: *mut u8) -> i32 {
    if p.is_null() || page.is_null() {
        return -1;
    }
    // SAFETY: `p` is a live pool (non-null checked) and no other reference to it
    // is held for this call, per the C ABI contract.
    let pool = unsafe { &mut *(p as *mut Zpool) };
    let cap = pool.alloc.capacity();
    if handle >= cap {
        return -1;
    }

    // Copy the blob out under the lock, then decompress outside it: a
    // decompression is slow and must not hold the pool spinlock.
    let tmp = kmalloc(PAGE);
    if tmp.is_null() {
        return -1;
    }
    lock_acquire(core::ptr::addr_of_mut!(pool.lock));
    // SAFETY: `pool.slots` points at `cap` slots (allocated in `zpool_create`).
    let slots = unsafe { core::slice::from_raw_parts_mut(pool.slots, cap as usize) };
    let len = slots[handle as usize].len as usize;
    let src = slots[handle as usize].blob;
    if src.is_null() || len == 0 || len > PAGE {
        lock_release(core::ptr::addr_of_mut!(pool.lock));
        // SAFETY: `tmp` is a live heap block from kmalloc above.
        unsafe { kfree(tmp) };
        return -1;
    }
    // SAFETY: `src` is a live `len`-byte blob and `tmp` is a `PAGE`-byte block.
    unsafe { core::ptr::copy_nonoverlapping(src, tmp, len) };
    pool.pages_loaded += 1;
    lock_release(core::ptr::addr_of_mut!(pool.lock));

    let ok = if len == PAGE {
        // SAFETY: `tmp` holds a raw page and `page` is the destination page.
        unsafe { core::ptr::copy_nonoverlapping(tmp, page, PAGE) };
        true
    } else {
        zstd_decompress(tmp, len, page) == PAGE
    };
    // SAFETY: `tmp` is a live heap block from kmalloc above.
    unsafe { kfree(tmp) };

    if ok { 0 } else { -1 }
}

/// Release the slot behind `handle` (and its blob).  A no-op for an
/// out-of-range or already-free handle, so a double free cannot corrupt the
/// free list.
///
/// # Safety
///
/// `p` must be a live pool pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_free(p: *mut c_void, handle: u32) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live pool (non-null checked) and no other reference to it
    // is held for this call, per the C ABI contract.
    let pool = unsafe { &mut *(p as *mut Zpool) };
    let cap = pool.alloc.capacity();
    if handle >= cap {
        return;
    }

    lock_acquire(core::ptr::addr_of_mut!(pool.lock));
    // SAFETY: `pool.slots` points at `cap` slots (allocated in `zpool_create`).
    let slots = unsafe { core::slice::from_raw_parts_mut(pool.slots, cap as usize) };
    let blob = slots[handle as usize].blob;
    let len = slots[handle as usize].len as u64;
    if blob.is_null() {
        // Already free: the free-list cannot detect this, so guard here.
        lock_release(core::ptr::addr_of_mut!(pool.lock));
        return;
    }
    slots[handle as usize].blob = core::ptr::null_mut();
    slots[handle as usize].len = 0;
    // SAFETY: `pool.links` points at `cap` u32s (allocated in `zpool_create`).
    let links = unsafe { core::slice::from_raw_parts_mut(pool.links, cap as usize) };
    pool.alloc.free(links, handle, len);
    pool.stored_bytes = pool.stored_bytes.saturating_sub(len);
    lock_release(core::ptr::addr_of_mut!(pool.lock));

    // Free the blob outside the lock; it is no longer reachable from the pool.
    // SAFETY: `blob` is a live heap block from `zpool_store`.
    unsafe { kfree(blob) };
}

/// Fill `out` with a snapshot of the pool's accounting.  Returns 0 or -1.
///
/// # Safety
///
/// `p` must be a live pool pointer; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zpool_get_stats(p: *mut c_void, out: *mut ZpoolStats) -> i32 {
    if p.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: `p` is a live pool (non-null checked) and no other reference to it
    // is held for this call, per the C ABI contract.
    let pool = unsafe { &mut *(p as *mut Zpool) };

    lock_acquire(core::ptr::addr_of_mut!(pool.lock));
    let live = pool.alloc.live();
    let stats = ZpoolStats {
        capacity_pages: pool.alloc.capacity(),
        live_pages: live,
        pages_stored: pool.pages_stored,
        pages_loaded: pool.pages_loaded,
        budget_bytes: pool.alloc.budget_bytes(),
        stored_bytes: pool.stored_bytes,
        original_bytes: live as u64 * PAGE as u64,
    };
    lock_release(core::ptr::addr_of_mut!(pool.lock));

    // SAFETY: `out` is a valid writable `ZpoolStats` (checked non-null).
    unsafe { *out = stats };
    0
}
