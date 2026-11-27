// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! zswap: a compressed cache in front of the swap backing device.
//!
//! When a page is evicted, zswap first tries to hold it compressed in a zpool;
//! only a page the pool cannot take goes on to the swap device.  A pooled PTE
//! carries `PAGE_ZSWAP` alongside `PAGE_SWAPPED` and stores the pool handle in
//! the frame field, so fault-in knows to read the pool instead of the device
//! (see `fault::swap_pte`).  With `writeback` on, a full pool first migrates one
//! of its own pages to the device, freeing a slot, and the store is retried.
//!
//! The pool is created on the first [`zswap_enable`] and **never freed**:
//! [`zswap_disable`] only stops new stores, and pooled pages drain back through
//! fault-in.  That keeps the eviction/fault hot paths free of any lifetime lock
//! — the pool pointer is written once and stays valid.  A later enable may still
//! *grow* the pool (raising the limit) and re-level it; shrinking is refused,
//! since handles live in page tables and must stay valid.

use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use crate::comp::zpool::{
    zpool_create, zpool_free, zpool_get_stats, zpool_grow, zpool_load, zpool_set_level,
    zpool_store,
};
use crate::ffi::*;
use crate::safe::{KStatic, flush_tlb, klog_msg, lock_acquire, lock_release};

use super::swap_pte;

/// Negated errno codes `zswap_enable` hands back to the ioctl layer.
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;

/// The pool, set exactly once (under `G_INIT_LOCK` in [`zswap_enable`]) and
/// never freed; an unlocked read is therefore sound, like `swap`'s own flags.
static G_POOL: KStatic<*mut c_void> = KStatic::new(core::ptr::null_mut());
static G_INIT_LOCK: KStatic<IrqSpinlock> = KStatic::new(IrqSpinlock::new());
/// Serialises first-use initialisation of `G_INIT_LOCK` itself.
static G_INIT_DONE: AtomicI32 = AtomicI32::new(0);

static G_ENABLED: AtomicI32 = AtomicI32::new(0);
static G_WRITEBACK: AtomicI32 = AtomicI32::new(0);
static G_LEVEL: AtomicI32 = AtomicI32::new(0);
static G_STORES: AtomicU32 = AtomicU32::new(0);
static G_STORE_FAIL: AtomicU32 = AtomicU32::new(0);
static G_LOADS: AtomicU32 = AtomicU32::new(0);
static G_WRITEBACKS: AtomicU32 = AtomicU32::new(0);
/// Clock hand for the writeback scan (see [`zswap_writeback_one`]).
static G_WB_CLOCK: AtomicU32 = AtomicU32::new(USER_SPACE_START);
/// Scratch frame reserved for writeback (see [`zswap_writeback_one`]).
///
/// Writeback decompresses a pooled page into a frame before handing it to the
/// device, but it runs *inside* eviction — which happens only once the PMM has
/// no free frame left and has suppressed its own reclaim (`EVICT_BUSY`) — so
/// `kalloc` can never supply one there.  One frame is therefore taken at
/// `zswap_enable(writeback=1)` and kept for the life of the kernel (the pool it
/// serves is never freed either).  Used serially: only one eviction runs at a
/// time, so only one writeback does.
static G_WB_FRAME: KStatic<*mut u8> = KStatic::new(core::ptr::null_mut());

/// Read the pool pointer (see the `G_POOL` note for why this needs no lock).
fn pool() -> *mut c_void {
    // SAFETY: `G_POOL` is written once and the pool it names is never freed, so
    // an unlocked read cannot observe a dangling value.
    let p = unsafe { *KStatic::get_mut(G_POOL.as_ptr()) };
    p
}

fn init_lock() {
    if G_INIT_DONE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        irq_spinlock_init(G_INIT_LOCK.as_ptr());
    }
}

/// Initialise the module-level lock.  Called from `swap_init` during boot so
/// the first `zswap_enable` (from /dev/zmem) never races an uninitialised lock.
pub fn zswap_early_init() {
    init_lock();
}

pub fn zswap_is_enabled() -> bool {
    G_ENABLED.load(Ordering::Relaxed) != 0
}

#[unsafe(no_mangle)]
pub extern "C" fn zswap_is_enabled_ffi() -> i32 {
    G_ENABLED.load(Ordering::Relaxed)
}

/// Load pool entry `handle` into the frame at physical `phys`, keeping the
/// entry allocated.  Returns true on success.
fn pool_load_keep(p: *mut c_void, handle: u32, frame: *mut u8) -> bool {
    // SAFETY: `p` is the live pool, `frame` a writable 4 KiB frame, and the
    // handle came from this pool.
    unsafe { zpool_load(p, handle, frame) == 0 }
}

/// Compress the frame at physical `phys` into the pool.  Returns the pool
/// handle, or `None` when zswap is off or the pool is full / out of memory.
///
/// # Safety contract
///
/// `phys` must be a page-aligned physical frame address of a live frame the
/// caller is about to evict.
pub fn zswap_store(phys: u64) -> Option<u32> {
    if !zswap_is_enabled() {
        return None;
    }
    let p = pool();
    if p.is_null() {
        return None;
    }
    let page = crate::vmm::paging::p2v(phys) as *mut u8;
    let mut handle: u32 = 0;
    // SAFETY: `p` is the live pool and `page` the direct-map alias of the frame.
    let rc = unsafe { zpool_store(p, page as *const u8, &mut handle) };
    if rc == 0 {
        G_STORES.fetch_add(1, Ordering::Relaxed);
        Some(handle)
    } else {
        G_STORE_FAIL.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Read pool entry `handle` into the frame at physical `phys`, **keeping** the
/// entry allocated.  The fault path releases it only after winning a
/// compare-exchange on the PTE (see `fault::swap`), so that a racing fault and a
/// `swapoff` migration cannot both free it.
pub fn load_keep(handle: u32, phys: u64) -> bool {
    let p = pool();
    if p.is_null() {
        return false;
    }
    let page = crate::vmm::paging::p2v(phys) as *mut u8;
    if !pool_load_keep(p, handle, page) {
        return false;
    }
    G_LOADS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Release a pool entry the caller owns (it won the PTE compare-exchange, so no
/// other PTE can still name it).
pub fn free_handle(handle: u32) {
    let p = pool();
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is the live pool and `handle` names a live entry.
    unsafe { zpool_free(p, handle) };
}

/// Decompress pool entry `handle` into the frame at physical `phys` and release
/// the entry.  Returns true on success.
pub fn zswap_load(handle: u32, phys: u64) -> bool {
    if !load_keep(handle, phys) {
        return false;
    }
    free_handle(handle);
    true
}

/// One writeback step: find a page of `pd` held in the pool, put it on the
/// swap device and repoint its PTE at the device slot — freeing the pool entry.
/// Returns true when a page was migrated.
///
/// The caller must have verified that a swap device is attached.
///
/// # Safety
///
/// `pd` must be a live page directory whose user PTEs the caller may mutate and
/// must not race another page-table walker.
unsafe fn zswap_writeback_one(pd: *mut u64) -> bool {
    let p = pool();
    if p.is_null() || pd.is_null() {
        return false;
    }

    let mut va = G_WB_CLOCK.load(Ordering::Relaxed);
    if !(USER_SPACE_START..USER_STACK_TOP).contains(&va) {
        va = USER_SPACE_START;
    }
    let max_iter: u32 = 2 * 1024 * 992;
    let mut it: u32 = 0;
    while it < max_iter {
        it += 1;
        // SAFETY: `pd` is the caller's live page map; the walk only reads it.
        let w = crate::vmm::paging::walk(pd, va as u64, false, false);
        if !w.pte_entry.is_null() {
            let entry = w.pte_entry as *mut AtomicU64;
            // SAFETY: `entry` points at one live atomic PTE.
            let pte = unsafe { (*entry).load(Ordering::Acquire) };
            if swap_pte::in_zswap(pte) {
                let handle = swap_pte::decode(pte);
                // Use the frame reserved at enable, not `kalloc`: writeback runs
                // inside eviction, where the PMM is empty and its reclaim is
                // suppressed, so `kalloc` would always fail (see `G_WB_FRAME`).
                // SAFETY: `G_WB_FRAME` is set once under `G_INIT_LOCK` before any
                // writeback can run, and is never freed.
                let frame = unsafe { *KStatic::get_mut(G_WB_FRAME.as_ptr()) };
                if frame.is_null() {
                    return false;
                }
                if !pool_load_keep(p, handle, frame) {
                    return false;
                }
                let mut slot: u32 = 0;
                let frame_phys = crate::vmm::paging::v2p(frame);
                // SAFETY: `frame_phys` is the reserved frame's live address and
                // `slot` a live local.
                if unsafe { crate::fault::swap::swap_out_page(frame_phys, &mut slot) } != 0 {
                    // Nowhere to put it: leave the pool entry (and the PTE) as
                    // they were — nothing has been freed yet.
                    return false;
                }
                // SAFETY: `p` is the live pool and `handle` is a live entry.
                unsafe { zpool_free(p, handle) };

                let new_pte = swap_pte::encode_device(slot)
                    | (pte & ((PAGE_RW | PAGE_USER) as u64));
                // SAFETY: `entry` points at one live atomic PTE.
                unsafe { (*entry).store(new_pte, Ordering::Release) };
                flush_tlb(va as u64);
                G_WRITEBACKS.fetch_add(1, Ordering::Relaxed);
                let next = va + PAGE_SIZE;
                G_WB_CLOCK.store(
                    if next >= USER_STACK_TOP { USER_SPACE_START } else { next },
                    Ordering::Relaxed,
                );
                return true;
            }
        }
        va += PAGE_SIZE;
        if va >= USER_STACK_TOP {
            va = USER_SPACE_START;
        }
    }
    false
}

/// Try to make room in a full pool by migrating one pooled page of `pd` to the
/// swap device.  A no-op (`false`) unless `writeback` is on.
///
/// # Safety
///
/// As [`zswap_writeback_one`].
pub unsafe fn zswap_try_writeback(pd: *mut u64) -> bool {
    if G_WRITEBACK.load(Ordering::Relaxed) == 0 {
        return false;
    }
    // SAFETY: forwarded to the caller's contract.
    unsafe { zswap_writeback_one(pd) }
}

/// Enable the front-end and point it at `max_pool_pct`% of RAM, compressing at
/// zstd `level`.  The first call creates the pool; a later call *grows* it when
/// the percentage is higher (handles are slot indices, so already-pooled pages
/// keep theirs) and re-levels it — a zstd frame is self-describing, so live
/// entries stay readable.  A lower percentage is refused: shrinking would have
/// to invalidate handles held in page tables.  Returns 0, `-EINVAL` (bad
/// percentage or a shrink) or `-ENOMEM` (no memory).
#[unsafe(no_mangle)]
pub extern "C" fn zswap_enable(max_pool_pct: u32, level: i32, writeback: i32) -> i32 {
    if max_pool_pct == 0 || max_pool_pct > 100 {
        return -EINVAL;
    }
    G_WRITEBACK.store(if writeback != 0 { 1 } else { 0 }, Ordering::Relaxed);

    let total = crate::pmm::pmm_total_frames() as u64 * PAGE_SIZE as u64;
    let budget = total / 100 * max_pool_pct as u64;
    let pages64 = budget / PAGE_SIZE as u64;
    // A handle lives in 20 PTE bits, so the pool may hold at most 2^20 pages.
    if pages64 == 0 || pages64 > swap_pte::SLOT_MAX as u64 {
        return -EINVAL;
    }
    let capacity = pages64 as u32;

    init_lock();
    lock_acquire(G_INIT_LOCK.as_ptr());

    // Reserve the writeback scratch frame first — see `G_WB_FRAME`: it can only
    // be taken while the PMM still has frames, and taking it before the pool
    // leaves a failure with nothing to undo.
    if writeback != 0 && unsafe { *KStatic::get_mut(G_WB_FRAME.as_ptr()) }.is_null() {
        let f = crate::pmm::kalloc();
        if f.is_null() {
            lock_release(G_INIT_LOCK.as_ptr());
            return -ENOMEM;
        }
        // SAFETY: the reservation is written once, under `G_INIT_LOCK`, before
        // any eviction can reach the writeback path.
        *unsafe { KStatic::get_mut(G_WB_FRAME.as_ptr()) } = f;
    }

    // SAFETY: pool creation/growth is serialised by `G_INIT_LOCK`.
    let pool = unsafe { *KStatic::get_mut(G_POOL.as_ptr()) };
    let rc = if pool.is_null() {
        // SAFETY: `zpool_create` builds a fresh pool or returns null.
        let new_pool = unsafe { zpool_create(capacity, pages64 * PAGE_SIZE as u64, level) };
        if new_pool.is_null() {
            -ENOMEM
        } else {
            // SAFETY: the pool pointer is written once, here, under `G_INIT_LOCK`.
            *unsafe { KStatic::get_mut(G_POOL.as_ptr()) } = new_pool;
            0
        }
    } else {
        // The pool already exists: a raised limit grows it (handles are slot
        // indices, so existing pooled pages keep theirs), and the level can
        // change on the fly.  A *lower* limit is refused — shrinking would have
        // to invalidate handles that live in page tables.
        // SAFETY: `pool` is the live pool, serialised by `G_INIT_LOCK`.
        unsafe { zpool_set_level(pool, level) };
        let mut st = ZpoolStats::default();
        // SAFETY: `pool` is live and `st` a local.
        let have_stats = unsafe { zpool_get_stats(pool, &mut st) } == 0;
        if !have_stats || capacity < st.capacity_pages {
            -EINVAL
        } else {
            // SAFETY: `pool` is live; growing keeps `st.capacity_pages` handles valid.
            let g = unsafe { zpool_grow(pool, capacity, pages64 * PAGE_SIZE as u64) };
            if g == 0 { 0 } else { -ENOMEM }
        }
    };
    if rc == 0 {
        G_LEVEL.store(level, Ordering::Relaxed);
    }
    lock_release(G_INIT_LOCK.as_ptr());
    if rc != 0 {
        return rc;
    }

    G_ENABLED.store(1, Ordering::Relaxed);
    klog_msg(
        LOG_OK,
        c"zswap: enabled (compressed cache in front of swap)".as_ptr() as *const u8,
    );
    0
}

/// Stop accepting new pages.  The pool is kept: already-pooled pages drain back
/// through fault-in, and the pool stays valid for the life of the kernel.
#[unsafe(no_mangle)]
pub extern "C" fn zswap_disable() -> i32 {
    G_ENABLED.store(0, Ordering::Relaxed);
    0
}

/// # Safety
///
/// `out` must be null or point to a writable `ZswapStats`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zswap_get_stats(out: *mut ZswapStats) -> i32 {
    if out.is_null() {
        return -1;
    }
    let p = pool();
    let mut st = ZswapStats {
        enabled: if zswap_is_enabled() { 1 } else { 0 },
        writeback: G_WRITEBACK.load(Ordering::Relaxed) as u32,
        level: G_LEVEL.load(Ordering::Relaxed),
        stores: G_STORES.load(Ordering::Relaxed),
        store_fail: G_STORE_FAIL.load(Ordering::Relaxed),
        loads: G_LOADS.load(Ordering::Relaxed),
        writebacks: G_WRITEBACKS.load(Ordering::Relaxed),
        ..Default::default()
    };
    if !p.is_null() {
        let mut pool_st = ZpoolStats::default();
        // SAFETY: `p` is the live pool and `pool_st` a live local.
        if unsafe { zpool_get_stats(p, &mut pool_st) } == 0 {
            st.capacity_pages = pool_st.capacity_pages;
            st.pool_pages = pool_st.live_pages;
            st.budget_bytes = pool_st.budget_bytes;
            st.stored_bytes = pool_st.stored_bytes;
            st.original_bytes = pool_st.original_bytes;
        }
    }
    // SAFETY: `out` is a writable `ZswapStats` (checked non-null).
    unsafe { *out = st };
    0
}

/// Boot hook (from `kernel_setup_hardware`): enable the front-end when the
/// command line carries `zswap=<pct>%` or the bare `zswap=1` (which uses
/// `BOOT_DEFAULT_PCT`); `zswap=0` leaves it off.
///
/// The value is read into a bounded, NUL-terminated buffer, so the parsing is
/// ordinary safe indexing.
#[unsafe(no_mangle)]
pub extern "C" fn zswap_init() {
    /// Limit used by the bare `zswap=1` form.
    const BOOT_DEFAULT_PCT: u32 = 20;

    let mut buf = [0u8; 24];
    // `mb2_cmdline_value` writes at most `buf.len()` bytes into `buf` and
    // NUL-terminates; the `c"zswap"` literal is NUL-terminated.
    let rc = kernel_rust::mm::mb2_cmdline_value(
        c"zswap".as_ptr() as *const u8,
        buf.as_mut_ptr(),
        buf.len() as i32,
    );
    if rc != 1 {
        return; // absent (0), or the value did not fit (-1)
    }

    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let tok = &buf[..end];
    let (digits, had_pct) = match tok.split_last() {
        Some((&b'%', rest)) => (rest, true),
        _ => (tok, false),
    };
    let mut pct: u32 = 0;
    if digits.is_empty() {
        klog_msg(LOG_WARN, c"zswap: malformed zswap=, ignored".as_ptr() as *const u8);
        return;
    }
    for &b in digits {
        if !b.is_ascii_digit() {
            klog_msg(LOG_WARN, c"zswap: malformed zswap=, ignored".as_ptr() as *const u8);
            return;
        }
        pct = pct.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    if !had_pct {
        // "zswap=1" means "on with the default limit"; a bare 0 disables.
        if pct == 0 {
            return;
        }
        if pct == 1 {
            pct = BOOT_DEFAULT_PCT;
        }
    }
    if pct > 100 {
        klog_msg(LOG_WARN, c"zswap: limit over 100, ignored".as_ptr() as *const u8);
        return;
    }
    if zswap_enable(pct, 0, 0) != 0 {
        klog_msg(LOG_WARN, c"zswap: enable from cmdline failed".as_ptr() as *const u8);
    }
}
