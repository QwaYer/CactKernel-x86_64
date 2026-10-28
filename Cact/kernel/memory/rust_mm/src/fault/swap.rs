//! Swap backing store: slot bitmap, clock hand, and C callbacks for block read/write.
//!
//! Encodes swapped-out PTEs with `PAGE_SWAPPED`; cooperates with the page-fault path.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ffi::*;
use crate::pmm::{kalloc, free_page};
use crate::safe::{KStatic, lock_acquire, lock_release, kprint_str, kprint_int, klog_msg, flush_tlb};

pub type SwapSlot = u32;
pub type SwapReadFn = Option<unsafe extern "C" fn(u32, *mut u8, u32) -> i32>;
pub type SwapWriteFn = Option<unsafe extern "C" fn(u32, *const u8, u32) -> i32>;

static G_READ: KStatic<SwapReadFn> = KStatic::new(None);
static G_WRITE: KStatic<SwapWriteFn> = KStatic::new(None);
static G_BITMAP: KStatic<[u8; SWAP_BITMAP_SIZE as usize]> = KStatic::new([0u8; SWAP_BITMAP_SIZE as usize]);
static G_TOTAL_SLOTS: KStatic<u32> = KStatic::new(0);
static G_ENABLED: KStatic<i32> = KStatic::new(0);
static G_STATS: KStatic<SwapStats> = KStatic::new(SwapStats {
    total_slots: 0,
    used_slots: 0,
    pages_swapped_out: 0,
    pages_swapped_in: 0,
    swap_failures: 0,
});
static G_SWAP_LOCK: KStatic<IrqSpinlock> = KStatic::new(IrqSpinlock { spin_locked: 0, saved_flags: 0 });
/// Clock hand for the eviction scan: the user virtual address the next scan
/// starts from (page-aligned, inside the user window).  Only advanced by
/// `swap_evict_page`; a torn read across CPUs merely restarts the scan earlier.
static G_CLOCK_VA: KStatic<u32> = KStatic::new(USER_SPACE_START);

fn bitmap_alloc() -> SwapSlot {
    // SAFETY: `G_TOTAL_SLOTS` is written once by `swap_init` at boot; `bitmap_alloc`
    // itself is only called while holding `G_SWAP_LOCK`.
    let total = *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) };
    // SAFETY: `G_BITMAP` slot bitmap, mutated under `G_SWAP_LOCK` — held by every
    // caller of `bitmap_alloc`.
    let bm = unsafe { KStatic::get_mut(G_BITMAP.as_ptr()) };
    // SAFETY: `G_STATS.used_slots` alongside the bitmap update, under `G_SWAP_LOCK`.
    let stats = unsafe { KStatic::get_mut(G_STATS.as_ptr()) };
    for i in 0..total {
        if bm[(i / 8) as usize] & (1u8 << (i % 8)) == 0 {
            bm[(i / 8) as usize] |= 1u8 << (i % 8);
            stats.used_slots += 1;
            return i;
        }
    }
    u32::MAX
}

fn bitmap_free(slot: SwapSlot) {
    // SAFETY: `G_TOTAL_SLOTS` read; `bitmap_free` callers hold `G_SWAP_LOCK`.
    let total = *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) };
    if slot >= total {
        return;
    }
    // SAFETY: `G_BITMAP` mutated under `G_SWAP_LOCK`.
    let bm = unsafe { KStatic::get_mut(G_BITMAP.as_ptr()) };
    // SAFETY: `G_STATS.used_slots` decremented with the bitmap, under `G_SWAP_LOCK`.
    let stats = unsafe { KStatic::get_mut(G_STATS.as_ptr()) };
    if bm[(slot / 8) as usize] & (1u8 << (slot % 8)) != 0 {
        bm[(slot / 8) as usize] &= !(1u8 << (slot % 8));
        if stats.used_slots > 0 {
            stats.used_slots -= 1;
        }
    }
}

fn slot_to_lba(slot: SwapSlot) -> u32 {
    SWAP_DATA_START_LBA + slot * (PAGE_SIZE / 512)
}

fn swap_encode_pte(slot: SwapSlot) -> u64 {
    ((slot as u64) << 12 & 0xFFFFF000) | PAGE_SWAPPED as u64
}

fn swap_decode_pte(pte: u64) -> SwapSlot {
    ((pte & 0xFFFFF000) >> 12) as SwapSlot
}

pub fn swap_pte_is_swapped(pte: u64) -> bool {
    (pte & PAGE_PRESENT as u64 == 0) && (pte & PAGE_SWAPPED as u64 != 0)
}

pub fn swap_is_enabled() -> bool {
    // SAFETY: `G_ENABLED` is written once by `swap_init` during boot and only read
    // afterwards, so it is effectively immutable.
    *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } != 0
}

/// Install the backing-store I/O callbacks and leave swap **disabled**.
///
/// Swap used to size itself to `SWAP_MAX_SLOTS` and turn itself on here, which
/// made a diskless boot advertise a swap area (and page against whatever device
/// answered the LBA reads).  Capacity now comes from a real swap partition, via
/// `swap_enable`.
#[unsafe(no_mangle)]
pub extern "C" fn swap_init(
    read_fn: unsafe extern "C" fn(u32, *mut u8, u32) -> i32,
    write_fn: unsafe extern "C" fn(u32, *const u8, u32) -> i32,
) -> i32 {
    // SAFETY: boot-time `swap_init`: single-threaded, no other swap user yet.
    *unsafe { KStatic::get_mut(G_READ.as_ptr()) } = Some(read_fn);
    // SAFETY: same single-threaded boot init of `G_WRITE`.
    *unsafe { KStatic::get_mut(G_WRITE.as_ptr()) } = Some(write_fn);

    {
        // SAFETY: zeroing the `G_BITMAP` slot bitmap during single-threaded boot init.
        let bm = unsafe { KStatic::get_mut(G_BITMAP.as_ptr()) };
        bm.fill(0);
    }
    // SAFETY: zeroing stats at boot time.
    unsafe {
        core::ptr::write_bytes(G_STATS.as_ptr() as *mut u8, 0, core::mem::size_of::<SwapStats>());
    }
    // SAFETY: no capacity until a backing device is attached.
    *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) } = 0;

    // SAFETY: boot-time init.
    unsafe { irq_spinlock_init(G_SWAP_LOCK.as_ptr()) };
    // SAFETY: stays off; set last so no reader can see `G_ENABLED` before the
    // tables above are initialised.
    *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } = 0;
    0
}

/// Attach a backing store holding `slots` pages and turn swap on.
///
/// Rejects a zero slot count and a missing I/O callback, so swap cannot be
/// turned on without a device behind it.
#[unsafe(no_mangle)]
pub extern "C" fn swap_enable(slots: u32) -> i32 {
    if slots == 0 {
        return -1;
    }
    // SAFETY: `G_READ`/`G_WRITE` are set once by `swap_init` and never changed.
    if unsafe { KStatic::get_mut(G_READ.as_ptr()) }.is_none()
        || unsafe { KStatic::get_mut(G_WRITE.as_ptr()) }.is_none()
    {
        return -1;
    }
    let total = if slots > SWAP_MAX_SLOTS { SWAP_MAX_SLOTS } else { slots };

    lock_acquire(G_SWAP_LOCK.as_ptr());
    {
        // SAFETY: `G_STATS` mutated under `G_SWAP_LOCK`.
        let stats = unsafe { KStatic::get_mut(G_STATS.as_ptr()) };
        // Resetting the bitmap is only correct while nothing is swapped out:
        // slots still held by swapped-out pages must stay reserved across a
        // device re-attach (a rescan drops and recreates the partition), or a
        // later fault-in would read whatever page took the slot.
        if stats.used_slots == 0 {
            // SAFETY: `G_BITMAP` mutated under `G_SWAP_LOCK`.
            let bm = unsafe { KStatic::get_mut(G_BITMAP.as_ptr()) };
            bm.fill(0);
        }
        stats.total_slots = total;
        stats.swap_failures = 0;
    }
    lock_release(G_SWAP_LOCK.as_ptr());

    // SAFETY: `G_TOTAL_SLOTS` bounds `bitmap_alloc`; published before enabling
    // so no swapper can see capacity with a stale slot count.
    *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) } = total;
    // SAFETY: restart the eviction clock hand on a new backing store.
    *unsafe { KStatic::get_mut(G_CLOCK_VA.as_ptr()) } = USER_SPACE_START;
    // SAFETY: enabling, last, so no concurrent reader sees `G_ENABLED` set
    // before the tables above are ready.
    *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } = 1;
    0
}

/// Detach the backing store: swap stops advertising capacity and refuses new
/// evictions.  The slot bitmap and its counters are kept on purpose — the slots
/// held by swapped-out pages stay reserved, so re-attaching the (or another)
/// device cannot hand them to a new page.
#[unsafe(no_mangle)]
pub extern "C" fn swap_disable() {
    // SAFETY: leaving the bitmap alone; only the enable flag and the advertised
    // capacity change.
    *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } = 0;
    // SAFETY: withdraw the advertised capacity.
    *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) } = 0;
    // SAFETY: `G_STATS.total_slots` follows `G_TOTAL_SLOTS`; `used_slots` is
    // deliberately left alone, see above.
    (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).total_slots = 0;
}

#[unsafe(no_mangle)]
pub extern "C" fn swap_is_enabled_ffi() -> i32 {
    // SAFETY: `G_ENABLED` is immutable after `swap_init`.
    *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) }
}

/// # Safety
///
/// `out_slot` must be null or point to a writable `SwapSlot` valid for the
/// call, and `phys_addr` must be a page-aligned physical frame address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swap_out_page(phys_addr: u64, out_slot: *mut SwapSlot) -> i32 {
    // SAFETY: `G_ENABLED` is immutable after `swap_init`.
    if *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } == 0 {
        return -1;
    }
    if !phys_addr.is_multiple_of(PAGE_SIZE as u64) {
        return -1;
    }

    lock_acquire(G_SWAP_LOCK.as_ptr());
    let slot = bitmap_alloc();
    lock_release(G_SWAP_LOCK.as_ptr());

    if slot == u32::MAX {
        // SAFETY: `G_STATS.swap_failures` — a diagnostic counter; this increment is not
        // taken under `G_SWAP_LOCK` and is not serialised across CPUs, but a lost count
        // is harmless.
        (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).swap_failures += 1;
        klog_msg(LOG_WARN, c"swap out failed: no free slots".as_ptr() as *const u8);
        return -1;
    }

    let lba = slot_to_lba(slot);
    // SAFETY: `G_WRITE` callback pointer is set once at boot and left unchanged.
    let write_fn = *unsafe { KStatic::get_mut(G_WRITE.as_ptr()) };
    let write_fn = match write_fn {
        Some(f) => f,
        None => return -1,
    };
    // SAFETY: calling the C-provided write function.
    let rc = unsafe { write_fn(lba, phys_addr as *const u8, PAGE_SIZE / 512) };
    if rc != 0 {
        lock_acquire(G_SWAP_LOCK.as_ptr());
        bitmap_free(slot);
        lock_release(G_SWAP_LOCK.as_ptr());
        // SAFETY: `G_STATS.swap_failures` — unlocked diagnostic counter, see above.
        (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).swap_failures += 1;
        return -1;
    }

    // SAFETY: `G_STATS.pages_swapped_out` — unlocked diagnostic counter, see above.
    (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).pages_swapped_out += 1;
    // SAFETY: out_slot is a valid pointer provided by the caller.
    unsafe { *out_slot = slot; }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn swap_in_page(slot: SwapSlot, phys_addr: u64) -> i32 {
    // SAFETY: `G_ENABLED` immutable after boot init.
    if *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } == 0 {
        return -1;
    }
    // SAFETY: `G_TOTAL_SLOTS` immutable after boot init; slotted reads are validated
    // against it.
    if slot >= *unsafe { KStatic::get_mut(G_TOTAL_SLOTS.as_ptr()) } {
        return -1;
    }
    if !phys_addr.is_multiple_of(PAGE_SIZE as u64) {
        return -1;
    }

    let lba = slot_to_lba(slot);
    // SAFETY: `G_READ` callback pointer is set once at boot and left unchanged.
    let read_fn = *unsafe { KStatic::get_mut(G_READ.as_ptr()) };
    let read_fn = match read_fn {
        Some(f) => f,
        None => return -1,
    };
    // SAFETY: calling the C-provided read function.
    let rc = unsafe { read_fn(lba, phys_addr as *mut u8, PAGE_SIZE / 512) };
    if rc != 0 {
        // SAFETY: `G_STATS.swap_failures` — unlocked diagnostic counter, see above.
        (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).swap_failures += 1;
        return -1;
    }

    lock_acquire(G_SWAP_LOCK.as_ptr());
    bitmap_free(slot);
    lock_release(G_SWAP_LOCK.as_ptr());

    // SAFETY: `G_STATS.pages_swapped_in` — unlocked diagnostic counter, see above.
    (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).pages_swapped_in += 1;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn swap_free_slot(slot: SwapSlot) {
    // SAFETY: `G_ENABLED` immutable after boot init.
    if *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } == 0 {
        return;
    }
    lock_acquire(G_SWAP_LOCK.as_ptr());
    bitmap_free(slot);
    lock_release(G_SWAP_LOCK.as_ptr());
}

/// # Safety
///
/// `pd` must be null or a valid page directory whose user PTEs the caller is
/// allowed to mutate; the caller must not race another page-table walker.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swap_evict_page(pd: *mut u64) -> i32 {
    // SAFETY: `G_ENABLED` immutable after boot init.
    if *unsafe { KStatic::get_mut(G_ENABLED.as_ptr()) } == 0 || pd.is_null() {
        return -1;
    }

    let mut iterations: u32 = 0;
    let max_iter: u32 = 2 * 1024 * 992;

    // SAFETY: `G_CLOCK_VA` is the clock hand's virtual address, only advanced by
    // `swap_evict_page`; a torn read across CPUs merely restarts the scan earlier.
    let mut va = *unsafe { KStatic::get_mut(G_CLOCK_VA.as_ptr()) };
    if va < USER_SPACE_START || va >= USER_STACK_TOP {
        va = USER_SPACE_START;
    }

    while iterations < max_iter {
        iterations += 1;

        // Resolve `va` to its page-table entry through the real four-level walk
        // (reading only, `create` false), so the scan follows exactly the tables
        // the CPU walks rather than assuming a two-level layout.
        // SAFETY: `pd` is the caller's live page map and the walk only reads it.
        let w = unsafe { crate::vmm::paging::walk(pd, va as u64, false, false) };
        if !w.pte_entry.is_null() {
            let pte_entry = w.pte_entry as *mut AtomicU64;
            // SAFETY: `pte_entry` points at one live atomic PTE; a relaxed load is
            // a single atomic access, so no torn value can be observed.
            let pte = unsafe { (*pte_entry).load(Ordering::Relaxed) };

            if pte & PAGE_PRESENT as u64 != 0
                && !swap_pte_is_swapped(pte)
                && pte & PAGE_USER as u64 != 0
            {
                if pte & PTE_ACCESSED as u64 != 0 {
                    // Second chance: give an accessed page another lap and clear
                    // Accessed so the next pass sees it as a candidate.
                    // SAFETY: `pte_entry` points at one live atomic PTE; the
                    // fetch_and is a single atomic RMW, so no torn value is seen.
                    unsafe { (*pte_entry).fetch_and(!(PTE_ACCESSED as u64), Ordering::AcqRel) };
                    flush_tlb(va as u64);
                } else {
                    let phys = pte & !0xFFF;
                    let mut slot: SwapSlot = 0;
                    // SAFETY: `phys` is the page-aligned frame selected by the scan
                    // and `slot` is a live local receiving the assigned swap slot.
                    if unsafe { swap_out_page(phys, &mut slot) } != 0 {
                        return -1;
                    }

                    let mut new_pte = swap_encode_pte(slot);
                    new_pte |= (pte & ((PAGE_RW | PAGE_USER) as u64)) & !(PAGE_PRESENT as u64);
                    // SAFETY: `pte_entry` is the live PTE for `va`; the store
                    // publishes the swapped-out entry.
                    unsafe { (*pte_entry).store(new_pte, Ordering::Release) };

                    flush_tlb(va as u64);

                    // SAFETY: the frame is live and PMM-managed; this call releases
                    // exactly one reference to it.
                    unsafe { free_page(phys as *mut u8) };

                    let next = va + PAGE_SIZE;
                    // SAFETY: saving the clock hand after a successful eviction;
                    // best-effort scan position shared between CPUs, see above.
                    *unsafe { KStatic::get_mut(G_CLOCK_VA.as_ptr()) } =
                        if next >= USER_STACK_TOP { USER_SPACE_START } else { next };
                    return 0;
                }
            }
        }

        va += PAGE_SIZE;
        if va >= USER_STACK_TOP {
            va = USER_SPACE_START;
        }
    }

    klog_msg(LOG_WARN, c"swap evict failed: no candidate page".as_ptr() as *const u8);
    -1
}

/// # Safety
///
/// `pd` must be null or a valid page directory whose user PTEs the caller is
/// allowed to mutate; the caller must not race another page-table walker.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn swap_handle_fault(pd: *mut u64, fault_addr: u64) -> i32 {
    if pd.is_null() {
        return -1;
    }

    let page_va = fault_addr & !0xFFF;

    // SAFETY: `pd` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    let w = unsafe { crate::vmm::paging::walk(pd, page_va, false, false) };
    if w.pte_entry.is_null() {
        return -1;
    }
    // The page table exists, so the walk found one: the entry the swap markers
    // live in.
    let pte_entry = w.pte_entry as *mut AtomicU64;
    // SAFETY: `pte_entry` points at one live atomic PTE; an acquire load is a
    // single atomic access.
    let pte = unsafe { (*pte_entry).load(Ordering::Acquire) };

    if !swap_pte_is_swapped(pte) {
        return -1;
    }

    let slot = swap_decode_pte(pte);

    let mut phys = kalloc();
    if phys.is_null() {
        // SAFETY: `pd` is a valid page directory (checked at entry); eviction only
        // touches that directory's own user PTEs.
        if unsafe { swap_evict_page(pd) } != 0 {
            return -1;
        }
        phys = kalloc();
        if phys.is_null() {
            return -1;
        }
    }

    if swap_in_page(slot, phys as u64) != 0 {
        // SAFETY: the frame is live and PMM-managed; this call releases exactly one reference to it.
        unsafe { free_page(phys) };
        return -1;
    }

    let old_flags = pte & ((PAGE_RW | PAGE_USER) as u64);
    // SAFETY: `pte_entry` points at one live atomic PTE; the store publishes the
    // restored mapping.
    unsafe {
        (*pte_entry).store(
            (phys as u64 & !0xFFF) | old_flags | PAGE_PRESENT as u64,
            Ordering::Release,
        )
    };
    flush_tlb(page_va);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn swap_get_stats() -> SwapStats {
    // SAFETY: read-only snapshot of the swap counters for the C caller.
    *unsafe { KStatic::get_mut(G_STATS.as_ptr()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn swap_print_stats() {
    // SAFETY: read-only snapshot of the swap counters for printing.
    let stats = *unsafe { KStatic::get_mut(G_STATS.as_ptr()) };
    kprint_str(c"[SWAP] === Swap Statistics ===\n".as_ptr() as *const u8);
    kprint_str(c"  total_slots:       ".as_ptr() as *const u8);
    kprint_int(stats.total_slots as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
    kprint_str(c"  used_slots:        ".as_ptr() as *const u8);
    kprint_int(stats.used_slots as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
    kprint_str(c"  pages_swapped_out: ".as_ptr() as *const u8);
    kprint_int(stats.pages_swapped_out as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
    kprint_str(c"  pages_swapped_in:  ".as_ptr() as *const u8);
    kprint_int(stats.pages_swapped_in as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
    kprint_str(c"  swap_failures:     ".as_ptr() as *const u8);
    kprint_int(stats.swap_failures as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
}
