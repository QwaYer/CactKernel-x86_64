// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Physical memory manager: bitmap of free frames, per-page refcounts, and `kalloc`/`free_page`.
//!
//! Addresses are 64-bit and the bitmap/refcount arrays are sized at boot from
//! the Multiboot2 map, so RAM above 4 GiB is managed like any other.  The
//! arrays themselves are carved out of the boot reservation (see
//! [`pmm_alloc_tables`]), not baked in as compile-time statics.

use crate::ffi::*;
use crate::pmm_math::{self, addr_to_page, page_to_addr};
use crate::safe::{lock_acquire, lock_release, kprint_str, klog_msg};
use crate::vmm::paging::{p2v, v2p};
use kernel_rust::cell::KCell;

// The pure math module and the FFI ABI must agree on the page size; if they
// ever drift, this fails the build instead of corrupting the bitmap.
const _: () = assert!(PAGE_SIZE == pmm_math::PAGE_SIZE);

/// Base of the free-frame bitmap, one bit per 4 KiB frame.  Set once by
/// [`pmm_alloc_tables`] during single-threaded boot; read-only afterwards.
static MEMORY_BITMAP: KCell<*mut u8> = KCell::new(core::ptr::null_mut());

/// Base of the per-frame reference counts (fork/COW), same policy as the bitmap.
static PAGE_REFCOUNTS: KCell<*mut u16> = KCell::new(core::ptr::null_mut());

/// Number of 4 KiB frames the two arrays above describe — the highest physical
/// address the boot map reports, rounded up.  Fixed once boot has sized them.
static MANAGED_FRAMES: KCell<u64> = KCell::new(0);

/// Size of the bitmap in bytes (`ceil(MANAGED_FRAMES / 8)`), cached so the
/// free-frame scan does not recompute it.
static BITMAP_BYTES: KCell<u64> = KCell::new(0);

static FIRST_AVAILABLE_PAGE: KCell<u64> = KCell::new(0);

/// Runtime physical RAM/MMIO boundary: the page-aligned top of usable RAM
/// *below* the 32-bit PCI hole, discovered from the Multiboot2 map in
/// `init_memory_manager`.  Defaults to `PCI_HOLE_START` until then and on
/// machines with no usable map.  Physical addresses in `[RAM_END, 4 GiB)` are
/// device MMIO (mapped uncached); RAM above 4 GiB is managed normally.
static RAM_END: KCell<u64> = KCell::new(PCI_HOLE_START as u64);

/// Highest physical address the boot map calls available (below or above
/// 4 GiB).  The direct map has to cover it; 0 when the map yielded nothing.
static MAX_RAM_ADDR: KCell<u64> = KCell::new(0);

/// Base VA of the kernel's fixed MMIO windows (ACPI temp map, PCIe ECAM).
/// Placed at or above `PCI_HOLE_START` (the kernel half, `>= USER_STACK_TOP`)
/// so a window VA can never collide with a user mapping.  Computed in
/// `init_memory_manager`.
static MMIO_WINDOW_BASE: KCell<u64> = KCell::new(PCI_HOLE_START as u64);

/// Physical address at which device MMIO begins (device BARs live here).
pub(crate) fn ram_end() -> u64 {
    RAM_END.get()
}

/// Highest available physical address; 0 before `init_memory_manager`, or when
/// the boot map was empty.
pub(crate) fn max_ram_addr() -> u64 {
    MAX_RAM_ADDR.get()
}

/// Lowest VA of the fixed kernel MMIO windows.
pub(crate) fn mmio_window_base() -> u64 {
    MMIO_WINDOW_BASE.get()
}

/// C entry point: ACPI/PCIe need the window base VA after PMM init.
#[unsafe(no_mangle)]
pub extern "C" fn cact_mmio_window_base() -> u32 {
    mmio_window_base() as u32
}

/// Number of frames the PMM was ever handed by the boot map (every available
/// frame, low and high).  Fixed after `init_memory_manager`; reported as the
/// machine's usable RAM (see `pmm_total_frames`).
static TOTAL_USABLE_FRAMES: KCell<u32> = KCell::new(0);

/// End of the physical range the PMM never hands out, and base of the kernel
/// heap window that follows it.  Starts at the compile-time low reservation
/// (`RESERVED_END`) and is raised by `pmm_reserve_boot_images()` past the
/// Multiboot2 module images, then by `pmm_alloc_tables()` past the PMM's own
/// arrays: GRUB loads the modules into ordinary available RAM right after the
/// kernel, and they are handed to userspace *in place* (the firmrepo archive
/// via /dev/firmrepo), so `kalloc` and `kmalloc` must both stay off that RAM.
/// Written once during single-threaded boot, read-only afterwards.
static BOOT_RESERVED_END: KCell<u32> = KCell::new(RESERVED_END);

pub(crate) fn reserved_end() -> u32 {
    BOOT_RESERVED_END.get()
}

/// Base of the kernel heap window: right after the boot reservation.
pub(crate) fn heap_start() -> u32 {
    reserved_end()
}

/// End of the kernel heap window (exclusive), clipped to the PCI hole and to the
/// RAM the PMM actually manages.
pub(crate) fn heap_end() -> u32 {
    heap_start()
        .saturating_add(HEAP_SIZE)
        .min(PCI_HOLE_START)
        // Never above managed RAM: the frame arrays sit just past the
        // reservation, so a window past the RAM end would land on top of them
        // (and the first heap block header written there would be corrupted).
        .min(ram_end() as u32)
}

/// C entry point: reserve the RAM the bootloader loaded its module images into.
///
/// `end` is the highest module end address from the Multiboot2 tags; 0 when the
/// medium carried no modules.  Must be called before `init_memory_manager`, and
/// returns the boundary now in use (the low reservation raised past `end`).
#[unsafe(no_mangle)]
pub extern "C" fn pmm_reserve_boot_images(end: u32) -> u32 {
    const ALIGN: u32 = 2 * 1024 * 1024;
    let aligned = match end.checked_add(ALIGN - 1) {
        Some(v) => v & !(ALIGN - 1),
        None => RESERVED_END,
    };
    let value = if aligned > RESERVED_END { aligned } else { RESERVED_END };
    BOOT_RESERVED_END.set(value);
    value
}

pub(crate) static PAGE_LOCK: KCell<IrqSpinlock> = KCell::new(IrqSpinlock::new());

static MMAP_TABLE: KCell<Mb2MmapTable> = KCell::new(Mb2MmapTable {
    entries: [Mb2MmapFlat { base: 0, len: 0, ty: 0 }; MB2_MMAP_MAX_ENTRIES],
    count: 0,
});

/// Free-frame bitmap base.  Set once at boot.
#[inline(always)]
fn bitmap_ptr() -> *mut u8 {
    MEMORY_BITMAP.get()
}

/// Per-frame refcount array base.  Set once at boot.
#[inline(always)]
fn refcount_ptr() -> *mut u16 {
    PAGE_REFCOUNTS.get()
}

/// Number of frames the frame arrays describe (fixed after boot).
#[inline(always)]
fn managed_frames() -> u64 {
    MANAGED_FRAMES.get()
}

/// Size of the free-frame bitmap in bytes (fixed after boot).
#[inline(always)]
fn bitmap_bytes() -> u64 {
    BITMAP_BYTES.get()
}

#[inline(always)]
fn bitmap_set(idx: u64) {
    let byte = pmm_math::bitmap_byte(idx);
    let mask = pmm_math::bitmap_mask(idx);
    // `idx` lies inside the bitmap (`managed_frames()` bounds it at every call
    // site) and `bitmap_ptr()` is set once at boot.  `bitmap_set` runs either
    // during single-threaded boot (`init_memory_manager`) or with `PAGE_LOCK`
    // held (`kalloc`/`free_page`), so the access is exclusive.
    *kernel_rust::ptr::as_mut(bitmap_ptr().wrapping_add(byte)) |= mask;
}

#[inline(always)]
fn bitmap_clear(idx: u64) {
    let byte = pmm_math::bitmap_byte(idx);
    let mask = pmm_math::bitmap_mask(idx);
    // `idx` lies inside the bitmap; callers are `init_memory_manager` (boot,
    // single-threaded) or `free_page` (holds `PAGE_LOCK`).
    *kernel_rust::ptr::as_mut(bitmap_ptr().wrapping_add(byte)) &= !mask;
}

#[inline(always)]
fn bitmap_test(idx: u64) -> bool {
    // `idx` lies inside the bitmap; only `kalloc` calls this, and it holds
    // `PAGE_LOCK` across the whole first-fit scan.
    (kernel_rust::ptr::read(bitmap_ptr().wrapping_add(pmm_math::bitmap_byte(idx)))
        & pmm_math::bitmap_mask(idx))
        != 0
}

/// Low user VA window the reservation must keep so the ELF image and its `brk`
/// heap still fit below the floor (see `RESERVED_END` in ffi.rs).
const MIN_USER_WINDOW: u64 = 64 * 1024 * 1024;
/// Hard lower bound for the reservation floor.
const MIN_RESERVED_END: u64 = USER_HEAP_START as u64 + MIN_USER_WINDOW;
/// RAM to keep above the heap window for `kalloc`, so that lowering the floor on
/// a small-RAM machine still leaves a usable frame pool.  Without it the floor
/// only just fits the window and the pool is a sliver — early allocations fail
/// (the loader then dereferences a NULL).
const MIN_KALLOC_POOL: u64 = 64 * 1024 * 1024;

/// Carve the frame arrays out of the boot reservation and point the PMM at
/// them.
///
/// `ram_hi` is the highest address the boot map reports (or the reservation
/// end, whichever is higher).  The arrays go at the current reservation
/// boundary — RAM just past the boot modules, which the PMM must never hand
/// out — and the reservation is extended past them, so `init_memory_manager`
/// marks them used.  The kernel reaches them through the direct map.
fn pmm_alloc_tables(ram_hi: u64) {
    const ALIGN: u64 = 2 * 1024 * 1024;
    // The fixed floor (`RESERVED_END`, 512 MiB) assumes a machine with RAM to
    // spare above it.  On a small-RAM one it consumes every frame and puts the
    // heap window on top of these very arrays — the first heap block header was
    // written into the array and read back with a zero size, which panicked the
    // allocator.  So lower the floor to the largest 2 MiB-aligned value that
    // still leaves room inside `ram_hi` for the arrays and the heap window, but
    // never below the low user VA window (`USER_HEAP_START..floor`), whose
    // addresses map into the reserved range.
    let floor_max = reserved_end() as u64;
    let low_top   = ram_hi.min(LOW_MEM_END);
    let slack     = low_top / 1024 + (1024 * 1024);  // bitmap + refcount arrays
    // Above the floor the machine needs: the heap window, a usable kalloc pool,
    // and room for the arrays themselves.
    let want      = low_top.saturating_sub(HEAP_SIZE as u64 + MIN_KALLOC_POOL + slack);
    let floor     = if floor_max > want {
        let lowered = (want.max(MIN_RESERVED_END) & !(ALIGN - 1)).min(floor_max);
        if lowered < floor_max {
            klog_msg(
                LOG_WARN,
                c"pmm: small RAM — lowering the reservation floor to fit the heap"
                    .as_ptr() as *const u8,
            );
        }
        lowered
    } else {
        floor_max
    };
    BOOT_RESERVED_END.set(floor as u32);

    let mut frames = addr_to_page(ram_hi.max(reserved_end() as u64));
    let bitmap_at = reserved_end() as u64;
    let mut bitmap_size;
    let mut refcounts_at;
    let mut new_reserved;
    // The arrays sit just above the reservation, so their own frames must be
    // covered too.  A second pass is always enough (they are ~0.05% of the RAM
    // they describe), but loop until the fixed point is reached.
    loop {
        bitmap_size = (frames + 7) / 8;
        refcounts_at = (bitmap_at + bitmap_size + 1) & !1;
        let refcount_bytes = frames * core::mem::size_of::<u16>() as u64;
        new_reserved = (refcounts_at + refcount_bytes + ALIGN - 1) & !(ALIGN - 1);
        let need = addr_to_page(ram_hi.max(new_reserved));
        if need <= frames {
            break;
        }
        frames = need;
    }

    // Each is written once, single-threaded, before `init_memory_manager`
    // reads them and long before any allocator caller.
    BOOT_RESERVED_END.set(new_reserved as u32);
    MANAGED_FRAMES.set(frames);
    BITMAP_BYTES.set(bitmap_size);
    MEMORY_BITMAP.set(p2v(bitmap_at) as *mut u8);
    PAGE_REFCOUNTS.set(p2v(refcounts_at) as *mut u16);
}

/// `mmap` must be null or point to a valid `Mb2MmapTable` (the bootloader's
/// static MMAP table) that stays valid for the call, and this must be invoked
/// once, single-threaded, during boot.
#[unsafe(no_mangle)]
pub extern "C" fn pmm_init_from_mmap(mmap: *const Mb2MmapTable) {
    if mmap.is_null() {
        klog_msg(LOG_WARN, c"pmm mmap pointer is null; using fallback".as_ptr() as *const u8);
        // The fallback assumes RAM up to the PCI hole, so size the arrays for it
        // and give them a home before `init_memory_manager` runs.
        pmm_alloc_tables(PCI_HOLE_START as u64);
        return;
    }
    // `mmap` is valid C-side static storage.
    let src = kernel_rust::ptr::as_ref(mmap);
    let count = (src.count as usize).min(MB2_MMAP_MAX_ENTRIES);
    let mut ram_hi = reserved_end() as u64;
    // `MMAP_TABLE` is written only here, from the C boot code before the
    // scheduler starts; the kernel is still single-threaded.
    MMAP_TABLE.with(|dst| {
        dst.count = count as u32;
        for i in 0..count {
            let e = src.entries[i];
            dst.entries[i] = e;
            if e.ty == MB2_MMAP_TYPE_AVAILABLE && e.len > 0 {
                let end = e.base.saturating_add(e.len);
                if end > ram_hi {
                    ram_hi = end;
                }
            }
        }
    });
    pmm_alloc_tables(ram_hi);
}

#[unsafe(no_mangle)]
pub extern "C" fn init_memory_manager() {
    irq_spinlock_init(PAGE_LOCK.as_ptr());
    {
        // The bitmap was carved out during single-threaded boot and is filled
        // here, before `kalloc` can run.
        let bm = kernel_rust::ptr::slice_mut(bitmap_ptr(), bitmap_bytes() as usize);
        for b in bm.iter_mut() {
            *b = 0xFF;
        }
    }

    // `MMAP_TABLE` was filled by `pmm_init_from_mmap` during boot and is only
    // read here, still single-threaded.
    let have_mmap = MMAP_TABLE.with(|mmap| mmap.count) > 0;
    let frames = managed_frames();

    // Frames the boot map offers to the PMM (later the low reservation and the
    // heap window are re-marked used, but they still count as installed RAM).
    let mut usable_frames: u32 = 0;
    // Highest available end below / at or above the 32-bit hole.
    let mut low_ram_end: u64 = 0;
    let mut high_ram_end: u64 = 0;

    if have_mmap {
        MMAP_TABLE.with(|mmap| {
            for &e in &mmap.entries[..mmap.count as usize] {
                if e.ty != MB2_MMAP_TYPE_AVAILABLE { continue; }
                if e.len == 0 { continue; }

                let region_end = e.base.saturating_add(e.len);
                if e.base < LOW_MEM_END {
                    // The top of *low* RAM is where the 32-bit device hole begins.
                    let clip_end = region_end.min(LOW_MEM_END);
                    if clip_end > low_ram_end { low_ram_end = clip_end; }
                } else if region_end > high_ram_end {
                    high_ram_end = region_end;
                }

                let (first_page, last_page) = pmm_math::aligned_page_range(e.base, region_end);
                if first_page >= last_page { continue; }

                for pg in first_page..last_page {
                    if pg < frames {
                        bitmap_clear(pg);
                        usable_frames += 1;
                    }
                }
            }
        });
    } else {
        klog_msg(LOG_WARN, c"pmm has no mmap; assuming RAM above reserved area".as_ptr() as *const u8);
        let first_free = addr_to_page(reserved_end() as u64);
        let fallback_end = addr_to_page(PCI_HOLE_START as u64);
        for pg in first_free..fallback_end {
            if pg < frames {
                bitmap_clear(pg);
                usable_frames += 1;
            }
        }
        low_ram_end = PCI_HOLE_START as u64;
    }

    // Publish the RAM/MMIO boundary (top of low RAM) and the fixed-window VA
    // base, and record the highest available address for the direct map.  Keep
    // the conservative default when the map yielded no low RAM.
    let ram_end = pmm_math::ram_end_from_candidate(low_ram_end, reserved_end() as u64, LOW_MEM_END)
        .unwrap_or(PCI_HOLE_START as u64);
    // The ACPI/PCIe windows live in the shared kernel half: keep their base at
    // or above PCI_HOLE_START (= USER_STACK_TOP) so no window VA can collide
    // with a user mapping, and 2 MiB-aligned so each window stays clear of its
    // neighbours.
    let window_base = pmm_math::mmio_window_base(ram_end, PCI_HOLE_START as u64);
    let ram_hi = low_ram_end.max(high_ram_end);
    // Each is written once during single-threaded boot, before paging is enabled
    // and before any ACPI/PCIe user of the window runs.
    RAM_END.set(ram_end);
    MMIO_WINDOW_BASE.set(window_base);
    MAX_RAM_ADDR.set(ram_hi);
    TOTAL_USABLE_FRAMES.set(usable_frames);

    let reserved_pages = addr_to_page(reserved_end() as u64);
    for pg in 0..reserved_pages {
        bitmap_set(pg);
    }

    // Keep the dedicated heap window out of PMM allocations even when
    // the reservation covers everything below it (C/Rust layout sync).
    let heap_start_page = addr_to_page(heap_start() as u64);
    let heap_end_page = addr_to_page(heap_end() as u64);
    if heap_start_page < heap_end_page {
        for pg in heap_start_page..heap_end_page {
            bitmap_set(pg);
        }
    }

    // Initialise the first-fit search hint: first frame past the heap window.
    // `FIRST_AVAILABLE_PAGE` is the first-fit hint; initialising it during
    // single-threaded boot cannot race `kalloc`/`free_page`.
    FIRST_AVAILABLE_PAGE.set(heap_end_page);
}

/// Allocate one 4 KiB frame.
///
/// The result is a **virtual** address: the frame is handed out through the
/// direct map (`p2v`), so a caller can dereference it, hand it to `vmm_map`
/// after a `v2p`, or give it back to [`free_page`] unchanged.  A caller that
/// needs the physical address itself asks `v2p`.
#[unsafe(no_mangle)]
pub extern "C" fn kalloc() -> *mut u8 {
    const MAX_RECLAIM_ROUNDS: u32 = 4;

    let mut round: u32 = 0;
    // Scan the whole managed range, not just the low RAM below the hole: RAM
    // above 4 GiB sits past the device hole, whose frames the bitmap marks used,
    // so the first-fit search skips straight over it.
    let limit = managed_frames();
    loop {
        lock_acquire(PAGE_LOCK.as_ptr());
        // `FIRST_AVAILABLE_PAGE` is read while holding `PAGE_LOCK`, which
        // serialises it against `free_page` and the other `kalloc` CPU.
        let hint = FIRST_AVAILABLE_PAGE.get();
        let mut i = hint;
        while i < limit {
            if !bitmap_test(i) {
                bitmap_set(i);
                // `PAGE_REFCOUNTS[i]` initialised under `PAGE_LOCK`, held here
                // for the whole allocation.
                kernel_rust::ptr::write(refcount_ptr().wrapping_add(i as usize), 1);
                // `FIRST_AVAILABLE_PAGE` write while holding `PAGE_LOCK`.
                FIRST_AVAILABLE_PAGE.set(i + 1);
                lock_release(PAGE_LOCK.as_ptr());
                // The bitmap indexes *physical* frames; the frame itself is
                // reached through the direct map.
                return p2v(page_to_addr(i)) as *mut u8;
            }
            i += 1;
        }
        lock_release(PAGE_LOCK.as_ptr());

        if round >= MAX_RECLAIM_ROUNDS {
            break;
        }
        round += 1;

        // A kalloc running inside an eviction or a `swapoff` migration must not
        // start a pass of its own: an eviction could pick the page being
        // evicted and free its frame twice, and a migration holds the
        // `scheduler_lock` its reclaim would try to take again.  Fail this
        // allocation instead — the caller is expected to handle null.
        if crate::fault::swap::eviction_in_progress()
            || crate::fault::swap::swapoff_in_progress()
        {
            return core::ptr::null_mut();
        }

        // An empty slab page is the cheapest memory to get back, so hand the slab
        // caches' free slabs to the PMM before evicting a user page or killing a
        // task.  (kalloc released PAGE_LOCK above, and slab_shrink_all only takes
        // the cache lock, so the ordering is PAGE_LOCK -> G_CACHE_LOCK with nothing
        // the other way.)
        let freed_from_slab = crate::alloc::slab::slab_shrink_all();

        let reclaimed = if freed_from_slab > 0 {
            true
        } else if crate::fault::swap::swap_is_enabled()
            || crate::fault::zswap::zswap_is_enabled()
        {
            let pd = crate::safe::current_task_page_dir();
            // `pd` is the live page directory of the running task (or `CR3`
            // when it has none — see `current_task_page_dir`), and eviction only
            // walks/mutates that directory's own user PTEs.
            if !pd.is_null() && crate::fault::swap::swap_evict_page(pd) == 0 {
                true
            } else {
                crate::fault::oom::oom_kill() == 0
            }
        } else {
            crate::fault::oom::oom_kill() == 0
        };

        if !reclaimed {
            break;
        }
    }

    kprint_str(c"[PMM] kalloc: OUT OF MEMORY\n".as_ptr() as *const u8);
    core::ptr::null_mut()
}

/// Allocate `nframes` **physically contiguous** 4 KiB frames and return their
/// direct-map VA, or null when no such run is free.
///
/// Only frames below `PCI_HOLE_START` are considered, so the run is expressible
/// as a 32-bit physical range (what the heap's regions need).  This is a
/// best-effort primitive for the heap's growth path: it never reclaims, so it
/// fails rather than evict, exactly like the caller can handle.
pub(crate) fn kalloc_contig(nframes: u32) -> *mut u8 {
    if nframes == 0 {
        return core::ptr::null_mut();
    }
    let need = nframes as u64;
    let limit = addr_to_page(PCI_HOLE_START as u64).min(managed_frames());
    lock_acquire(PAGE_LOCK.as_ptr());
    let mut run_start: u64 = 0;
    let mut run_len: u64 = 0;
    let mut i: u64 = 0;
    while i < limit {
        if bitmap_test(i) {
            run_len = 0;
        } else {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len == need {
                for k in 0..need {
                    bitmap_set(run_start + k);
                    // `run_start + k` lies inside the managed range (`< limit`),
                    // the same invariant `kalloc` sets refcounts under.
                    kernel_rust::ptr::write(
                        refcount_ptr().wrapping_add((run_start + k) as usize),
                        1,
                    );
                }
                lock_release(PAGE_LOCK.as_ptr());
                return p2v(page_to_addr(run_start)) as *mut u8;
            }
        }
        i += 1;
    }
    lock_release(PAGE_LOCK.as_ptr());
    core::ptr::null_mut()
}

/// `ptr` must be null or a page-aligned **virtual** address of a frame previously
/// returned by the page allocator (whatever `kalloc` handed out — a direct-map
/// VA — or a kernel-image VA of a PMM-managed page, or a C caller honouring the
/// same contract) that has not already been freed.  The bitmap and the refcounts
/// are indexed by physical address, so the translation happens here.
#[unsafe(no_mangle)]
pub extern "C" fn free_page(ptr: *mut u8) {
    if ptr.is_null() { return; }

    let addr = v2p(ptr);
    // Must be page-aligned and within the managed range.
    if !addr.is_multiple_of(PAGE_SIZE as u64) { return; }

    let page_idx = addr_to_page(addr);
    if page_idx >= managed_frames() { return; }

    // Never allow freeing the reserved boot range (below the heap window).
    if addr < reserved_end() as u64 { return; }

    // The heap window starts at the reservation end and is not tracked like
    // kalloc pages, so its pages must never be returned to the PMM.
    if addr >= heap_start() as u64 && addr < heap_end() as u64 {
        return;
    }

    lock_acquire(PAGE_LOCK.as_ptr());

    // `PAGE_REFCOUNTS[page_idx]` read under `PAGE_LOCK`, held here for the whole
    // function.
    let rc = kernel_rust::ptr::read(refcount_ptr().wrapping_add(page_idx as usize));
    if rc > 1 {
        // Same slot, still under `PAGE_LOCK`.
        kernel_rust::ptr::write(refcount_ptr().wrapping_add(page_idx as usize), rc - 1);
        lock_release(PAGE_LOCK.as_ptr());
        return;
    }
    // Same slot, still under `PAGE_LOCK`.
    kernel_rust::ptr::write(refcount_ptr().wrapping_add(page_idx as usize), 0);
    bitmap_clear(page_idx);

    // Update first-fit hint if this page is earlier than the current hint.
    // `FIRST_AVAILABLE_PAGE` lowered to `page_idx` under `PAGE_LOCK`.
    let first = FIRST_AVAILABLE_PAGE.get();
    if page_idx < first {
        FIRST_AVAILABLE_PAGE.set(page_idx);
    }

    lock_release(PAGE_LOCK.as_ptr());
}

/// Take one more reference on the frame a caller addresses by VA.
///
/// The pointer is the same kind of value `kalloc`/`free_page` use — a direct-map
/// VA of a PMM-managed frame (a PTE's physical address goes through `p2v`
/// first) — because the refcount array is indexed physically.
pub fn page_ref_inc(ptr: *const u8) {
    let addr = v2p(ptr);
    if addr < reserved_end() as u64 { return; }
    let idx = addr_to_page(addr);
    if idx >= managed_frames() { return; }

    lock_acquire(PAGE_LOCK.as_ptr());
    // `PAGE_REFCOUNTS[idx]` read under `PAGE_LOCK`, taken above.
    let rc = kernel_rust::ptr::read(refcount_ptr().wrapping_add(idx as usize));
    // Same slot, still under `PAGE_LOCK`.
    kernel_rust::ptr::write(
        refcount_ptr().wrapping_add(idx as usize),
        rc.saturating_add(1),
    );
    lock_release(PAGE_LOCK.as_ptr());
}

/// Read the reference count of a page addressed by VA (as for
/// [`page_ref_inc`]) under `PAGE_LOCK`.
///
/// The lock guarantees that the value is not stale: `page_ref_inc` and
/// `free_page` both modify the count under the same lock, so holding it
/// here provides a sequentially-consistent view of the refcount.
pub fn page_ref_get(ptr: *const u8) -> u16 {
    let addr = v2p(ptr);
    if addr < reserved_end() as u64 { return 0; }
    let idx = addr_to_page(addr);
    if idx >= managed_frames() { return 0; }
    lock_acquire(PAGE_LOCK.as_ptr());
    // `PAGE_REFCOUNTS[idx]` read under `PAGE_LOCK`, which is held until after
    // the load, so the value cannot be changed in between.
    let rc = kernel_rust::ptr::read(refcount_ptr().wrapping_add(idx as usize));
    lock_release(PAGE_LOCK.as_ptr());
    rc
}

/// Read the reference count **without** acquiring `PAGE_LOCK`.  As for
/// [`page_ref_inc`], `ptr` is a VA of a PMM-managed frame.
///
/// # Safety
/// The caller **must** already hold `PAGE_LOCK`.  Use this inside a critical
/// section where the lock is acquired around a check-then-act sequence (e.g.
/// the COW sole-owner fast path in `vmm_handle_cow`).
pub(crate) fn page_ref_get_locked(ptr: *const u8) -> u16 {
    let addr = v2p(ptr);
    if addr < reserved_end() as u64 { return 0; }
    let idx = addr_to_page(addr);
    if idx >= managed_frames() { return 0; }
    // `PAGE_REFCOUNTS[idx]` read without taking `PAGE_LOCK`; that is this
    // function's documented contract — every caller already holds `PAGE_LOCK`.
    kernel_rust::ptr::read(refcount_ptr().wrapping_add(idx as usize))
}

/// Installed RAM the PMM recognised at boot, in 4 KiB frames (fixed after
/// `init_memory_manager`).  Includes the hard-reserved low region and the heap
/// window; callers subtract what they want to exclude.
#[unsafe(no_mangle)]
pub extern "C" fn pmm_total_frames() -> u32 {
    TOTAL_USABLE_FRAMES.get()
}

/// Frames currently on the free list (bit clear in the PMM bitmap), in 4 KiB
/// frames.  This excludes the low reservation and the heap window.
#[unsafe(no_mangle)]
pub extern "C" fn pmm_free_frames() -> u32 {
    let mut free: u32 = 0;
    lock_acquire(PAGE_LOCK.as_ptr());
    // The bitmap region (`bitmap_ptr()`/`bitmap_bytes()`) was carved out at
    // boot; read while holding `PAGE_LOCK`, which serialises it against every
    // bitmap writer (`init_memory_manager`, `kalloc`, `free_page`).
    let bm = kernel_rust::ptr::slice(bitmap_ptr(), bitmap_bytes() as usize);
    for b in bm.iter() {
        // A set bit means "in use"; the rest of the byte is free.
        free += 8 - b.count_ones();
    }
    lock_release(PAGE_LOCK.as_ptr());
    free
}

/// Live boot-reservation boundary in bytes: the `RESERVED_END` floor, raised by
/// `pmm_reserve_boot_images` past the Multiboot2 module images.  Nothing below
/// it is handed to `kalloc` or the heap.  Reported by /proc/meminfo as
/// `MemReserved`.
#[unsafe(no_mangle)]
pub extern "C" fn pmm_reserved_end() -> u32 {
    reserved_end()
}
