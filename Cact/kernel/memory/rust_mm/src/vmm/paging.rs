// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel page tables (four-level), the linear map of RAM, per-process maps,
//! and the C-exported VMM helpers.
//!
//! Long mode walks PML4 → PDPT → PD → PT, and every entry on the way is *eight*
//! bytes wide: the low bits carry the physical address and the flags, the top
//! bit NX.  The kernel's current address layout keeps every address below
//! 4 GiB, so the whole low half lives under `PML4[0]` and the kernel's own image
//! is reached through `PML4[511]`; RAM is mapped with 2 MiB pages (one page
//! directory per 1 GiB window), user mappings with 4 KiB pages, so a caller that
//! needs a page inside a 2 MiB mapping makes the walk split it into a page table
//! first — see [`walk`].

use crate::ffi::*;
use crate::safe::kprint_str;
use crate::pmm::{kalloc, free_page};

/// Number of entries in each level.
const TABLE_ENTRIES: usize = 512;

/// Index of the first PDPT entry that belongs to the kernel half of the 32-bit
/// address space (`USER_STACK_TOP` upwards).  Every process address space shares
/// that entry with the kernel: interrupt handlers, the heap and MMIO all have to
/// be reachable under any `CR3`, and no user mapping may claim it.
pub(crate) const PD_KERNEL_ENTRIES: usize = ((USER_STACK_TOP >> 30) & 0x1FF) as usize;

/// Virtual address at which the kernel image is linked.
const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// Base of the direct map: physical address `p` is reachable at
/// `DIRECT_MAP_BASE + p`.  This is PML4[256], the first entry of the canonical
/// upper half, away from both the low user half and the kernel image window, so
/// a frame the kernel reaches here can never be shadowed by a user mapping.
pub(crate) const DIRECT_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

#[repr(C, align(4096))]
struct Aligned4K<T>(T);

/// A page table: eight-byte entries, as the hardware reads them.
type Table = [u64; TABLE_ENTRIES];

/// The kernel's own address space — what `CR3` holds while the kernel runs.
///
/// The C side knows this symbol as `page_directory` and passes it to `vmm_map`,
/// `vmm_get_phys` and friends as "the kernel map"; in long mode that map's root
/// is the PML4, so the name in C predates the extra level but the meaning — the
/// kernel address space — is the same one.
#[no_mangle]
static mut page_directory: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// PML4[0]: the kernel's low half.  With the identity alias gone, exactly one
/// page is installed here — the AP trampoline (see [`PT_TRAMP`]) in window 0.
/// The kernel's fixed MMIO windows are added later at `PDPT_LOW[3]` (VAs
/// `0xC000_0000` and up) by `vmm_map`, and every process inherits these entries.
static mut PDPT_LOW: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// PML4[511]: the kernel's own image (physical `[0, reserved_end)`) at
/// `0xFFFFFFFF80000000`.  This is how the kernel reaches its code, data and
/// static tables — a distinct VA range, not an identity alias.
static mut PDPT_HIGH: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// The kernel-image window's page directory: physical `[0, 1 GiB)`, 2 MiB per
/// entry (only the boot reservation is present).
static mut PD_HIGH: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// The low window's page directory.  Only entry 0 is populated, pointing at
/// [`PT_TRAMP`]; the rest of the low half is reached through the direct map.
static mut PD_LOW: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// The low-half identity window's page table: the AP trampoline at `TRAMP_ADDR`
/// and the ACPI S3 wake trampoline at `WAKE_TRAMP_ADDR`.  A woken core starts
/// fetching at its physical address with the kernel's CR3 and reads its stack
/// and info block from the same page before jumping to the higher half, so those
/// pages cannot be reached through the direct map.  Supervisor-only, so no user
/// mapping can touch them.
static mut PT_TRAMP: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// PML4[256]: the direct map of physical memory at `DIRECT_MAP_BASE`.
static mut PDPT_DIRECT: Aligned4K<Table> = Aligned4K([0u64; TABLE_ENTRIES]);

/// The direct map's page directories — window `w` maps physical
/// `w GiB … (w+1) GiB`, mirroring the identity map's coverage.
static mut PD_DIRECT: Aligned4K<[Table; 4]> = Aligned4K([[0u64; TABLE_ENTRIES]; 4]);

/// Address of entry `idx` inside a page table.
///
/// Every level of the walk addresses its entries through here, so the tables'
/// *stride* — eight bytes, the width the hardware reads — lives in one place and
/// a walk cannot split an entry in half.
///
/// # Safety
///
/// `table` must point at a live table and `idx` must be below `TABLE_ENTRIES`.
#[inline(always)]
unsafe fn entry(table: *mut u64, idx: u32) -> *mut u64 {
    unsafe { table.add(idx as usize) }
}

/// Read entry `idx` of a page table.
///
/// # Safety
///
/// As [`entry`].
#[inline(always)]
pub(crate) unsafe fn entry_val(table: *const u64, idx: u32) -> u64 {
    unsafe { *entry(table as *mut u64, idx) }
}

/// Physical address behind a pointer the kernel can already dereference.
///
/// The kernel's own tables live in its image, in the higher half, and the PML4
/// maps that half so that physical `p` is reachable at `KERNEL_VMA + p`.  Page
/// tables want the physical side, so anything at or above the link base has the
/// base subtracted; everything below it is reached through the identity map and
/// is already physical.
#[inline(always)]
pub(crate) fn v2p<T>(ptr: *const T) -> u64 {
    let addr = ptr as u64;
    if addr >= KERNEL_VMA {
        addr - KERNEL_VMA
    } else if addr >= DIRECT_MAP_BASE {
        addr - DIRECT_MAP_BASE
    } else {
        addr
    }
}

/// Virtual address at which physical `phys` is reachable — the inverse of
/// [`v2p`].  Frames the kernel owns are addressed through the direct map.
#[inline(always)]
pub(crate) fn p2v(phys: u64) -> u64 {
    DIRECT_MAP_BASE + phys
}

/// C entry point: the physical address behind a pointer the kernel can
/// dereference (see [`v2p`]).
///
/// The C side uses this wherever a `kalloc`'d frame has to go into a page-table
/// entry; it is declared for C in `memory.h`.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_v2p(ptr: *const u8) -> u64 {
    v2p(ptr)
}

/// C entry point: the direct-map VA at which physical `phys` is reachable (see
/// [`p2v`]).
///
/// The C side uses this wherever an address out of a page-table entry — or out
/// of `vmm_get_phys` — has to be dereferenced; it is declared for C in
/// `memory.h`.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_p2v(phys: u64) -> *mut u8 {
    p2v(phys) as *mut u8
}

/// The kernel page map — the PML4 the C side knows as `page_directory`.
pub fn get_kernel_pd() -> *mut u64 {
    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference; the PML4 lives for the whole kernel lifetime and never moves.
    unsafe { core::ptr::addr_of_mut!(page_directory.0).cast::<u64>() }
}

/// The kernel page map as the table it really is.
fn kernel_table() -> *mut u64 {
    // SAFETY: as `get_kernel_pd`, for the table view.
    unsafe { core::ptr::addr_of_mut!(page_directory.0).cast::<u64>() }
}

fn as_table(pd: *mut u64) -> *mut u64 {
    pd
}

/// One descent through the page tables for a virtual address.
pub struct Walk {
    /// The PDPT entry for this address: 1 GiB granularity, the level at which
    /// the kernel's window is shared between every address space.
    pub pdpt_entry: *mut u64,
    /// The PD entry for this address: either a 2 MiB page or a page table.
    pub pd_entry: *mut u64,
    /// The page table `pd_entry` names, or null when it maps a 2 MiB page and
    /// the walk was not allowed to split it.
    pub pt: *mut u64,
    /// The page-table entry for this address, or null when `pt` is null.
    pub pte_entry: *mut u64,
}

/// Walk `pml4` down to the entry that maps `vaddr`.
///
/// With `create` the missing tables are allocated (from `kalloc`) and a 2 MiB
/// page in the way is *split* into a page table, so the caller can install a
/// 4 KiB mapping inside it; without it, an absent table or a large page is
/// simply reported (`pt`/`pte_entry` left null).
///
/// `private` says the caller is mapping into its *own* address space.  The
/// kernel's page tables are shared by every process (2 MiB pages, no
/// `PDE_PRIVATE`), so a private walk copies a shared page directory before
/// touching any of its entries — otherwise splitting one large page for one
/// process would punch a hole in the kernel's view for all of them.
///
/// # Safety
///
/// `pml4` must be null or a live page map that the caller owns and may mutate,
/// and no other CPU may be walking the same tables concurrently.
pub unsafe fn walk(pml4: *mut u64, vaddr: u64, create: bool, private: bool) -> Walk {
    let mut out = Walk {
        pdpt_entry: core::ptr::null_mut(),
        pd_entry: core::ptr::null_mut(),
        pt: core::ptr::null_mut(),
        pte_entry: core::ptr::null_mut(),
    };
    if pml4.is_null() {
        return out;
    }
    let root = as_table(pml4);

    // PML4 → PDPT.
    // SAFETY: `root` is a live 512-entry table and the index masks to 9 bits, so
    // this entry pointer is in bounds.
    let pml4_entry = unsafe { entry(root, pml4_index(vaddr)) };
    // SAFETY: in-bounds entry pointer, initialised.
    if unsafe { *pml4_entry } & PAGE_PRESENT as u64 == 0 {
        if !create {
            return out;
        }
        let pdpt = new_table();
        if pdpt.is_null() {
            return out;
        }
        // SAFETY: `pml4_entry` is in bounds; the fresh PDPT is recorded in it.
        // The entry takes the table's *physical* address, the table is a
        // direct-map VA — hence `v2p`.
        unsafe {
            *pml4_entry = v2p(pdpt) | PAGE_PRESENT as u64 | PAGE_RW as u64
                | if private { PDE_PRIVATE as u64 } else { 0 }
        };
    }
    // SAFETY: the entry is present and names a 4 KiB-aligned table, which the
    // kernel reaches through the direct map.
    let pdpt = unsafe { p2v(*pml4_entry & !0xFFF) as *mut u64 };

    // PDPT → PD.
    // SAFETY: `pdpt` is the live table from the PML4 entry and the index masks
    // to 9 bits.
    out.pdpt_entry = unsafe { entry(pdpt, pdpt_index(vaddr)) };
    // SAFETY: in-bounds entry pointer, initialised.
    let pdpt_val = unsafe { *out.pdpt_entry };
    if pdpt_val & PAGE_PRESENT as u64 == 0 {
        if !create {
            return out;
        }
        let pd = new_table();
        if pd.is_null() {
            return out;
        }
        // SAFETY: `out.pdpt_entry` is in bounds; the fresh page directory is
        // recorded in it, by its physical address (the table itself is a
        // direct-map VA).
        unsafe {
            *out.pdpt_entry = v2p(pd) | PAGE_PRESENT as u64 | PAGE_RW as u64
                | if private { PDE_PRIVATE as u64 } else { 0 }
        };
    } else if pdpt_val & PAGE_PS as u64 != 0 {
        // A 1 GiB page.  The kernel maps 2 MiB pages, so this is not a shape it
        // produces, and splitting down two levels is not something to guess at.
        return out;
    } else if private && pdpt_val & PDE_PRIVATE as u64 == 0 {
        // The kernel's own 1 GiB window.  Copy the page directory before
        // splitting anything in it: those entries are the kernel's identity map
        // (and every other process's), not this address space's to change.
        if !create {
            return out;
        }
        let shared = p2v(pdpt_val & !0xFFF) as *const u64;
        let pd = new_table();
        if pd.is_null() {
            return out;
        }
        // SAFETY: `shared` is the live 512-entry page directory named by the
        // present kernel entry and `pd` is the fresh table; distinct frames.
        unsafe { core::ptr::copy_nonoverlapping(shared, pd, TABLE_ENTRIES) };
        // SAFETY: `out.pdpt_entry` is in bounds; it now names the private copy
        // by its physical address.
        unsafe { *out.pdpt_entry = v2p(pd) | (pdpt_val & 0xFFF) | PDE_PRIVATE as u64 };
    }
    // SAFETY: the PDPT entry is present, is not a large page, and names a table
    // the kernel reaches through the direct map.
    let pd = unsafe { p2v(*out.pdpt_entry & !0xFFF) as *mut u64 };

    // PD → PT, or the 2 MiB page itself.
    // SAFETY: `pd` is the live page directory from the PDPT entry and the index
    // masks to 9 bits.
    out.pd_entry = unsafe { entry(pd, pd_index(vaddr)) };
    // SAFETY: in-bounds entry pointer, initialised.
    let pd_val = unsafe { *out.pd_entry };
    if pd_val & PAGE_PRESENT as u64 != 0 && pd_val & PAGE_PS as u64 != 0 {
        if !create {
            return out;
        }
        // SAFETY: `out.pd_entry` names a 2 MiB page covering this address; the
        // split allocates a table describing the same physical range.
        let pt = unsafe { split_large_page(out.pd_entry, private) };
        if pt.is_null() {
            return out;
        }
        // The 2 MiB entry this replaced is still in the TLB, and it covers all
        // 512 pages of the region — including the one the caller is about to
        // remap.  Without this flush a store to the newly mapped page keeps
        // going to the old translation (the identity frame the 2 MiB entry
        // named) until some unrelated CR3 load happens to drop it.
        crate::safe::flush_tlb(vaddr);
    } else if pd_val & PAGE_PRESENT as u64 == 0 {
        if !create {
            return out;
        }
        let pt = new_table();
        if pt.is_null() {
            return out;
        }
        // SAFETY: `out.pd_entry` is in bounds and the fresh table is recorded in
        // it, by its physical address, private when the caller is mapping in its
        // own space.
        unsafe {
            *out.pd_entry = v2p(pt) | PAGE_PRESENT as u64 | PAGE_RW as u64
                | if private { PDE_PRIVATE as u64 } else { 0 }
        };
    }

    // SAFETY: the PD entry is present, is not a large page any more, and names a
    // 512-entry page table the kernel reaches through the direct map.
    out.pt = unsafe { p2v(*out.pd_entry & !0xFFF) as *mut u64 };
    // SAFETY: `out.pt` is that live table and the index masks to 9 bits.
    out.pte_entry = unsafe { entry(out.pt, pt_index(vaddr)) };
    out
}

/// A fresh, zeroed page table, or null when the allocator is out of frames.
fn new_table() -> *mut u64 {
    let t = kalloc() as *mut u64;
    if t.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `t` is a fresh 4 KiB frame, so the 512-entry slice is in bounds
    // and exclusive.
    unsafe { core::slice::from_raw_parts_mut(t, TABLE_ENTRIES).fill(0) };
    t
}

/// Replace the 2 MiB page named by `pd_entry` with a page table mapping the
/// same physical range in 4 KiB pages, and return that table.
///
/// # Safety
///
/// `pd_entry` must point at a present PD entry with `PAGE_PS` set, inside a
/// table the caller owns.
unsafe fn split_large_page(pd_entry: *mut u64, private: bool) -> *mut u64 {
    // SAFETY: `pd_entry` is the caller's present large-page entry.
    let entry_value = unsafe { *pd_entry };
    let base = entry_value & !(LARGE_PAGE_SIZE as u64 - 1);
    let flags = (entry_value & 0xFFF) & !(PAGE_PS as u64);

    let pt = new_table();
    if pt.is_null() {
        kprint_str(c"[ERR] vmm: out of frames splitting a 2 MiB page\n".as_ptr() as *const u8);
        return core::ptr::null_mut();
    }
    // SAFETY: `pt` is the fresh 512-entry table; the fill covers all of it with
    // eight-byte entries whose low bits are the mapping.
    unsafe {
        for i in 0..TABLE_ENTRIES {
            *pt.add(i) = base + (i as u64) * PAGE_SIZE as u64 | flags | PAGE_PRESENT as u64;
        }
    }
    // SAFETY: `pd_entry` is in bounds; it now names the page table, by its
    // physical address, keeping the private mark so the teardown and fork paths
    // treat it as one of the caller's own tables.
    unsafe {
        *pd_entry = v2p(pt) | flags | PAGE_PRESENT as u64
            | if private { PDE_PRIVATE as u64 } else { 0 }
    };
    pt
}

/// Build the kernel's page tables: the identity map of the *boot reservation*
/// (the RAM the kernel image and the bootloader's modules occupy), the direct
/// map of all physical memory, and the kernel's own window at
/// `0xFFFFFFFF80000000`.
///
/// The identity map is deliberately limited to `[0, pmm::reserved_end())`.
/// Above it — managed RAM and device MMIO alike — the kernel reaches memory
/// only through the direct map, whose PML4 entry is shared by every address
/// space and lives in the upper half.  That is what lets a user VA window sit
/// anywhere without displacing the kernel's view of a live frame, which was the
/// sole reason `USER_FRAME_CEIL` existed.
fn build_kernel_map() {
    let ram_end = crate::pmm::ram_end();
    let reserved_end = crate::pmm::reserved_end() as u64;

    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference; the cast to `*mut u64` gives a one-entry stride.
    let pdpt_low = unsafe { core::ptr::addr_of_mut!(PDPT_LOW.0).cast::<u64>() };
    // SAFETY: as above.
    let pdpt_high = unsafe { core::ptr::addr_of_mut!(PDPT_HIGH.0).cast::<u64>() };
    // SAFETY: as above.
    let pml4 = unsafe { core::ptr::addr_of_mut!(page_directory.0).cast::<u64>() };

    // Kernel-image window: physical `[0, reserved_end)` at `KERNEL_VMA`, 2 MiB
    // write-back pages.  This is how the kernel reaches its own code, data and
    // static tables; the image sits in the first few MiB of the reservation.
    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference; the cast gives a one-entry stride.
    let pd_high = unsafe { core::ptr::addr_of_mut!(PD_HIGH.0).cast::<u64>() };
    for slot in 0..TABLE_ENTRIES {
        let phys = slot as u64 * LARGE_PAGE_SIZE as u64;
        // SAFETY: `slot < 512`, so this write is inside the static table.
        unsafe {
            *pd_high.add(slot) = if phys < reserved_end {
                phys | PAGE_PRESENT as u64 | PAGE_RW as u64 | PAGE_PS as u64
            } else {
                0
            }
        };
    }
    // SAFETY: `510 < 512`, so this PDPT entry is in bounds; the table is
    // recorded by its physical address.
    unsafe { *entry(pdpt_high, 510) = v2p(pd_high) | PAGE_PRESENT as u64 | PAGE_RW as u64 };

    // Identity map: two pages — the AP trampoline at `TRAMP_ADDR` and the ACPI
    // S3 wake trampoline at `WAKE_TRAMP_ADDR`.  They are the only things that
    // must be reachable at their physical address: a woken core (INIT-SIPI or
    // S3 resume) lands there with the kernel's CR3 and runs from it until it
    // jumps to the higher half.  Everything else in the low half goes through
    // the direct map.  Both addresses are inside the boot reservation and below
    // 2 MiB, so they fit window 0's first page directory entry; the pages are
    // supervisor-only.
    const TRAMP_ADDR: u64 = 0x8000;   // must match `smp.rs`
    const WAKE_TRAMP_ADDR: u64 = 0xA000;   // must match `power.c`
    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference; the cast gives a one-entry stride.
    let pt_tramp = unsafe { core::ptr::addr_of_mut!(PT_TRAMP.0).cast::<u64>() };
    for slot in 0..TABLE_ENTRIES {
        // SAFETY: `slot < 512`, so this write is inside the static table.
        unsafe { *pt_tramp.add(slot) = 0 };
    }
    // SAFETY: `(TRAMP_ADDR >> 12) < 512`, so this PTE is in bounds.
    unsafe {
        *pt_tramp.add((TRAMP_ADDR >> 12) as usize) =
            TRAMP_ADDR | PAGE_PRESENT as u64 | PAGE_RW as u64
    };
    // SAFETY: `(WAKE_TRAMP_ADDR >> 12) < 512`, so this PTE is in bounds.
    unsafe {
        *pt_tramp.add((WAKE_TRAMP_ADDR >> 12) as usize) =
            WAKE_TRAMP_ADDR | PAGE_PRESENT as u64 | PAGE_RW as u64
    };
    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference (the same one-entry stride as above).
    let pd_low = unsafe { core::ptr::addr_of_mut!(PD_LOW.0).cast::<u64>() };
    for slot in 0..TABLE_ENTRIES {
        // SAFETY: `slot < 512`, so this write is inside the static table.
        unsafe { *pd_low.add(slot) = 0 };
    }
    // A 4 KiB page-directory entry for `[0, 2 MiB)`, so window 0 slot 0's single
    // mapped page lives in `PT_TRAMP` (all other slots stay absent).
    // SAFETY: `0 < 512`, so this PDE is in bounds.
    unsafe { *pd_low = v2p(pt_tramp) | PAGE_PRESENT as u64 | PAGE_RW as u64 };
    // SAFETY: `0 < 512`, so this PDPT entry is in bounds.
    unsafe { *entry(pdpt_low, 0) = v2p(pd_low) | PAGE_PRESENT as u64 | PAGE_RW as u64 };

    // Direct map: every managed physical address at `DIRECT_MAP_BASE`, so the
    // kernel can address a frame — or a device register — without an alias in
    // the low (user) half.  The low four 1 GiB windows use the static tables;
    // any RAM above 4 GiB gets a page directory from `kalloc` (whose frames live
    // below the low RAM top, already covered by the direct map in force).
    // SAFETY: `addr_of_mut!` projects the address of the static table without
    // forming a reference; the cast to `*mut u64` makes the stride one entry.
    let pd_direct = unsafe { core::ptr::addr_of_mut!(PD_DIRECT.0).cast::<u64>() };
    // SAFETY: `addr_of_mut!` projects the address of the static without forming
    // a reference.
    let pdpt_direct = unsafe { core::ptr::addr_of_mut!(PDPT_DIRECT.0).cast::<u64>() };
    let map_end = core::cmp::max(LOW_MEM_END, crate::pmm::max_ram_addr());
    let windows_needed =
        (((map_end + (1u64 << 30) - 1) >> 30) as usize).min(TABLE_ENTRIES);
    for w in 0..windows_needed {
        let table: *mut u64 = if w < 4 {
            // SAFETY: `w < 4`, so `w` tables into the static array is in bounds.
            unsafe { pd_direct.add(w * TABLE_ENTRIES) }
        } else {
            let t = new_table();
            if t.is_null() {
                break;
            }
            t
        };
        for slot in 0..TABLE_ENTRIES {
            let phys = (w * TABLE_ENTRIES + slot) as u64 * LARGE_PAGE_SIZE as u64;
            // Device space — the 32-bit PCI hole — must not be cached, or a
            // register read would be served from cache.  Above 4 GiB the map is
            // RAM again.
            let cache = if phys >= ram_end && phys < LOW_MEM_END {
                PAGE_PCD | PAGE_PWT
            } else {
                0
            };
            // SAFETY: `table` is a live 512-entry table (static, or a fresh
            // kalloc'd frame) and `slot < 512`, so this write is in bounds.
            unsafe {
                *table.add(slot) = phys | PAGE_PRESENT as u64 | PAGE_RW as u64
                    | PAGE_PS as u64 | cache as u64
            };
        }
        // SAFETY: `w < TABLE_ENTRIES`, so this PDPT entry is in bounds; the
        // table is recorded by its physical address.
        unsafe { *entry(pdpt_direct, w as u32) = v2p(table) | PAGE_PRESENT as u64 | PAGE_RW as u64 };
    }

    // 0xFFFFFFFF80000000 is PML4[511] (the image); PML4[256] carries the direct
    // map (0xFFFF800000000000); PML4[0] keeps the low half — the trampoline page
    // plus the kernel MMIO windows installed later by `vmm_map`.
    // SAFETY: the PML4 entries are in bounds and their tables are initialised
    // above.
    unsafe {
        *entry(pml4, 0) = v2p(pdpt_low) | PAGE_PRESENT as u64 | PAGE_RW as u64;
        *entry(pml4, 256) = v2p(pdpt_direct) | PAGE_PRESENT as u64 | PAGE_RW as u64;
        *entry(pml4, 511) = v2p(pdpt_high) | PAGE_PRESENT as u64 | PAGE_RW as u64;
    }
}

/// Build the kernel's map and make it current.
#[unsafe(no_mangle)]
pub extern "C" fn init_paging() {
    build_kernel_map();

    // Paging may already be on (the boot bootstrap turned it on with its own
    // tables); loading this PML4 swaps in the real map, and `enable_paging` is
    // then a no-op.  CR3 takes a *physical* address, and this table lives in the
    // kernel image — hence the translation.
    // SAFETY: this is the one-time, single-threaded boot sequence, and the new
    // map covers everything the bootstrap's did — the kernel image through
    // PML4[511], RAM and MMIO through the identity map.
    unsafe { load_page_directory(v2p(kernel_table()) as *mut u64) };
    // SAFETY: as above — paging is enabled once, right after the map is loaded.
    unsafe { enable_paging() };
}

/// Keep one address space's view of the kernel's shared mappings in step with
/// the kernel template.
///
/// Two things are shared: the kernel's own PML4 entry (its image) and the low
/// half's kernel window, which is shared at the PDPT level so that a mapping
/// installed later appears everywhere.
///
/// # Safety
///
/// `pd` must be null or a live page map the caller owns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_sync_kernel_mmio_mappings(pd: *mut u64) {
    if pd.is_null() {
        return;
    }
    let src = kernel_table();
    let dst = as_table(pd);
    if core::ptr::eq(dst, src) {
        return;
    }
    // SAFETY: both are live 512-entry tables and distinct frames; only one is
    // written.
    unsafe {
        // The kernel's high half must be identical everywhere: it is how the
        // kernel reaches its own code and data under a process CR3 (entry 511,
        // the image) and its frames (entry 256, the direct map).
        *entry(dst, 511) = entry_val(src, 511);
        *entry(dst, 256) = entry_val(src, 256);
        let dst_low = entry_val(dst, 0);
        let src_low = entry_val(src, 0);
        if dst_low & PAGE_PRESENT as u64 == 0
            || dst_low & PAGE_PS as u64 != 0
            || src_low & PAGE_PRESENT as u64 == 0
        {
            return;
        }
        let dst_pdpt = p2v(dst_low & !0xFFF) as *mut u64;
        let src_pdpt = p2v(src_low & !0xFFF) as *const u64;
        for i in PD_KERNEL_ENTRIES..TABLE_ENTRIES {
            // SAFETY: both PDPTs are live 512-entry tables and `i` is in bounds.
            *entry(dst_pdpt, i as u32) = entry_val(src_pdpt, i as u32);
        }
    }
}

/// # Safety
///
/// `pd` must be null or a live page map the caller owns and may mutate; the
/// caller must serialise concurrent mapping changes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_map(pd: *mut u64, virtual_addr: u64, physical_addr: u64, flags: i32) {
    if pd.is_null() {
        return;
    }
    if virtual_addr % PAGE_SIZE as u64 != 0 || physical_addr % PAGE_SIZE as u64 != 0 {
        kprint_str(c"[ERR] vmm_map: addresses not page-aligned\n".as_ptr() as *const u8);
        return;
    }

    let mut flags = flags as u32;
    let caller_uncached = flags & (PAGE_PCD | PAGE_PWT) != 0;
    if physical_addr >= crate::pmm::ram_end() {
        flags |= PAGE_PCD | PAGE_PWT;
    }
    // The user stack is pushed into from user mode: a present user page without
    // R/W would fault with #PF err=0x07 on the first store.
    if (USER_STACK_LIMIT as u64..USER_STACK_TOP as u64).contains(&virtual_addr)
        && flags & PAGE_USER != 0
    {
        flags |= PAGE_RW;
    }
    // A user mapping must never land in the kernel half: that PDPT entry is
    // shared by every address space, so a page installed there would be visible
    // to — and writable by — every process.
    if flags & PAGE_USER != 0 && virtual_addr >= USER_STACK_TOP as u64 {
        kprint_str(c"[ERR] vmm_map: refusing user mapping in kernel half\n".as_ptr() as *const u8);
        return;
    }

    // A mapping the kernel shares — the kernel half, or uncacheable device
    // memory wherever firmware placed it — belongs to the kernel's own tables,
    // so that interrupt handlers and every process see it.
    let is_kernel_mmio = virtual_addr >= USER_STACK_TOP as u64 || caller_uncached;

    // SAFETY: `pd` is a live page map (checked non-null); the walk creates what
    // it needs and copies a shared page directory before touching it when this
    // is a private mapping.
    let w = unsafe { walk(pd, virtual_addr, true, !is_kernel_mmio) };
    if w.pte_entry.is_null() {
        kprint_str(c"[ERR] vmm_map: walk failed\n".as_ptr() as *const u8);
        return;
    }
    // SAFETY: `w.pte_entry` is an in-bounds page-table entry.
    let old_pte = unsafe { *w.pte_entry };
    // Release the old COW frame if this mapping replaces it.
    if old_pte & PAGE_PRESENT as u64 != 0
        && old_pte & PAGE_COW as u64 != 0
        && (old_pte & !0xFFF) != (physical_addr & !0xFFF)
    {
        // SAFETY: the frame is live and PMM-managed; this releases exactly one
        // reference to it.  The entry names a physical address, which the
        // allocator wants as a VA.
        unsafe { free_page(p2v(old_pte & !0xFFF) as *mut u8) };
    }
    if is_kernel_mmio || flags & PAGE_USER != 0 {
        // The permission bits have to reach the levels above the page table as
        // well, because a process map points straight at them and a user access
        // checks U/S at *every* level: a supervisor-only PDPTE/PDE faults with
        // #PF err=0x05 even though the leaf itself allows the access.  A shared
        // kernel/MMIO entry carries no private bit; a user entry belongs to this
        // address space alone.
        // SAFETY: both entry pointers are in bounds (the walk created the path).
        unsafe {
            *w.pd_entry |= (flags & (PAGE_USER | PAGE_RW)) as u64;
            *w.pdpt_entry |= (flags & (PAGE_USER | PAGE_RW)) as u64;
        }
    }
    // SAFETY: `w.pte_entry` receives the mapping.
    unsafe { *w.pte_entry = (physical_addr & !0xFFF) | flags as u64 | PAGE_PRESENT as u64 };
    // Whatever this VA translated to before (an inherited identity entry, a
    // mapping being replaced, a 2 MiB page this walk just split) is still in the
    // TLB and would keep serving accesses to the old frame.
    crate::safe::flush_tlb(virtual_addr);

    // A new kernel/MMIO mapping must also appear in the address space loaded
    // right now, or a driver would fault inside IRQ context before the next
    // switch.
    if pd == get_kernel_pd() && is_kernel_mmio {
        let active = crate::safe::current_page_dir();
        if !active.is_null() && active != pd {
            // SAFETY: `active` is the page map currently loaded in CR3, owned by
            // this CPU right now.
            unsafe { vmm_sync_kernel_mmio_mappings(active) };
        }
    }
}

/// Translate a virtual address to a physical one under `pd` (the kernel's map
/// when `pd` is null).  Returns 0 when the mapping is absent; the page offset is
/// preserved.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_get_phys(pd: *mut u64, virtual_addr: u64) -> u64 {
    let pml4 = if pd.is_null() { get_kernel_pd() } else { pd };
    if pml4.is_null() {
        return 0;
    }
    // SAFETY: `pml4` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    let w = unsafe { walk(pml4, virtual_addr, false, false) };
    if !w.pd_entry.is_null() {
        // SAFETY: `w.pd_entry` is an in-bounds PD entry.
        let pd_val = unsafe { *w.pd_entry };
        if pd_val & PAGE_PRESENT as u64 != 0 && pd_val & PAGE_PS as u64 != 0 {
            return large_page_phys(pd_val, virtual_addr);
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
    (pte & !0xFFF) | page_offset(virtual_addr)
}

/// Report the low flag bits of the mapping for `virtual_addr` under `pd` (0 when
/// the address is unmapped).  The fault and diagnostic paths need the permission
/// bits — is it present, user, writable — not the frame the mapping names.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_pte_flags(pd: *mut u64, virtual_addr: u64) -> u32 {
    let pml4 = if pd.is_null() { get_kernel_pd() } else { pd };
    if pml4.is_null() {
        return 0;
    }
    // SAFETY: `pml4` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    let w = unsafe { walk(pml4, virtual_addr, false, false) };
    if !w.pd_entry.is_null() {
        // SAFETY: `w.pd_entry` is an in-bounds PD entry.
        let pd_val = unsafe { *w.pd_entry };
        if pd_val & PAGE_PRESENT as u64 != 0 && pd_val & PAGE_PS as u64 != 0 {
            return (pd_val & 0xFFF) as u32;
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
    (pte & 0xFFF) as u32
}

/// Clear the 4 KiB mapping for `virtual_addr` under `pd` and return the physical
/// address that was mapped (0 when the address was not mapped, or when it is
/// covered by a 2 MiB page rather than a page table).
///
/// # Safety
///
/// `pd` must be a live page map the caller owns and may mutate, and no other CPU
/// may be walking the same tables concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_unmap(pd: *mut u64, virtual_addr: u64) -> u64 {
    if pd.is_null() {
        return 0;
    }
    // SAFETY: `pd` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated.
    let w = unsafe { walk(pd, virtual_addr, false, false) };
    if w.pte_entry.is_null() {
        return 0;
    }
    // SAFETY: `w.pte_entry` is an in-bounds page-table entry.
    let pte = unsafe { *w.pte_entry };
    if pte & PAGE_PRESENT as u64 == 0 {
        return 0;
    }
    // SAFETY: `w.pte_entry` is the live entry for this address; clearing it
    // removes the mapping.
    unsafe { *w.pte_entry = 0 };
    // SAFETY: invalidating one TLB entry is side-effect-free otherwise.
    crate::safe::flush_tlb(virtual_addr);
    pte & !0xFFF
}

/// Set and clear cache-attribute bits on the kernel mapping for `va`.
///
/// The kernel's own window is mapped with 2 MiB pages, so the entry that carries
/// the cache policy is the *page-directory* one, not a PTE; this walks to
/// whichever of the two describes `va` and rewrites it.  pat.c uses it to make
/// the framebuffer write-combining (PAT set, PCD/PWT clear).
///
/// The PAT bit is *not* in the same place at both shapes.  A 4 KiB PTE carries
/// it in bit 7; in a 2 MiB (or 1 GiB) entry bit 7 is `PAGE_PS` and the PAT
/// selection moved to bit 12.  The caller passes the PTE bit (bit 7) — the only
/// value a page-table entry can carry — so when the walk lands on a large page
/// this re-targets it to bit 12.  Without that, `(PAT=1, PCD=0, PWT=0)` becomes
/// `(PAT=0, PCD=0, PWT=0)`: the request clears PCD/PWT and quietly selects PAT
/// entry 0 (write-back) instead of entry 4 (write-combining), which on real
/// device memory means read-for-ownership traffic against MMIO.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_set_kernel_cache(va: u64, set: u64, clear: u64) {
    /// PAT bit in a 4 KiB page-table entry.
    const PTE_PAT: u64 = 0x080;
    /// PAT bit in a 2 MiB / 1 GiB large-page entry (bit 7 there is `PAGE_PS`).
    const LARGE_PAT: u64 = 0x1000;

    // SAFETY: the kernel's own map is a live page map; the walk only reads it.
    let w = unsafe { walk(get_kernel_pd(), va, false, false) };
    // A non-null PTE is a 4 KiB mapping; with none, the relevant entry is the
    // page-directory one — a 2 MiB large page when present (`walk` reports a
    // page table through `pte_entry`, so an absent PTE means large or absent).
    let (which, large_page) = if !w.pte_entry.is_null() {
        (w.pte_entry, false)
    } else {
        (w.pd_entry, true)
    };
    if which.is_null() {
        return;
    }
    // SAFETY: `which` is an in-bounds entry of the kernel's own tables.
    if unsafe { *which } & PAGE_PRESENT as u64 == 0 {
        return;
    }
    let (set, clear) = if large_page {
        (
            if set & PTE_PAT != 0 { (set & !PTE_PAT) | LARGE_PAT } else { set },
            if clear & PTE_PAT != 0 { (clear & !PTE_PAT) | LARGE_PAT } else { clear },
        )
    } else {
        (set, clear)
    };
    // SAFETY: `which` is an in-bounds, present entry of the kernel's own tables.
    unsafe { *which = (*which | set) & !clear };
}

/// A fresh address space: the kernel's own view of the high half, and a private
/// copy of the low half's page-directory-pointer table so that user mappings can
/// carve into it without touching the kernel's.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_create_address_space() -> *mut u64 {
    let pml4 = new_table();
    if pml4.is_null() {
        return core::ptr::null_mut();
    }
    let kernel = kernel_table();
    // SAFETY: `kernel` is the live kernel PML4 and `pml4` the fresh map just
    // checked non-null; the two are distinct frames.  The kernel image (511) and
    // the direct map (256) are shared verbatim.
    unsafe {
        *entry(pml4, 511) = entry_val(kernel, 511);
        *entry(pml4, 256) = entry_val(kernel, 256);
    }

    let pdpt = new_table();
    if pdpt.is_null() {
        // SAFETY: `pml4` is the fresh frame; without a PDPT it is useless.
        unsafe { free_page(pml4 as *mut u8) };
        return core::ptr::null_mut();
    }
    // SAFETY: `kernel` is the live kernel PML4, `pdpt` the fresh table.
    let kernel_low = unsafe { entry_val(kernel, 0) };
    if kernel_low & PAGE_PRESENT as u64 != 0 {
        let src = p2v(kernel_low & !0xFFF) as *const u64;
        // SAFETY: `src` is the kernel's live low PDPT and `pdpt` is the fresh
        // one; both span 512 entries and do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(src, pdpt, TABLE_ENTRIES) };
        // The copied entries *name the kernel's tables*, not this address
        // space's.  `walk` treats an entry that lacks `PDE_PRIVATE` as shared
        // and copies the table before touching it; an entry that kept the
        // kernel's private mark makes a user mapping carve straight into the
        // kernel's page directory — replacing the kernel's own view of the RAM
        // it reaches through that identity map.  The kernel then faults on its
        // own memory, or silently writes into user data.
        for i in 0..TABLE_ENTRIES {
            // SAFETY: `pdpt` is the fresh 512-entry table just filled, so `i`
            // is in bounds.
            unsafe { *pdpt.add(i) &= !(PDE_PRIVATE as u64) };
        }
    }
    // SAFETY: `pml4` is the fresh map; entry 0 takes the private PDPT, by its
    // physical address.  It carries PAGE_USER because the low half is where user
    // mappings live, and a user access needs U/S set at every level — starting
    // with this one.  The kernel's own low-half leaves (the AP trampoline) stay
    // supervisor-only, so the effective permission there is unchanged.
    unsafe {
        *entry(pml4, 0) =
            v2p(pdpt) | PAGE_PRESENT as u64 | PAGE_RW as u64 | PAGE_USER as u64
                | PDE_PRIVATE as u64
    };
    pml4
}

/// # Safety
///
/// `pd` must be null or a page map previously handed out by
/// `vmm_create_address_space`, and must not be used again afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_free_address_space(pd: *mut u64) {
    if pd.is_null() {
        return;
    }
    let root = as_table(pd);
    // SAFETY: `root` is the caller's live page map (512 entries).
    let low = unsafe { entry_val(root, 0) };
    if low & PAGE_PRESENT as u64 == 0 || low & PDE_PRIVATE as u64 == 0 {
        // The kernel's own map, or a map that was never made private: nothing
        // here is the caller's to release.
        return;
    }
    let pdpt = p2v(low & !0xFFF) as *mut u64;
    for i in 0..PD_KERNEL_ENTRIES {
        // SAFETY: the PDPT belongs to this map and `i` is in bounds.
        let pd_val = unsafe { entry_val(pdpt, i as u32) };
        if pd_val & PAGE_PRESENT as u64 == 0 || pd_val & PDE_PRIVATE as u64 == 0 {
            // The kernel window, or a page directory this map never copied.
            continue;
        }
        if pd_val & PAGE_PS as u64 != 0 {
            continue;
        }
        let pdt = p2v(pd_val & !0xFFF) as *mut u64;
        for j in 0..TABLE_ENTRIES {
            // SAFETY: the page directory is private to this map and `j` is in
            // bounds.
            let pd_entry_val = unsafe { entry_val(pdt, j as u32) };
            if pd_entry_val & PAGE_PRESENT as u64 == 0
                || pd_entry_val & PAGE_PS as u64 != 0
                || pd_entry_val & PDE_PRIVATE as u64 == 0
            {
                continue;
            }
            let pt = p2v(pd_entry_val & !0xFFF) as *mut u64;
            for k in 0..TABLE_ENTRIES {
                // SAFETY: the page table is private to this map and `k` is in
                // bounds.
                let pte = unsafe { entry_val(pt, k as u32) };
                // Only user pages are per-process; the rest belong to the PMM's
                // own accounting and must not be freed a second time.  The
                // entry names a physical address, which `free_page` wants as a
                // direct-map VA.
                if pte & PAGE_PRESENT as u64 != 0 && pte & PAGE_USER as u64 != 0 {
                    // SAFETY: the frame is live and PMM-managed; this releases
                    // one reference to it.
                    unsafe { free_page(p2v(pte & !0xFFF) as *mut u8) };
                }
            }
            // SAFETY: the table was kalloc'd for this map, so `pt` is already a
            // direct-map VA.
            unsafe { free_page(pt as *mut u8) };
        }
        // SAFETY: the page directory was kalloc'd for this map.
        unsafe { free_page(pdt as *mut u8) };
    }
    // SAFETY: the PDPT was kalloc'd for this map.
    unsafe { free_page(pdpt as *mut u8) };
    // SAFETY: the PML4 was kalloc'd by `vmm_create_address_space`.
    unsafe { free_page(pd as *mut u8) };
}

/// # Safety
///
/// `src_pd` and `dst_pd` must be null or live page maps owned by the caller,
/// and neither may be mutated concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vmm_copy_address_space(src_pd: *mut u64, dst_pd: *mut u64) {
    if src_pd.is_null() || dst_pd.is_null() {
        return;
    }
    let src_root = as_table(src_pd);
    let dst_root = as_table(dst_pd);

    // SAFETY: both are live page maps and distinct frames.
    unsafe {
        // The kernel half is shared verbatim: the image (511) and the direct
        // map (256).
        *entry(dst_root, 511) = entry_val(src_root, 511);
        *entry(dst_root, 256) = entry_val(src_root, 256);

        let src_low = entry_val(src_root, 0);
        let dst_low = entry_val(dst_root, 0);
        if src_low & PAGE_PRESENT as u64 == 0 || dst_low & PAGE_PRESENT as u64 == 0 {
            return;
        }
        let src_pdpt = p2v(src_low & !0xFFF) as *const u64;
        let dst_pdpt = p2v(dst_low & !0xFFF) as *mut u64;

        for i in 0..PD_KERNEL_ENTRIES {
            let src_pd_val = entry_val(src_pdpt, i as u32);
            if src_pd_val & PAGE_PRESENT as u64 == 0 || src_pd_val & PDE_PRIVATE as u64 == 0 {
                // Shared kernel window: copy the reference, not the data.
                *entry(dst_pdpt, i as u32) = src_pd_val;
                continue;
            }
            let src_pdt = p2v(src_pd_val & !0xFFF) as *const u64;
            let dst_pd = new_table();
            if dst_pd.is_null() {
                continue;
            }
            for j in 0..TABLE_ENTRIES {
                let src_entry = entry_val(src_pdt, j as u32);
                if src_entry & PAGE_PRESENT as u64 == 0
                    || src_entry & PAGE_PS as u64 != 0
                    || src_entry & PDE_PRIVATE as u64 == 0
                {
                    // Absent, a large page (shared by construction), or a shared
                    // kernel table: copy the reference as-is.
                    *entry(dst_pd, j as u32) = src_entry;
                    continue;
                }
                let src_pt = p2v(src_entry & !0xFFF) as *const u64;
                let dst_pt = new_table();
                if dst_pt.is_null() {
                    continue;
                }
                for k in 0..TABLE_ENTRIES {
                    let src_pte = entry_val(src_pt, k as u32);
                    if src_pte & PAGE_PRESENT as u64 == 0 || src_pte & PAGE_USER as u64 == 0 {
                        continue;
                    }
                    let new_page = kalloc();
                    if new_page.is_null() {
                        continue;
                    }
                    // SAFETY: `src_pte` names a present frame (reached through
                    // the direct map) and `new_page` is a fresh 4 KiB frame, so
                    // the copy is in bounds.
                    core::ptr::copy_nonoverlapping(
                        p2v(src_pte & !0xFFF) as *const u8,
                        new_page,
                        PAGE_SIZE as usize,
                    );
                    // Both the destination table and the copied frame go into
                    // the entry by physical address.
                    *entry(dst_pt, k as u32) = (v2p(new_page) & !0xFFF) | (src_pte & 0xFFF);
                }
                *entry(dst_pd, j as u32) = (v2p(dst_pt) & !0xFFF) | (src_entry & 0xFFF);
            }
            *entry(dst_pdpt, i as u32) = (v2p(dst_pd) & !0xFFF) | (src_pd_val & 0xFFF);
        }
    }
}
