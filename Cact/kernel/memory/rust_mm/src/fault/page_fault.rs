// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! x86 `#PF` handler logic: COW, demand zero, swap-in, guard `CR3` during PTE walks.

use crate::ffi::*;
use crate::pmm::{kalloc, free_page, page_ref_get_locked, PAGE_LOCK};
use crate::vmm::paging::{get_kernel_pd, vmm_map, p2v, v2p};
use crate::fault::swap::{swap_pte_is_swapped, swap_handle_fault};
use crate::fault::oom::oom_kill;
use crate::safe::{KStatic, zero_page, flush_tlb, kprint_str, read_cr2_val, current_page_dir};

/// Switch to the kernel page directory for the rest of this fault handler so PTE
/// walks cannot recurse with user `CR3` when the faulting `pd` omits its own tables.
struct Cr3Guard {
    saved: u64,
    restore: bool,
}

impl Cr3Guard {
    fn install_kernel_pd() -> Self {
        let saved: u64;
        // SAFETY: reading CR3 is side-effect-free.
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) saved, options(nomem, nostack)) };
        // CR3 takes the physical address of the page map, and the kernel's map
        // lives in its image in the higher half — hence the translation.
        let k = crate::vmm::paging::v2p(get_kernel_pd()) as u64;
        // SAFETY: the kernel page map covers the kernel image and all of RAM;
        // loading it in is what makes the map current.
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) k, options(nomem, nostack)) };
        Self { saved, restore: true }
    }

    /// Put the interrupted address space back, leaving the kernel map behind.
    /// The kernel map is installed to keep the PTE walks of the fault itself
    /// safe, but everything after the fault is resolved runs on behalf of the
    /// *task* and writes its memory — the signal frame on the user stack,
    /// `clear_child_tid` — and those must go through the task's own page tables.
    /// Left as the kernel map, such a store lands in the kernel's identity view
    /// of that address instead of the task's frame (or faults inside the fault
    /// handler, which recurses).
    fn restore_address_space(&mut self) {
        if !self.restore {
            return;
        }
        // SAFETY: `saved` was read from CR3 in `install_kernel_pd` and the map
        // it names is still live (the task has not been switched away).
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) self.saved, options(nomem, nostack)) };
        self.restore = false;
    }
}

impl Drop for Cr3Guard {
    fn drop(&mut self) {
        if self.restore {
            // SAFETY: `saved` was read from CR3 at handler entry; valid for restore before iret.
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) self.saved, options(nomem, nostack)) };
        }
    }
}

/// Walk to the page-table entry for a user address, creating the tables it
/// needs (a split included) as tables private to this address space.
///
/// # Safety
///
/// `pd` must point at a live page map that the caller owns and may mutate, and
/// the caller must serialise page-table changes.
pub(crate) unsafe fn ensure_private_pte(pd: *mut u64, va: u64, extra_flags: u32) -> *mut u64 {
    if pd.is_null() || va >= USER_STACK_TOP as u64 {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller guarantees `pd` is a live page map it owns; `create`
    // makes the walk allocate the missing levels and split a large page, marked
    // private because this is the caller's own address space.
    let w = crate::vmm::paging::walk(pd, va, true, true);
    if w.pte_entry.is_null() {
        return core::ptr::null_mut();
    }
    // The user bit has to reach the levels above the page table as well, or the
    // CPU would fault on a ring-3 access with #PF err=0x07.
    if !w.pd_entry.is_null() {
        // SAFETY: `w.pd_entry` is an in-bounds PD entry.
        unsafe { *w.pd_entry |= (extra_flags & (PAGE_USER | PAGE_RW)) as u64 };
    }
    if !w.pdpt_entry.is_null() {
        // SAFETY: `w.pdpt_entry` is an in-bounds PDPT entry.
        unsafe { *w.pdpt_entry |= (extra_flags & (PAGE_USER | PAGE_RW)) as u64 };
    }
    w.pte_entry
}

static G_STATS: KStatic<PfStats> = KStatic::new(PfStats {
    total_faults: 0,
    demand_allocs: 0,
    cow_copies: 0,
    stack_grows: 0,
    zero_pages: 0,
    swap_ins: 0,
    protection_faults: 0,
    invalid_access: 0,
});

const PF_PRESENT: u32 = 0x01;
const PF_WRITE: u32 = 0x02;
const PF_USER_BIT: u32 = 0x04;

pub(crate) fn pte_get(pd: *mut u64, vaddr: u64) -> *mut u64 {
    if pd.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `pd` is a live page map and the walk only reads it (`create`
    // false), so nothing is allocated or mutated.
    crate::vmm::paging::walk(pd, vaddr, false, false).pte_entry
}

fn kill_current(fault_addr: u64, _err: u32, _rip: u64, regs: *mut ContextFrame, cr3: &mut Cr3Guard) {
    // The fault is resolved (or not) already; from here everything runs on the
    // task's behalf and may write its memory, so put its address space back.
    cr3.restore_address_space();

    dump_context_frame(regs, fault_addr, SIGSEGV);

    let t = cact_current_task_get();
    // SAFETY: `t` is non-null here and points to a live `TaskStruct`.
    if !t.is_null() && unsafe { (*t).is_kernel } == 0 {
        // SAFETY: `(*t).pid` of the live current task.
        let pid = unsafe { (*t).pid };
        // SAFETY: diagnostic counter — `G_STATS` is written only from this #PF handler,
        // which runs with interrupts disabled on this CPU.  Note: not serialised
        // across CPUs; a lost increment is harmless.
        (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).protection_faults += 1;
        task_signal_code(pid, SIGSEGV, SI_KERNEL, fault_addr);
        // Act on the signal on this very frame instead of waiting for a syscall
        // return that a faulting instruction never reaches: a default
        // disposition marks the task a Zombie *before* `schedule` parks it — a
        // Zombie is left unqueued, so the faulting instruction is never
        // re-executed.  Delivering a *handler* is left to `deliver_pending_signal`
        // on the syscall-return path, where the frame it builds on the user
        // stack belongs; doing it here means writing user memory from inside the
        // fault handler.
        task_handle_signals(t);
        schedule();
        return;
    }

    // SAFETY: diagnostic counter — see the note above: `G_STATS` is only updated
    // from the #PF handler, unsynchronised across CPUs but harmless.
    (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).protection_faults += 1;
    printk_color(
        c"[PF] KERNEL PAGE FAULT \u{2014} SYSTEM HALTED\n".as_ptr() as *const u8,
        COLOR_LIGHT_RED,
    );
    // SAFETY: a kernel page fault on the boot path has no recovery; spin in `hlt`
    // forever on this CPU.
    unsafe {
        loop {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn page_fault_init() {
    // SAFETY: zeroing the stats struct at boot time, no concurrency.
    unsafe {
        core::ptr::write_bytes(G_STATS.as_ptr() as *mut u8, 0, core::mem::size_of::<PfStats>());
    }
}

/// # Safety
///
/// `regs` must point to the live interrupt frame the CPU pushed for this #PF
/// (a fully valid `ContextFrame`), and the caller must be the IDT vector entry
/// running with interrupts disabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn page_fault_handler(regs: *mut ContextFrame) {
    let fault_addr = read_cr2_val();
    // SAFETY: regs is provided by the interrupt frame.
    // The error code itself is 32 bits wide (bits above 15 are reserved zero);
    // only the word that carries it in the frame is 64-bit.
    let err = unsafe { (*regs).err_code } as u32;
    // SAFETY: `regs` is the interrupt frame handed to the #PF handler.  RIP is a
    // full 64-bit address in long mode.
    let eip = unsafe { (*regs).rip };

    // SAFETY: `G_STATS.total_faults` bumped from the #PF handler; interrupts are
    // disabled on this CPU, and a cross-CPU lost count is only cosmetic.
    (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).total_faults += 1;

    let t = cact_current_task_get();
    // SAFETY: `t` is non-null and live; `page_directory` is a valid pointer or null.
    let pd = if !t.is_null() && !unsafe { (*t).page_directory }.is_null() {
        // SAFETY: same live `TaskStruct`; the non-null check is the enclosing `if`.
        unsafe { (*t).page_directory }
    } else {
        current_page_dir()
    };

    let mut cr3_guard = Cr3Guard::install_kernel_pd();

    if (err & PF_PRESENT != 0) && (err & PF_WRITE != 0) {
        let pte_ptr = pte_get(pd, fault_addr);

        // COW handler: present + write + PAGE_COW in PTE.
        // SAFETY: `pte_ptr` is the result of `pte_get`, checked non-null on the left of
        // the `&&`; it points into the faulting address space's page table.
        if !pte_ptr.is_null() && unsafe { *pte_ptr & PAGE_COW as u64 != 0 }
            && vmm_handle_cow(pd, fault_addr & !0xFFF) == 0 {
                // SAFETY: `G_STATS.cow_copies` — unprotected diagnostic counter, see the note
                // at the top of the handler.
                (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).cow_copies += 1;
                return;
            }

        // Protection fault from user mode: page is present but lacks PAGE_USER.
        // This happens when the stack grows into a page that was inherited from
        // the kernel identity map (PAGE_PRESENT|PAGE_RW, no PAGE_USER).
        // Allocate a fresh zero user page and remap it properly.
        if (err & PF_USER_BIT != 0)
            && (USER_STACK_LIMIT as u64..USER_STACK_TOP as u64).contains(&fault_addr)
            && !pte_ptr.is_null()
            // SAFETY: `pte_ptr` is non-null (checked in the enclosing condition) and points
            // at the PTE for this fault address.
            && unsafe { *pte_ptr & PAGE_USER as u64 == 0 }
        {
            let page_va = fault_addr & !0xFFF;
            let mut phys = kalloc();
            if phys.is_null() && oom_kill() == 0 {
                phys = kalloc();
            }
            if phys.is_null() {
                kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
                return;
            }
            zero_page(phys);
            // SAFETY: `pd` is the faulting task's page directory, `page_va` is in
            // the user stack window and `phys` is the zeroed frame just allocated.
            vmm_map(pd, page_va, v2p(phys), (PAGE_PRESENT | PAGE_RW | PAGE_USER) as i32);
            flush_tlb(page_va);
            // SAFETY: `G_STATS.stack_grows` — unprotected diagnostic counter; see the
            // note above.
            (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).stack_grows += 1;
            return;
        }

        kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
        return;
    }

    // Read protection fault from user mode (PF_PRESENT=1, no PF_WRITE) on a
    // page in the stack region that has no PAGE_USER.  Same root cause as the
    // write case above: kernel identity-map entry without PAGE_USER.
    if (err & PF_PRESENT != 0)
        && (err & PF_USER_BIT != 0)
        && (USER_STACK_LIMIT as u64..USER_STACK_TOP as u64).contains(&fault_addr)
    {
        let pte_ptr = pte_get(pd, fault_addr);
        // SAFETY: `pte_ptr` is non-null on the left of `&&` and valid for this fault.
        if !pte_ptr.is_null() && unsafe { *pte_ptr & PAGE_USER as u64 == 0 } {
            let page_va = fault_addr & !0xFFF;
            let mut phys = kalloc();
            if phys.is_null() && oom_kill() == 0 {
                phys = kalloc();
            }
            if phys.is_null() {
                kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
                return;
            }
            zero_page(phys);
            // SAFETY: `pd` is the faulting task's page directory, `page_va` is in
            // the user stack window and `phys` is the zeroed frame just allocated.
            vmm_map(pd, page_va, v2p(phys), (PAGE_PRESENT | PAGE_RW | PAGE_USER) as i32);
            flush_tlb(page_va);
            // SAFETY: `G_STATS.stack_grows` — unprotected diagnostic counter; see above.
            (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).stack_grows += 1;
            return;
        }
    }

    if err & PF_PRESENT == 0 {
        let page_va = fault_addr & !0xFFF;
        let pte = pte_get(pd, fault_addr);

        // SAFETY: `pte` is non-null on the left of `&&`; it is the PTE for the faulting
        // address in `pd`.
        if !pte.is_null() && swap_pte_is_swapped(unsafe { *pte }) {
            // SAFETY: `pd` is the faulting task's page directory, `fault_addr` is
            // the address that just faulted, and a swapped PTE was confirmed above.
            if unsafe { swap_handle_fault(pd, fault_addr) } == 0 {
                // SAFETY: `G_STATS.swap_ins` — unprotected diagnostic counter; see above.
                (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).swap_ins += 1;
                return;
            }
            kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
            return;
        }

        // SAFETY: `pte` is non-null on the left of `&&`; the demand bit lives in that
        // live PTE.
        if !pte.is_null() && unsafe { *pte & PAGE_DEMAND as u64 != 0 } {
            let mut phys = kalloc();
            if phys.is_null() && oom_kill() == 0 {
                phys = kalloc();
            }
            if phys.is_null() {
                kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
                return;
            }

            // SAFETY: `pte` is non-null (checked above) and its demand flag is set.
            if unsafe { *pte & PAGE_ZERO as u64 != 0 } {
                zero_page(phys);
                // SAFETY: `G_STATS.zero_pages` — unprotected diagnostic counter; see above.
                (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).zero_pages += 1;
            }

            // SAFETY: pte is valid.
            let pte_val = unsafe { *pte };
            // The page inherits the permission bits the demand entry carried —
            // PAGE_USER, and PAGE_RW only when the mapping was writable.
            // Forcing PAGE_RW here would make a read-only mmap(PROT_READ)
            // writable on its first fault.
            let flags = (pte_val & 0xFFF) & !((PAGE_DEMAND | PAGE_ZERO) as u64);
            let flags = flags | PAGE_PRESENT as u64;
            // SAFETY: `pte` is the live PTE for this demand page; the new frame `phys` was
            // just allocated and zeroed, so publishing its physical address here is
            // well-defined.
            unsafe { *pte = (v2p(phys) & !0xFFF) | flags; }
            flush_tlb(page_va);

            // SAFETY: `G_STATS.demand_allocs` — unprotected diagnostic counter; see above.
            (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).demand_allocs += 1;
            return;
        }

        // SAFETY: `pte` non-null on the left of `&&`, COW bit set in that live PTE.
        if !pte.is_null() && unsafe { *pte & PAGE_COW as u64 != 0 } {
            // SAFETY: `pte` is non-null and present; the low bits masked off give the
            // page-aligned physical frame it points at.
            let old_phys = unsafe { *pte & !0xFFF };

            // ── Sole-owner check + act under PAGE_LOCK (C-01 fix) ────────────
            crate::safe::lock_acquire(PAGE_LOCK.as_ptr());
            let rc = page_ref_get_locked(p2v(old_phys) as *const u8);
            if rc <= 1 {
                // Sole owner — promote the existing frame to writable in-place.
                // SAFETY: `pte` is a live PTE (non-null, checked above).
                let pte_val = unsafe { *pte };
                let flags =
                    ((pte_val & 0xFFF) & !(PAGE_COW as u64)) | PAGE_PRESENT as u64 | PAGE_RW as u64;
                // SAFETY: promoting the existing frame to writable under `PAGE_LOCK`; `pte` is
                // the valid PTE for this page.
                unsafe { *pte = (old_phys & !0xFFF) | flags; }
                crate::safe::lock_release(PAGE_LOCK.as_ptr());
                flush_tlb(page_va);
                // SAFETY: `G_STATS.cow_copies` — unprotected diagnostic counter; see above.
                (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).cow_copies += 1;
                return;
            }
            crate::safe::lock_release(PAGE_LOCK.as_ptr());

            // ── Multi-owner — allocate a private copy ────────────────────────
            let mut phys = kalloc();
            if phys.is_null() && oom_kill() == 0 {
                phys = kalloc();
            }
            if phys.is_null() {
                kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
                return;
            }

            // SAFETY: `old_phys` names the shared frame read through the direct map
            // and `phys` is a fresh kalloc page (a direct-map VA), so the copy is in
            // bounds.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    p2v(old_phys) as *const u8,
                    phys,
                    PAGE_SIZE as usize,
                );
            }
            // SAFETY: `pte` is non-null and present; its value is read to derive the new
            // PTE flags.
            let pte_val = unsafe { *pte };
            let flags =
                ((pte_val & 0xFFF) & !(PAGE_COW as u64)) | PAGE_PRESENT as u64 | PAGE_RW as u64;
            // SAFETY: publishing the freshly copied frame's physical address into the
            // live PTE.
            unsafe { *pte = (v2p(phys) & !0xFFF) | flags; }
            // SAFETY: the frame is live and PMM-managed; this call releases exactly one reference to it.
            // The PTE names a physical address, which `free_page` wants as a VA.
            unsafe { free_page(p2v(old_phys) as *mut u8) };
            flush_tlb(page_va);

            // SAFETY: `G_STATS.cow_copies` — unprotected diagnostic counter; see above.
            (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).cow_copies += 1;
            return;
        }

        if (USER_STACK_LIMIT as u64..USER_STACK_TOP as u64).contains(&fault_addr) {
            // Stack grow: missing page OR present kernel-only page (no PAGE_USER).
            let existing = pte_get(pd, fault_addr);
            let need_alloc = existing.is_null()
                // SAFETY: `existing` is the PTE returned by `pte_get` and checked non-null on
                // the left of `||`.
                || unsafe { *existing & PAGE_PRESENT as u64 == 0 }
                // SAFETY: same non-null `existing` PTE as the previous condition.
                || unsafe { *existing & PAGE_USER as u64 == 0 };

            if need_alloc {
                let mut phys = kalloc();
                if phys.is_null() && oom_kill() == 0 {
                    phys = kalloc();
                }
                if phys.is_null() {
                    kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
                    return;
                }
                zero_page(phys);
                // SAFETY: `pd` is valid, `page_va` is inside the user stack window
                // and `phys` is the zeroed frame just allocated for it; the mapping
                // takes the frame's physical address.
                vmm_map(
                    pd,
                    page_va,
                    v2p(phys),
                    (PAGE_PRESENT | PAGE_RW | PAGE_USER) as i32,
                );
                flush_tlb(page_va);
                // SAFETY: `G_STATS.stack_grows` — unprotected diagnostic counter; see above.
                (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).stack_grows += 1;
                return;
            }
        }

        // SAFETY: `G_STATS.invalid_access` — unprotected diagnostic counter; see above.
        (unsafe { KStatic::get_mut(G_STATS.as_ptr()) }).invalid_access += 1;
        kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
        return;
    }
    kill_current(fault_addr, err, eip, regs, &mut cr3_guard);
}

#[path = "page_fault_map.rs"]
mod page_fault_map;
pub use page_fault_map::*;

#[unsafe(no_mangle)]
pub extern "C" fn pf_get_stats() -> PfStats {
    // SAFETY: read-only snapshot of the #PF counters for the C caller.
    *unsafe { KStatic::get_mut(G_STATS.as_ptr()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn pf_print_stats() {
    let mut buf = [0u8; 16];
    kprint_str(c"[PF] === Page Fault Statistics ===\n".as_ptr() as *const u8);

    macro_rules! pf_stat {
        ($label:expr, $field:expr) => {
            kprint_str($label.as_ptr());
            itoa($field as i32, buf.as_mut_ptr());
            printk(buf.as_ptr());
            kprint_str(b"\n\0".as_ptr());
        };
    }

    // SAFETY: read-only snapshot of `G_STATS` for printing.
    let stats = unsafe { KStatic::get_mut(G_STATS.as_ptr()) };
    pf_stat!(b"  total_faults: \0", stats.total_faults);
    pf_stat!(b"  demand_allocs: \0", stats.demand_allocs);
    pf_stat!(b"  cow_copies: \0", stats.cow_copies);
    pf_stat!(b"  stack_grows: \0", stats.stack_grows);
    pf_stat!(b"  zero_pages: \0", stats.zero_pages);
    pf_stat!(b"  swap_ins: \0", stats.swap_ins);
    pf_stat!(b"  prot_faults: \0", stats.protection_faults);
    pf_stat!(b"  invalid_access: \0", stats.invalid_access);
}
