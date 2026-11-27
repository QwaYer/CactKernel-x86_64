// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for kernel primitives.
//!
//! This module provides abstractions that encapsulate `unsafe` operations
//! behind safe interfaces, following the kernel's synchronization protocol
//! (IRQ-safe spinlocks) to guarantee memory safety at runtime.

// ---------------------------------------------------------------------------
// Parking the CPU
// ---------------------------------------------------------------------------

/// Park this CPU permanently in `hlt`.
///
/// The kernel's one `hlt` loop: a CPU that has nothing left to do (a kernel
/// page fault on the boot path) halts here rather than spinning, so it stays
/// parked until a reset or a non-maskable interrupt.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` only halts this CPU until the next interrupt and touches
        // no memory; the call sites run with maskable interrupts masked, so the
        // CPU stays parked.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: zero a page safely
// ---------------------------------------------------------------------------

use crate::ffi::PAGE_SIZE;

/// Zero-fill an entire 4 KiB page starting at `ptr`.
///
/// Does nothing if `ptr` is null.
pub fn zero_page(ptr: *mut u8) {
    if !ptr.is_null() {
        // The caller guarantees `ptr` points to a valid 4 KiB page.
        kernel_rust::ptr::write_bytes(ptr, 0, PAGE_SIZE as usize);
    }
}

// ---------------------------------------------------------------------------
// Safe wrappers around the kernel's low-level helpers
// ---------------------------------------------------------------------------

use crate::ffi::{cact_current_task_get, itoa, printk};

/// Read the CR2 register (page-fault linear address).  CR2 is 64-bit in long mode.
pub fn read_cr2_val() -> u64 {
    kernel_rust::cpu::read_cr2()
}

/// Flush a single TLB entry for `vaddr`.
pub fn flush_tlb(vaddr: u64) {
    kernel_rust::cpu::tlb_flush(vaddr)
}

/// Flush the entire TLB by reloading CR3.
pub fn flush_tlb_all() {
    kernel_rust::cpu::tlb_flush_all()
}

/// The current page directory (the PML4 in long mode) as a kernel VA: CR3 holds
/// its physical address, translated here through the direct map.
pub fn current_page_dir() -> *mut u64 {
    crate::vmm::paging::p2v(kernel_rust::cpu::read_cr3()) as *mut u64
}

/// The page directory of the running task, falling back to `CR3` when it has
/// none (a kernel thread, or during early boot).
///
/// This is what a reclaim must scan, not `CR3`: a `#PF` installs the *kernel*
/// page map in `CR3` for the duration of its PTE walks (see `Cr3Guard`) and
/// operates on the faulting task's own map explicitly, so a `kalloc` triggered
/// from inside a fault sees the kernel map in `CR3` — one that holds no user
/// pages, leaving eviction with nothing to pick.  The fault's own pd is the
/// address space the pressure came from.
pub fn current_task_page_dir() -> *mut u64 {
    let t = cact_current_task_get();
    if !t.is_null() {
        // `t` is the live current task; `page_directory` is a valid pointer or
        // null, checked before use.
        let pd = kernel_rust::ptr::as_ref(t).page_directory;
        if !pd.is_null() {
            return pd;
        }
    }
    current_page_dir()
}

/// Print a null-terminated byte string via the kernel console.
pub fn kprint_str(s: *const u8) {
    if !s.is_null() {
        // The caller guarantees `s` is a valid null-terminated string.
        printk(s);
    }
}

/// Print a signed integer.
pub fn kprint_int(n: i32) {
    let mut buf = [0u8; 16];
    // `buf` is a live 16-byte stack array, so `itoa` writes its digits (and
    // terminator) in bounds; `buf` is then a valid NUL-terminated string.
    itoa(n, buf.as_mut_ptr());
    printk(buf.as_ptr());
}

/// Log a message at the given level (KERN_SOH + level prefix).
///
/// `msg` must be null or point to a null-terminated byte string that stays
/// valid for the duration of the call.
pub fn klog_msg(level: u32, msg: *const u8) {
    if !msg.is_null() {
        let mut buf = [0u8; 1024];
        let lvl = match level {
            0 => b'6',          // LOG_OK  -> KERN_INFO
            1 => b'4',          // LOG_WARN -> KERN_WARNING
            _ => b'3',          // LOG_ERROR/LOG_FAIL -> KERN_ERR
        };
        buf[0] = 0x01;          // KERN_SOH
        buf[1] = lvl;
        let mut n = 2;
        loop {
            // `n` is capped at `buf.len() - 2`, keeping every write inside `buf`.
            if n >= buf.len() - 2 {
                break;
            }
            // The caller contract states `msg` is a null-terminated string, so
            // `n - 2` indexes it in bounds.
            let byte = kernel_rust::ptr::read(kernel_rust::ptr::add(msg, n - 2));
            if byte == 0 {
                break;
            }
            buf[n] = byte;
            n += 1;
        }
        buf[n] = b'\n';
        buf[n + 1] = 0;
        printk(buf.as_ptr());
    }
}

/// Acquire an IRQ-safe spinlock.
pub fn lock_acquire(lock: *mut crate::ffi::IrqSpinlock) {
    if !lock.is_null() {
        kernel_rust::ptr::as_mut(lock).acquire();
    }
}

/// Release an IRQ-safe spinlock.
pub fn lock_release(lock: *mut crate::ffi::IrqSpinlock) {
    if !lock.is_null() {
        kernel_rust::ptr::as_mut(lock).release();
    }
}
