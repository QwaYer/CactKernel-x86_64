// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe C-ABI entry points for the low-level spinlocks.
//!
//! The primitive types (`spinlock_t`, `irq_spinlock_t`, `IrqLock`) and their
//! `acquire`/`release` live in `kernel_rust::sync` — the graph's one `unsafe`
//! crate — because they execute asm and hand out interior mutability.  The
//! functions here are the safe wrappers the C side reaches through the
//! `#[no_mangle]` thunks in `kernel_abi`; each documents the C-boundary
//! contract it relies on.

use kernel_rust::cpu;
use kernel_rust::ptr;
use kernel_rust::sync::{irq_spinlock_t, spinlock_t};

// The C-boundary contract shared by every entry point below: the lock pointer
// is non-null, properly aligned, and points to live storage the caller may
// access for the duration of the call.

/// Initialise an unheld `spinlock_t`.
pub fn spin_lock_init(lock: *mut spinlock_t) {
    ptr::as_mut(lock).init();
}

/// Acquire `lock`, spinning until it is free.
pub fn spin_lock(lock: *mut spinlock_t) {
    ptr::as_mut(lock).acquire();
}

/// Release `lock`, which the calling task must hold.
pub fn spin_unlock(lock: *mut spinlock_t) {
    ptr::as_mut(lock).release();
}

/// Initialise an unheld `irq_spinlock_t`.
pub fn irq_spinlock_init(lock: *mut irq_spinlock_t) {
    ptr::as_mut(lock).init();
}

/// Acquire `lock` with interrupts disabled (the IF flag is saved in the lock).
pub fn irq_spinlock_acquire(lock: *mut irq_spinlock_t) {
    ptr::as_mut(lock).acquire();
}

/// Release `lock`, restoring interrupts if they were enabled on acquire.
pub fn irq_spinlock_release(lock: *mut irq_spinlock_t) {
    ptr::as_mut(lock).release();
}

// Linux-style IRQ-safe spinlocks: flags live in a caller-local variable.
//   unsigned long flags; spin_lock_irqsave(&lock, &flags);
//   ... spin_unlock_irqrestore(&lock, flags);

/// Acquire `lock` with interrupts disabled, saving the previous EFLAGS into
/// `flags` (which may be null, in which case the saved value is discarded).
pub fn spin_lock_irqsave(lock: *mut spinlock_t, flags: *mut u32) {
    let saved = cpu::eflags_read();
    cpu::interrupts_disable();
    ptr::as_mut(lock).acquire();
    if !flags.is_null() {
        ptr::write(flags, saved);
    }
}

/// Release `lock` and restore the interrupt flag captured by the matching
/// [`spin_lock_irqsave`].
pub fn spin_unlock_irqrestore(lock: *mut spinlock_t, flags: u32) {
    ptr::as_mut(lock).release();
    if flags & (1 << 9) != 0 {
        cpu::interrupts_enable();
    }
}
