// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel synchronization primitives — the lock types themselves, plus the
//! scheduler/console plumbing the higher-level primitives need.
//!
//! A ticketless spinlock (`pause` while spinning) and its IRQ-saving variant are
//! inherently `unsafe`: they execute asm and hand out interior mutability.  They
//! live here, in the graph's one `unsafe` crate; the sleeping mutexes and
//! semaphores built on top of them live in `cact_sync`, which re-exports these
//! types and calls this crate instead of carrying `unsafe` of its own.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::cpu;
use crate::sys;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct spinlock_t {
    pub locked: AtomicU32,
}

impl spinlock_t {
    pub const fn new() -> Self {
        Self { locked: AtomicU32::new(0) }
    }

    pub fn init(&mut self) {
        self.locked.store(0, Ordering::Relaxed);
    }

    pub fn acquire(&mut self) {
        loop {
            if self
                .locked
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.locked.load(Ordering::Relaxed) != 0 {
                cpu::pause();
            }
        }
    }

    pub fn release(&mut self) {
        self.locked.store(0, Ordering::Release);
    }
}

impl Default for spinlock_t {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct irq_spinlock_t {
    pub spin:        spinlock_t,
    pub saved_flags: u32,
}

impl irq_spinlock_t {
    pub const fn new() -> Self {
        Self {
            spin:        spinlock_t::new(),
            saved_flags: 0,
        }
    }

    pub fn init(&mut self) {
        self.spin.init();
        self.saved_flags = 0;
    }

    pub fn acquire(&mut self) {
        let flags = cpu::eflags_read();
        cpu::interrupts_disable();
        self.spin.acquire();
        self.saved_flags = flags;
    }

    pub fn release(&mut self) {
        let flags = self.saved_flags;
        self.spin.release();
        if flags & (1 << 9) != 0 {
            cpu::interrupts_enable();
        }
    }
}

impl Default for irq_spinlock_t {
    fn default() -> Self {
        Self::new()
    }
}

/// A kernel IRQ-saving spinlock usable from a `static`: `lock()`/`unlock()` take
/// `&self` (interior mutability), so a guard type can hold one without `static
/// mut`.
#[repr(C)]
pub struct IrqLock(UnsafeCell<irq_spinlock_t>);

// SAFETY: every access goes through `lock`/`unlock`, which serialize on the inner
// IRQ-saving spinlock.
unsafe impl Sync for IrqLock {}

impl IrqLock {
    pub const fn new() -> Self {
        IrqLock(UnsafeCell::new(irq_spinlock_t::new()))
    }

    /// Acquire the lock (not recursive); interrupts are disabled until `unlock`.
    pub fn lock(&self) {
        // SAFETY: the caller takes the lock; the `&mut` to the inner lock is
        // consumed by `acquire` and no other thread holds it.
        unsafe { (*self.0.get()).acquire() }
    }

    /// Release the lock, restoring interrupts if they were enabled on acquire.
    pub fn unlock(&self) {
        // SAFETY: the matching release for `lock`.
        unsafe { (*self.0.get()).release() }
    }
}

impl Default for IrqLock {
    fn default() -> Self {
        Self::new()
    }
}

/// IRQ-safe spinlock `Mutex` with a `Deref`/`DerefMut` guard — the small lock
/// for leaf kernel state that is touched from several contexts (the crypto
/// crate's CSPRNG).  Distinct from [`mutex_t`](crate::sync), the
/// scheduler-cooperating sleeping mutex: this one never sleeps, so it is safe
/// from interrupt context.
pub struct Mutex<T: ?Sized> {
    lock: IrqLock,
    data: UnsafeCell<T>,
}

// SAFETY: `Mutex` hands its `T` to whichever task holds the lock, and the
// `UnsafeCell` is reachable only through a guard taken while `lock` is held, so
// `T: Send` is enough to move the whole cell.
unsafe impl<T: Send + ?Sized> Send for Mutex<T> {}
// SAFETY: `&Mutex<T>` exposes `T` only through `lock()`, which serialises every
// access on the IRQ-saving spinlock, so sharing needs only `T: Send`.
unsafe impl<T: Send + ?Sized> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(t: T) -> Self {
        Mutex {
            lock: IrqLock::new(),
            data: UnsafeCell::new(t),
        }
    }

    /// Acquire the lock; interrupts are disabled until the returned guard drops.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.lock.lock();
        MutexGuard { mutex: self }
    }
}

/// Exclusive access to a [`Mutex`]'s value; unlocks the mutex on drop.
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while `mutex.lock` is held, so no other
        // task holds a `&`/`&mut` to `data`, and the borrow cannot outlive the
        // guard.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: `&mut self` proves this guard is the unique accessor and the
        // mutex is still locked, so no other task can alias `data`.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.lock.unlock();
    }
}

// ---- scheduler/console plumbing used by the sync primitives ---------------

/// Yield the CPU to the scheduler (`schedule`).
pub fn schedule_yield() {
    // SAFETY: `schedule` is the scheduler entry point supplied by `sched`; it
    // takes no arguments and may be called from any task context.
    unsafe { sys::schedule() }
}

/// State-aware wake (unlinks a Sleeping task from the sleep queue first).
/// Requires the scheduler lock to be held by the caller.
pub fn mlfq_wake_locked(task: *mut c_void) {
    // SAFETY: caller holds the scheduler lock (documented precondition) and
    // passes a task pointer that the scheduler owns.
    unsafe { sys::sched_mlfq_wake_task_locked(task) }
}

/// The task running on the calling CPU, as an opaque pointer (possibly null).
pub fn current_task() -> *mut c_void {
    // SAFETY: `cact_current_task_get` is the scheduler's per-CPU accessor; it
    // takes no arguments and returns this CPU's live running-task pointer.
    unsafe { sys::cact_current_task_get() }
}

/// `&'static mut` to the global scheduler IRQ spinlock.
///
/// # Safety
///
/// `scheduler_lock` is a single kernel object; callers must ensure at most one
/// live `&mut` by always pairing with the real lock acquire/release protocol
/// from `sched`.
pub fn scheduler_lock() -> &'static mut irq_spinlock_t {
    // SAFETY: `scheduler_lock` is a single object that is never moved or freed,
    // so the pointer is valid and aligned for `'static`.  The caller contract
    // (see # Safety) ensures at most one live `&mut` at a time.
    unsafe { &mut *core::ptr::addr_of_mut!(sys::scheduler_lock) }
}
