// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The sync primitives' exported C ABI: every `#[no_mangle]` entry point the C
//! side (`sync.h`) calls into `cact_sync`.  Each is a thin thunk onto a safe
//! `pub fn` of the same name; the raw-pointer contract the function relies on is
//! the C caller's, as documented at the `cact_sync` definition.

#![allow(unsafe_code)] // for `#[no_mangle]` only; the bodies are plain calls

use cact_sync::{irq_spinlock_t, mutex_t, semaphore_t, spinlock_t};

// ---- spinlocks -------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn spin_lock_init(lock: *mut spinlock_t) {
    cact_sync::spin_lock_init(lock)
}
#[no_mangle]
pub unsafe extern "C" fn spin_lock(lock: *mut spinlock_t) {
    cact_sync::spin_lock(lock)
}
#[no_mangle]
pub unsafe extern "C" fn spin_unlock(lock: *mut spinlock_t) {
    cact_sync::spin_unlock(lock)
}
#[no_mangle]
pub unsafe extern "C" fn spin_lock_irqsave(lock: *mut spinlock_t, flags: *mut u32) {
    cact_sync::spin_lock_irqsave(lock, flags)
}
#[no_mangle]
pub unsafe extern "C" fn spin_unlock_irqrestore(lock: *mut spinlock_t, flags: u32) {
    cact_sync::spin_unlock_irqrestore(lock, flags)
}
#[no_mangle]
pub unsafe extern "C" fn irq_spinlock_init(lock: *mut irq_spinlock_t) {
    cact_sync::irq_spinlock_init(lock)
}
#[no_mangle]
pub unsafe extern "C" fn irq_spinlock_acquire(lock: *mut irq_spinlock_t) {
    cact_sync::irq_spinlock_acquire(lock)
}
#[no_mangle]
pub unsafe extern "C" fn irq_spinlock_release(lock: *mut irq_spinlock_t) {
    cact_sync::irq_spinlock_release(lock)
}

// ---- mutexes ---------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn mutex_init(m: *mut mutex_t) {
    cact_sync::mutex_init(m)
}
#[no_mangle]
pub unsafe extern "C" fn mutex_lock(m: *mut mutex_t) {
    cact_sync::mutex_lock(m)
}
#[no_mangle]
pub unsafe extern "C" fn mutex_unlock(m: *mut mutex_t) {
    cact_sync::mutex_unlock(m)
}
#[no_mangle]
pub unsafe extern "C" fn mutex_trylock(m: *mut mutex_t) -> i32 {
    cact_sync::mutex_trylock(m)
}

// ---- semaphores ------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn sema_init(s: *mut semaphore_t, val: i32) {
    cact_sync::sema_init(s, val)
}
#[no_mangle]
pub unsafe extern "C" fn down(s: *mut semaphore_t) {
    cact_sync::down(s)
}
#[no_mangle]
pub unsafe extern "C" fn up(s: *mut semaphore_t) {
    cact_sync::up(s)
}
#[no_mangle]
pub unsafe extern "C" fn sema_try_down(s: *mut semaphore_t) -> i32 {
    cact_sync::sema_try_down(s)
}
