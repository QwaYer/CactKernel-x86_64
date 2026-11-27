// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers over the scheduler and console symbols the sync primitives
//! need.
//!
//! The `extern "C"` declarations themselves live in `kernel_rust` (the graph's
//! one `unsafe` crate); here they are re-typed onto this crate's `TaskStruct`
//! and keep the raw-pointer casts, which are safe.

use kernel_rust::ptr;
use kernel_rust::sync;

use crate::task_abi::{TaskState, TaskStruct};

#[inline]
pub(crate) fn schedule_yield() {
    sync::schedule_yield();
}

/// State-aware wake (unlinks a Sleeping task from the sleep queue first).
/// Requires the scheduler lock to be held by the caller.
#[inline]
pub(crate) fn mlfq_wake_locked(task: *mut TaskStruct) {
    sync::mlfq_wake_locked(task as *mut core::ffi::c_void);
}

/// The task running on the calling CPU (possibly null).
#[inline]
pub(crate) fn current_task_ptr() -> *mut TaskStruct {
    sync::current_task() as *mut TaskStruct
}

/// Returns `&'static mut` to the global scheduler IRQ spinlock.
///
/// # Safety
///
/// The scheduler lock is a single kernel object; callers must ensure at most one
/// live `&mut` by always pairing with the real lock acquire/release protocol
/// from `sched`.
#[inline]
pub(crate) fn scheduler_lock_mut() -> &'static mut crate::irq_spinlock_t {
    sync::scheduler_lock()
}

#[inline]
pub(crate) fn task_state_set(t: *mut TaskStruct, st: TaskState) {
    if !t.is_null() {
        ptr::as_mut(t).state = st;
    }
}

/// True when `t` has been marked Zombie — a terminating signal was handled for
/// it while it was running.  A park path must then NOT overwrite the state with
/// `Sleeping`/`Waiting`: that resurrects the task (it gets queued as a sleeper
/// and rescheduled) and it is never reaped, so a process looping on
/// `recvfrom <= 0 → sleep(1)` would ignore Ctrl+C forever.
#[inline]
pub(crate) fn task_is_zombie(t: *mut TaskStruct) -> bool {
    if t.is_null() {
        return false;
    }
    matches!(ptr::as_ref(t).state, TaskState::Zombie)
}
