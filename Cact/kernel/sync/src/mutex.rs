// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Sleeping mutex: FIFO wait queue, [`crate::spinlock_t`] for the wait list, and
//! scheduler integration when the lock is held (block current task, yield).
//!
//! Every field is mutated only under the internal `guard` spinlock (or during
//! single-threaded `init`), which is what makes the type usable from a `static
//! mut` or an inner `KCell` without any `unsafe impl`.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sched_link;
use crate::task_abi::{TaskState, TaskStruct};

pub const MUTEX_WAIT_QUEUE_MAX: usize = 64;

#[repr(C)]
pub struct mutex_t {
    pub locked:          AtomicU32,
    pub guard:           crate::spinlock_t,
    pub owner:           *mut TaskStruct,
    pub waiters:         [*mut TaskStruct; MUTEX_WAIT_QUEUE_MAX],
    pub waiter_count:    u32,
    pub recursion_count: u32,
}

/// Initialise `m` as an unheld mutex.  `m` must be non-null, properly aligned,
/// and point to storage the caller owns exclusively for this call.
pub fn mutex_init(m: *mut mutex_t) {
    mutex_init_impl(kernel_rust::ptr::as_mut(m));
}

fn mutex_init_impl(m: &mut mutex_t) {
    m.locked.store(0, Ordering::Relaxed);
    m.guard.init();
    m.owner = ptr::null_mut();
    m.waiter_count = 0;
    m.recursion_count = 0;
    m.waiters.fill(ptr::null_mut());
}

/// Acquire `m`, blocking the calling task while it is held.  `m` must be
/// non-null, properly aligned, and point to an initialised live `mutex_t`.
pub fn mutex_lock(m: *mut mutex_t) {
    mutex_lock_impl(kernel_rust::ptr::as_mut(m));
}

fn mutex_lock_impl(m: &mut mutex_t) {
    loop {
        m.guard.acquire();

        if m.owner == sched_link::current_task_ptr() {
            m.recursion_count += 1;
            m.guard.release();
            return;
        }

        if m.locked.load(Ordering::Relaxed) == 0 {
            m.locked.store(1, Ordering::Relaxed);
            m.owner = sched_link::current_task_ptr();
            m.recursion_count = 0;
            m.guard.release();
            return;
        }

        let cur = sched_link::current_task_ptr();
        if !cur.is_null() && (m.waiter_count as usize) < MUTEX_WAIT_QUEUE_MAX {
            let sched = sched_link::scheduler_lock_mut();
            sched.acquire();

            // Checked under `SCHEDULER_LOCK`, the same lock the timer tick holds
            // when it marks the running task Zombie: the check and the state
            // write are atomic against it, so a terminating signal cannot slip
            // between them and be clobbered by `Sleeping`.
            if sched_link::task_is_zombie(cur) {
                sched.release();
                m.guard.release();
                sched_link::schedule_yield();
                continue;
            }

            let idx = m.waiter_count as usize;
            m.waiters[idx] = cur;
            m.waiter_count += 1;
            sched_link::task_state_set(cur, TaskState::Sleeping);
            sched.release();

            m.guard.release();

            sched_link::schedule_yield();
        } else {
            m.guard.release();
            kernel_rust::cpu::pause();
        }
    }
}

/// Try to acquire `m` without blocking: `0` on success, `-1` when held.  `m`
/// must be non-null, properly aligned, and point to an initialised live mutex.
pub fn mutex_trylock(m: *mut mutex_t) -> i32 {
    mutex_trylock_impl(kernel_rust::ptr::as_mut(m))
}

fn mutex_trylock_impl(m: &mut mutex_t) -> i32 {
    m.guard.acquire();
    if m.owner == sched_link::current_task_ptr() {
        m.recursion_count += 1;
        m.guard.release();
        return 0;
    }
    if m.locked.load(Ordering::Relaxed) == 0 {
        m.locked.store(1, Ordering::Relaxed);
        m.owner = sched_link::current_task_ptr();
        m.recursion_count = 0;
        m.guard.release();
        return 0;
    }
    m.guard.release();
    -1
}

/// Release `m`, waking one waiter.  `m` must be non-null, properly aligned, and
/// point to an initialised live mutex held by the calling task.
pub fn mutex_unlock(m: *mut mutex_t) {
    mutex_unlock_impl(kernel_rust::ptr::as_mut(m));
}

fn mutex_unlock_impl(m: &mut mutex_t) {
    m.guard.acquire();

    if m.locked.load(Ordering::Relaxed) == 0 {
        m.guard.release();
        kernel_rust::console::printk_bytes(b"mutex: unlock of unlocked mutex!\n\0");
        return;
    }

    if m.owner == sched_link::current_task_ptr() && m.recursion_count > 0 {
        m.recursion_count -= 1;
        m.guard.release();
        return;
    }

    // Fully release, then wake one waiter.  The waiter must re-acquire through
    // the normal path so its `recursion_count` starts at 0; transferring
    // ownership directly (`owner = woken`) made the woken task take the
    // recursive branch and increment `recursion_count`, so its first unlock was
    // a no-op and the mutex stayed locked forever.
    let woken = if m.waiter_count > 0 {
        let w = m.waiters[0];
        let count = m.waiter_count as usize;
        for i in 1..count {
            m.waiters[i - 1] = m.waiters[i];
        }
        m.waiter_count -= 1;
        m.waiters[count - 1] = ptr::null_mut();
        w
    } else {
        ptr::null_mut()
    };

    m.locked.store(0, Ordering::Release);
    m.owner = ptr::null_mut();
    m.recursion_count = 0;
    m.guard.release();

    if !woken.is_null() {
        let sched = sched_link::scheduler_lock_mut();
        sched.acquire();
        // State-aware wake: also unlinks a Sleeping task from the sleep queue.
        sched_link::mlfq_wake_locked(woken);
        sched.release();
    }
}
