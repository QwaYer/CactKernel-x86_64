// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Counting semaphore with a bounded FIFO waiter list; uses the scheduler when
//! `down` must block on a zero count.
//!
//! Every field is mutated only under the internal `guard` spinlock (taken with
//! the scheduler lock when a wake-up must be ordered), so the type needs no
//! `unsafe impl`.

use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::mutex::MUTEX_WAIT_QUEUE_MAX;
use crate::sched_link;
use crate::task_abi::{TaskState, TaskStruct};

#[repr(C)]
pub struct semaphore_t {
    pub guard:        crate::spinlock_t,
    pub count:        AtomicI32,
    pub waiters:      [*mut TaskStruct; MUTEX_WAIT_QUEUE_MAX],
    pub waiter_count: u32,
}

fn sema_init_impl(s: &mut semaphore_t, val: i32) {
    s.guard.init();
    s.count.store(val, Ordering::Relaxed);
    s.waiter_count = 0;
    s.waiters.fill(ptr::null_mut());
}

/// Initialise `s` with `val` tokens.  `s` must be non-null, properly aligned,
/// and point to storage the caller owns exclusively for this call.
pub fn sema_init(s: *mut semaphore_t, val: i32) {
    sema_init_impl(kernel_rust::ptr::as_mut(s), val);
}

/// Safe wrapper over [`sema_init`]: initialise `s` with `val` tokens.
pub fn sema_init_ref(s: &mut semaphore_t, val: i32) {
    sema_init_impl(s, val);
}

/// Borrow-taking wrapper over [`down`] for the safe Rust callers: block until a
/// token is available.
pub fn sema_down(s: &semaphore_t) {
    down(s as *const semaphore_t as *mut semaphore_t);
}

/// Borrow-taking wrapper over [`up`] for the safe Rust callers: release a token.
pub fn sema_up(s: &semaphore_t) {
    up(s as *const semaphore_t as *mut semaphore_t);
}

/// Borrow-taking wrapper over [`sema_try_down`]: `0` if a token was taken,
/// `-1` otherwise.
pub fn sema_try_down_ref(s: &semaphore_t) -> i32 {
    sema_try_down(s as *const semaphore_t as *mut semaphore_t)
}

fn sema_down_impl(s: &mut semaphore_t) {
    loop {
        let cur_val = s.count.load(Ordering::Acquire);
        if cur_val > 0 {
            if s.count
                .compare_exchange(cur_val, cur_val - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            continue;
        }

        let sched = sched_link::scheduler_lock_mut();
        sched.acquire();
        s.guard.acquire();

        if s.count.load(Ordering::Relaxed) > 0 {
            s.guard.release();
            sched.release();
            continue;
        }

        let cur = sched_link::current_task_ptr();
        if sched_link::task_is_zombie(cur) {
            // Terminated while running: parking here would clobber the Zombie
            // state and resurrect us (and leave a stale waiter entry).  Switch
            // away instead; the scheduler leaves a Zombie task unqueued.
            s.guard.release();
            sched.release();
            sched_link::schedule_yield();
            continue;
        }
        if !cur.is_null() && (s.waiter_count as usize) < MUTEX_WAIT_QUEUE_MAX {
            let idx = s.waiter_count as usize;
            s.waiters[idx] = cur;
            s.waiter_count += 1;

            sched_link::task_state_set(cur, TaskState::Sleeping);

            s.guard.release();
            sched.release();

            sched_link::schedule_yield();
        } else {
            s.guard.release();
            sched.release();
            kernel_rust::cpu::pause();
        }
    }
}

/// Block until a token is available.  `s` must be non-null, properly aligned,
/// and point to an initialised live `semaphore_t`; it must not be accessed
/// concurrently except through this semaphore's own operations.
pub fn down(s: *mut semaphore_t) {
    sema_down_impl(kernel_rust::ptr::as_mut(s));
}

/// Non-blocking `down`: take one token if one is free, otherwise return
/// immediately without parking.
///
/// It exists so a caller that must stay interruptible (the shared DNS socket)
/// can poll for the token between signal checks instead of parking in `down`,
/// which no signal wakes.
///
/// Returns 0 when the token was taken, -1 when the semaphore is empty.
///
/// `s` must be non-null, properly aligned, and point to an initialised live
/// `semaphore_t`.
pub fn sema_try_down(s: *mut semaphore_t) -> i32 {
    let s = kernel_rust::ptr::as_mut(s);
    loop {
        let cur_val = s.count.load(Ordering::Acquire);
        if cur_val <= 0 {
            return -1;
        }
        if s.count
            .compare_exchange(cur_val, cur_val - 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
    }
}

fn sema_up_impl(s: &mut semaphore_t) {
    let sched = sched_link::scheduler_lock_mut();
    sched.acquire();
    s.guard.acquire();

    if s.waiter_count > 0 {
        let woken = s.waiters[0];
        let count = s.waiter_count as usize;
        for i in 1..count {
            s.waiters[i - 1] = s.waiters[i];
        }
        s.waiter_count -= 1;

        // Hand the token over: the woken task re-checks `count` in
        // `sema_down_impl` and must find it incremented, otherwise it blocks
        // again and the wake-up is lost (the caller waits forever).
        s.count.fetch_add(1, Ordering::Release);

        s.guard.release();

        // `mlfq_wake_locked` unlinks a Sleeping task from the sleep queue
        // before enqueuing it; a plain enqueue would leave it in both lists.
        sched_link::mlfq_wake_locked(woken);
    } else {
        s.count.fetch_add(1, Ordering::Release);
        s.guard.release();
    }

    sched.release();
}

/// Release a token, waking a waiter if one is parked.  `s` must be non-null,
/// properly aligned, and point to an initialised live `semaphore_t`.
pub fn up(s: *mut semaphore_t) {
    sema_up_impl(kernel_rust::ptr::as_mut(s));
}
