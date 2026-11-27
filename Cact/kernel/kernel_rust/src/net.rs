// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for the C kernel services the network stack (`cact_net`) uses.

use crate::sys;

/// Current kernel tick counter.
pub fn timer_ticks_get() -> u32 {
    // SAFETY: no preconditions.
    unsafe { sys::timer_ticks_get() }
}

/// Microseconds since boot.
pub fn ktime_get_usec() -> u64 {
    // SAFETY: no preconditions.
    unsafe { sys::ktime_get_usec() }
}

/// Busy-wait for `us` microseconds.
pub fn ktime_busy_wait_us(us: u64) {
    // SAFETY: no preconditions; it only spins on the TSC/timer.
    unsafe { sys::ktime_busy_wait_us(us) };
}

/// Receive up to `buf.len()` bytes from TCP socket `sock`; returns the count,
/// or a negative value on error.  `max_len` is clamped to `u16`.
pub fn tcp_recv(sock: i32, buf: &mut [u8]) -> i32 {
    let max = core::cmp::min(buf.len(), u16::MAX as usize) as u16;
    // SAFETY: `buf` is a live writable slice of at least `max` bytes; `sock` is
    // a socket index the caller owns.
    unsafe { sys::tcp_recv(sock, buf.as_mut_ptr(), max) }
}

/// The active NIC driver pointer (`*mut net_driver_t`).  Its storage is the
/// `#[no_mangle]` symbol C and driver modules read via ksym; it is defined in
/// `kernel_abi`, and touched here only on the single-threaded driver path.
pub fn active_nic() -> *mut core::ffi::c_void {
    // SAFETY: single-threaded driver registration/teardown; an aligned
    // pointer-sized load cannot tear.
    unsafe { sys::active_nic }
}

/// Set [`active_nic`] (same single-threaded driver path).
pub fn set_active_nic(ptr: *mut core::ffi::c_void) {
    // SAFETY: as above.
    unsafe { sys::active_nic = ptr };
}
