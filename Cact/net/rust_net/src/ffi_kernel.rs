// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel services used by the Rust network stack.
//!
//! The `extern "C"` surface itself now lives in `kernel_rust` (the graph's one
//! `unsafe` crate); this module re-exports its safe wrappers under the names the
//! stack already used, plus a few helpers kept here.

use core::ffi::c_int;

use crate::types::{MacAddr, Skb};

// Safe wrappers over the C kernel services (declared and wrapped in `kernel_rust`).
pub use kernel_rust::net::{ktime_busy_wait_us, ktime_get_usec, timer_ticks_get};

pub use cact_mm::kmalloc;
// The scheduler's semaphore/lock entry points are `cact_sync`'s own
// functions (Rust), called here by crate path instead of by C ABI.
pub use cact_sync::{down, irq_spinlock_acquire, irq_spinlock_release, sema_init, sema_try_down, up};
pub use cact_mm::kmalloc_aligned;
pub use cact_mm::kfree;

pub const LOG_OK: c_int = 0;
pub const LOG_WARN: c_int = 1;
pub const LOG_ERROR: c_int = 2;
pub const LOG_FAIL: c_int = 3;

/// `msg` must be a static `b"...\0"` slice (NUL-terminated).  Builds a
/// KERN_SOH + level prefixed buffer and forwards it to `printk`.
#[inline]
pub fn klog_static(level: c_int, msg: &'static [u8]) {
    debug_assert!(
        msg.last().copied() == Some(0),
        "klog_static requires NUL-terminated message"
    );
    let mut buf = [0u8; 1024];
    let lvl = match level {
        0 => b'6',              // LOG_OK  -> KERN_INFO
        1 => b'4',              // LOG_WARN -> KERN_WARNING
        _ => b'3',              // LOG_ERROR/LOG_FAIL -> KERN_ERR
    };
    buf[0] = 0x01;              // KERN_SOH
    buf[1] = lvl;
    let len = core::cmp::min(msg.len().saturating_sub(1), buf.len() - 3);
    buf[2..2 + len].copy_from_slice(&msg[..len]);
    buf[2 + len] = b'\n';
    buf[3 + len] = 0;
    kernel_rust::console::printk_bytes(&buf[..3 + len + 1]);
}

pub fn mac_equal(a: &MacAddr, b: &MacAddr) -> bool {
    a.b == b.b
}

/// Pointer to `skb`'s payload, at its current `data_offset`.  `skb` must be
/// non-null and point to a live, initialised [`Skb`] — one returned by
/// `skb_alloc` or received by a NIC driver — with `data_offset` maintained
/// within `SKB_MAX_SIZE` (which every producer in this crate guarantees).
pub fn skb_data_ptr(skb: *mut Skb) -> *mut u8 {
    let s = kernel_rust::ptr::as_mut(skb);
    let offset = s.data_offset as usize;
    s.data[offset..].as_mut_ptr()
}
