// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for the kernel's eventfd (`fs/eventfd/eventfd.c`).  A syncobj
//! registration holds one eventfd open and signals it when the syncobj becomes
//! signalled.

use core::ffi::{c_int, c_void};

use crate::sys;

/// Look up the eventfd vnode behind descriptor `fd`; on success stores it in
/// `out` and returns 0.
pub fn node_get(fd: c_int, out: *mut *mut c_void) -> c_int {
    // SAFETY: `out` is the caller's writable out-pointer.
    unsafe { sys::eventfd_node_get(fd, out) }
}

/// Drop the reference [`node_get`] took on the eventfd node.
pub fn node_put(node: *mut c_void) {
    // SAFETY: `node` came from [`node_get`] and has not been put yet.
    unsafe { sys::eventfd_node_put(node) };
}

/// Signal the eventfd node, adding `n` to its counter.
pub fn node_signal(node: *mut c_void, n: u64) -> c_int {
    // SAFETY: `node` is a live eventfd node the caller holds a reference to.
    unsafe { sys::eventfd_node_signal(node, n) }
}
