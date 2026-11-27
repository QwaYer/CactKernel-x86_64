// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for the kernel's fd table and the memfd-backed shared RAM
//! object (`core/syscall/helper.h`, `fs/memfd/memfd.h`).  A driver that needs a
//! buffer other processes can share — the DRM/GEM path does — allocates a
//! memfd and wraps its frames.

use core::ffi::{c_int, c_void};

use crate::sys;

/// Install `node` as a new descriptor in the current task's fd table; returns
/// the fd, or a negative error.  `node` must be a live vfs node the caller owns
/// a reference to.
pub fn alloc_fd(node: *mut c_void) -> c_int {
    // SAFETY: `node` is a live node the caller owns a reference to.
    unsafe { sys::alloc_fd(node) }
}

/// Create a memfd named `name` (`name_len` bytes); returns its handle (or a
/// negative error).  `flags` are the memfd creation flags.
pub fn memfd_create(name: *const u8, name_len: u32, flags: c_int) -> c_int {
    // SAFETY: `name` is `name_len` readable bytes (or null, checked by C).
    unsafe { sys::memfd_create(name, name_len, flags) }
}

/// Resize a memfd to `size` bytes; 0 on success.
pub fn memfd_truncate(handle: c_int, size: u64) -> c_int {
    // SAFETY: `handle` names a live memfd the caller owns.
    unsafe { sys::memfd_truncate(handle, size) }
}

/// Drop the caller's reference to a memfd.
pub fn memfd_close(handle: c_int) -> c_int {
    // SAFETY: `handle` names a live memfd the caller owns.
    unsafe { sys::memfd_close(handle) }
}

/// Take an extra reference on a memfd.
pub fn memfd_ref(handle: c_int) -> c_int {
    // SAFETY: `handle` names a live memfd the caller owns.
    unsafe { sys::memfd_ref(handle) }
}

/// Kernel-visible base of frame `idx` of a memfd, or null when out of range.
pub fn memfd_get_page(handle: c_int, idx: u32) -> *mut c_void {
    // SAFETY: `handle` names a live memfd the caller owns.
    unsafe { sys::memfd_get_page(handle, idx) }
}

/// A memfd's length in bytes (negative on error).
pub fn memfd_size(handle: c_int) -> i64 {
    // SAFETY: `handle` names a live memfd the caller owns.
    unsafe { sys::memfd_size(handle) }
}

/// The memfd handle behind file descriptor `fd` (negative on error).
pub fn memfd_fd_handle(fd: c_int) -> c_int {
    // SAFETY: `fd` is a descriptor the caller holds.
    unsafe { sys::memfd_fd_handle(fd) }
}

/// Wrap a memfd in a fresh vnode named `name` with reported length `size`; the
/// caller gets a node it owns.  Null on failure.
pub fn memfd_vnode_from_handle(handle: c_int, name: *const u8, size: u32) -> *mut c_void {
    // SAFETY: `handle` names a live memfd and `name` is a NUL-terminated string.
    unsafe { sys::memfd_vnode_from_handle(handle, name, size) }
}
