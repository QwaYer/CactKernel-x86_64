// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for the VFS core helpers a driver node's hooks call
//! (`Cact/fs/vfs`).  The node layouts themselves are the driver crate's own
//! mirrors and cross here opaquely.

use core::ffi::c_void;

use crate::sys;

/// Fill the generic `cact_stat_t` fields from `node`.  `node` is the node whose
/// ops table carries the calling `stat` hook, and `buf` a writable stat struct
/// of the caller's own layout.
pub fn fill_stat(node: *mut c_void, buf: *mut c_void) {
    // SAFETY: both are live objects owned by the calling VFS hook.
    unsafe { sys::vfs_fill_stat(node, buf) };
}

/// Read `size` bytes at `off` from `node` into `buf` (`read_vfs`), returning the
/// byte count (or a negative error).  Used by the demand-paging path to fault a
/// file-backed page in.
pub fn read(node: *mut c_void, off: u64, size: u32, buf: *mut u8) -> i32 {
    // SAFETY: `node` is a live VFS node and `buf` a writable buffer of `size`
    // bytes, which is the contract the C reader upholds.
    unsafe { sys::read_vfs(node, off, size, buf) }
}

/// Resolve an fd + mmap offset to a shared backing object (`vfs_mmap_resolve`).
/// Returns 0 and writes the object handle + in-object byte offset when the fd is
/// backed (memfd, DRM GEM, …); < 0 when it is not.
pub fn mmap_resolve(
    fd: i32,
    off: u32,
    len: u32,
    backing_out: *mut i32,
    obj_off_out: *mut u32,
) -> i32 {
    // SAFETY: `backing_out`/`obj_off_out` are live out-parameters the C routine
    // writes only on success.
    unsafe { sys::vfs_mmap_resolve(fd, off, len, backing_out, obj_off_out) }
}

/// Flush a file-backed mapping's page-cache range back to its filesystem
/// (`vfs_as_flush_fd`).
pub fn as_flush_fd(fd: i32, off: u32, size: u32) {
    // SAFETY: `fd`/`off`/`size` name a live mapping the caller owns; no pointers
    // cross.
    unsafe { sys::vfs_as_flush_fd(fd, off, size) };
}
