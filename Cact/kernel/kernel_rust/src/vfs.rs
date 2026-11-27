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
