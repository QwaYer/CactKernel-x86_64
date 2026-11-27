// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for devfs character-device registration (`devfs.h`).  A driver
//! hands devfs its callback table once at bring-up and drops the node at
//! teardown; the table's layout is the driver crate's own `devfs_driver_t`
//! mirror, passed here opaquely.

use core::ffi::{c_void, CStr};

use crate::sys;

/// Register a character device `name` with the given `flags`; `drv` points to
/// the caller's live driver table and `drv_priv` is handed back to its
/// callbacks.  Returns the registered node, or null on failure.
pub fn register_chrdev(name: &CStr, flags: u32, drv: *mut c_void, drv_priv: *mut c_void) -> *mut c_void {
    // SAFETY: `name` is a NUL-terminated C string; `drv` is the caller's live
    // devfs driver table and `drv_priv` the value its callbacks expect.
    unsafe { sys::register_chrdev(name.as_ptr(), flags, drv, drv_priv) }
}

/// Remove the character device `name` (ignored when it is not registered).
pub fn unregister_chrdev(name: &CStr) {
    // SAFETY: `name` is a NUL-terminated C string.
    unsafe { sys::unregister_chrdev(name.as_ptr()) };
}
