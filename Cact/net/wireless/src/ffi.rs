// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! C-layout mirrors for devfs character-device registration.
//!
//! The kernel services themselves go through `kernel_rust` (`kernel_rust::devfs`
//! for `register_chrdev`/`unregister_chrdev`, `kernel_rust::user` for the copy
//! helpers); this module keeps the one `#[repr(C)]` callback table the engine
//! hands to `register_chrdev`.

use core::ffi::{c_char, c_int, c_void};

/// Mirrors `devfs_driver_t` in `Cact/fs/vfs/devfs/devfs.h` (7 slots, 56 bytes
/// on x86-64).  The `ctl`/`status` slots are legacy but keep their positions.
#[repr(C)]
pub struct DevfsDriver {
    pub read: Option<extern "C" fn(*mut c_void, u64, u32, *mut c_char) -> c_int>,
    pub write: Option<extern "C" fn(*mut c_void, u64, u32, *mut c_char) -> c_int>,
    pub ctl: Option<extern "C" fn(*mut c_void, *const c_char, u32) -> c_int>,
    pub status: Option<extern "C" fn(*mut c_void, *mut c_char, u32) -> c_int>,
    pub ioctl: Option<extern "C" fn(*mut c_void, u32, *mut c_void) -> c_int>,
    pub walk: Option<extern "C" fn(*mut c_void, *const c_char) -> *mut c_void>,
    pub readdir: Option<extern "C" fn(*mut c_void, u32) -> *mut c_void>,
}

const _: () = assert!(core::mem::size_of::<DevfsDriver>() == 56);

/// `DEVFS_F_CHAR` (devfs.h).
pub const DEVFS_F_CHAR: u32 = 0x04;
