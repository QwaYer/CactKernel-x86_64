// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe wrappers for the kernel's user-pointer validation and copy services
//! (`validate.h`): a driver takes an ioctl argument from user space, validates
//! the range, then copies a struct across the boundary.

use core::ffi::c_void;

use crate::sys;

/// Whether `ptr` names a `size`-byte range in user space the caller may access.
pub fn validate_user_ptr(ptr: *const c_void, size: u32) -> bool {
    // SAFETY: a kernel validation service; it only inspects the pointer.
    unsafe { sys::validate_user_ptr(ptr, size) != 0 }
}

/// Copy `size` bytes from the user range `src` to the kernel buffer `dst`.
/// Returns `true` on success.
///
/// `src` must be a range the caller validated with [`validate_user_ptr`].
pub fn copy_from_user(dst: *mut c_void, src: *const c_void, size: u32) -> bool {
    // SAFETY: `dst` is a kernel buffer of `size` writable bytes and `src` is a
    // caller-validated user range of the same size.
    unsafe { sys::copy_from_user(dst, src, size) == 0 }
}

/// Copy `size` bytes from the kernel buffer `src` to the user range `dst`.
/// Returns `true` on success.
///
/// `dst` must be a range the caller validated with [`validate_user_ptr`].
pub fn copy_to_user(dst: *mut c_void, src: *const c_void, size: u32) -> bool {
    // SAFETY: `src` is a kernel buffer of `size` readable bytes and `dst` is a
    // caller-validated user range of the same size.
    unsafe { sys::copy_to_user(dst, src, size) == 0 }
}
