// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe console access: the C kernel's `printk` and `serial_putc`.

use core::ffi::c_char;

use crate::sys;

/// Write a **NUL-terminated** byte string to the kernel console.
///
/// `printk` is printf-style; an empty format string followed by the caller's
/// assembled line is how a crate that cannot call it variadically emits text.
/// The buffer the caller passes must end in a NUL byte — the model's console
/// builder always appends one.
pub fn printk_bytes(buf: &[u8]) {
    // SAFETY: `buf` is NUL-terminated (caller contract above), so `printk` sees
    // a valid C string that outlives the call.
    unsafe { sys::printk(buf.as_ptr() as *const c_char) };
}

/// Emit one byte on the host's serial port (COM1).
pub fn serial_putc(byte: u8) {
    // SAFETY: `serial_putc` takes the byte by value and touches no memory.
    unsafe { sys::serial_putc(byte as c_char) };
}
