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

/// Write a **NUL-terminated** byte string to the kernel console (`printk`),
/// reached by raw pointer rather than a slice.
pub fn printk(msg: *const u8) {
    // SAFETY: the caller contract is a NUL-terminated string that outlives the
    // call, which is what `printk` reads.
    unsafe { sys::printk(msg as *const c_char) };
}

/// Like [`printk`], but the line is drawn in `color` on the framebuffer console.
pub fn printk_color(msg: *const u8, color: u32) {
    // SAFETY: as in `printk`; `color` is a plain value.
    unsafe { sys::printk_color(msg as *const c_char, color) };
}

/// Print `n` in hexadecimal via the kernel console (`printk_hex`).
pub fn printk_hex(n: u32) {
    // SAFETY: `printk_hex` takes `n` by value and touches no caller memory.
    unsafe { sys::printk_hex(n) };
}

/// Render `n` as a decimal, NUL-terminated string into `buf` (`itoa`).
///
/// `buf` must be a writable buffer of at least 12 bytes (an `i32`, its sign and
/// the terminator), which is what the C routine writes.
pub fn itoa(n: i32, buf: *mut u8) {
    // SAFETY: the caller contract above sizes `buf` for the full rendering.
    unsafe { sys::itoa(n, buf) };
}

/// Render `n` as a NUL-terminated hex string into `buf` (`hex_to_ascii`).
///
/// `buf` must be a writable buffer of at least 11 bytes (`0x` + 8 digits +
/// terminator), which is what the C routine writes.
pub fn hex_to_ascii(n: u32, buf: *mut u8) {
    // SAFETY: the caller contract above sizes `buf` for the full rendering.
    unsafe { sys::hex_to_ascii(n, buf) };
}
