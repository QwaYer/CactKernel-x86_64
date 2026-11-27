// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe helpers for the C-ABI buffer arguments the `/dev/crypto` entry points
//! receive: the shared `(ptr, len)` convention and a bounded C-string read.  All
//! pointer work goes through `kernel_rust::ptr` (the graph's one `unsafe` crate).

use alloc::string::String;
use core::ffi::c_char;

use kernel_rust::ptr;

/// Interpret a C `(ptr, len)` pair as a byte slice.  A null pointer with length
/// zero is the empty slice; a null pointer with a non-zero length is rejected
/// (`None`).  The caller guarantees `len` readable bytes when `ptr` is non-null.
pub(crate) fn cslice<'a>(p: *const u8, len: u32) -> Option<&'a [u8]> {
    if p.is_null() {
        return if len == 0 { Some(&[]) } else { None };
    }
    Some(ptr::slice(p, len as usize))
}

/// Read a NUL-terminated C string, bounded to 255 bytes so a hostile input
/// cannot scan kernel memory forever.  The caller guarantees `ptr` points into a
/// readable allocation holding a NUL-terminated string.
pub(crate) fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let p = p as *const u8;
    let mut len = 0usize;
    while ptr::read(ptr::add(p, len)) != 0 {
        len += 1;
        if len > 255 {
            return None;
        }
    }
    core::str::from_utf8(ptr::slice(p, len))
        .ok()
        .map(String::from)
}
