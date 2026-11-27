// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel services the memory subsystem (`cact_mm`) calls but that do not belong
//! to a more specific sibling: the zstd glue behind the compressed page pool,
//! the Multiboot2 command-line lookup zswap's boot hook uses, and the fault
//! dumper's frame print.
//!
//! Each wraps a C symbol declared in [`crate::sys`].

use core::ffi::c_void;

use crate::sys;

/// Worst-case compressed size of a `src_size`-byte input (`zpool`).
pub fn zstd_bound(src_size: usize) -> usize {
    // SAFETY: `cact_zstd_compress_bound` only computes a size from its argument.
    unsafe { sys::cact_zstd_compress_bound(src_size) }
}

/// Compress `src_size` bytes of `src` into `dst`; returns the compressed length,
/// or 0 on failure.  `dst` must be writable for `dst_cap` bytes.
pub fn zstd_compress(
    level: i32,
    src: *const u8,
    src_size: usize,
    dst: *mut u8,
    dst_cap: usize,
) -> usize {
    // SAFETY: the caller guarantees `src` is readable for `src_size` bytes and
    // `dst` writable for `dst_cap`; the glue touches only those.
    unsafe { sys::cact_zstd_compress(level, src, src_size, dst, dst_cap) }
}

/// Decompress a `src_size`-byte frame into `dst`; returns the bytes written.
/// `dst` must be writable for `dst_cap` bytes.
pub fn zstd_decompress(src: *const u8, src_size: usize, dst: *mut u8, dst_cap: usize) -> usize {
    // SAFETY: the caller guarantees `src` is readable for `src_size` bytes and
    // `dst` writable for `dst_cap`; the glue touches only those.
    unsafe { sys::cact_zstd_decompress(src, src_size, dst, dst_cap) }
}

/// Bounded Multiboot2 command-line lookup: `1` found, `0` absent, `-1` too long.
/// `key` is NUL-terminated; `buf` is written up to `cap` bytes and NUL-terminated.
pub fn mb2_cmdline_value(key: *const u8, buf: *mut u8, cap: i32) -> i32 {
    // SAFETY: `key` is a NUL-terminated literal, and `buf`/`cap` describe a
    // writable buffer the C reader respects.
    unsafe { sys::mb2_cmdline_value(key as *const core::ffi::c_char, buf, cap) }
}

/// Dump a faulting register frame and signal to the console (`kernel_exc.c`).
/// `regs` points at the exception's `struct context_frame`.
pub fn dump_context_frame(regs: *const c_void, fault_addr: u64, signal: u32) {
    // SAFETY: `regs` is the live frame the entry stub built; the dumper only
    // reads it.
    unsafe { sys::dump_context_frame(regs, fault_addr, signal) };
}
