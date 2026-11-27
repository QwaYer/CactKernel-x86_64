// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe reads/writes through pointers the C side hands over.
//!
//! The C ABI entry points a crate exports receive raw pointers to kernel
//! structs (an ioctl argument, a register frame).  Dereferencing them here —
//! once, in the graph's one `unsafe` crate — is how the receiving crate stays
//! free of `unsafe`.  The contract is the ABI itself: the pointer names a live,
//! properly aligned object of type `T`, which every `..._ctl` handler in
//! `Cact/kernel/hypervisor/chv.c` upholds.

/// Read a `Copy` value through a pointer from the C side.
pub fn read<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller holds the C-boundary contract above.
    unsafe { core::ptr::read(p) }
}

/// Write a value through a pointer from the C side.
pub fn write<T>(p: *mut T, value: T) {
    // SAFETY: the caller holds the C-boundary contract above.
    unsafe { core::ptr::write(p, value) };
}

/// Exclusive reference through a pointer from the C side (the pointer names a
/// live, aligned, unaliased object for the borrow's duration).
pub fn as_mut<'a, T>(p: *mut T) -> &'a mut T {
    // SAFETY: the C-boundary contract above.
    unsafe { &mut *p }
}

/// Shared reference through a pointer from the C side.
pub fn as_ref<'a, T>(p: *const T) -> &'a T {
    // SAFETY: the C-boundary contract above.
    unsafe { &*p }
}

/// `core::ptr::copy_nonoverlapping` with a safe signature.
pub fn copy_nonoverlapping<T>(src: *const T, dst: *mut T, count: usize) {
    // SAFETY: `src`/`dst` are C-boundary buffers of `count` elements.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, count) };
}

/// `core::ptr::write_bytes` with a safe signature.
pub fn write_bytes<T>(p: *mut T, val: u8, count: usize) {
    // SAFETY: `p` is a C-boundary buffer of `count` elements.
    unsafe { core::ptr::write_bytes(p, val, count) };
}

/// `core::slice::from_raw_parts` with a safe signature.
pub fn slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    // SAFETY: `p` is a C-boundary buffer of `len` readable elements.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// `core::slice::from_raw_parts_mut` with a safe signature.
pub fn slice_mut<'a, T>(p: *mut T, len: usize) -> &'a mut [T] {
    // SAFETY: `p` is a C-boundary buffer of `len` writable elements.
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

/// Advance a pointer by `count` elements (`p.add(count)`) without dereferencing.
/// The caller guarantees the result stays within the same allocated object.
pub fn add<T>(p: *const T, count: usize) -> *const T {
    // SAFETY: the caller guarantees the result stays in `p`'s allocation.
    unsafe { p.add(count) }
}
