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
