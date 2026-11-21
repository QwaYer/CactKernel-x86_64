// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure size-class mapping for the kernel heap's segregated free lists.
//!
//! Each free block is linked into one of `CLASS_COUNT` lists, one per
//! power-of-two block size, so `kmalloc` takes a block off a class list instead
//! of scanning the whole heap.  `class_of` is the single decision that places a
//! block in a list, so it lives here alone and is unit-tested on the host
//! (P2.1) — the allocator and the tests must agree on it.  Nothing here may
//! reference `crate::`.

/// Number of size classes.  Class `c` holds blocks of size in `(2^(c-1), 2^c]`,
/// so 32 classes cover every block size the 16 MiB heap can produce.
pub const CLASS_COUNT: usize = 32;

/// Index of the smallest class whose size is at least `size`: the ceiling of
/// `log2(size)`.  `size` must be non-zero; the heap never makes a block below 16
/// bytes, so the result is always at least 4.
pub const fn class_of(size: u32) -> usize {
    let bits = u32::BITS - (size - 1).leading_zeros();
    let bits = bits as usize;
    if bits < CLASS_COUNT {
        bits
    } else {
        CLASS_COUNT - 1
    }
}

/// Smallest block size in class `c` (a power of two).
pub const fn class_size(c: usize) -> u32 {
    1u32 << c
}
