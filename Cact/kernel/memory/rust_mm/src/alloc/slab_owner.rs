// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure ownership decision for `slab_kfree`: is the page header under an
//! allocation a live slab header, or is the allocation a plain heap block?
//!
//! No hardware access, no globals and no FFI, so this is the single source of
//! truth for the decision and it is unit-tested on the host by
//! `Kernel-Unit-Tests-for-Cact/` (P2.1).  `slab_kfree` reads the page header and
//! calls `is_slab_header`; nothing here may reference `crate::`.

/// Stamped into every slab page header (`Slab::magic`).  A plain `kmalloc` block
/// almost never carries this word at its page base, which is what makes the
/// check trustworthy where the old `capacity` range test was not.  Mirrored by
/// `SLAB_MAGIC` in `Cact/kernel/memory/slab.h` for documentation only.
pub const SLAB_MAGIC: u32 = 0x51AB_5EED;

/// True when a page header is a live slab header: the magic matches, the owning
/// cache pointer is set and the object capacity is non-zero.  Anything else is a
/// plain heap block (or garbage) and must go to `kfree`.
pub fn is_slab_header(magic: u32, capacity: u32, cache_non_null: bool) -> bool {
    magic == SLAB_MAGIC && capacity > 0 && cache_non_null
}
