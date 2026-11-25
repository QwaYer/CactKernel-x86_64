// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure encoding of a swapped-out page's PTE.
//!
//! A swapped page is a **non-present** PTE (PAGE_PRESENT clear) carrying the
//! [`PAGE_SWAPPED`] marker and, in the frame field, either a device slot or a
//! zswap pool handle — [`PAGE_ZSWAP`] says which.  Kept free of FFI and globals
//! so the bit layout is pinned by `cargo test`; `fault::swap` and
//! `fault::zswap` are the only users.
//!
//! `PAGE_SWAPPED` reuses bit 3, which is `PAGE_PWT` (ffi.rs) in a *present* PTE:
//! the hardware only consults PWT when PRESENT is set, so the bit is free once
//! PRESENT is clear.  `PAGE_PRESENT` is mirrored here (it is the fixed
//! architectural bit 0) so this module needs no imports.

/// Bit 0 — the entry is valid.  Mirrors `ffi::PAGE_PRESENT`.
pub const PAGE_PRESENT: u32 = 0x001;
/// "This PTE is paged out" marker (bit 3 = PWT while PRESENT is clear).
pub const PAGE_SWAPPED: u32 = 0x008;
/// Set alongside `PAGE_SWAPPED` when the slot field holds a zswap pool handle
/// rather than a device slot (bit 6, otherwise unused in a PTE).
pub const PAGE_ZSWAP: u32 = 0x040;
/// The slot/handle sits in the frame field, bits 12..31.
pub const SLOT_MASK: u32 = 0xFFFF_F000;
pub const SLOT_SHIFT: u32 = 12;
/// Largest representable slot/handle (20 bits) — the value `decode` can return.
pub const SLOT_MAX: u32 = SLOT_MASK >> SLOT_SHIFT;

/// Encode a device slot: `PAGE_SWAPPED` + the slot in the frame field.
pub fn encode_device(slot: u32) -> u64 {
    (((slot << SLOT_SHIFT) & SLOT_MASK) as u64) | PAGE_SWAPPED as u64
}

/// Encode a zswap pool handle: a device-slot encoding plus the `PAGE_ZSWAP`
/// discriminator, so a fault-in knows to look in the pool instead of the device.
pub fn encode_zswap(handle: u32) -> u64 {
    encode_device(handle) | PAGE_ZSWAP as u64
}

/// The slot (device) or handle (zswap) stored in a swapped PTE.
pub fn decode(pte: u64) -> u32 {
    ((pte & SLOT_MASK as u64) >> SLOT_SHIFT) as u32
}

/// Is this PTE a swapped-out page?
pub fn is_swapped(pte: u64) -> bool {
    (pte & PAGE_PRESENT as u64 == 0) && (pte & PAGE_SWAPPED as u64 != 0)
}

/// Is this swapped PTE backed by the zswap pool (rather than the device)?
pub fn in_zswap(pte: u64) -> bool {
    is_swapped(pte) && (pte & PAGE_ZSWAP as u64 != 0)
}
