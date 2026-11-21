// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure decision logic for `krealloc_aligned`: can a block be resized in place,
//! must it absorb its physically next free neighbour, or does it have to move?
//!
//! No hardware access, no globals and no FFI, so this is the single source of
//! truth for the size arithmetic and it is unit-tested on the host by
//! `Kernel-Unit-Tests-for-Cact/` (P2.1).  Nothing here may reference `crate::`.

/// Alignment the heap keeps every block size (and block address) at, so the
/// next block's header stays aligned.
pub const ALIGN: u32 = 8;

/// Smallest block the heap keeps.  A free block stores its two segregated-list
/// links in its own payload, so it must be at least this many bytes; no split
/// leaves a smaller remainder.
pub const MIN_FREE: u32 = 16;

const fn align_up(v: u32) -> u32 {
    match v.checked_add(ALIGN - 1) {
        Some(x) => x & !(ALIGN - 1),
        // Saturate rather than wrap: a request this large can never be served,
        // and the caller rejects it before touching the heap.
        None => u32::MAX & !(ALIGN - 1),
    }
}

/// Smallest raw block size that leaves `want` bytes usable from `off` bytes into
/// the block, keeping the trailing four-byte tail canary.
///
/// `off` is the caller's pointer minus the block address (`off >= hdr`); a
/// `kmalloc_aligned` block has `off > hdr`.  The block never shrinks below `off`
/// — the pointer itself must stay inside it.
pub fn required_block_size(off: u32, hdr: u32, want: u32) -> u32 {
    // payload = size - (off - hdr) - 4 (canary) >= want
    let extra = off.saturating_sub(hdr) as u64;
    let need = (want as u64) + 4 + extra;
    let need = if need > u32::MAX as u64 { u32::MAX } else { need as u32 };
    let req = align_up(need);
    let min = align_up(off);
    if req > min { req } else { min }
}

/// What `krealloc_aligned` can do with an existing block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Realloc {
    /// The block already fits: keep the pointer at this raw size.  A shrink may
    /// still be split off as a free block when `should_split` holds.
    InPlace { block_size: u32 },
    /// Absorb the physically next free block (large enough together), then keep
    /// the pointer at this raw size.
    MergeNext { block_size: u32 },
    /// Neither: allocate `want` elsewhere and copy.
    Move,
}

/// Choose the resize action for a `block_size`-byte block whose pointer sits
/// `off` bytes in, given its physically next block — its size, when that block
/// is free.
pub fn plan(
    block_size: u32,
    off: u32,
    hdr: u32,
    next_free_size: Option<u32>,
    want: u32,
) -> Realloc {
    let req = required_block_size(off, hdr, want);
    if block_size >= req {
        return Realloc::InPlace { block_size: req };
    }
    if let Some(ns) = next_free_size {
        // The next block is absorbed whole, its header included.
        if (block_size as u64) + (hdr as u64) + (ns as u64) >= req as u64 {
            return Realloc::MergeNext { block_size: req };
        }
    }
    Realloc::Move
}

/// True when the slack left by an in-place resize can carry its own block
/// header plus a minimal free block, i.e. it is worth splitting off instead of
/// keeping as internal slack.
pub fn should_split(block_size: u32, new_size: u32, hdr: u32) -> bool {
    block_size >= new_size + hdr + MIN_FREE
}
