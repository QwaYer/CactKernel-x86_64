// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure range math for `munmap`: how a request `[addr, end)` clips the regions
//! of an mmap table.
//!
//! No hardware access, no globals and no FFI, so this is the single source of
//! truth for the split arithmetic and it is unit-tested on the host by
//! `Kernel-Unit-Tests-for-Cact/` (P2.1).  `do_munmap` calls into it; nothing
//! here may reference `crate::`.

/// Which part of a region `[base, base+len)` a request removes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MunmapClip {
    /// The request covers the whole region: it goes away.
    Whole,
    /// The request takes the front; the region keeps `[hi, base+len)`.
    Front,
    /// The request takes the back; the region keeps `[base, lo)`.
    Back,
    /// The request takes a slice out of the middle: the region keeps
    /// `[base, lo)` and a new region must carry `[hi, base+len)`.
    Middle,
}

impl MunmapClip {
    /// True when the caller must reserve a second region slot for the tail.
    pub const fn needs_slot(self) -> bool {
        matches!(self, MunmapClip::Middle)
    }
}

/// The intersection of a request with one region.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MunmapSlice {
    /// First byte removed (inclusive).
    pub lo: u32,
    /// One past the last byte removed.
    pub hi: u32,
    pub kind: MunmapClip,
}

/// Classify the overlap of request `[addr, end)` with a region `[base, base+len)`.
///
/// Returns `None` when they do not overlap.  The shared end is exclusive, so a
/// region that merely abuts the request (starts at `end`, or ends at `addr`) is
/// not touched.  Regions are confined below 4 GiB, so `base + len` cannot wrap.
pub const fn clip_region(base: u32, len: u32, addr: u32, end: u32) -> Option<MunmapSlice> {
    let r_end = base + len;
    if base >= end || r_end <= addr {
        return None;
    }
    let lo = if addr > base { addr } else { base };
    let hi = if end < r_end { end } else { r_end };
    let front = lo == base;
    let back = hi == r_end;
    let kind = if front && back {
        MunmapClip::Whole
    } else if front {
        MunmapClip::Front
    } else if back {
        MunmapClip::Back
    } else {
        MunmapClip::Middle
    };
    Some(MunmapSlice { lo, hi, kind })
}
