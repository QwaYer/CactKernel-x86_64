// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The GPR frame a C/asm VM-exit stub hands to Rust.

/// A borrowed register frame (`*mut u64`) passed up from the C VMX stub:
/// `frame[k]` = RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8..R15.  Holding the raw
/// pointer is safe; only the volatile reads/writes go through this type.
pub struct Frame {
    ptr: *mut u64,
}

impl Frame {
    /// Wrap the frame pointer the C stub passes.  The caller must hold the live
    /// GPR frame of the current VM exit — the exit entry point is the only
    /// user, and it receives exactly that pointer.
    pub fn new(ptr: *mut u64) -> Frame {
        Frame { ptr }
    }

    /// Read slot `i`.
    pub fn read(&self, i: usize) -> u64 {
        // SAFETY: `ptr` is the live frame (caller contract in `new`).
        unsafe { core::ptr::read_volatile(self.ptr.add(i)) }
    }

    /// Write slot `i`.
    pub fn write(&self, i: usize, value: u64) {
        // SAFETY: as in `read`.
        unsafe { core::ptr::write_volatile(self.ptr.add(i), value) };
    }
}
