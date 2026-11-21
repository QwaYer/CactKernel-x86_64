// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure aggregation of a kernel-heap free-list walk into a fragmentation
//! summary.
//!
//! No hardware access, no globals and no FFI, so the arithmetic is the single
//! source of truth and it is unit-tested on the host by
//! `Kernel-Unit-Tests-for-Cact/` (P2.1).  `heap_get_stats` walks the list and
//! folds each block in here; nothing in this module may reference `crate::`.

/// Heap free-list totals, accumulated one block at a time.
///
/// A block's `size` is its raw payload size (`HeapBlock::size`), so the totals
/// exclude the per-block headers; `free_bytes + used_bytes` is the window minus
/// the headers, not the window.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HeapAggregate {
    /// Sum of the sizes of the free blocks.
    pub free_bytes: u32,
    /// Sum of the sizes of the in-use blocks.
    pub used_bytes: u32,
    /// Number of free blocks.
    pub free_blocks: u32,
    /// Number of blocks of any kind.
    pub total_blocks: u32,
    /// Size of the largest free block (0 when the list holds no free block).
    pub largest_free: u32,
}

impl HeapAggregate {
    /// An empty aggregate.
    pub const fn new() -> Self {
        Self {
            free_bytes: 0,
            used_bytes: 0,
            free_blocks: 0,
            total_blocks: 0,
            largest_free: 0,
        }
    }

    /// Fold one heap block into the totals.  `size` is the block's raw size and
    /// `is_free` its state.
    pub fn add(&mut self, size: u32, is_free: bool) {
        self.total_blocks = self.total_blocks.saturating_add(1);
        if is_free {
            self.free_bytes = self.free_bytes.saturating_add(size);
            self.free_blocks = self.free_blocks.saturating_add(1);
            if size > self.largest_free {
                self.largest_free = size;
            }
        } else {
            self.used_bytes = self.used_bytes.saturating_add(size);
        }
    }
}
