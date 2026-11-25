// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Pure slot allocator for the compressed-page pool (`comp::zpool`).
//!
//! A fixed table of `capacity` slots is threaded onto a LIFO free list whose
//! links live in a caller-owned `&mut [u32]` — the kernel glue keeps that array
//! in the heap, the host tests keep it on the stack.  There is no FFI, no
//! global and no allocation here, so the free-list and budget rules are covered
//! by `cargo test` instead of only by a boot.

/// A handle that names no slot (also the free-list terminator).
pub const HANDLE_NONE: u32 = u32::MAX;

/// Why `alloc` refused.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AllocError {
    /// Every slot is in use.
    NoSlot,
    /// A free slot exists, but the payload would exceed the byte budget.
    NoBudget,
}

/// Free-list and byte-budget state of one pool.  The payload length of each
/// live slot is tracked by the caller, which owns the blobs; `alloc`/`free`
/// are only charged with it so the budget can be enforced.
pub struct SlotAlloc {
    capacity: u32,
    head: u32,
    live: u32,
    used_bytes: u64,
    budget_bytes: u64,
}

impl SlotAlloc {
    pub const fn new() -> Self {
        SlotAlloc {
            capacity: 0,
            head: HANDLE_NONE,
            live: 0,
            used_bytes: 0,
            budget_bytes: 0,
        }
    }

    /// Build the free list over `links` (`links.len()` slots, linked 0..n), with
    /// a byte budget for the payloads the caller will store.
    pub fn init(&mut self, links: &mut [u32], budget_bytes: u64) {
        let capacity = links.len() as u32;
        self.capacity = capacity;
        self.head = if capacity == 0 { HANDLE_NONE } else { 0 };
        self.live = 0;
        self.used_bytes = 0;
        self.budget_bytes = budget_bytes;
        for (i, link) in links.iter_mut().enumerate() {
            *link = if (i as u32) + 1 < capacity {
                i as u32 + 1
            } else {
                HANDLE_NONE
            };
        }
    }

    /// Reserve a slot for a `payload_bytes` payload.  A refusal changes nothing,
    /// so a caller that hits [`AllocError::NoBudget`] can still free space and
    /// retry.
    pub fn alloc(&mut self, links: &mut [u32], payload_bytes: u64) -> Result<u32, AllocError> {
        if self.head == HANDLE_NONE {
            return Err(AllocError::NoSlot);
        }
        if self.used_bytes + payload_bytes > self.budget_bytes {
            return Err(AllocError::NoBudget);
        }
        let handle = self.head;
        self.head = links[handle as usize];
        links[handle as usize] = HANDLE_NONE;
        self.used_bytes += payload_bytes;
        self.live += 1;
        Ok(handle)
    }

    /// Return `handle` to the free list.  `payload_bytes` must be the value the
    /// matching `alloc` was charged.  Returns `false` for an out-of-range
    /// handle; freeing a handle twice is a caller error (a double free would
    /// corrupt the list, so the glue guards it with its blob table).
    pub fn free(&mut self, links: &mut [u32], handle: u32, payload_bytes: u64) -> bool {
        if handle >= self.capacity {
            return false;
        }
        links[handle as usize] = self.head;
        self.head = handle;
        self.used_bytes = self.used_bytes.saturating_sub(payload_bytes);
        self.live = self.live.saturating_sub(1);
        true
    }

    /// Adopt a rebuilt free list over a possibly larger table: take the new
    /// capacity, free-list head and payload budget, keeping the live count and
    /// the charged bytes (growing a table neither allocates nor frees a slot).
    /// Used by `zpool_grow`, where the blob table is the source of truth for
    /// what is in use.
    pub fn adopt(&mut self, capacity: u32, head: u32, budget_bytes: u64) {
        self.capacity = capacity;
        self.head = head;
        self.budget_bytes = budget_bytes;
    }

    /// Set the payload budget without touching the free list (a budget-only
    /// change; the caller keeps it at or above what is already charged).
    pub fn set_budget(&mut self, budget_bytes: u64) {
        self.budget_bytes = budget_bytes;
    }

    /// Slots the pool was created with.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Slots currently holding a payload.
    pub fn live(&self) -> u32 {
        self.live
    }

    /// Slots still on the free list.
    pub fn free_slots(&self) -> u32 {
        self.capacity - self.live
    }

    /// Bytes of payload currently charged against the budget.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// The payload budget.
    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

impl Default for SlotAlloc {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuild `links` as a free list over an *externally known* liveness: slot `i`
/// is linked exactly when `is_free(i)`.  Returns the head (`HANDLE_NONE` when
/// nothing is free).
///
/// Used when a slot table grows: the table's blob pointers are the source of
/// truth for what is in use, so the links are recomputed from them instead of
/// being carried across the reallocation.
pub fn rebuild_free_list(links: &mut [u32], is_free: impl Fn(u32) -> bool) -> u32 {
    let mut head = HANDLE_NONE;
    for i in (0..links.len()).rev() {
        if is_free(i as u32) {
            links[i] = head;
            head = i as u32;
        } else {
            links[i] = HANDLE_NONE;
        }
    }
    head
}
