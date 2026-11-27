// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel allocators: intrusive heap (`kmalloc`) and slab caches for fixed object sizes.
//!
//! The `#[global_allocator]` that bridges Rust's `alloc` crate to this heap is
//! an `unsafe` lang-item, so it lives in `kernel_rust` (see its `galloc`), not
//! here.

pub mod heap;
pub mod heap_class;
pub mod heap_stats;
pub mod realloc_plan;
pub mod slab;
pub mod slab_owner;
