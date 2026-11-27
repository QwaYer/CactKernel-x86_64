// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel allocators: intrusive heap (`kmalloc`) and slab caches for fixed object sizes.

mod global;
pub mod heap;
pub mod heap_class;
pub mod heap_stats;
pub mod realloc_plan;
pub mod slab;
pub mod slab_owner;
