// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Virtual memory: kernel page tables, fork/COW, and mmap bookkeeping.

pub mod paging;
pub mod pat;
pub mod cow;
pub mod mmap;
pub mod stats;
