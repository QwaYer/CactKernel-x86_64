// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Page-fault handling, swap-out/in, and out-of-memory recovery.

pub mod page_fault;
pub mod swap;
pub mod swap_pte;
pub mod zswap;
pub mod oom;
