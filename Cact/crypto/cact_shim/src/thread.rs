// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

/// Stub. No threads in the kernel.
pub struct Thread;
pub fn current() -> Thread { Thread }
pub fn yield_now() {}
pub fn sleep(_dur: crate::time::Duration) {}
