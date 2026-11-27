// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The kernel's Rust link crate.
//!
//! Every kernel Rust crate is an `rlib` so that Rust code can call Rust code
//! with plain `use` (`cact_mm::kfree`, `sched::task_fork`, …) — `extern "C"`
//! is reserved for the real C kernel (`printk`, VFS, ELF loader, APIC, …).
//!
//! Something still has to be a `staticlib`, because meson links one archive
//! into `kernel.bin`.  That is this crate: it depends on the whole Rust graph
//! and pulls every crate into a single archive, so each symbol — and each
//! `#[no_mangle]` C-ABI entry point — exists exactly once in the final image.
//!
//! It holds no code of its own.  The graph's single `#[panic_handler]` and
//! `#[global_allocator]` both live in `cact_mm`, next to the heap they serve
//! (a crate graph may define each exactly once).  This crate is therefore
//! free of `unsafe` and forbids it outright.

#![no_std]
// This crate holds no code of its own — the graph's global allocator lives in
// `cact_mm` (see the module docs) — so it must never grow any `unsafe`.  That
// is stronger than the per-crate lint baseline the other crates carry, which
// exists to audit the `unsafe` they legitimately need.
#![forbid(unsafe_code)]

pub use cact_drm as drm;
pub use cact_hmac_ffi as hmac;
pub use cact_hv as hv;
pub use cact_mm as mm;
pub use cact_net as net;
pub use cact80211 as wireless;
pub use cact_vfs as vfs;
pub use sched as sched;
