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
//! (including the safe kernel-interface crate `kernel_rust`) and pulls every
//! crate into a single archive, so each symbol — and each `#[no_mangle]`
//! C-ABI entry point — exists exactly once in the final image.
//!
//! It holds no code of its own, so it must never grow any `unsafe`.  The
//! `unsafe` of the Rust graph lives in exactly one crate: [`kernel_rust`], the
//! safe Rust/C interface (see its docs).

#![no_std]
#![forbid(unsafe_code)]

pub use cact_drm as drm;
pub use cact_hv as hv;
pub use cact_mm as mm;
pub use cact_net as net;
pub use cact80211 as wireless;
pub use cact_vfs as vfs;
pub use kernel_abi as abi;
pub use kernel_rust as krt;
pub use sched as sched;
