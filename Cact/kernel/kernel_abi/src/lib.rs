// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The kernel's exported C ABI: every `#[no_mangle]` entry point the C side
//! calls into Rust.  Each is a thin thunk onto a safe Rust function in a logic
//! crate (today `cact_hv`).
//!
//! **Why this crate exists.**  Rust's `unsafe_code` lint counts `#[no_mangle]`
//! as unsafe — the linker cannot check a hand-picked symbol against a clash —
//! and `forbid` cannot be overridden by an inner `allow`.  So a crate that
//! exports C symbols cannot `forbid(unsafe_code)`.  Isolating the exports here
//! keeps every logic crate `#![forbid(unsafe_code)]` and confines the attribute
//! to exactly one place.  The graph's `unsafe` *code* stays in `kernel_rust`
//! (the safe Rust <-> C interface); this crate only re-declares symbols.

#![no_std]
// The whole crate is the C-ABI boundary, so the `#[no_mangle]` allowance is
// crate-wide.  The thunks below hold no `unsafe` of their own — each is a
// single call into a safe function.
#![allow(unsafe_code)]

mod crypto;
mod drm;
mod mm;
mod net;
mod sync;
mod wireless;

use cact_hv::{ChvMem, ChvMsrs, ChvRegs, ChvSregs};

#[no_mangle]
pub extern "C" fn hv_get_regs(out: *mut ChvRegs) -> i32 {
    cact_hv::hv_get_regs(out)
}

#[no_mangle]
pub extern "C" fn hv_set_regs(inp: *const ChvRegs) -> i32 {
    cact_hv::hv_set_regs(inp)
}

#[no_mangle]
pub extern "C" fn hv_get_sregs(out: *mut ChvSregs) -> i32 {
    cact_hv::hv_get_sregs(out)
}

#[no_mangle]
pub extern "C" fn hv_set_sregs(inp: *const ChvSregs) -> i32 {
    cact_hv::hv_set_sregs(inp)
}

#[no_mangle]
pub extern "C" fn hv_get_msrs(io: *mut ChvMsrs) -> i32 {
    cact_hv::hv_get_msrs(io)
}

#[no_mangle]
pub extern "C" fn hv_set_msrs(io: *const ChvMsrs) -> i32 {
    cact_hv::hv_set_msrs(io)
}

#[no_mangle]
pub extern "C" fn hv_inject_irq(vector: u32) -> i32 {
    cact_hv::hv_inject_irq(vector)
}

#[no_mangle]
pub extern "C" fn hv_add_memory_region(inp: *const ChvMem, pd: *mut u64) -> i32 {
    cact_hv::hv_add_memory_region(inp, pd)
}

#[no_mangle]
pub extern "C" fn hv_del_memory_region(inp: *const ChvMem) -> i32 {
    cact_hv::hv_del_memory_region(inp)
}

#[no_mangle]
pub extern "C" fn cact_hv_guest_table_pages() -> u32 {
    cact_hv::cact_hv_guest_table_pages()
}

/// VM-exit entry, called by the C/asm stub.
#[no_mangle]
pub extern "C" fn hv_vmx_exit_entry(regs: *mut u64) -> i32 {
    cact_hv::hv_vmx_exit_entry(regs)
}

/// `/dev/chv` RUN, called from `Cact/kernel/hypervisor/chv.c`.
#[no_mangle]
pub extern "C" fn hv_run_guest(out_exit_reason: *mut u64) -> i32 {
    cact_hv::hv_run_guest(out_exit_reason)
}
