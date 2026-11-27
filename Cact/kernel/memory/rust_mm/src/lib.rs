#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

#![allow(internal_features)]
// This crate talks to the C kernel only through `kernel_rust`, the graph's one
// `unsafe` crate: the `extern "C"` surface and the raw-pointer/`static mut`
// plumbing both live there, so this crate holds no `unsafe` of its own and
// forbids it outright.  Its C-ABI exports (`#[no_mangle]`) live in `kernel_abi`.
#![forbid(unsafe_code)]
// The C-ABI hooks this crate defines (`extern "C" fn` slab ctor/dtor and the
// swap read/write callbacks) still have to be FFI-safe, so that check stays in
// addition to the `unsafe_code` ban.
#![deny(improper_ctypes, improper_ctypes_definitions)]

//! Rust-side memory management: physical allocator, kernel heap, page tables, COW,
//! page faults, mmap, and per-process helpers. Calls into C for low-level VMM/PMM.

// `ffi` holds the crate's C-ABI mirror types (`ContextFrame`, `Mb2MmapTable`,
// the `*Stats` mirrors).  It is `pub` so `kernel_abi` can name those types in
// the C-ABI thunks it now owns: a `pub struct` inside a private module is not
// nameable from another crate, and the thunks must reproduce the exact ABI.
pub mod ffi;
// Rust API for other kernel crates: the same functions the C ABI exports, but
// reachable as ordinary Rust items, so `sched`/`rust_drm`/`rust_net` call them
// with `use cact_mm::…` instead of re-declaring `extern "C"` themselves.
pub use crate::alloc::heap::{
    kfree, kmalloc, kmalloc_aligned, kmalloc_usable_size, krealloc_aligned,
};
pub use crate::ffi::PMM_MAX_FRAMES;
pub use crate::pmm::{free_page, kalloc};
pub use crate::process::proc_mm::{proc_free_pages, proc_tracker_add};
pub use crate::process::shm::shm_detach_all;
pub use crate::vmm::mmap::{mmap_table_clone, mmap_table_free, mmap_table_init};
pub use crate::vmm::cow::vmm_fork_address_space;
pub use crate::vmm::paging::{
    vmm_create_address_space, vmm_free_address_space, vmm_map, vmm_p2v, vmm_sync_kernel_mmio_mappings,
    vmm_v2p,
};
mod safe;
pub mod pmm;
pub mod pmm_math;
pub mod munmap_plan;
pub mod alloc;
pub mod vmm;
pub mod fault;
pub mod process;
pub mod comp;

/// Console sink for the panic path: forwards formatting output to `printk` in
/// NUL-terminated chunks.  No allocation and no locking — the CPU is already
/// unrecoverable, and `printk` itself may be re-entered only from here.
struct PanicConsole;

impl core::fmt::Write for PanicConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let mut buf = [0u8; 160];
        let mut off = 0;
        while off < bytes.len() {
            let n = core::cmp::min(bytes.len() - off, buf.len() - 1);
            buf[..n].copy_from_slice(&bytes[off..off + n]);
            buf[n] = 0;
            crate::ffi::printk(buf.as_ptr());
            off += n;
        }
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // The payload and source location are the whole point of a panic: print both
    // before parking, so a Rust fault is diagnosable from COM1 alone instead of
    // leaving a bare "[RUST] PANIC" with no message and no file:line.
    let _ = core::fmt::write(&mut PanicConsole, format_args!("[RUST] PANIC: {info}\n"));
    // Panicking CPU, unrecoverable state: clearing IF stops the interrupt storm
    // while the CPU parks in `hlt` below.
    kernel_rust::cpu::interrupts_disable();
    kernel_rust::cpu::halt_forever()
}
