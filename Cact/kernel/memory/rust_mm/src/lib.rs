#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

#![allow(internal_features)]
// Safety baseline: implicit unsafe ops inside `unsafe fn` bodies are rejected, and
// every `unsafe` block must carry a SAFETY comment (enforced under clippy).
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_unsafe)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![deny(static_mut_refs)]
#![deny(improper_ctypes, improper_ctypes_definitions)]
// Additional safety lints (all verified zero-hit when enabled, 2026-09-26):
// transmute misuse, byte-vs-element count confusion and assumptions that
// uninitialised memory is valid become hard errors instead of silent warnings.
#![deny(clippy::transmute_ptr_to_ref)]
#![deny(clippy::transmute_ptr_to_ptr)]
#![deny(clippy::useless_transmute)]
#![deny(clippy::size_of_in_element_count)]
#![deny(clippy::uninit_assumed_init)]
#![deny(invalid_reference_casting)]
// Finally, at most one unsafe operation per `unsafe` block, so every block is
// small enough to audit on its own (the same maximal tightening applied to the
// scheduler and the network stack).
#![deny(clippy::multiple_unsafe_ops_per_block)]

//! Rust-side memory management: physical allocator, kernel heap, page tables, COW,
//! page faults, mmap, and per-process helpers. Calls into C for low-level VMM/PMM.

mod ffi;
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
            // SAFETY: `buf` holds `n` bytes plus the NUL just written, so `printk` sees a valid
            // NUL-terminated string that outlives the call.
            unsafe { crate::ffi::printk(buf.as_ptr()) };
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
    // SAFETY: panicking CPU, unrecoverable state; `cli` touches no memory and clearing IF stops
    // the interrupt storm while the CPU parks below.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
    loop {
        // SAFETY: hlt is the only safe way to spin in a kernel panic.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
