#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

#![feature(sync_unsafe_cell)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// Safety baseline: unsafe ops inside `unsafe fn` bodies must be explicit, and every
// `unsafe` block needs a SAFETY comment (the latter enforced under clippy).
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
// Maximal-safety: one unsafe operation per `unsafe` block, so each `// SAFETY:`
// justifies exactly one operation.
#![deny(clippy::multiple_unsafe_ops_per_block)]

pub mod ffi;
pub mod energy_model;
pub mod topology;
pub mod cpu_topo;
pub mod placement;
pub mod intrusive_queue;
pub mod mlfq_policy;
pub mod task;
pub mod mlfq;
pub mod mlfq_map;
pub mod percpu;
pub mod energy;
pub mod cstate;
pub mod monitor;
pub mod decision;
pub mod balance;
pub mod balance_policy;
pub mod smp;
pub mod timer_wheel;

pub mod sync {
    pub use cact_sync::*;
}

// The panic handler for the whole kernel Rust graph lives in `cact_mm` (which
// this crate depends on), so it is not defined here — a crate graph may have
// exactly one `#[panic_handler]` lang item.

const _ABI_CHECK: () = {
    use core::mem::offset_of;
    use cact_sync::task_abi::{ProcMeta, ProcShared, TaskStruct};

    assert!(offset_of!(TaskStruct, esp)             == 0, "esp offset mismatch");
    assert!(offset_of!(TaskStruct, page_directory)  == 8, "page_directory offset mismatch");
    assert!(offset_of!(TaskStruct, fpu_context_ptr) == 16, "fpu_context_ptr offset mismatch");
    assert!(offset_of!(TaskStruct, pid)             == 24, "pid offset mismatch");
    assert!(offset_of!(TaskStruct, state)           == 28, "state offset mismatch");
    assert!(offset_of!(TaskStruct, is_kernel)       == 32, "is_kernel offset mismatch");
    assert!(offset_of!(TaskStruct, next)            == 40, "next offset mismatch");
    assert!(offset_of!(TaskStruct, queue_next)      == 48, "queue_next offset mismatch");
    assert!(offset_of!(TaskStruct, priority)        == 56, "priority offset mismatch");
    assert!(offset_of!(TaskStruct, time_slice)      == 60, "time_slice offset mismatch");
    assert!(offset_of!(TaskStruct, ticks_used)      == 64, "ticks_used offset mismatch");
    assert!(offset_of!(TaskStruct, proc)            == 72, "proc offset mismatch");
    assert!(core::mem::size_of::<TaskStruct>() == 80, "TaskStruct size mismatch");

    assert!(offset_of!(ProcMeta, stack_base)         == 0, "stack_base offset mismatch");
    assert!(offset_of!(ProcMeta, ustack_phys)        == 8, "ustack_phys offset mismatch");
    assert!(offset_of!(ProcMeta, ustack_virt)        == 16, "ustack_virt offset mismatch");
    assert!(offset_of!(ProcMeta, ustack_phys_extra)  == 24, "ustack_phys_extra offset mismatch");
    assert!(offset_of!(ProcMeta, pending_signals)    == 48, "pending_signals offset mismatch");
    assert!(offset_of!(ProcMeta, signal_mask)        == 52, "signal_mask offset mismatch");
    assert!(offset_of!(ProcMeta, saved_signal_mask)  == 56, "saved_signal_mask offset mismatch");
    assert!(offset_of!(ProcMeta, in_sigsuspend)      == 60, "in_sigsuspend offset mismatch");
    assert!(offset_of!(ProcMeta, signal_handlers)    == 64, "signal_handlers offset mismatch");
    assert!(offset_of!(ProcMeta, sigreturn_trampoline) == 168, "sigreturn_trampoline offset mismatch");
    assert!(offset_of!(ProcMeta, alarm_ticks)        == 176, "alarm_ticks offset mismatch");
    assert!(offset_of!(ProcMeta, itimer_value)       == 180, "itimer_value offset mismatch");
    assert!(offset_of!(ProcMeta, itimer_interval)    == 184, "itimer_interval offset mismatch");
    assert!(offset_of!(ProcMeta, fds)                 == 192, "fds offset mismatch");
    assert!(offset_of!(ProcMeta, mm)                  == 200, "mm offset mismatch");
    assert!(offset_of!(ProcMeta, mmap_table)          == 224, "mmap_table offset mismatch");
    assert!(offset_of!(ProcMeta, parent_pid)          == 232, "parent_pid offset mismatch");
    assert!(offset_of!(ProcMeta, exit_code)           == 236, "exit_code offset mismatch");
    assert!(offset_of!(ProcMeta, wait_for_pid)        == 240, "wait_for_pid offset mismatch");
    assert!(offset_of!(ProcMeta, brk_start)           == 248, "brk_start offset mismatch");
    assert!(offset_of!(ProcMeta, brk_current)         == 256, "brk_current offset mismatch");
    assert!(offset_of!(ProcMeta, sleep_until)         == 264, "sleep_until offset mismatch");
    assert!(offset_of!(ProcMeta, cwd)                 == 268, "cwd offset mismatch");
    assert!(offset_of!(ProcMeta, uid)                 == 524, "uid offset mismatch");
    assert!(offset_of!(ProcMeta, gid)                 == 528, "gid offset mismatch");
    assert!(offset_of!(ProcMeta, euid)                == 532, "euid offset mismatch");
    assert!(offset_of!(ProcMeta, egid)                == 536, "egid offset mismatch");
    assert!(offset_of!(ProcMeta, shm_attachments)     == 540, "shm_attachments offset mismatch");
    assert!(offset_of!(ProcMeta, wait_next)           == 672, "wait_next offset mismatch");
    assert!(offset_of!(ProcMeta, pgid)                == 680, "pgid offset mismatch");
    assert!(offset_of!(ProcMeta, sid)                 == 684, "sid offset mismatch");
    assert!(offset_of!(ProcMeta, umask)               == 688, "umask offset mismatch");
    assert!(offset_of!(ProcMeta, root)                == 696, "root offset mismatch");
    assert!(offset_of!(ProcMeta, exec_base)            == 704, "exec_base offset mismatch");
    assert!(offset_of!(ProcMeta, exec_symtab)          == 712, "exec_symtab offset mismatch");
    assert!(offset_of!(ProcMeta, exec_strtab)          == 720, "exec_strtab offset mismatch");
    assert!(offset_of!(ProcMeta, exec_symtab_count)    == 728, "exec_symtab_count offset mismatch");
    assert!(offset_of!(ProcMeta, tgid)                 == 732, "tgid offset mismatch");
    assert!(offset_of!(ProcMeta, is_thread)            == 736, "is_thread offset mismatch");
    assert!(offset_of!(ProcMeta, shared)               == 744, "shared offset mismatch");
    assert!(offset_of!(ProcMeta, clr_tid)              == 752, "clr_tid offset mismatch");
    assert!(offset_of!(ProcMeta, intr_wait)            == 760, "intr_wait offset mismatch");
    assert!(offset_of!(ProcMeta, altstack_sp)          == 768, "altstack_sp offset mismatch");
    assert!(offset_of!(ProcMeta, altstack_size)        == 776, "altstack_size offset mismatch");
    assert!(offset_of!(ProcMeta, altstack_flags)       == 780, "altstack_flags offset mismatch");
    assert!(offset_of!(ProcMeta, signal_flags)         == 784, "signal_flags offset mismatch");
    assert!(offset_of!(ProcMeta, tls_base)             == 840, "tls_base offset mismatch");
    assert!(offset_of!(ProcMeta, signal_masks)         == 848, "signal_masks offset mismatch");
    assert!(offset_of!(ProcMeta, signal_codes)         == 900, "signal_codes offset mismatch");
    assert!(offset_of!(ProcMeta, signal_addr)          == 952, "signal_addr offset mismatch");
    assert!(offset_of!(ProcMeta, sigwait_set)          == 960, "sigwait_set offset mismatch");
    assert!(offset_of!(ProcMeta, signal_value)         == 964, "signal_value offset mismatch");
    assert!(core::mem::size_of::<ProcMeta>() == 968, "ProcMeta size mismatch");

    assert!(offset_of!(ProcShared, refcount)    == 0, "ProcShared refcount offset mismatch");
    assert!(offset_of!(ProcShared, brk_start)   == 8, "ProcShared brk_start offset mismatch");
    assert!(offset_of!(ProcShared, brk_current) == 16, "ProcShared brk_current offset mismatch");
    assert!(offset_of!(ProcShared, tgid)        == 24, "ProcShared tgid offset mismatch");
    assert!(offset_of!(ProcShared, mm)          == 32, "ProcShared mm offset mismatch");
    assert!(core::mem::size_of::<ProcShared>() == 56, "ProcShared size mismatch");
};


