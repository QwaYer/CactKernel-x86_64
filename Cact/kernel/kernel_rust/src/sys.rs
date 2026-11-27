// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The raw `extern "C"` surface of the C kernel — every symbol the Rust graph
//! calls.  Nothing here is meant to be called directly: each item is wrapped by
//! a **safe** function in a sibling module ([`crate::console`], [`crate::cpu`],
//! [`crate::mem`]), and that is the whole point of this crate — the `unsafe` of
//! talking to C lives here, once, and the rest of the graph calls the safe
//! wrappers.

use core::ffi::{c_char, c_int, c_void};

use crate::cpu::VmxEptMap;
use crate::sync::irq_spinlock_t;

extern "C" {
    // ---- console --------------------------------------------------------
    pub fn printk(s: *const c_char);
    pub fn serial_putc(c: c_char);

    // ---- CPU / MSR / VMX ------------------------------------------------
    pub fn cact_rdmsr(msr: u32) -> u64;
    pub fn cact_cpuid(leaf: u32, subleaf: u32, eax: *mut u32, ebx: *mut u32,
                      ecx: *mut u32, edx: *mut u32);
    pub fn cact_vmread(field: u64, value: *mut u64) -> i32;
    pub fn cact_vmwrite(field: u64, value: u64) -> i32;
    pub fn cact_vmclear(phys: u64) -> i32;
    pub fn cact_vmptrld(phys: u64) -> i32;
    pub fn cact_vmx_launch_regs(gprs: *const u64) -> i32;
    pub fn cact_vmx_exit_stub_addr() -> u64;
    pub fn cact_cpu_state_snapshot(out: *mut u64);
    pub fn vmx_host_enable() -> i32;
    pub fn vmx_host_disable();
    pub fn vmx_ept_supported() -> i32;
    pub fn vmx_ept_build(maps: *const VmxEptMap, count: u32) -> u64;
    pub fn vmx_ept_free();
    pub fn vmx_ept_invept_single(eptp: u64) -> i32;

    // ---- memory ---------------------------------------------------------
    pub fn kalloc() -> *mut u8;
    pub fn kfree(ptr: *mut u8);
    pub fn free_page(ptr: *mut u8);
    /// `cact_mm`'s heap entry points, reached over the C ABI by the
    /// `#[global_allocator]` (see [`crate::galloc`]).
    pub fn kmalloc_aligned(size: usize, align: usize) -> *mut u8;
    pub fn krealloc_aligned(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8;
    pub fn vmm_v2p(ptr: *const u8) -> u64;
    pub fn vmm_pin_range(pd: *mut u64, va: u64, size: u64, out_phys: *mut u64) -> i64;
    pub fn vmm_unpin_frames(phys: *const u64, count: u64);

    // ---- kernel services used by the network stack ----------------------
    pub fn timer_ticks_get() -> u32;
    pub fn ktime_get_usec() -> u64;
    pub fn ktime_busy_wait_us(us: u64);
    pub fn tcp_recv(sock: i32, buf: *mut u8, max_len: u16) -> i32;

    // ---- C-visible state whose storage lives in `kernel_abi` ------------
    pub static mut active_nic: *mut c_void;

    // ---- scheduler services the sync primitives build on ----------------
    // Supplied by the `sched` crate (task context only).  Task pointers cross
    // as `*mut c_void` so this crate stays a leaf that names no task type.
    pub fn schedule();
    pub fn sched_mlfq_wake_task_locked(task: *mut c_void);
    pub fn cact_current_task_get() -> *mut c_void;
    /// The scheduler's global IRQ spinlock (defined by `sched`).
    pub static mut scheduler_lock: irq_spinlock_t;

    // ---- user-copy / validation services (validate.h) -------------------
    pub fn validate_user_ptr(ptr: *const c_void, size: u32) -> i32;
    pub fn copy_from_user(dst: *mut c_void, src: *const c_void, size: u32) -> i32;
    pub fn copy_to_user(dst: *mut c_void, src: *const c_void, size: u32) -> i32;

    // ---- CPU feature query (cpudev.h) -----------------------------------
    pub fn cpu_has_rdrand() -> i32;

    // ---- devfs character-device registration ----------------------------
    pub fn register_chrdev(
        name: *const c_char,
        flags: u32,
        drv: *mut c_void,
        drv_priv: *mut c_void,
    ) -> *mut c_void;
    pub fn unregister_chrdev(name: *const c_char) -> i32;

    // ---- fs: fd table + shared RAM object (helper.h, memfd.h) -----------
    pub fn alloc_fd(node: *mut c_void) -> c_int;
    pub fn memfd_create(name: *const u8, name_len: u32, flags: c_int) -> c_int;
    pub fn memfd_truncate(handle: c_int, size: u64) -> c_int;
    pub fn memfd_close(handle: c_int) -> c_int;
    pub fn memfd_ref(handle: c_int) -> c_int;
    pub fn memfd_get_page(handle: c_int, idx: u32) -> *mut c_void;
    pub fn memfd_size(handle: c_int) -> i64;
    pub fn memfd_fd_handle(fd: c_int) -> c_int;
    pub fn memfd_vnode_from_handle(handle: c_int, name: *const u8, size: u32) -> *mut c_void;

    // ---- eventfd (fs/eventfd/eventfd.c) ---------------------------------
    pub fn eventfd_node_get(fd: c_int, out: *mut *mut c_void) -> c_int;
    pub fn eventfd_node_put(node: *mut c_void);
    pub fn eventfd_node_signal(node: *mut c_void, n: u64) -> c_int;

    // ---- VFS stat fill (rust_vfs) ---------------------------------------
    pub fn vfs_fill_stat(node: *mut c_void, buf: *mut c_void);

    // ---- page-table walk (kernel/memory/rust_mm) ------------------------
    pub fn vmm_get_phys(pd: *mut u64, va: u64) -> u64;

    // ---- scheduler sleep (proc/sched) -----------------------------------
    pub fn sched_sleep_ticks(ticks: u32);
}
