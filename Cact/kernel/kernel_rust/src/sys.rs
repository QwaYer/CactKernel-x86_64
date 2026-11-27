// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The raw `extern "C"` surface of the C kernel — every symbol the Rust graph
//! calls.  Nothing here is meant to be called directly: each item is wrapped by
//! a **safe** function in a sibling module ([`crate::console`], [`crate::cpu`],
//! [`crate::mem`]), and that is the whole point of this crate — the `unsafe` of
//! talking to C lives here, once, and the rest of the graph calls the safe
//! wrappers.

use core::ffi::{c_char, c_void};

use crate::cpu::VmxEptMap;

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
}
