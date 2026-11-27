// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe CPU access: MSR reads, CPUID, and the VT-x/VMCS/EPT primitives.  The
//! instructions themselves (in the C/asm kernel) stay unsafe; each wrapper
//! here fixes the pointer plumbing so callers pass plain values and slices.

use crate::sys;

/// One EPT leaf mapping, as `vmx/ept.h` declares it: guest-physical page ->
/// host-physical page with the given permissions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmxEptMap {
    pub gpa: u64,
    pub hpa: u64,
    pub flags: u32,
}

/// The four CPUID outputs.
#[derive(Clone, Copy)]
pub struct Cpuid {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Read an MSR (`cact_rdmsr`).
pub fn rdmsr(msr: u32) -> u64 {
    // SAFETY: reading a valid MSR has no preconditions; an invalid MSR faults
    // the same way it would for the C caller.
    unsafe { sys::cact_rdmsr(msr) }
}

/// `CPUID` for `leaf`/`subleaf`.
pub fn cpuid(leaf: u32, subleaf: u32) -> Cpuid {
    let (mut eax, mut ebx, mut ecx, mut edx) = (0u32, 0u32, 0u32, 0u32);
    // SAFETY: the four `&mut` are distinct live `u32`; `cact_cpuid` writes
    // exactly those four out-pointers.
    unsafe { sys::cact_cpuid(leaf, subleaf, &mut eax, &mut ebx, &mut ecx, &mut edx) };
    Cpuid { eax, ebx, ecx, edx }
}

/// `VMREAD` a VMCS field.  Returns the C status (`0` = ok); `out` is left
/// untouched on failure.
pub fn vmread(field: u64, out: &mut u64) -> i32 {
    // SAFETY: `out` is a live `u64`; the caller runs with the VMCS current.
    unsafe { sys::cact_vmread(field, out) }
}

/// `VMWRITE` a VMCS field.  Returns the C status (`0` = ok).
pub fn vmwrite(field: u64, value: u64) -> i32 {
    // SAFETY: the caller runs with the VMCS current.
    unsafe { sys::cact_vmwrite(field, value) }
}

/// `VMCLEAR` the VMCS whose physical address is `phys`.
pub fn vmclear(phys: u64) -> i32 {
    // SAFETY: `phys` names a VMCS region the caller owns.
    unsafe { sys::cact_vmclear(phys) }
}

/// `VMPTRLD` (make current) the VMCS at `phys`.
pub fn vmptrld(phys: u64) -> i32 {
    // SAFETY: `phys` names a VMCS region the caller owns.
    unsafe { sys::cact_vmptrld(phys) }
}

/// `VMLAUNCH` with the given GPR frame (15 entries: RAX..R15).
pub fn vmx_launch_regs(gprs: &[u64]) -> i32 {
    // SAFETY: `gprs` is a live slice; the asm stub reads the 15 it expects.
    unsafe { sys::cact_vmx_launch_regs(gprs.as_ptr()) }
}

/// Guest-linear address of the C/asm VM-exit stub (the VMCS host RIP).
pub fn vmx_exit_stub_addr() -> u64 {
    // SAFETY: no preconditions.
    unsafe { sys::cact_vmx_exit_stub_addr() }
}

/// Snapshot the host's control-register state into `out` (16 entries).
pub fn cpu_state_snapshot(out: &mut [u64]) {
    // SAFETY: the caller passes a 16-entry buffer, which is what the C routine
    // writes.
    unsafe { sys::cact_cpu_state_snapshot(out.as_mut_ptr()) };
}

/// Enter VT-x host mode.  Returns `0` on success.
pub fn vmx_host_enable() -> i32 {
    // SAFETY: no preconditions; the routine does VMXON on this CPU.
    unsafe { sys::vmx_host_enable() }
}

/// Leave VT-x host mode (always paired with [`vmx_host_enable`]).
pub fn vmx_host_disable() {
    // SAFETY: callable whenever host mode may be active; VMXOFF.
    unsafe { sys::vmx_host_disable() };
}

/// Whether EPT is available on this CPU (`0` = no).
pub fn vmx_ept_supported() -> i32 {
    // SAFETY: no preconditions.
    unsafe { sys::vmx_ept_supported() }
}

/// Build the EPT from `maps`; returns the EPTP (`0` on failure).
pub fn vmx_ept_build(maps: &[VmxEptMap]) -> u64 {
    // SAFETY: `maps` is a live slice and the count matches its length.
    unsafe { sys::vmx_ept_build(maps.as_ptr(), maps.len() as u32) }
}

/// Free the current EPT tables.
pub fn vmx_ept_free() {
    // SAFETY: no preconditions.
    unsafe { sys::vmx_ept_free() };
}

/// `INVEPT` (single-context) for the given EPTP.  Returns `0` on success.
pub fn vmx_ept_invept_single(eptp: u64) -> i32 {
    // SAFETY: `eptp` is an EPTP the caller just built.
    unsafe { sys::vmx_ept_invept_single(eptp) }
}
