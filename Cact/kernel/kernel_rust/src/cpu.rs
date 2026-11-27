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

/// Write an MSR (`cact_wrmsr`).
pub fn wrmsr(msr: u32, value: u64) {
    // SAFETY: writing an MSR is the caller's responsibility — the same one the C
    // `cact_wrmsr` carries; no memory is touched.
    unsafe { sys::cact_wrmsr(msr, value) };
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

// ---- spin-loop / interrupt-flag primitives used by the sync locks ----------

/// Spin-wait backoff hint (`pause`), issued while a lock spins.
pub fn pause() {
    // SAFETY: `pause` is a hint instruction defined for every x86 CPU this
    // kernel runs on (a plain `rep nop` on parts without SSE2); it touches no
    // memory and no flags, so it cannot corrupt the spin loop.
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
    }
}

/// Clear IF on this CPU (`cli`).
pub fn interrupts_disable() {
    // SAFETY: `cli` only clears IF on the current CPU and writes no memory; the
    // caller is a lock primitive that must run this critical section with
    // maskable interrupts off.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

/// Set IF on this CPU (`sti`).
pub fn interrupts_enable() {
    // SAFETY: `sti` only sets IF on the current CPU and writes no memory; the
    // caller has already restored the lock's saved state and expects interrupts
    // to become enabled.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

/// Snapshot RFLAGS (the low 32 bits).
pub fn eflags_read() -> u32 {
    // SAFETY: `pushfq` pushes RFLAGS onto the (valid) kernel stack and `pop`
    // reads it back into a register; both are unprivileged and the sequence is
    // stack-balanced, so it only reports the current RFLAGS value.
    unsafe {
        let flags: u64;
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
        flags as u32
    }
}

// ---- entropy / timing instructions (CSPRNG seeding) ------------------------

/// True when the CPU advertises RDRAND (CPUID leaf 1, ECX bit 30).
pub fn has_rdrand() -> bool {
    // SAFETY: `cpu_has_rdrand` is the kernel's CPUID helper; no preconditions.
    unsafe { sys::cpu_has_rdrand() != 0 }
}

/// One 32-bit RDRAND word, or `None` when the CPU has no RDRAND or the few
/// retries all failed (RDRAND is allowed to signal transient failure).
pub fn rdrand32() -> Option<u32> {
    if !has_rdrand() {
        return None;
    }
    for _ in 0..10 {
        let mut v: u32 = 0;
        // SAFETY: RDRAND was confirmed present by the CPUID check above, and
        // `&mut v` is a valid place for the instruction to write its result.
        let ok = unsafe { core::arch::x86_64::_rdrand32_step(&mut v) };
        if ok == 1 {
            return Some(v);
        }
    }
    None
}

/// Time-stamp counter (`rdtsc`).  Callers harvest the *low* bits as timing
/// jitter, so they take deltas rather than absolute values.
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is readable in ring 0, writes only the two named output
    // registers and touches no memory or flags.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

// ---- control registers, TLB and paging ------------------------------------

/// Read CR2 — the linear address of the fault that invoked the current `#PF`.
pub fn read_cr2() -> u64 {
    let val: u64;
    // SAFETY: reading CR2 is side-effect-free.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) val, options(nomem, nostack)) };
    val
}

/// Read CR3 — the **physical** address of the live top-level page table.
///
/// The value is raw: callers that dereference it translate through the direct
/// map first.
pub fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: reading CR3 is side-effect-free.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nomem, nostack)) };
    val
}

/// Invalidate one TLB entry for `vaddr`.
pub fn tlb_flush(vaddr: u64) {
    // SAFETY: INVLPG is safe for any address.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack)) };
}

/// Flush the whole TLB by reloading CR3 with its current value.
pub fn tlb_flush_all() {
    // SAFETY: reloading CR3 with the current value only flushes the TLB.
    unsafe {
        core::arch::asm!(
            "mov rax, cr3",
            "mov cr3, rax",
            out("rax") _,
            options(nostack)
        );
    }
}

/// Install `dir` (a physical PML4 address) as CR3 (`load_page_directory`).
pub fn load_page_directory(dir: *mut u64) {
    // SAFETY: the caller passes a live, correctly built top-level page table.
    unsafe { sys::load_page_directory(dir) };
}

/// Turn on paging (`enable_paging`).
pub fn enable_paging() {
    // SAFETY: the caller has loaded a valid CR3 first.
    unsafe { sys::enable_paging() };
}

/// Park the calling CPU forever in `hlt` — the kernel's panic/unrecoverable
/// parking loop.  A CPU that has nothing left to do halts here (rather than
/// spinning) until a reset or a non-maskable interrupt.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` only halts this CPU until the next interrupt and touches
        // no memory; callers run with maskable interrupts masked, so the CPU
        // stays parked.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    }
}
