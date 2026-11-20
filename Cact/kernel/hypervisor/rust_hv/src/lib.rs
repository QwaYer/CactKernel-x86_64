// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! CactOS hypervisor — the model half.
//!
//! The low-level primitives (the VMX/SVM instructions, the VMCS field
//! encodings, the VM-exit stub) live in C/asm in the parent directory; this is
//! where the VM/vCPU model, the VMCS construction and the VM-exit dispatch
//! live.  The crate is an rlib pulled into `kernel.bin` by
//! `Cact/kernel/kernel_rust`, and its `#[no_mangle]` entry points are called
//! from C: `hv_run_guest()` runs the model's guest on demand, from the
//! `/dev/chv` device (`Cact/kernel/hypervisor/chv.c`).
//!
//! Phase H3 builds one hard-coded guest and runs it: 64-bit mode, 4-level
//! identity paging for the code page, no EPT.  The guest program is
//! `mov eax, 0xdeadbeef; hlt`; VMLAUNCH runs it and the `hlt` traps back to the
//! host as VM-exit reason 12.

#![no_std]

use core::ffi::c_char;

extern "C" {
    fn printk(s: *const c_char);

    fn cact_rdmsr(msr: u32) -> u64;
    fn cact_vmread(field: u64, value: *mut u64) -> i32;
    fn cact_vmwrite(field: u64, value: u64) -> i32;
    fn cact_vmclear(phys: u64) -> i32;
    fn cact_vmptrld(phys: u64) -> i32;
    fn cact_vmx_launch() -> i32;
    fn cact_vmx_exit_stub_addr() -> u64;
    fn cact_cpu_state_snapshot(out: *mut u64);
    fn vmx_host_enable() -> i32;
    fn vmx_host_disable();

    fn kalloc() -> *mut u8;
    fn free_page(ptr: *mut u8);
    fn vmm_v2p(ptr: *const u8) -> u64;
}

/* ---- model-specific registers ------------------------------------------ */
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_EFER: u32 = 0xC0000080;

/* ---- VMCS field encodings (mirror vmcs_fields.h) ------------------------ */
const VMCS_GUEST_ES_SELECTOR: u64 = 0x0800;
const VMCS_GUEST_CS_SELECTOR: u64 = 0x0802;
const VMCS_GUEST_SS_SELECTOR: u64 = 0x0804;
const VMCS_GUEST_DS_SELECTOR: u64 = 0x0806;
const VMCS_GUEST_FS_SELECTOR: u64 = 0x0808;
const VMCS_GUEST_GS_SELECTOR: u64 = 0x080A;
const VMCS_GUEST_LDTR_SELECTOR: u64 = 0x080C;
const VMCS_GUEST_TR_SELECTOR: u64 = 0x080E;
const VMCS_HOST_ES_SELECTOR: u64 = 0x0C00;
const VMCS_HOST_CS_SELECTOR: u64 = 0x0C02;
const VMCS_HOST_SS_SELECTOR: u64 = 0x0C04;
const VMCS_HOST_DS_SELECTOR: u64 = 0x0C06;
const VMCS_HOST_FS_SELECTOR: u64 = 0x0C08;
const VMCS_HOST_GS_SELECTOR: u64 = 0x0C0A;
const VMCS_HOST_TR_SELECTOR: u64 = 0x0C0C;
const VMCS_VMCS_LINK_POINTER: u64 = 0x2800;
const VMCS_GUEST_IA32_EFER: u64 = 0x2806;
const VMCS_HOST_IA32_EFER: u64 = 0x2C02;
const VMCS_PIN_BASED_VM_EXEC_CTRL: u64 = 0x4000;
const VMCS_PRIMARY_PROC_BASED_CTRL: u64 = 0x4002;
const VMCS_EXCEPTION_BITMAP: u64 = 0x4004;
const VMCS_PF_ERROR_CODE_MASK: u64 = 0x4006;
const VMCS_PF_ERROR_CODE_MATCH: u64 = 0x4008;
const VMCS_CR3_TARGET_COUNT: u64 = 0x400A;
const VMCS_VM_EXIT_CTRLS: u64 = 0x400C;
const VMCS_VM_EXIT_MSR_STORE_COUNT: u64 = 0x400E;
const VMCS_VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
const VMCS_VM_ENTRY_CTRLS: u64 = 0x4012;
const VMCS_VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
const VMCS_VM_ENTRY_INTR_INFO: u64 = 0x4016;
const VMCS_VM_ENTRY_EXCEPTION_ERR: u64 = 0x4018;
const VMCS_VM_ENTRY_INSTRUCTION_LEN: u64 = 0x401A;
const VMCS_VM_INSTRUCTION_ERROR: u64 = 0x4400;
const VMCS_VM_EXIT_REASON: u64 = 0x4402;
const VMCS_GUEST_ES_LIMIT: u64 = 0x4800;
const VMCS_GUEST_CS_LIMIT: u64 = 0x4802;
const VMCS_GUEST_SS_LIMIT: u64 = 0x4804;
const VMCS_GUEST_DS_LIMIT: u64 = 0x4806;
const VMCS_GUEST_FS_LIMIT: u64 = 0x4808;
const VMCS_GUEST_GS_LIMIT: u64 = 0x480A;
const VMCS_GUEST_LDTR_LIMIT: u64 = 0x480C;
const VMCS_GUEST_TR_LIMIT: u64 = 0x480E;
const VMCS_GUEST_GDTR_LIMIT: u64 = 0x4810;
const VMCS_GUEST_IDTR_LIMIT: u64 = 0x4812;
const VMCS_GUEST_ES_AR: u64 = 0x4814;
const VMCS_GUEST_CS_AR: u64 = 0x4816;
const VMCS_GUEST_SS_AR: u64 = 0x4818;
const VMCS_GUEST_DS_AR: u64 = 0x481A;
const VMCS_GUEST_FS_AR: u64 = 0x481C;
const VMCS_GUEST_GS_AR: u64 = 0x481E;
const VMCS_GUEST_LDTR_AR: u64 = 0x4820;
const VMCS_GUEST_TR_AR: u64 = 0x4822;
const VMCS_GUEST_INTERRUPTIBILITY: u64 = 0x4824;
const VMCS_GUEST_ACTIVITY_STATE: u64 = 0x4826;
const VMCS_GUEST_IA32_SYSENTER_CS: u64 = 0x482A;
const VMCS_HOST_IA32_SYSENTER_CS: u64 = 0x4C00;
const VMCS_CR0_GUEST_HOST_MASK: u64 = 0x6000;
const VMCS_CR4_GUEST_HOST_MASK: u64 = 0x6002;
const VMCS_CR0_READ_SHADOW: u64 = 0x6004;
const VMCS_CR4_READ_SHADOW: u64 = 0x6006;
const VMCS_GUEST_CR0: u64 = 0x6800;
const VMCS_GUEST_CR3: u64 = 0x6802;
const VMCS_GUEST_CR4: u64 = 0x6804;
const VMCS_GUEST_ES_BASE: u64 = 0x6806;
const VMCS_GUEST_CS_BASE: u64 = 0x6808;
const VMCS_GUEST_SS_BASE: u64 = 0x680A;
const VMCS_GUEST_DS_BASE: u64 = 0x680C;
const VMCS_GUEST_FS_BASE: u64 = 0x680E;
const VMCS_GUEST_GS_BASE: u64 = 0x6810;
const VMCS_GUEST_LDTR_BASE: u64 = 0x6812;
const VMCS_GUEST_TR_BASE: u64 = 0x6814;
const VMCS_GUEST_GDTR_BASE: u64 = 0x6816;
const VMCS_GUEST_IDTR_BASE: u64 = 0x6818;
const VMCS_GUEST_DR7: u64 = 0x681A;
const VMCS_GUEST_RSP: u64 = 0x681C;
const VMCS_GUEST_RIP: u64 = 0x681E;
const VMCS_GUEST_RFLAGS: u64 = 0x6820;
const VMCS_GUEST_PENDING_DBG_EXC: u64 = 0x6822;
const VMCS_GUEST_IA32_SYSENTER_ESP: u64 = 0x6824;
const VMCS_GUEST_IA32_SYSENTER_EIP: u64 = 0x6826;
const VMCS_HOST_CR0: u64 = 0x6C00;
const VMCS_HOST_CR3: u64 = 0x6C02;
const VMCS_HOST_CR4: u64 = 0x6C04;
const VMCS_HOST_FS_BASE: u64 = 0x6C06;
const VMCS_HOST_GS_BASE: u64 = 0x6C08;
const VMCS_HOST_TR_BASE: u64 = 0x6C0A;
const VMCS_HOST_GDTR_BASE: u64 = 0x6C0C;
const VMCS_HOST_IDTR_BASE: u64 = 0x6C0E;
const VMCS_HOST_RSP: u64 = 0x6C14;
const VMCS_HOST_RIP: u64 = 0x6C16;

/* Primary processor-based control: exit on HLT.  Without it the guest's HLT
 * just halts the logical processor and the host never regains control. */
const CPU_BASED_HLT_EXITING: u64 = 1 << 7;

/* VM-exit controls: the host is in 64-bit mode, and its EFER is reloaded on the
 * way out (the guest ran with its own EFER). */
const VM_EXIT_HOST_ADDR_SIZE: u64 = 1 << 9;
const VM_EXIT_LOAD_IA32_EFER: u64 = 1 << 21;

/* VM-entry controls: the guest is in IA-32e mode and its EFER is loaded. */
const VM_ENTRY_IA32E_MODE: u64 = 1 << 9;
const VM_ENTRY_LOAD_IA32_EFER: u64 = 1 << 15;

/* Segment access rights: P|S|DPL0, G=1.  CS is a 64-bit code segment (L=1,
 * D/B=0); the data segments keep D/B=1. */
const AR_CODE64: u64 = 0xA09B;
const AR_DATA: u64 = 0xC093;

/* The guest program: `mov eax, 0xdeadbeef; hlt`. */
const GUEST_CODE: [u8; 6] = [0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xF4];

/* Guest constants.  VMX requires the guest CR4 to carry every CR4_FIXED0 bit —
 * and on a CPU that supports VMX that includes CR4.VMXE — plus PAE for a
 * IA-32e guest; CR0 is the usual PE|NE|PG (plus ET). */
const GUEST_CR0: u64 = 0x8000_0031; // PE | ET | NE | PG
const GUEST_CR4: u64 = 0x2020;      // PAE | VMXE
const GUEST_EFER: u64 = 0x500;      // LME | LMA

/* The exit reason the last handled VM exit reported. */
static mut EXIT_REASON: u64 = 0;

/* First VMCS field whose VMWRITE failed (0 = none); diagnostics only. */
static mut VMW_FAIL_FIELD: u64 = 0;

/* The host stack the CPU switches to on VM exit (HOST_RSP). */
#[repr(C, align(16))]
struct HostStack([u8; 16384]);
static mut HOST_STACK: HostStack = HostStack([0; 16384]);

/// Print `tag` followed by `value` as `0x%016x` and a newline — `printk` is
/// printf-style, which a `no_std` crate cannot call variadically, so the model
/// formats numbers itself.
unsafe fn print_tag_hex(tag: *const c_char, value: u64) {
    // SAFETY: `tag` is a static NUL-terminated literal.
    unsafe { printk(tag) };
    let mut buf = [0u8; 20];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((value >> (60 - i * 4)) & 0xF) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    buf[18] = b'\n';
    buf[19] = 0;
    // SAFETY: `buf` is a valid NUL-terminated buffer for the call.
    unsafe { printk(buf.as_ptr() as *const c_char) };
}

/// Zero a freshly `kalloc`'d page (`kalloc` does not guarantee zeroed frames).
unsafe fn zero_page(page: *mut u8) {
    for i in 0..4096 {
        // SAFETY: the caller passes a live page frame.
        unsafe { core::ptr::write_volatile(page.add(i), 0) };
    }
}

/// A control value the CPU accepts: bits the capability MSR pins to 1 are
/// forced, bits it forbids are cleared, and `desired` fills the rest.
unsafe fn ctl(msr: u32, desired: u64) -> u64 {
    // SAFETY: rdmsr has no preconditions.
    let cap = unsafe { cact_rdmsr(msr) };
    (desired | (cap & 0xFFFF_FFFF)) & (cap >> 32)
}

/// VMWRITE that records (once) the first field the CPU refused, so a silently
/// zeroed field cannot hide an invalid guest state.
unsafe fn vmw(field: u64, value: u64) {
    // SAFETY: VMCS accessor with a valid field encoding.
    let rc = unsafe { cact_vmwrite(field, value) };
    if rc != 0 {
        // SAFETY: single-threaded bring-up probe.
        unsafe {
            if VMW_FAIL_FIELD == 0 {
                VMW_FAIL_FIELD = field;
            }
        }
    }
}

/// Allocate a zeroed 4 KiB page, or null.
unsafe fn page() -> *mut u8 {
    // SAFETY: allocation has no preconditions.
    let p = unsafe { kalloc() };
    if !p.is_null() {
        // SAFETY: `p` is a live frame.
        unsafe { zero_page(p) };
    }
    p
}

/// Free the guest's pages (the VMCS included).  A page that is still a live
/// VMCS must not go back to the allocator, so callers VMCLEAR it first.
unsafe fn free_guest_pages(pages: &[*mut u8]) {
    for &p in pages {
        if !p.is_null() {
            // SAFETY: every non-null entry is a live kalloc page owned here.
            unsafe { free_page(p) };
        }
    }
}

/// VM-exit entry, called by the C/asm stub with RDI = the saved-GPR frame.
#[no_mangle]
pub extern "C" fn hv_vmx_exit_entry(_regs: *mut u64) -> i32 {
    let mut reason = 0u64;
    // SAFETY: the stub runs with the current VMCS loaded.
    let _ = unsafe { cact_vmread(VMCS_VM_EXIT_REASON, &mut reason) };
    // SAFETY: single-threaded bring-up probe.
    unsafe { EXIT_REASON = reason };
    // Ask the stub to finish (it currently only supports finishing).
    0
}

/// Run the model's guest on demand; called from the `/dev/chv` device.
///
/// Enters VMX root, builds the VMCS, launches the guest, records the VM-exit
/// reason in `*out_exit_reason`, and — this is the part the old boot probe got
/// wrong — leaves VMX root again before returning.  A kernel that stays in VMX
/// root keeps CR4.VMXE/CR0.NE set and a live VMCS for the rest of its life, and
/// the next thing that trips VMX (a VM-entry/exit abort) is a silent machine
/// reset no handler can see.
///
/// Returns 0 once the guest has exited, -1 when VT-x host mode is unavailable.
#[no_mangle]
pub extern "C" fn hv_run_guest(out_exit_reason: *mut u64) -> i32 {
    if !out_exit_reason.is_null() {
        // SAFETY: the caller passes a valid `u64` for the exit reason.
        unsafe { *out_exit_reason = 0 };
    }
    // SAFETY: the /dev/chv run mutex serialises runs, so one VMCS is live at a
    // time; every pointer comes from kalloc.
    unsafe {
        if vmx_host_enable() != 0 {
            printk(c"hv: no VT-x host mode — guest run skipped\n".as_ptr());
            return -1;
        }
        let rc = run_guest();
        // Always leave VMX root, whatever the launch did.
        vmx_host_disable();
        if !out_exit_reason.is_null() {
            *out_exit_reason = EXIT_REASON;
        }
        rc
    }
}

/// Build the VMCS for one hard-coded guest and run it.  Returns 0 once the
/// guest's `hlt` trapped back to us.
unsafe fn run_guest() -> i32 {
    // SAFETY: every step below is guarded; pointers are live kalloc pages.
    unsafe {
        let vmcs = page();
        let code = page();
        let pml4 = page();
        let pdpt = page();
        let pd = page();
        let pt = page();
        let tss = page();
        let guest_pages = [vmcs, code, pml4, pdpt, pd, pt, tss];
        if guest_pages.iter().any(|p| p.is_null()) {
            printk(c"hv: guest launch: out of memory\n".as_ptr());
            free_guest_pages(&guest_pages);
            return 1;
        }

        let vmcs_phys = vmm_v2p(vmcs);
        let code_phys = vmm_v2p(code);
        let pml4_phys = vmm_v2p(pml4);
        let pdpt_phys = vmm_v2p(pdpt);
        let pd_phys = vmm_v2p(pd);
        let pt_phys = vmm_v2p(pt);
        let tss_phys = vmm_v2p(tss);

        /* Guest code + a 64-bit identity page table for the code page. */
        for (i, b) in GUEST_CODE.iter().enumerate() {
            core::ptr::write_volatile(code.add(i), *b);
        }
        core::ptr::write_volatile(pml4 as *mut u64, pdpt_phys | 0x3);
        core::ptr::write_volatile(pdpt as *mut u64, pd_phys | 0x3);
        let pde_i = ((code_phys >> 21) & 0x1FF) as usize;
        let pte_i = ((code_phys >> 12) & 0x1FF) as usize;
        core::ptr::write_volatile((pd as *mut u64).add(pde_i), pt_phys | 0x3);
        core::ptr::write_volatile((pt as *mut u64).add(pte_i), code_phys | 0x3);

        /* VMCS region: revision identifier first, then make it current. */
        core::ptr::write_volatile(
            vmcs as *mut u32,
            (cact_rdmsr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32,
        );
        if cact_vmclear(vmcs_phys) != 0 {
            printk(c"hv: guest launch: VMCLEAR failed\n".as_ptr());
            free_guest_pages(&guest_pages);
            return 1;
        }
        if cact_vmptrld(vmcs_phys) != 0 {
            printk(c"hv: guest launch: VMPTRLD failed\n".as_ptr());
            free_guest_pages(&guest_pages);
            return 1;
        }

        /* Controls. */
        vmw(VMCS_PIN_BASED_VM_EXEC_CTRL, ctl(IA32_VMX_PINBASED_CTLS, 0));
        vmw(VMCS_PRIMARY_PROC_BASED_CTRL, ctl(IA32_VMX_PROCBASED_CTLS, CPU_BASED_HLT_EXITING));
        vmw(VMCS_VM_EXIT_CTRLS, ctl(IA32_VMX_EXIT_CTLS, VM_EXIT_HOST_ADDR_SIZE | VM_EXIT_LOAD_IA32_EFER));
        vmw(VMCS_VM_ENTRY_CTRLS, ctl(IA32_VMX_ENTRY_CTLS, VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER));
        vmw(VMCS_EXCEPTION_BITMAP, 0);
        vmw(VMCS_PF_ERROR_CODE_MASK, 0);
        vmw(VMCS_PF_ERROR_CODE_MATCH, 0);
        vmw(VMCS_CR3_TARGET_COUNT, 0);
        vmw(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);
        vmw(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
        vmw(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
        vmw(VMCS_VM_ENTRY_INTR_INFO, 0);
        vmw(VMCS_VM_ENTRY_EXCEPTION_ERR, 0);
        vmw(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);

        /* Host state — the kernel's own, so the exit stub and the code after it
         * run in the same context the launch was made from. */
        let mut host = [0u64; 16];
        cact_cpu_state_snapshot(host.as_mut_ptr());
        let host_sp = core::ptr::addr_of_mut!(HOST_STACK) as u64 + 16384;
        vmw(VMCS_HOST_CR0, host[12]);
        vmw(VMCS_HOST_CR3, host[13]);
        vmw(VMCS_HOST_CR4, host[14]);
        /* Host DS/ES/FS/GS selectors are ignored in IA-32e (only their bases
         * matter) but VMX still validates them, and the kernel leaves DS/ES
         * holding whatever the last ring-3 return loaded — RPL=3, which VM
         * entry rejects with "invalid host-state field(s)" (vm-instruction
         * error 8).  Publish the kernel's data selector for all four; the
         * bases below are still taken from the snapshot. */
        let kernel_data = host[1];   /* SS — the kernel data selector (RPL 0) */
        vmw(VMCS_HOST_ES_SELECTOR, kernel_data);
        vmw(VMCS_HOST_CS_SELECTOR, host[0]);
        vmw(VMCS_HOST_SS_SELECTOR, host[1]);
        vmw(VMCS_HOST_DS_SELECTOR, kernel_data);
        vmw(VMCS_HOST_FS_SELECTOR, kernel_data);
        vmw(VMCS_HOST_GS_SELECTOR, kernel_data);
        vmw(VMCS_HOST_TR_SELECTOR, host[6]);
        vmw(VMCS_HOST_FS_BASE, host[7]);
        vmw(VMCS_HOST_GS_BASE, host[8]);
        vmw(VMCS_HOST_TR_BASE, host[9]);
        vmw(VMCS_HOST_GDTR_BASE, host[10]);
        vmw(VMCS_HOST_IDTR_BASE, host[11]);
        vmw(VMCS_HOST_IA32_SYSENTER_CS, 0);
        vmw(VMCS_HOST_RSP, host_sp);
        vmw(VMCS_HOST_RIP, cact_vmx_exit_stub_addr());
        vmw(VMCS_HOST_IA32_EFER, cact_rdmsr(IA32_EFER));

        /* Guest state: 64-bit mode, identity mapped. */
        vmw(VMCS_VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);
        vmw(VMCS_GUEST_IA32_EFER, GUEST_EFER);
        vmw(VMCS_GUEST_CR0, GUEST_CR0);
        vmw(VMCS_GUEST_CR3, pml4_phys);
        vmw(VMCS_GUEST_CR4, GUEST_CR4);

        vmw(VMCS_GUEST_ES_SELECTOR, 0x10);
        vmw(VMCS_GUEST_CS_SELECTOR, 0x08);
        vmw(VMCS_GUEST_SS_SELECTOR, 0x10);
        vmw(VMCS_GUEST_DS_SELECTOR, 0x10);
        vmw(VMCS_GUEST_FS_SELECTOR, 0x10);
        vmw(VMCS_GUEST_GS_SELECTOR, 0x10);
        vmw(VMCS_GUEST_LDTR_SELECTOR, 0);
        vmw(VMCS_GUEST_TR_SELECTOR, 0x18);

        vmw(VMCS_GUEST_ES_BASE, 0);
        vmw(VMCS_GUEST_CS_BASE, 0);
        vmw(VMCS_GUEST_SS_BASE, 0);
        vmw(VMCS_GUEST_DS_BASE, 0);
        vmw(VMCS_GUEST_FS_BASE, 0);
        vmw(VMCS_GUEST_GS_BASE, 0);
        vmw(VMCS_GUEST_LDTR_BASE, 0);
        vmw(VMCS_GUEST_TR_BASE, tss_phys);
        vmw(VMCS_GUEST_GDTR_BASE, 0);
        vmw(VMCS_GUEST_IDTR_BASE, 0);

        vmw(VMCS_GUEST_ES_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_CS_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_SS_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_DS_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_FS_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_GS_LIMIT, 0xFFFF_FFFF);
        vmw(VMCS_GUEST_LDTR_LIMIT, 0);
        vmw(VMCS_GUEST_TR_LIMIT, 0x67);
        vmw(VMCS_GUEST_GDTR_LIMIT, 0);
        vmw(VMCS_GUEST_IDTR_LIMIT, 0);

        vmw(VMCS_GUEST_ES_AR, AR_DATA);
        vmw(VMCS_GUEST_CS_AR, AR_CODE64);
        vmw(VMCS_GUEST_SS_AR, AR_DATA);
        vmw(VMCS_GUEST_DS_AR, AR_DATA);
        vmw(VMCS_GUEST_FS_AR, AR_DATA);
        vmw(VMCS_GUEST_GS_AR, AR_DATA);
        vmw(VMCS_GUEST_LDTR_AR, 0x1_0000); // unusable (required in IA-32e mode)
        vmw(VMCS_GUEST_TR_AR, 0x8B);       // busy 32-bit TSS

        vmw(VMCS_GUEST_INTERRUPTIBILITY, 0);
        vmw(VMCS_GUEST_ACTIVITY_STATE, 0);
        vmw(VMCS_GUEST_IA32_SYSENTER_CS, 0);
        vmw(VMCS_GUEST_IA32_SYSENTER_ESP, 0);
        vmw(VMCS_GUEST_IA32_SYSENTER_EIP, 0);
        vmw(VMCS_GUEST_PENDING_DBG_EXC, 0);
        vmw(VMCS_GUEST_DR7, 0x400);
        vmw(VMCS_GUEST_RSP, 0);
        vmw(VMCS_GUEST_RIP, code_phys);
        vmw(VMCS_GUEST_RFLAGS, 0x2);

        /* The guest owns CR0/CR4, so no CR access causes an exit. */
        vmw(VMCS_CR0_GUEST_HOST_MASK, 0);
        vmw(VMCS_CR4_GUEST_HOST_MASK, 0);
        vmw(VMCS_CR0_READ_SHADOW, GUEST_CR0);
        vmw(VMCS_CR4_READ_SHADOW, GUEST_CR4);

        if VMW_FAIL_FIELD != 0 {
            printk(c"hv: guest launch: VMCS write rejected, field ".as_ptr());
            print_tag_hex(c"".as_ptr(), VMW_FAIL_FIELD);
        }

        /* Launch.  On success this only returns after the guest has exited. */
        if cact_vmx_launch() != 0 {
            let mut err = 0u64;
            let _ = cact_vmread(VMCS_VM_INSTRUCTION_ERROR, &mut err);
            printk(c"hv: guest launch: VMLAUNCH failed, instruction error ".as_ptr());
            print_tag_hex(c"".as_ptr(), err);
            free_guest_pages(&guest_pages);
            return 1;
        }

        printk(c"hv: guest ran, VM-exit reason ".as_ptr());
        print_tag_hex(c"".as_ptr(), EXIT_REASON);
        if EXIT_REASON == 12 {
            printk(c"hv: guest hlt -> exit reason 12 (HLT), launch OK\n".as_ptr());
        }

        // Drop the VMCS and hand every guest page back: a run must not leak its
        // pages, and the next run builds a fresh VMCS.
        let _ = cact_vmclear(vmcs_phys);
        free_guest_pages(&guest_pages);
        0
    }
}
