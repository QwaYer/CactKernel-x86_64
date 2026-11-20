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
//! Phase H3 built one hard-coded guest and ran it with its own 4-level paging
//! and no second-level translation: 64-bit mode, identity paging for the code
//! page, `mov eax, 0xdeadbeef; hlt`.  Phase H4 puts the guest under EPT.  The
//! guest's CR3 now names guest-physical addresses, and the EPT tables built by
//! `vmx/ept.c` translate them to host frames the guest never names: the guest
//! stores a magic value through a mapped GPA (the host reads it back out of the
//! host frame — the translation proof) and then stores through a GPA that EPT
//! deliberately leaves unmapped, which comes back as an EPT violation
//! (VM-exit reason 48) carrying that GPA.

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

    fn vmx_ept_supported() -> i32;
    fn vmx_ept_build(maps: *const VmxEptMap, count: u32) -> u64;
    fn vmx_ept_free();
    fn vmx_ept_invept_single(eptp: u64) -> i32;
}

/// One EPT leaf mapping, as `vmx/ept.h` declares it: guest-physical page ->
/// host-physical page with the given permissions.
#[repr(C)]
struct VmxEptMap {
    gpa: u64,
    hpa: u64,
    flags: u32,
}

/* ---- model-specific registers ------------------------------------------ */
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
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
const VMCS_EPT_POINTER: u64 = 0x201A;
const VMCS_GUEST_PHYSICAL_ADDRESS: u64 = 0x2400;
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
const VMCS_SECONDARY_PROC_BASED_CTRL: u64 = 0x401E;
const VMCS_VM_INSTRUCTION_ERROR: u64 = 0x4400;
const VMCS_VM_EXIT_REASON: u64 = 0x4402;
const VMCS_EXIT_QUALIFICATION: u64 = 0x6400;
const VMCS_GUEST_LINEAR_ADDRESS: u64 = 0x640A;
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

/* Primary control bit 31: the secondary controls below take effect at all.
 * EPT lives in the secondary controls (bit 1). */
const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u64 = 1 << 31;
const SECONDARY_EXEC_ENABLE_EPT: u64 = 1 << 1;

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

/* EPT leaf permissions (mirror vmx/ept.h). */
const EPT_R: u32 = 0x1;
const EPT_W: u32 = 0x2;
const EPT_X: u32 = 0x4;

/*
 * Guest-physical layout (Phase H4).
 *
 * The guest's own 4-level page tables live at GPAs 0x1000-0x4000 and the pages
 * they name at 0x5000/0x6000.  EPT maps every one of those GPAs to a distinct
 * host frame, so a guest address of X does NOT reach host physical X — the two
 * spaces are genuinely separate, which is the whole point of the stage.
 *
 * GPA_TRAP is the exception: the guest's page tables name it (so the guest's
 * own paging walk succeeds) but EPT does not map it, so the access falls
 * through to an EPT violation with the guest physical address in the VMCS.
 */
const GPA_PML4: u64 = 0x1000;
const GPA_PDPT: u64 = 0x2000;
const GPA_PD: u64 = 0x3000;
const GPA_PT: u64 = 0x4000;
const GPA_CODE: u64 = 0x5000;
const GPA_DATA: u64 = 0x6000;
const GPA_TRAP: u64 = 0x9000;

/* Guest virtual addresses the program touches.  All sit in PML4/PDPT index 0
 * and PDE index 2, so one PT page reaches all three. */
const GVA_CODE: u64 = 0x40_0000;
const GVA_DATA: u64 = 0x40_1000;
const GVA_TRAP: u64 = 0x40_2000;

/* Guest constants.  VMX requires the guest CR4 to carry every CR4_FIXED0 bit —
 * and on a CPU that supports VMX that includes CR4.VMXE — plus PAE for a
 * IA-32e guest; CR0 is the usual PE|NE|PG (plus ET). */
const GUEST_CR0: u64 = 0x8000_0031; // PE | ET | NE | PG
const GUEST_CR4: u64 = 0x2020;      // PAE | VMXE
const GUEST_EFER: u64 = 0x500;      // LME | LMA

/* The magic the guest stores and the host checks for. */
const GUEST_MAGIC: u32 = 0xdead_beef;

/* The exit reason the last handled VM exit reported. */
static mut EXIT_REASON: u64 = 0;

/* First VMCS field whose VMWRITE failed (0 = none); diagnostics only. */
static mut VMW_FAIL_FIELD: u64 = 0;

/* The host stack the CPU switches to on VM exit (HOST_RSP). */
#[repr(C, align(16))]
struct HostStack([u8; 16384]);
static mut HOST_STACK: HostStack = HostStack([0; 16384]);

/// Append `bytes` to `buf` at `*n`, never overrunning the reserved tail.
unsafe fn put(buf: &mut [u8; 256], n: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *n < 254 {
            buf[*n] = b;
            *n += 1;
        }
    }
}

/// Emit one console line at NOTICE level, ending in a newline.  `label` is
/// printed first, then — when `value` is given — `0x%016x`, then `text`.
///
/// The level matters: the kernel raises the console log level to NOTICE once
/// userspace init is launched, so an unlevelled `printk` (KERN_INFO) stops
/// reaching the console/COM1 and lands in /dev/kmsg only.  These stage markers
/// are exactly what a headless run greps for, so they ride at NOTICE.  `printk`
/// is printf-style and this crate cannot call it variadically, so the line is
/// assembled here.
unsafe fn notice_line(label: &str, text: &str, value: Option<u64>) {
    let mut buf = [0u8; 256];
    let mut n = 0usize;
    // SAFETY: `put` stays within `buf`; the final NUL is written past `n`.
    unsafe {
        put(&mut buf, &mut n, &[0x01, b'5']); // KERN_NOTICE: SOH + '5'
        put(&mut buf, &mut n, label.as_bytes());
        if let Some(v) = value {
            put(&mut buf, &mut n, b"0x");
            let mut hex = [0u8; 16];
            for (i, slot) in hex.iter_mut().enumerate() {
                let nib = ((v >> (60 - i * 4)) & 0xF) as u8;
                *slot = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
            }
            put(&mut buf, &mut n, &hex);
        }
        put(&mut buf, &mut n, text.as_bytes());
        buf[n] = b'\n';
        buf[n + 1] = 0;
        printk(buf.as_ptr() as *const c_char);
    }
}

/// A NOTICE-level console line (newline appended).
unsafe fn notice(text: &str) {
    // SAFETY: forwards to the guarded builder.
    unsafe { notice_line("", text, None) };
}

/// `label` followed by `value` as `0x%016x`, at NOTICE level.
unsafe fn notice_hex(label: &str, value: u64) {
    // SAFETY: forwards to the guarded builder.
    unsafe { notice_line(label, "", Some(value)) };
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
            notice("hv: no VT-x host mode — guest run skipped");
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

/// VM-exit reasons this model handles (Intel SDM Vol. 3C, Appendix C).
const EXIT_HLT: u64 = 12;
const EXIT_EPT_VIOLATION: u64 = 48;

/// Copy `bytes` into the code page at `at`, advancing it.
unsafe fn emit(code: *mut u8, at: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        // SAFETY: the caller keeps `at` within the code page.
        unsafe { core::ptr::write_volatile(code.add(*at), b) };
        *at += 1;
    }
}

/// Write one guest page-table entry.
unsafe fn pte(table: *mut u8, index: usize, value: u64) {
    // SAFETY: `table` is a live page and `index` is within its 512 entries.
    unsafe { core::ptr::write_volatile((table as *mut u64).add(index), value) };
}

/// The guest program (Phase H4):
///   mov eax, 0xdeadbeef
///   mov [GVA_DATA], eax     ; mapped: EPT translates it, guest continues
///   mov [GVA_TRAP], eax     ; guest paging maps it, EPT does not -> exit 48
///   hlt                     ; not reached while the trap stays in place
///
/// The absolute `mov` uses the SIB/no-base form (`89 04 25 disp32`), which is
/// absolute in 64-bit mode and needs no address-size prefix for a sub-4 GiB
/// address.  The stores are emitted from the GVA constants so code and layout
/// cannot drift apart.
unsafe fn emit_guest_program(code: *mut u8) {
    let mut at = 0usize;
    // SAFETY: `code` is a live page; every write stays inside it.
    unsafe {
        emit(code, &mut at, &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE]); // mov eax, magic
        emit(code, &mut at, &[0x89, 0x04, 0x25]);             // mov [disp32], eax
        emit(code, &mut at, &(GVA_DATA as u32).to_le_bytes());
        emit(code, &mut at, &[0x89, 0x04, 0x25]);
        emit(code, &mut at, &(GVA_TRAP as u32).to_le_bytes());
        emit(code, &mut at, &[0xF4]);                          // hlt
    }
}

/// The guest's own 4-level page tables: one PT page reaches all three GVAs
/// (they share PML4/PDPT index 0 and PDE index 2).  Entries name *GPAs*, which
/// is what EPT then translates — including the trap GPA, which EPT leaves out.
unsafe fn build_guest_tables(pml4: *mut u8, pdpt: *mut u8, pd: *mut u8, pt: *mut u8) {
    let idx = |va: u64, shift: u32| ((va >> shift) & 0x1FF) as usize;
    // SAFETY: all four arguments are live pages.
    unsafe {
        pte(pml4, idx(GVA_CODE, 39), GPA_PDPT | 0x3); // present | writable
        pte(pdpt, idx(GVA_CODE, 30), GPA_PD | 0x3);
        pte(pd, idx(GVA_CODE, 21), GPA_PT | 0x3);
        pte(pt, idx(GVA_CODE, 12), GPA_CODE | 0x3);
        pte(pt, idx(GVA_DATA, 12), GPA_DATA | 0x3);
        pte(pt, idx(GVA_TRAP, 12), GPA_TRAP | 0x3);
    }
}

/// Build the VMCS for the model's one guest and run it under EPT (Phase H4).
/// Returns 0 once the guest has exited.
///
/// The guest stores a magic value through a mapped GPA; the host then reads it
/// back out of the *host* frame that GPA names — which is the proof that EPT
/// translated the access (the guest never named that physical address).  The
/// second store goes through a GPA the guest's own paging maps but EPT does
/// not, and must come back as an EPT violation carrying that GPA.
unsafe fn run_guest() -> i32 {
    // SAFETY: every step below is guarded; pointers are live kalloc pages.
    unsafe {
        let vmcs = page();
        let code = page();
        let data = page();
        let pml4 = page();
        let pdpt = page();
        let pd = page();
        let pt = page();
        let tss = page();
        let guest_pages = [vmcs, code, data, pml4, pdpt, pd, pt, tss];
        if guest_pages.iter().any(|p| p.is_null()) {
            notice("hv: guest launch: out of memory");
            free_guest_pages(&guest_pages);
            return 1;
        }

        let vmcs_phys = vmm_v2p(vmcs);
        let code_phys = vmm_v2p(code);
        let data_phys = vmm_v2p(data);
        let pml4_phys = vmm_v2p(pml4);
        let pdpt_phys = vmm_v2p(pdpt);
        let pd_phys = vmm_v2p(pd);
        let pt_phys = vmm_v2p(pt);
        let tss_phys = vmm_v2p(tss);

        emit_guest_program(code);
        build_guest_tables(pml4, pdpt, pd, pt);

        /* EPT: one mapping per guest page, each GPA naming a distinct host
         * frame.  GPA_TRAP is deliberately absent — that is the violation. */
        if vmx_ept_supported() == 0 {
            notice("hv: guest run needs EPT, unavailable on this CPU");
            free_guest_pages(&guest_pages);
            return 1;
        }
        let rwx = EPT_R | EPT_W | EPT_X;
        let maps = [
            VmxEptMap { gpa: GPA_PML4, hpa: pml4_phys, flags: rwx },
            VmxEptMap { gpa: GPA_PDPT, hpa: pdpt_phys, flags: rwx },
            VmxEptMap { gpa: GPA_PD,   hpa: pd_phys,   flags: rwx },
            VmxEptMap { gpa: GPA_PT,   hpa: pt_phys,   flags: rwx },
            VmxEptMap { gpa: GPA_CODE, hpa: code_phys, flags: rwx },
            VmxEptMap { gpa: GPA_DATA, hpa: data_phys, flags: rwx },
        ];
        let eptp = vmx_ept_build(maps.as_ptr(), maps.len() as u32);
        if eptp == 0 {
            notice("hv: guest launch: EPT build failed");
            free_guest_pages(&guest_pages);
            return 1;
        }
        /* A fresh EPTP is not enough on its own: EPT translations are tagged by
         * EPTP, and kalloc can hand the same physical PML4 page (hence the same
         * EPTP) back to the next run.  Flush before the launch. */
        if vmx_ept_invept_single(eptp) != 0 {
            notice("hv: guest launch: INVEPT failed");
            vmx_ept_free();
            free_guest_pages(&guest_pages);
            return 1;
        }

        /* VMCS region: revision identifier first, then make it current. */
        core::ptr::write_volatile(
            vmcs as *mut u32,
            (cact_rdmsr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32,
        );
        if cact_vmclear(vmcs_phys) != 0 {
            notice("hv: guest launch: VMCLEAR failed");
            vmx_ept_free();
            free_guest_pages(&guest_pages);
            return 1;
        }
        if cact_vmptrld(vmcs_phys) != 0 {
            notice("hv: guest launch: VMPTRLD failed");
            vmx_ept_free();
            free_guest_pages(&guest_pages);
            return 1;
        }

        /* Controls.  EPT rides in the secondary controls, which only take
         * effect once the primary "activate secondary controls" bit is set. */
        vmw(VMCS_PIN_BASED_VM_EXEC_CTRL, ctl(IA32_VMX_PINBASED_CTLS, 0));
        vmw(VMCS_PRIMARY_PROC_BASED_CTRL, ctl(
            IA32_VMX_PROCBASED_CTLS,
            CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
        ));
        let secondary = ctl(IA32_VMX_PROCBASED_CTLS2, SECONDARY_EXEC_ENABLE_EPT);
        if secondary & SECONDARY_EXEC_ENABLE_EPT == 0 {
            notice("hv: guest launch: CPU refused the enable-EPT control");
            let _ = cact_vmclear(vmcs_phys);
            vmx_ept_free();
            free_guest_pages(&guest_pages);
            return 1;
        }
        vmw(VMCS_SECONDARY_PROC_BASED_CTRL, secondary);
        vmw(VMCS_EPT_POINTER, eptp);
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

        /* Guest state: 64-bit mode, its CR3 naming a GPA, not a host frame. */
        vmw(VMCS_VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);
        vmw(VMCS_GUEST_IA32_EFER, GUEST_EFER);
        vmw(VMCS_GUEST_CR0, GUEST_CR0);
        vmw(VMCS_GUEST_CR3, GPA_PML4);
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
        vmw(VMCS_GUEST_RIP, GVA_CODE);
        vmw(VMCS_GUEST_RFLAGS, 0x2);

        /* The guest owns CR0/CR4, so no CR access causes an exit. */
        vmw(VMCS_CR0_GUEST_HOST_MASK, 0);
        vmw(VMCS_CR4_GUEST_HOST_MASK, 0);
        vmw(VMCS_CR0_READ_SHADOW, GUEST_CR0);
        vmw(VMCS_CR4_READ_SHADOW, GUEST_CR4);

        if VMW_FAIL_FIELD != 0 {
            notice_hex("hv: guest launch: VMCS write rejected, field ", VMW_FAIL_FIELD);
        }

        /* Launch.  On success this only returns after the guest has exited. */
        if cact_vmx_launch() != 0 {
            let mut err = 0u64;
            let _ = cact_vmread(VMCS_VM_INSTRUCTION_ERROR, &mut err);
            notice_hex("hv: guest launch: VMLAUNCH failed, instruction error ", err);
            let _ = cact_vmclear(vmcs_phys);
            vmx_ept_free();
            free_guest_pages(&guest_pages);
            return 1;
        }

        let mut qual = 0u64;
        let mut gpa = 0u64;
        let mut gla = 0u64;
        let _ = cact_vmread(VMCS_EXIT_QUALIFICATION, &mut qual);
        let _ = cact_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &mut gpa);
        let _ = cact_vmread(VMCS_GUEST_LINEAR_ADDRESS, &mut gla);

        notice_hex("hv: guest ran, VM-exit reason ", EXIT_REASON);

        /* The store through the mapped GPA must have landed in the *host* frame
         * that GPA names — the guest never wrote that physical address, so
         * reading the magic back is the translation proof. */
        let stored = core::ptr::read_volatile(data as *const u32);
        if stored == GUEST_MAGIC {
            notice("hv: EPT translation OK — mapped-GPA store reached the host frame");
        } else {
            notice_hex("hv: EPT translation FAILED — host frame holds ", stored as u64);
        }

        if EXIT_REASON == EXIT_EPT_VIOLATION {
            notice_hex("hv: EPT violation: guest-physical ", gpa);
            notice_hex("hv:   qualification ", qual);
            notice_hex("hv:   guest-linear  ", gla);
            if gpa == GPA_TRAP && (qual & 0x2) != 0 {
                notice("hv: EPT violation names the unmapped trap GPA on a write, as intended");
            }
        } else if EXIT_REASON == EXIT_HLT {
            notice("hv: guest hlt -> exit reason 12 (HLT)");
        }

        // Drop the VMCS and hand every page back: a run must not leak its own
        // pages, the EPT tables, or the VMCS.
        let _ = cact_vmclear(vmcs_phys);
        vmx_ept_free();
        free_guest_pages(&guest_pages);
        0
    }
}
