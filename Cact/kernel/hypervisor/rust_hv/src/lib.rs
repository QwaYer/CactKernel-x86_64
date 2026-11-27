// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! CactOS hypervisor — the model half.
//!
//! The low-level primitives (the VMX/SVM instructions, the VMCS field
//! encodings, the VM-exit stub) live in C/asm in the parent directory; this is
//! where the VM/vCPU model, the VMCS construction and the VM-exit dispatch
//! live.  The crate is an rlib pulled into `kernel.bin` by
//! `Cact/kernel/kernel_link`, and its `#[no_mangle]` entry points are called
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
//!
//! Phase H5.1 makes the exit path a *loop*: the C/asm stub now re-enters the
//! guest with VMRESUME after each handled exit (`vmx/vmx_launch.c`), so one run
//! sees many exits.  The model handles CPUID (1) and I/O (30) and emulates just
//! enough of a COM1 for the guest to speak: an `OUT 0x3F8` byte is relayed to
//! the host's serial port, so the guest's text shows up on COM1 — the same thing
//! a Linux guest will need.  The EPT violation is now a resumable hook too (the
//! MMIO shape H4 left open): the model reports it and skips the access, and the
//! guest runs on to `hlt`.
//!
//! Phase H7.1 exposes the vCPU to userspace (`/dev/chv`): the model owns one
//! persistent `Vcpu` (GPRs, RIP/RFLAGS, system registers, a small MSR set) and
//! the `hv_{get,set}_{regs,sregs,msrs}` / `hv_inject_irq` entry points read and
//! write it.  `run_guest()` seeds the VMCS from that state (its default
//! reproduces the fixture, so a RUN with no SET is unchanged) and folds the
//! exit state back; a queued external interrupt is delivered through the
//! VM-entry interruption-information field.  The fixture grew a GDT, an IDT and
//! a stack so an injected vector can actually land: it runs the 'I' handler,
//! every other vector parks ('P'), and delivery needs a real GDT (CS comes from
//! it, not the IDT).

#![no_std]
// This crate talks to the C kernel only through `kernel_rust`, the graph's one
// `unsafe` crate: the `extern "C"` surface and the raw-pointer/`static mut`
// plumbing both live there, so this crate holds no `unsafe` of its own.
//
// `unsafe_code` is denied rather than `forbid`-den, because the kernel's C-ABI
// entry points need `#[no_mangle]` and Rust groups that attribute under the
// same lint (a clashing symbol cannot be checked).  Each export carries a
// scoped `#[allow(unsafe_code)]`; nothing else in the crate may be unsafe.
#![deny(unsafe_code)]

use kernel_rust::cell::KCell;
use kernel_rust::console::{printk_bytes, serial_putc};
use kernel_rust::cpu::{self, VmxEptMap};
use kernel_rust::frame::Frame;
use kernel_rust::mem::{self, Page};
use kernel_rust::ptr;

const EPT_MAP_EMPTY: VmxEptMap = VmxEptMap { gpa: 0, hpa: 0, flags: 0 };

/* ---- the vCPU state and its uAPI (mirror ioctl_abi.h, chv.c) ------------ */

/// `cact_chv_regs_t`: the GPR file plus RIP/RFLAGS (KVM order — RSP/RBP sit
/// among the GPRs).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvRegs {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rsp: u64, pub rbp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
}

/// `cact_chv_seg_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvSeg {
    pub base: u64,
    pub limit: u32,
    pub selector: u32,
    pub ar: u32,
    pub reserved: u32,
}

/// `cact_chv_sregs_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvSregs {
    pub cs: ChvSeg, pub ss: ChvSeg, pub ds: ChvSeg,
    pub es: ChvSeg, pub fs: ChvSeg, pub gs: ChvSeg,
    pub gdtr_base: u64, pub idtr_base: u64,
    pub cr0: u64, pub cr2: u64, pub cr3: u64, pub cr4: u64,
    pub dr0: u64, pub dr1: u64, pub dr2: u64, pub dr3: u64,
    pub dr6: u64, pub dr7: u64,
    pub gdtr_limit: u32, pub idtr_limit: u32, pub reserved: u32,
}

/// `cact_chv_msr_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvMsr {
    pub index: u32,
    pub reserved: u32,
    pub value: u64,
}

/// `cact_chv_msrs_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvMsrs {
    pub count: u32,
    pub reserved: u32,
    pub entries: [ChvMsr; 16],
}

/// `cact_chv_memory_t`: one guest-memory slot — a userspace buffer `hva`
/// backing guest-physical `[gpa, gpa+size)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChvMem {
    pub slot: u32,
    pub flags: u32,
    pub gpa: u64,
    pub hva: u64,
    pub size: u64,
}

/* The MSR set the model tracks.  A guest RDMSR/WRMSR is not intercepted yet
 * (no MSR bitmap, no MSR-exit handler), so these are the values the model
 * *seeds* the guest with and reports back; EFER, FS_BASE and GS_BASE also reach
 * the guest state (the VMCS). */
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0084;
const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_GS_BASE: u32 = 0xC000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
const MSR_SYSENTER_CS: u32 = 0x174;
const MSR_SYSENTER_ESP: u32 = 0x175;
const MSR_SYSENTER_EIP: u32 = 0x176;
const MSR_PAT: u32 = 0x277;
const MSR_APIC_BASE: u32 = 0x1B;

const MSR_COUNT: usize = 12;
const MSR_SLOT_EFER: usize = 0;
const MSR_SLOT_FS_BASE: usize = 4;
const MSR_SLOT_GS_BASE: usize = 5;

const MSR_INDEX: [u32; MSR_COUNT] = [
    MSR_EFER, MSR_STAR, MSR_LSTAR, MSR_FMASK, MSR_FS_BASE, MSR_GS_BASE,
    MSR_KERNEL_GS_BASE, MSR_SYSENTER_CS, MSR_SYSENTER_ESP, MSR_SYSENTER_EIP,
    MSR_PAT, MSR_APIC_BASE,
];

/// Slot of `index` in `MSR_INDEX`, or None when the model does not track it.
fn msr_slot(index: u32) -> Option<usize> {
    let mut i = 0;
    while i < MSR_COUNT {
        if MSR_INDEX[i] == index {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The model's one vCPU.  `pending_irq` is a queued external interrupt (< 0 for
/// none) delivered at the next entry.
#[derive(Clone, Copy)]
struct Vcpu {
    regs: ChvRegs,
    sregs: ChvSregs,
    msrs: [u64; MSR_COUNT],
    pending_irq: i32,
}

const fn vcpu_default_msrs() -> [u64; MSR_COUNT] {
    let mut m = [0u64; MSR_COUNT];
    m[MSR_SLOT_EFER] = GUEST_EFER;
    m
}

/// Defaults reproduce the H4/H5 fixture exactly, so a RUN with no preceding SET
/// ioctl behaves as before.
const VCPU_DEFAULT: Vcpu = Vcpu {
    regs: ChvRegs {
        rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0,
        rsp: GVA_STACK + 0x800, rbp: 0,
        r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
        rip: GVA_CODE, rflags: 0x2,
    },
    sregs: ChvSregs {
        cs: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x08, ar: AR_CODE64 as u32, reserved: 0 },
        ss: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x10, ar: AR_DATA as u32, reserved: 0 },
        ds: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x10, ar: AR_DATA as u32, reserved: 0 },
        es: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x10, ar: AR_DATA as u32, reserved: 0 },
        fs: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x10, ar: AR_DATA as u32, reserved: 0 },
        gs: ChvSeg { base: 0, limit: 0xFFFF_FFFF, selector: 0x10, ar: AR_DATA as u32, reserved: 0 },
        gdtr_base: GVA_GDT, idtr_base: GVA_IDT,
        cr0: GUEST_CR0, cr2: 0, cr3: GPA_PML4, cr4: GUEST_CR4,
        dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0x400,
        gdtr_limit: 0x17, idtr_limit: 0xFFF,   // 3 GDT / 256 IDT entries
        reserved: 0,
    },
    msrs: vcpu_default_msrs(),
    pending_irq: -1,
};

static VCPU: KCell<Vcpu> = KCell::new(VCPU_DEFAULT);

/* ---- the vCPU uAPI entry points (called from chv.c) -------------------- */

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_get_regs(out: *mut ChvRegs) -> i32 {
    if out.is_null() {
        return 1;
    }
    ptr::write(out, VCPU.get().regs);
    0
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_set_regs(inp: *const ChvRegs) -> i32 {
    if inp.is_null() {
        return 1;
    }
    VCPU.with(|v| v.regs = ptr::read(inp));
    0
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_get_sregs(out: *mut ChvSregs) -> i32 {
    if out.is_null() {
        return 1;
    }
    ptr::write(out, VCPU.get().sregs);
    0
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_set_sregs(inp: *const ChvSregs) -> i32 {
    if inp.is_null() {
        return 1;
    }
    VCPU.with(|v| v.sregs = ptr::read(inp));
    0
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_get_msrs(io: *mut ChvMsrs) -> i32 {
    if io.is_null() {
        return 1;
    }
    let mut out = ptr::read(io);
    let n = if out.count > 16 { 16 } else { out.count };
    let msrs = VCPU.get().msrs;
    let mut i = 0u32;
    while i < n {
        match msr_slot(out.entries[i as usize].index) {
            Some(s) => {
                out.entries[i as usize].value = msrs[s];
                out.entries[i as usize].reserved = 0;
            }
            None => {
                out.entries[i as usize].value = 0;
                out.entries[i as usize].reserved = 1;
            }
        }
        i += 1;
    }
    out.count = n;
    ptr::write(io, out);
    0
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_set_msrs(io: *const ChvMsrs) -> i32 {
    if io.is_null() {
        return 1;
    }
    let inp = ptr::read(io);
    let n = if inp.count > 16 { 16 } else { inp.count };
    let mut rc = 0;
    VCPU.with(|v| {
        let mut i = 0u32;
        while i < n {
            match msr_slot(inp.entries[i as usize].index) {
                Some(s) => v.msrs[s] = inp.entries[i as usize].value,
                None => rc = 1,
            }
            i += 1;
        }
    });
    rc
}

#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_inject_irq(vector: u32) -> i32 {
    if vector > 255 {
        return 1;
    }
    // The /dev/chv lock serialises this against RUN.
    VCPU.with(|v| v.pending_irq = vector as i32);
    0
}

/* ---- guest memory slots (the MAP/UNMAP_MEMORY uAPI) --------------------- */

/// Max slots (mirror CACT_CHV_MEMORY_MAX).
const CHV_MEMORY_MAX: usize = 8;
/// Total guest-memory pages all slots may pin together (256 * 4 KiB = 1 MiB).
const CHV_MEMORY_PAGES_MAX: usize = 256;
/// The model's own guest pages occupy guest-physical [0x1000, 0xD000); a slot
/// may not shadow them.
const FIXTURE_GPA_LO: u64 = 0x1000;
const FIXTURE_GPA_HI: u64 = 0xD000;

/// One registered slot.  Its frames live at `MEM_SLOT_PHYS[off .. off+npages]`,
/// each pinned by `mem::pin_range` so swap cannot move it while mapped.
#[derive(Clone, Copy)]
struct MemSlot {
    used: bool,
    gpa: u64,
    size: u64,
    off: usize,
    npages: usize,
}
const MEM_SLOT_EMPTY: MemSlot = MemSlot { used: false, gpa: 0, size: 0, off: 0, npages: 0 };

static MEM_SLOTS: KCell<[MemSlot; CHV_MEMORY_MAX]> = KCell::new([MEM_SLOT_EMPTY; CHV_MEMORY_MAX]);
static MEM_SLOT_PHYS: KCell<[u64; CHV_MEMORY_PAGES_MAX]> = KCell::new([0; CHV_MEMORY_PAGES_MAX]);
static MEM_PAGES_USED: KCell<usize> = KCell::new(0);

/* The EPT leaf array for one launch: the model's own pages plus every
 * registered slot's pages.  Scratch, valid only while a run is in flight. */
static EPT_MAPS: KCell<[VmxEptMap; 16 + CHV_MEMORY_PAGES_MAX]> =
    KCell::new([EPT_MAP_EMPTY; 16 + CHV_MEMORY_PAGES_MAX]);

/// Half-open range overlap (sizes here are small, so the sums cannot wrap).
fn ranges_overlap(a: u64, asz: u64, b: u64, bsz: u64) -> bool {
    a < b + bsz && b < a + asz
}

/// Unpin a slot's frames and drop it, compacting the shared frame array so a
/// later MAP can reuse the space.
fn mem_slot_remove(s: usize) {
    let sl = MEM_SLOTS.with(|m| m[s]);
    if !sl.used {
        return;
    }
    MEM_SLOT_PHYS.with(|phys| mem::unpin_frames(&phys[sl.off..sl.off + sl.npages]));
    let tail = sl.off + sl.npages;
    let tail_len = MEM_PAGES_USED.get() - tail;
    MEM_SLOT_PHYS.with(|phys| phys.copy_within(tail..tail + tail_len, sl.off));
    MEM_PAGES_USED.with(|used| *used -= sl.npages);
    MEM_SLOTS.with(|m| {
        let mut t = 0;
        while t < CHV_MEMORY_MAX {
            if m[t].used && t != s && m[t].off > sl.off {
                m[t].off -= sl.npages;
            }
            t += 1;
        }
        m[s] = MEM_SLOT_EMPTY;
    });
}

/// `MAP_MEMORY`: resolve the caller's buffer `[hva, hva+size)` (`pd` is the
/// calling process's page map), pin its frames and record the slot for the next
/// RUN.  Returns 0, or 1 on a bad argument (alignment, overlap, unsupported
/// page, or out of slot space).
#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_add_memory_region(inp: *const ChvMem, pd: *mut u64) -> i32 {
    if inp.is_null() {
        return 1;
    }
    let r = ptr::read(inp);
    let slot = r.slot as usize;
    if slot >= CHV_MEMORY_MAX || r.size == 0 {
        return 1;
    }
    if r.size & 0xFFF != 0 || r.gpa & 0xFFF != 0 || r.hva & 0xFFF != 0 {
        return 1;
    }
    // Reject ranges that wrap, so the overlap and EPT arithmetic below cannot
    // be fooled by a huge (attacker-chosen) guest-physical base.
    if r.gpa.checked_add(r.size).is_none() || r.hva.checked_add(r.size).is_none() {
        return 1;
    }
    let npages = (r.size >> 12) as usize;
    if npages == 0 || npages > CHV_MEMORY_PAGES_MAX {
        return 1;
    }
    if ranges_overlap(r.gpa, r.size, FIXTURE_GPA_LO, FIXTURE_GPA_HI - FIXTURE_GPA_LO) {
        return 1;
    }
    let overlap = MEM_SLOTS.with(|m| {
        let mut s = 0;
        while s < CHV_MEMORY_MAX {
            if s != slot && m[s].used && ranges_overlap(r.gpa, r.size, m[s].gpa, m[s].size) {
                return true;
            }
            s += 1;
        }
        false
    });
    if overlap {
        return 1;
    }
    if MEM_SLOTS.with(|m| m[slot].used) {
        mem_slot_remove(slot);
    }
    let off = MEM_PAGES_USED.get();
    if off + npages > CHV_MEMORY_PAGES_MAX {
        return 1;
    }
    // `mem::pin_range` unpins whatever it pinned before returning -1/partial.
    let pinned =
        MEM_SLOT_PHYS.with(|phys| mem::pin_range(pd, r.hva, r.size, &mut phys[off..off + npages]));
    if pinned != npages as i64 {
        return 1;
    }
    MEM_SLOTS.with(|m| m[slot] = MemSlot { used: true, gpa: r.gpa, size: r.size, off, npages });
    MEM_PAGES_USED.set(off + npages);
    0
}

/// `UNMAP_MEMORY`: unpin a slot's frames and drop it.  Only `slot` matters.
#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_del_memory_region(inp: *const ChvMem) -> i32 {
    if inp.is_null() {
        return 1;
    }
    let r = ptr::read(inp);
    if r.slot as usize >= CHV_MEMORY_MAX {
        return 1;
    }
    if !MEM_SLOTS.with(|m| m[r.slot as usize].used) {
        return 1;
    }
    mem_slot_remove(r.slot as usize);
    0
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
const VMCS_VM_EXIT_INSTRUCTION_LEN: u64 = 0x440C;
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
 * just halts the logical processor and the host never regains control.  CPUID
 * exiting and unconditional I/O exiting (no I/O bitmap needed) give the model
 * the CPUID and I/O exits H5.1 handles — the latter is how the guest reaches
 * the emulated COM1. */
const CPU_BASED_HLT_EXITING: u64 = 1 << 7;
const CPU_BASED_CPUID_EXITING: u64 = 1 << 10;
const CPU_BASED_UNCOND_IO_EXITING: u64 = 1 << 24;

/* Primary control bit 2: exit when the guest becomes ready to receive
 * interrupts (RFLAGS.IF=1 and nothing is blocking them).  The model arms it on
 * demand when it has a queued vector but the guest entered with IF=0 — the CPU
 * then exits at the first moment the vector can be delivered (after an STI),
 * and the handler hands the vector to the next entry.  Without it a queued
 * interrupt aimed at an IF=0 guest would simply never arrive. */
const CPU_BASED_INTR_WINDOW_EXITING: u64 = 1 << 2;

/* Primary control bit 31: the secondary controls below take effect at all.
 * EPT lives in the secondary controls (bit 1); unrestricted guest in bit 7. */
const CPU_BASED_ACTIVATE_SECONDARY_CONTROLS: u64 = 1 << 31;
const SECONDARY_EXEC_ENABLE_EPT: u64 = 1 << 1;

/* Secondary control bit 7: unrestricted guest.  Lets the guest run with
 * CR0.PE=0/CR0.PG=0 — 16-bit real mode — instead of the CPU forcing protected
 * mode with paging on.  Requires EPT (already enabled).  This is what lets the
 * model start a guest at the real-mode entry state a BIOS/bootloader would. */
const SECONDARY_EXEC_UNRESTRICTED_GUEST: u64 = 1 << 7;

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

/* Real-mode (PE=0) segment access rights: 16-bit (L=0, D/B=0), G=0, DPL0,
 * present.  A real-mode 16-bit offset stays below 0x10000, so the limit is
 * 0xFFFF and the base is 0 — the guest then addresses guest-physical memory
 * directly, which EPT still translates. */
const AR_CODE16: u64 = 0x009B;
const AR_DATA16: u64 = 0x0093;

/* CR0/CR4/EFER/RFLAGS bits the launch path reads or forces.  `NW`/`CD` are the
 * bits the CPU always clears in a guest; `NE` is the one bit every VT-x guest
 * CR0 must carry (unrestricted-guest CPUs pin nothing else). */
const CR0_NE: u64 = 1 << 5;
const CR0_NW: u64 = 1 << 29;
const CR0_CD: u64 = 1 << 30;
const CR0_PG: u64 = 1 << 31;
const CR4_VMXE: u64 = 1 << 13;
const EFER_LMA: u64 = 1 << 10;
const RFLAGS_IF: u64 = 1 << 9;

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
const GPA_IDT: u64 = 0xA000;
const GPA_STACK: u64 = 0xB000;
const GPA_GDT: u64 = 0xC000;
const GPA_TRAP: u64 = 0x9000;

/* Guest virtual addresses the program touches.  All sit in PML4/PDPT index 0
 * and PDE index 2, so one PT page reaches all six. */
const GVA_CODE: u64 = 0x40_0000;
const GVA_DATA: u64 = 0x40_1000;
const GVA_TRAP: u64 = 0x40_2000;
const GVA_IDT: u64 = 0x40_3000;
const GVA_STACK: u64 = 0x40_4000;
const GVA_GDT: u64 = 0x40_5000;

/* Guest constants.  VMX requires the guest CR4 to carry every CR4_FIXED0 bit —
 * and on a CPU that supports VMX that includes CR4.VMXE — plus PAE for a
 * IA-32e guest; CR0 is the usual PE|NE|PG (plus ET). */
const GUEST_CR0: u64 = 0x8000_0031; // PE | ET | NE | PG
const GUEST_CR4: u64 = 0x2020;      // PAE | VMXE
const GUEST_EFER: u64 = 0x500;      // LME | LMA

/* The magic the guest stores and the host checks for. */
const GUEST_MAGIC: u32 = 0xdead_beef;

/* COM1: the base of the 16550 the host's own `serial_putc` drives.  The model
 * emulates only its data register (an OUT byte is relayed) and reports the line
 * status register as "transmitter ready", which is all the fixture needs. */
const COM1_BASE: u16 = 0x3F8;

/* The line the fixture guest prints over the emulated COM1. */
const GUEST_LINE: &[u8] = b"\r\n[guest] hello over emulated COM1\r\n";

/* The real-mode fixture (unrestricted guest): a 16-bit program entered with
 * CR0.PE=CR0.PG=0, CS.base=0.  Its offsets are therefore guest-physical
 * addresses directly — the code sits at the start of GPA_CODE and the stack
 * near the top of GPA_STACK (0xB800 < 0x10000).  It prints over the emulated
 * COM1 (the same I/O exit the long-mode fixture uses), stores a 16-bit magic
 * through the mapped GPA_DATA (the EPT translation proof), pokes the unmapped
 * GPA_TRAP (the MMIO hook, now in real mode) and halts. */
const RM_GUEST_LINE: &[u8] = b"\r\n[guest] real mode, unrestricted guest\r\n";
const RM_MAGIC: u16 = 0xBEEF;
const RM_ENTRY: u64 = GPA_CODE;
const RM_STACK: u64 = GPA_STACK + 0x800;

/* Guest GDT descriptors: a 64-bit code segment at selector 0x08 and a
 * read/write data segment at 0x10.  Interrupt delivery loads the handler's CS
 * from the GDT, so the guest needs a real one for the injected vector to land. */
const GDT_CODE: u64 = 0x00AF_9A00_0000_FFFF;
const GDT_DATA: u64 = 0x00CF_9200_0000_FFFF;

/* The exit reason the last handled VM exit reported. */
static EXIT_REASON: KCell<u64> = KCell::new(0);

/* The primary processor-based control value the current run loaded.  The
 * interrupt-window exit (reason 7) clears bit 2 out of it before resuming, so
 * the handler needs the exact value that was written (ctl() may have added
 * pinned bits). */
static PRIMARY_CTRL: KCell<u64> = KCell::new(0);

/* Per-run tallies and the last EPT violation the handler saw (the violation is
 * now a resumable hook, so it is not the final exit any more). */
static IO_EXITS: KCell<u64> = KCell::new(0);
static CPUID_EXITS: KCell<u64> = KCell::new(0);
static INTR_WINDOW_EXITS: KCell<u64> = KCell::new(0);
static SAW_EPT: KCell<bool> = KCell::new(false);
static LAST_GPA: KCell<u64> = KCell::new(0);
static LAST_QUAL: KCell<u64> = KCell::new(0);
static LAST_GLA: KCell<u64> = KCell::new(0);

/* First VMCS field whose VMWRITE failed (0 = none); diagnostics only. */
static VMW_FAIL_FIELD: KCell<u64> = KCell::new(0);

/* The host stack the CPU switches to on VM exit (HOST_RSP). */
#[repr(C, align(16))]
struct HostStack([u8; 16384]);
static HOST_STACK: KCell<HostStack> = KCell::new(HostStack([0; 16384]));

/* 4 KiB page-table pages the model holds for the guest while it is live (the
 * PML4/PDPT/PD/PT of `build_guest_tables`); 0 when no guest runs.  These are
 * host frames the hypervisor physically owns — reported by /proc/meminfo as
 * part of PageTables/HypervisorTables.  They are also EPT-mapped, so they show
 * up in GuestMemory too: the same frames serve as the guest's page tables and
 * as its addressable RAM. */
static GUEST_PTABLE_PAGES: KCell<u32> = KCell::new(0);

/// Guest page-table pages the model currently holds.
#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn cact_hv_guest_table_pages() -> u32 {
    GUEST_PTABLE_PAGES.get()
}

/// Append `bytes` to `buf` at `*n`, never overrunning the reserved tail.
fn put(buf: &mut [u8; 256], n: &mut usize, bytes: &[u8]) {
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
fn notice_line(label: &str, text: &str, value: Option<u64>) {
    let mut buf = [0u8; 256];
    let mut n = 0usize;
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
    printk_bytes(&buf[..n + 2]);
}

/// A NOTICE-level console line (newline appended).
fn notice(text: &str) {
    notice_line("", text, None);
}

/// `label` followed by `value` as `0x%016x`, at NOTICE level.
fn notice_hex(label: &str, value: u64) {
    notice_line(label, "", Some(value));
}

/// A control value the CPU accepts: bits the capability MSR pins to 1 are
/// forced, bits it forbids are cleared, and `desired` fills the rest.
fn ctl(msr: u32, desired: u64) -> u64 {
    let cap = cpu::rdmsr(msr);
    (desired | (cap & 0xFFFF_FFFF)) & (cap >> 32)
}

/// VMWRITE that records (once) the first field the CPU refused, so a silently
/// zeroed field cannot hide an invalid guest state.
fn vmw(field: u64, value: u64) {
    let rc = cpu::vmwrite(field, value);
    if rc != 0 {
        VMW_FAIL_FIELD.with(|f| {
            if *f == 0 {
                *f = field;
            }
        });
    }
}

/// Allocate a zeroed 4 KiB page, or `None` when the heap is exhausted.
fn page() -> Option<Page> {
    Page::alloc()
}

/// Free the guest's pages (the VMCS included).  A page that is still a live
/// VMCS must not go back to the allocator, so callers VMCLEAR it first.
fn free_guest_pages(pages: [Page; 11]) {
    for p in pages {
        p.free();
    }
    // The guest's page tables are among `pages` and are gone.
    GUEST_PTABLE_PAGES.set(0);
}

/// VM-exit entry, called by the C/asm stub with RDI = the saved-GPR frame
/// (`frame[k]` = RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8..R15).  Returns the
/// stub's verdict: 0 finishes the run, 1 re-enters the guest with VMRESUME.
#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_vmx_exit_entry(regs: *mut u64) -> i32 {
    let frame = Frame::new(regs);
    let mut reason = 0u64;
    let _ = cpu::vmread(VMCS_VM_EXIT_REASON, &mut reason);
    EXIT_REASON.set(reason);
    // Fold the guest's state back into the vCPU so GET_REGS/GET_SREGS read the
    // last exit.
    capture_vcpu(&frame);

    match reason {
        EXIT_CPUID => if handle_cpuid(&frame) { 1 } else { 0 },
        EXIT_IO => if handle_io(&frame) { 1 } else { 0 },
        // Not caused by an instruction: the guest reached an interruptible
        // point.  Hand the queued vector to the next entry and resume.
        EXIT_INTERRUPT_WINDOW => { handle_intr_window(); 1 }
        EXIT_EPT_VIOLATION => {
            // Skipped like an MMIO access; if the CPU gave no instruction length
            // we cannot step over it, so finish instead of spinning.
            record_ept();
            if advance_rip() { 1 } else { 0 }
        }
        _ => 0, // HLT and anything unhandled end the run
    }
}

/// Fold the guest's state at the current exit back into the vCPU: the GPR frame
/// the stub saved (`frame[k]` = RAX..R15) plus RSP/RIP/RFLAGS, which live in
/// the VMCS.
fn capture_vcpu(frame: &Frame) {
    let mut rsp = 0u64;
    let _ = cpu::vmread(VMCS_GUEST_RSP, &mut rsp);
    let mut rip = 0u64;
    let _ = cpu::vmread(VMCS_GUEST_RIP, &mut rip);
    let mut rflags = 0u64;
    let _ = cpu::vmread(VMCS_GUEST_RFLAGS, &mut rflags);
    VCPU.with(|v| {
        v.regs.rax = frame.read(0);
        v.regs.rbx = frame.read(1);
        v.regs.rcx = frame.read(2);
        v.regs.rdx = frame.read(3);
        v.regs.rsi = frame.read(4);
        v.regs.rdi = frame.read(5);
        v.regs.rbp = frame.read(6);
        v.regs.r8  = frame.read(7);
        v.regs.r9  = frame.read(8);
        v.regs.r10 = frame.read(9);
        v.regs.r11 = frame.read(10);
        v.regs.r12 = frame.read(11);
        v.regs.r13 = frame.read(12);
        v.regs.r14 = frame.read(13);
        v.regs.r15 = frame.read(14);
        v.regs.rsp = rsp;
        v.regs.rip = rip;
        v.regs.rflags = rflags;
    });
}

/// Advance the guest past the instruction that caused the current exit, using
/// the VMCS's instruction-length field.  Returns false when the CPU reported no
/// length (0) — the caller must then finish rather than re-enter on the same
/// exit forever.
fn advance_rip() -> bool {
    let mut len = 0u64;
    let _ = cpu::vmread(VMCS_VM_EXIT_INSTRUCTION_LEN, &mut len);
    if len == 0 {
        return false;
    }
    let mut rip = 0u64;
    let _ = cpu::vmread(VMCS_GUEST_RIP, &mut rip);
    cpu::vmwrite(VMCS_GUEST_RIP, rip + len);
    true
}

/// CPUID exit: run the host's CPUID for the guest's leaf/subleaf and write the
/// four results back into the GPR frame (RAX/RBX/RCX/RDX).  Pass-through — the
/// guest sees the same CPUID the host does, VMX bits and all.
fn handle_cpuid(frame: &Frame) -> bool {
    let leaf = frame.read(0) as u32;
    let subleaf = frame.read(2) as u32;
    let out = cpu::cpuid(leaf, subleaf);
    frame.write(0, out.eax as u64);
    frame.write(1, out.ebx as u64);
    frame.write(2, out.ecx as u64);
    frame.write(3, out.edx as u64);
    CPUID_EXITS.with(|c| *c += 1);
    // The CPUID exit carries its instruction length.
    advance_rip()
}

/// I/O exit: emulate the COM1 bit the fixture uses.  The exit qualification
/// carries port (31:16), direction (bit 3: 0 = OUT, 1 = IN) and size (2:0).
/// An OUT data byte is relayed to the host's serial port; an IN reports
/// "transmitter ready" (0x60) for the line-status register, else 0.  Anything
/// else is ignored and the instruction stepped over.  Returns false when the
/// CPU gave no instruction length.
fn handle_io(frame: &Frame) -> bool {
    let mut qual = 0u64;
    let _ = cpu::vmread(VMCS_EXIT_QUALIFICATION, &mut qual);
    let port = ((qual >> 16) & 0xFFFF) as u16;
    let size = (qual & 0x7) as u32;
    let is_in = (qual & 0x8) != 0;

    // The fixture uses byte accesses (size 0) to COM1; a wider or foreign
    // access is stepped over without emulation.
    if size == 0 && port >= COM1_BASE && port <= COM1_BASE + 7 {
        let reg = (port - COM1_BASE) as u32;
        let rax = frame.read(0); // AL holds the byte-sized I/O operand
        if is_in {
            let v = if reg == 5 { 0x60u64 } else { 0x00 }; // LSR: THRE|TEMT
            frame.write(0, (rax & !0xFF) | v);
        } else if reg == 0 {
            serial_putc((rax & 0xFF) as u8); // relay to the host's real COM1
        }
    }
    IO_EXITS.with(|c| *c += 1);
    // The I/O exit carries its instruction length.
    advance_rip()
}

/// Interrupt-window exit (reason 7): the guest just became ready to receive
/// interrupts while the window was armed for a queued vector.  Disarm the
/// window and put the vector in the VM-entry interruption-information field;
/// the stub then VMRESUMEs and the interrupt is delivered.  The exit is not
/// caused by an instruction, so RIP is left alone.
fn handle_intr_window() {
    let vector = VCPU.get().pending_irq;
    let primary = PRIMARY_CTRL.get();
    vmw(VMCS_PRIMARY_PROC_BASED_CTRL, primary & !CPU_BASED_INTR_WINDOW_EXITING);
    if vector >= 0 {
        vmw(VMCS_VM_ENTRY_INTR_INFO, (1u64 << 31) | ((vector as u64) & 0xFF));
        VCPU.with(|v| v.pending_irq = -1);
    }
    INTR_WINDOW_EXITS.with(|c| *c += 1);
    if vector >= 0 {
        notice_hex("hv: interrupt-window exit — guest ready, injecting vector ", vector as u64);
    } else {
        notice("hv: interrupt-window exit (no vector queued)");
    }
}

/// Remember the EPT violation the current exit reports, for the run's summary.
/// The violation is a resumable hook now, so it is no longer the final exit.
fn record_ept() {
    let mut gpa = 0u64;
    let mut qual = 0u64;
    let mut gla = 0u64;
    let _ = cpu::vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &mut gpa);
    let _ = cpu::vmread(VMCS_EXIT_QUALIFICATION, &mut qual);
    let _ = cpu::vmread(VMCS_GUEST_LINEAR_ADDRESS, &mut gla);
    LAST_GPA.set(gpa);
    LAST_QUAL.set(qual);
    LAST_GLA.set(gla);
    SAW_EPT.set(true);
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
#[allow(unsafe_code)] // for `#[no_mangle]`: exporting the C ABI, not memory-unsafe
#[no_mangle]
pub extern "C" fn hv_run_guest(out_exit_reason: *mut u64) -> i32 {
    if !out_exit_reason.is_null() {
        ptr::write(out_exit_reason, 0);
    }
    if cpu::vmx_host_enable() != 0 {
        notice("hv: no VT-x host mode — guest run skipped");
        return -1;
    }
    let rc = run_guest();
    // Always leave VMX root, whatever the launch did.
    cpu::vmx_host_disable();
    if !out_exit_reason.is_null() {
        ptr::write(out_exit_reason, EXIT_REASON.get());
    }
    rc
}

/// VM-exit reasons this model handles (Intel SDM Vol. 3C, Appendix C).
const EXIT_INTERRUPT_WINDOW: u64 = 7;
const EXIT_CPUID: u64 = 10;
const EXIT_HLT: u64 = 12;
const EXIT_IO: u64 = 30;
const EXIT_EPT_VIOLATION: u64 = 48;

/// Copy `bytes` into the code page at `at`, advancing it.
fn emit(code: &Page, at: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        code.write_u8(*at, b);
        *at += 1;
    }
}

/// Write one guest page-table entry.
fn pte(table: &Page, index: usize, value: u64) {
    table.write_u64(index * 8, value);
}

/// The guest program (Phase H5.1):
///   mov edx, 0x3F8
///   per line byte: mov al, b ; out dx, al   ; I/O exit -> host relays the byte
///   mov eax, 1 ; xor ecx, ecx ; cpuid       ; CPUID exit -> results written back
///   mov eax, 0xdeadbeef
///   mov [GVA_DATA], eax    ; mapped: EPT translates it, guest continues
///   mov [GVA_TRAP], eax    ; guest paging maps it, EPT does not -> exit 48,
///                          ; the handler skips it and the guest runs on
///   sti ; nop ; nop        ; with a queued vector + IF=0 the window opens
///                          ; after the STI shadow -> exit 7 (vector injected)
///   hlt                    ; exit 12 -> the run ends
///
/// COM1 is port 0x3F8, above 0xFF, so DX is set once and each data byte goes
/// through `out dx, al` (`EE`) — one I/O exit per byte.  The port move is the
/// 32-bit form (`BA`, `mov edx, 0x3F8`), not `mov dx, imm16`: the latter needs a
/// `0x66` operand-size prefix (`66 BA iw`), and a bare `BA iw` would decode as
/// `mov edx, imm32` and swallow the following two bytes — the first byte of the
/// guest's line among them.  The absolute `mov` uses the SIB/no-base form
/// (`89 04 25 disp32`), which is absolute in 64-bit mode and needs no
/// address-size prefix for a sub-4 GiB address.
///
/// The code page also carries two interrupt-entry stubs: the injected-interrupt
/// handler (writes 'I', then `hlt`) and a parking handler (writes 'P', then
/// `hlt`) that every other IDT vector points at, so a stray event reports and
/// halts instead of triple-faulting.  The function returns their offsets
/// `(handler_off, park_off)`, relative to GVA_CODE.
fn emit_guest_program(code: &Page) -> (usize, usize) {
    let mut at = 0usize;
    emit(code, &mut at, &[0xBA]);                          // mov edx, imm32
    emit(code, &mut at, &(COM1_BASE as u32).to_le_bytes());
    for &b in GUEST_LINE {
        emit(code, &mut at, &[0xB0, b]);                   // mov al, imm8
        emit(code, &mut at, &[0xEE]);                      // out dx, al
    }
    emit(code, &mut at, &[0xB8, 0x01, 0x00, 0x00, 0x00]);  // mov eax, 1
    emit(code, &mut at, &[0x31, 0xC9]);                    // xor ecx, ecx
    emit(code, &mut at, &[0x0F, 0xA2]);                    // cpuid
    emit(code, &mut at, &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE]);  // mov eax, magic
    emit(code, &mut at, &[0x89, 0x04, 0x25]);              // mov [disp32], eax
    emit(code, &mut at, &(GVA_DATA as u32).to_le_bytes());
    emit(code, &mut at, &[0x89, 0x04, 0x25]);
    emit(code, &mut at, &(GVA_TRAP as u32).to_le_bytes());
    /* Enable interrupts, then two NOPs, then halt.  With a queued vector
     * and IF=0 at entry the model armed interrupt-window exiting; STI only
     * opens the window after the STI "shadow" (the one instruction that
     * follows STI still runs with interrupts blocked), so the NOPs give the
     * CPU a boundary at which to take the window exit (reason 7) *before*
     * the HLT.  The handler injects the vector, the guest takes it in the
     * 'I' handler above and halts there.  With no queued vector nothing is
     * armed and these bytes are inert. */
    emit(code, &mut at, &[0xFB]);                          // sti
    emit(code, &mut at, &[0x90]);                          // nop
    emit(code, &mut at, &[0x90]);                          // nop
    emit(code, &mut at, &[0xF4]);                          // hlt

    /* Injected-interrupt handler: entered with fresh registers (delivery
     * sets none), so it re-loads DX, writes 'I' over the emulated COM1 and
     * halts — the marker that the interrupt arrived. */
    let handler_off = at;
    emit(code, &mut at, &[0xBA]);                          // mov edx, imm32
    emit(code, &mut at, &(COM1_BASE as u32).to_le_bytes());
    emit(code, &mut at, &[0xB0, b'I']);                    // mov al, 'I'
    emit(code, &mut at, &[0xEE]);                          // out dx, al
    emit(code, &mut at, &[0xF4]);                          // hlt

    /* Parking handler: every other IDT vector points here, so a stray event
     * (e.g. a host interrupt delivered to the guest) reports and halts
     * instead of triple-faulting. */
    let park_off = at;
    emit(code, &mut at, &[0xBA]);                          // mov edx, imm32
    emit(code, &mut at, &(COM1_BASE as u32).to_le_bytes());
    emit(code, &mut at, &[0xB0, b'P']);                    // mov al, 'P'
    emit(code, &mut at, &[0xEE]);                          // out dx, al
    emit(code, &mut at, &[0xF4]);                          // hlt

    (handler_off, park_off)
}

/// The real-mode fixture's program (unrestricted guest).  It is 16-bit code:
/// the default operand size is 16, so `mov dx, imm16` is a bare `BA iw` (no
/// `0x66` prefix) and `mov [moffs16], ax` is `A3 iw`.  Offsets are
/// guest-physical (CS.base=0), so the code runs from RM_ENTRY: it prints
/// RM_GUEST_LINE over the emulated COM1, stores RM_MAGIC through the mapped
/// GPA_DATA, pokes the unmapped GPA_TRAP (an EPT violation the handler skips)
/// and halts.  No IDT is used — real-mode interrupt delivery would go through
/// the IVT, which this fixture never exercises (the interrupt-window test runs
/// on the long-mode fixture, which has an IDT).
fn emit_real_mode_program(code: &Page) {
    let mut at = 0usize;
    emit(code, &mut at, &[0xBA]);                          // mov dx, imm16
    emit(code, &mut at, &(COM1_BASE as u16).to_le_bytes());
    for &b in RM_GUEST_LINE {
        emit(code, &mut at, &[0xB0, b]);                   // mov al, imm8
        emit(code, &mut at, &[0xEE]);                      // out dx, al
    }
    emit(code, &mut at, &[0xB8]);                          // mov ax, imm16
    emit(code, &mut at, &RM_MAGIC.to_le_bytes());
    emit(code, &mut at, &[0xA3]);                          // mov [moffs16], ax
    emit(code, &mut at, &(GPA_DATA as u16).to_le_bytes());
    emit(code, &mut at, &[0xA3]);                          // trap store -> exit 48
    emit(code, &mut at, &(GPA_TRAP as u16).to_le_bytes());
    emit(code, &mut at, &[0xF4]);                          // hlt
}

/// The guest's own 4-level page tables: one PT page reaches all five GVAs
/// (they share PML4/PDPT index 0 and PDE index 2).  Entries name *GPAs*, which
/// is what EPT then translates — including the trap GPA, which EPT leaves out.
fn build_guest_tables(pml4: &Page, pdpt: &Page, pd: &Page, pt: &Page) {
    let idx = |va: u64, shift: u32| ((va >> shift) & 0x1FF) as usize;
    pte(pml4, idx(GVA_CODE, 39), GPA_PDPT | 0x3); // present | writable
    pte(pdpt, idx(GVA_CODE, 30), GPA_PD | 0x3);
    pte(pd, idx(GVA_CODE, 21), GPA_PT | 0x3);
    pte(pt, idx(GVA_CODE, 12), GPA_CODE | 0x3);
    pte(pt, idx(GVA_DATA, 12), GPA_DATA | 0x3);
    pte(pt, idx(GVA_TRAP, 12), GPA_TRAP | 0x3);
    pte(pt, idx(GVA_IDT, 12), GPA_IDT | 0x3);
    pte(pt, idx(GVA_STACK, 12), GPA_STACK | 0x3);
    pte(pt, idx(GVA_GDT, 12), GPA_GDT | 0x3);
}

/// Write the guest's GDT page: null, a 64-bit code segment (selector 0x08) and
/// a read/write data segment (0x10).  Interrupt delivery loads CS from here.
fn build_gdt(gdt: &Page) {
    gdt.write_u64(0, 0);
    gdt.write_u64(8, GDT_CODE);
    gdt.write_u64(16, GDT_DATA);
}

/// Write the guest's 256-entry IDT: every vector points at the parking handler,
/// except `armed` (when >= 0), which points at the injected-interrupt handler —
/// both are guest-linear addresses.
fn build_idt(idt: &Page, handler_gva: u64, park_gva: u64, armed: i32) {
    let mut v = 0usize;
    while v < 256 {
        let target = if armed >= 0 && v == armed as usize { handler_gva } else { park_gva };
        let e = v * 16;
        idt.write_u16(e, (target & 0xFFFF) as u16);
        idt.write_u16(e + 2, 0x0008); // CS selector (RPL0)
        idt.write_u8(e + 4, 0);       // IST = 0
        idt.write_u8(e + 5, 0x8E);    // P | DPL0 | 64-bit interrupt gate
        idt.write_u16(e + 6, ((target >> 16) & 0xFFFF) as u16);
        idt.write_u32(e + 8, (target >> 32) as u32);
        idt.write_u32(e + 12, 0);
        v += 1;
    }
}

/// Build the VMCS for the model's one guest and run it under EPT (Phases H4,
/// H5.1).  Returns 0 once the guest has halted.
///
/// The guest prints a line over the emulated COM1 (I/O exits, relayed to the
/// host's serial port), executes a CPUID (exit, passed through), stores a magic
/// value through a mapped GPA and then through one EPT leaves unmapped.  The
/// host reads the magic back out of the *host* frame the mapped GPA names —
/// proof that EPT translated the access (the guest never named that physical
/// address) — and the trap store is reported as a skipped EPT violation.
fn run_guest() -> i32 {
    let slots: [Option<Page>; 11] = core::array::from_fn(|_| page());
    if slots.iter().any(|p| p.is_none()) {
        notice("hv: guest launch: out of memory");
        for p in slots.into_iter().flatten() {
            p.free();
        }
        return 1;
    }
    let [vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss] =
        slots.map(|p| p.expect("allocated above"));
    /* pml4/pdpt/pd/pt are the guest's own page tables; the rest are the
     * VMCS, code, data, IDT, stack, GDT and TSS pages. */
    GUEST_PTABLE_PAGES.set(4);

    /* Fresh tallies for this run. */
    IO_EXITS.set(0);
    CPUID_EXITS.set(0);
    INTR_WINDOW_EXITS.set(0);
    SAW_EPT.set(false);

    /* The vCPU decides the launch mode.  With CR0.PG=1 the model runs its
     * 64-bit fixture (the historical path); with CR0.PG=0 it starts a
     * 16-bit real-mode guest — the unrestricted-guest case. */
    let v = VCPU.get();
    let real_mode = (v.sregs.cr0 & CR0_PG) == 0;
    let long_mode = !real_mode;

    let vmcs_phys = vmcs.phys();
    let code_phys = code.phys();
    let data_phys = data.phys();
    let idt_phys = idt.phys();
    let stack_phys = stack.phys();
    let gdt_phys = gdt.phys();
    let pml4_phys = pml4.phys();
    let pdpt_phys = pdpt.phys();
    let pd_phys = pd.phys();
    let pt_phys = pt.phys();
    let tss_phys = tss.phys();

    /* Build the program, its IDT and its GDT.  The long-mode fixture has
     * two interrupt-entry stubs; the real-mode one needs neither (real-mode
     * delivery would use the IVT, which this fixture never touches).  A
     * queued interrupt (`pending_irq`) arms that one vector's gate with the
     * 'I' handler; every other vector parks. */
    let armed = v.pending_irq;
    if real_mode {
        emit_real_mode_program(&code);
    } else {
        let (handler_off, park_off) = emit_guest_program(&code);
        build_idt(
            &idt,
            GVA_CODE + handler_off as u64,
            GVA_CODE + park_off as u64,
            armed,
        );
    }
    build_guest_tables(&pml4, &pdpt, &pd, &pt);
    build_gdt(&gdt);

    /* EPT: one mapping per guest page, each GPA naming a distinct host
     * frame.  GPA_TRAP is deliberately absent — that is the violation.
     * The model's own fixture pages come first, then every registered
     * memory slot's pinned frames, one EPT leaf per page. */
    if cpu::vmx_ept_supported() == 0 {
        notice("hv: guest run needs EPT, unavailable on this CPU");
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    let rwx = EPT_R | EPT_W | EPT_X;
    let base: [(u64, u64); 9] = [
        (GPA_PML4, pml4_phys), (GPA_PDPT, pdpt_phys), (GPA_PD, pd_phys),
        (GPA_PT, pt_phys), (GPA_CODE, code_phys), (GPA_DATA, data_phys),
        (GPA_IDT, idt_phys), (GPA_STACK, stack_phys), (GPA_GDT, gdt_phys),
    ];
    let eptp = EPT_MAPS.with(|maps| {
        let mut nmap = 0usize;
        for &(g, h) in base.iter() {
            maps[nmap] = VmxEptMap { gpa: g, hpa: h, flags: rwx };
            nmap += 1;
        }
        let slots = MEM_SLOTS.get();
        let phys = MEM_SLOT_PHYS.get();
        let mut s = 0usize;
        while s < CHV_MEMORY_MAX {
            let sl = slots[s];
            if sl.used {
                let mut p = 0usize;
                while p < sl.npages {
                    maps[nmap] = VmxEptMap {
                        gpa: sl.gpa + (p as u64) * 0x1000,
                        hpa: phys[sl.off + p],
                        flags: rwx,
                    };
                    nmap += 1;
                    p += 1;
                }
            }
            s += 1;
        }
        cpu::vmx_ept_build(&maps[..nmap])
    });
    if eptp == 0 {
        notice("hv: guest launch: EPT build failed");
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    /* A fresh EPTP is not enough on its own: EPT translations are tagged by
     * EPTP, and kalloc can hand the same physical PML4 page (hence the same
     * EPTP) back to the next run.  Flush before the launch. */
    if cpu::vmx_ept_invept_single(eptp) != 0 {
        notice("hv: guest launch: INVEPT failed");
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }

    /* VMCS region: revision identifier first, then make it current. */
    vmcs.write_u32(0, (cpu::rdmsr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32);
    if cpu::vmclear(vmcs_phys) != 0 {
        notice("hv: guest launch: VMCLEAR failed");
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    if cpu::vmptrld(vmcs_phys) != 0 {
        notice("hv: guest launch: VMPTRLD failed");
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }

    /* Controls.  EPT rides in the secondary controls, which only take
     * effect once the primary "activate secondary controls" bit is set.
     * The interrupt-window bit is armed only when a vector is queued and
     * the guest entered with IF=0; the unrestricted-guest bit lets a
     * paging-off (real-mode) guest start at all. */
    let if_set = (v.regs.rflags & RFLAGS_IF) != 0;
    let pending = v.pending_irq;
    let arm_window = pending >= 0 && !if_set;

    vmw(VMCS_PIN_BASED_VM_EXEC_CTRL, ctl(IA32_VMX_PINBASED_CTLS, 0));
    let mut primary_desired = CPU_BASED_HLT_EXITING
        | CPU_BASED_CPUID_EXITING
        | CPU_BASED_UNCOND_IO_EXITING
        | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    if arm_window {
        primary_desired |= CPU_BASED_INTR_WINDOW_EXITING;
    }
    let primary = ctl(IA32_VMX_PROCBASED_CTLS, primary_desired);
    vmw(VMCS_PRIMARY_PROC_BASED_CTRL, primary);
    PRIMARY_CTRL.set(primary);
    /* The window is only real if the CPU kept the bit (it is mandatory in
     * practice; if it were refused we fall back to forcing IF below). */
    let window_on = arm_window && (primary & CPU_BASED_INTR_WINDOW_EXITING) != 0;

    let secondary = ctl(
        IA32_VMX_PROCBASED_CTLS2,
        SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_UNRESTRICTED_GUEST,
    );
    if secondary & SECONDARY_EXEC_ENABLE_EPT == 0 {
        notice("hv: guest launch: CPU refused the enable-EPT control");
        let _ = cpu::vmclear(vmcs_phys);
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    if real_mode && secondary & SECONDARY_EXEC_UNRESTRICTED_GUEST == 0 {
        notice("hv: real-mode launch needs unrestricted guest — unsupported on this CPU");
        let _ = cpu::vmclear(vmcs_phys);
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    vmw(VMCS_SECONDARY_PROC_BASED_CTRL, secondary);
    vmw(VMCS_EPT_POINTER, eptp);
    vmw(VMCS_VM_EXIT_CTRLS, ctl(IA32_VMX_EXIT_CTLS, VM_EXIT_HOST_ADDR_SIZE | VM_EXIT_LOAD_IA32_EFER));
    /* IA-32e mode only when the guest pages (long mode); a real-mode guest
     * enters with the control clear so VM entry does not demand LMA. */
    let mut entry_ctls = VM_ENTRY_LOAD_IA32_EFER;
    if long_mode {
        entry_ctls |= VM_ENTRY_IA32E_MODE;
    }
    vmw(VMCS_VM_ENTRY_CTRLS, ctl(IA32_VMX_ENTRY_CTLS, entry_ctls));
    vmw(VMCS_EXCEPTION_BITMAP, 0);
    vmw(VMCS_PF_ERROR_CODE_MASK, 0);
    vmw(VMCS_PF_ERROR_CODE_MATCH, 0);
    vmw(VMCS_CR3_TARGET_COUNT, 0);
    vmw(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);
    vmw(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
    vmw(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
    vmw(VMCS_VM_ENTRY_EXCEPTION_ERR, 0);
    vmw(VMCS_VM_ENTRY_INSTRUCTION_LEN, 0);

    /* Host state — the kernel's own, so the exit stub and the code after it
     * run in the same context the launch was made from. */
    let mut host = [0u64; 16];
    cpu::cpu_state_snapshot(&mut host);
    let host_sp = HOST_STACK.with(|h| h as *mut HostStack as u64 + 16384);
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
    vmw(VMCS_HOST_RIP, cpu::vmx_exit_stub_addr());
    vmw(VMCS_HOST_IA32_EFER, cpu::rdmsr(IA32_EFER));

    /* Guest state, seeded from the vCPU (`v`).  Its default reproduces the
     * fixture exactly, so a RUN with no preceding SET ioctl behaves as
     * before.  In real mode the model owns the whole state: CS/DS/... are
     * flat 16-bit segments (base 0) and RIP/RSP point into the mapped GPAs,
     * so a 16-bit offset reaches CODE/DATA/STACK with no paging at all. */
    let (g_cs, g_ds, g_es, g_fs, g_gs, g_ss) = if real_mode {
        let code = ChvSeg { base: 0, limit: 0xFFFF, selector: 0, ar: AR_CODE16 as u32, reserved: 0 };
        let data = ChvSeg { base: 0, limit: 0xFFFF, selector: 0, ar: AR_DATA16 as u32, reserved: 0 };
        (code, data, data, data, data, data)
    } else {
        (v.sregs.cs, v.sregs.ds, v.sregs.es, v.sregs.fs, v.sregs.gs, v.sregs.ss)
    };
    let (guest_rip, guest_rsp) = if real_mode {
        (RM_ENTRY, RM_STACK)
    } else {
        (v.regs.rip, v.regs.rsp)
    };
    let (fs_base, gs_base) = if real_mode {
        (0u64, 0u64)
    } else {
        (v.msrs[MSR_SLOT_FS_BASE], v.msrs[MSR_SLOT_GS_BASE])
    };
    /* Guest CR0: clear the always-cleared NW/CD bits and pin NE (the one bit
     * every VT-x guest CR0 carries).  CR4: pin VMXE.  A paging-off guest
     * keeps PG=0 — exactly what unrestricted guest permits. */
    let guest_cr0 = (v.sregs.cr0 & !(CR0_NW | CR0_CD)) | CR0_NE;
    let guest_cr4 = v.sregs.cr4 | CR4_VMXE;
    /* With paging off the guest is not in IA-32e mode, so EFER.LMA is
     * cleared (VM entry rejects LMA=1 without the IA-32e mode control). */
    let guest_efer = if long_mode {
        v.msrs[MSR_SLOT_EFER]
    } else {
        v.msrs[MSR_SLOT_EFER] & !EFER_LMA
    };

    vmw(VMCS_VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);
    vmw(VMCS_GUEST_IA32_EFER, guest_efer);
    vmw(VMCS_GUEST_CR0, guest_cr0);
    vmw(VMCS_GUEST_CR3, v.sregs.cr3);
    vmw(VMCS_GUEST_CR4, guest_cr4);

    vmw(VMCS_GUEST_ES_SELECTOR, g_es.selector as u64);
    vmw(VMCS_GUEST_CS_SELECTOR, g_cs.selector as u64);
    vmw(VMCS_GUEST_SS_SELECTOR, g_ss.selector as u64);
    vmw(VMCS_GUEST_DS_SELECTOR, g_ds.selector as u64);
    vmw(VMCS_GUEST_FS_SELECTOR, g_fs.selector as u64);
    vmw(VMCS_GUEST_GS_SELECTOR, g_gs.selector as u64);
    vmw(VMCS_GUEST_LDTR_SELECTOR, 0);
    vmw(VMCS_GUEST_TR_SELECTOR, 0x18);

    vmw(VMCS_GUEST_ES_BASE, g_es.base);
    vmw(VMCS_GUEST_CS_BASE, g_cs.base);
    vmw(VMCS_GUEST_SS_BASE, g_ss.base);
    vmw(VMCS_GUEST_DS_BASE, g_ds.base);
    vmw(VMCS_GUEST_FS_BASE, fs_base);
    vmw(VMCS_GUEST_GS_BASE, gs_base);
    vmw(VMCS_GUEST_LDTR_BASE, 0);
    vmw(VMCS_GUEST_TR_BASE, tss_phys);
    vmw(VMCS_GUEST_GDTR_BASE, v.sregs.gdtr_base);
    vmw(VMCS_GUEST_IDTR_BASE, v.sregs.idtr_base);

    vmw(VMCS_GUEST_ES_LIMIT, g_es.limit as u64);
    vmw(VMCS_GUEST_CS_LIMIT, g_cs.limit as u64);
    vmw(VMCS_GUEST_SS_LIMIT, g_ss.limit as u64);
    vmw(VMCS_GUEST_DS_LIMIT, g_ds.limit as u64);
    vmw(VMCS_GUEST_FS_LIMIT, g_fs.limit as u64);
    vmw(VMCS_GUEST_GS_LIMIT, g_gs.limit as u64);
    vmw(VMCS_GUEST_LDTR_LIMIT, 0);
    vmw(VMCS_GUEST_TR_LIMIT, 0x67);
    vmw(VMCS_GUEST_GDTR_LIMIT, v.sregs.gdtr_limit as u64);
    vmw(VMCS_GUEST_IDTR_LIMIT, v.sregs.idtr_limit as u64);

    vmw(VMCS_GUEST_ES_AR, g_es.ar as u64);
    vmw(VMCS_GUEST_CS_AR, g_cs.ar as u64);
    vmw(VMCS_GUEST_SS_AR, g_ss.ar as u64);
    vmw(VMCS_GUEST_DS_AR, g_ds.ar as u64);
    vmw(VMCS_GUEST_FS_AR, g_fs.ar as u64);
    vmw(VMCS_GUEST_GS_AR, g_gs.ar as u64);
    vmw(VMCS_GUEST_LDTR_AR, 0x1_0000); // unusable (required in IA-32e mode)
    vmw(VMCS_GUEST_TR_AR, 0x8B);       // busy 32-bit TSS

    vmw(VMCS_GUEST_INTERRUPTIBILITY, 0);
    vmw(VMCS_GUEST_ACTIVITY_STATE, 0);
    vmw(VMCS_GUEST_IA32_SYSENTER_CS, 0);
    vmw(VMCS_GUEST_IA32_SYSENTER_ESP, 0);
    vmw(VMCS_GUEST_IA32_SYSENTER_EIP, 0);
    vmw(VMCS_GUEST_PENDING_DBG_EXC, 0);
    vmw(VMCS_GUEST_DR7, v.sregs.dr7);
    vmw(VMCS_GUEST_RSP, guest_rsp);
    vmw(VMCS_GUEST_RIP, guest_rip);

    /* A queued external interrupt (INJECT_IRQ, type 0).  If the guest is
     * already ready (IF=1) it is delivered at this entry through the
     * VM-entry interruption-information field.  If IF=0 the model instead
     * armed interrupt-window exiting above and leaves IF alone: the CPU
     * exits (reason 7) at the first point the guest could take it, and the
     * handler injects it there.  Should the CPU have refused the window
     * control (mandatory in practice), fall back to forcing IF and
     * delivering now — every IDT vector has a handler, so a stray host
     * event parks and halts rather than triple-faulting. */
    let mut entry_rflags = v.regs.rflags;
    if pending >= 0 && (if_set || !window_on) {
        if !if_set {
            entry_rflags |= RFLAGS_IF;
        }
        vmw(VMCS_VM_ENTRY_INTR_INFO, (1u64 << 31) | ((pending as u64) & 0xFF));
    } else {
        vmw(VMCS_VM_ENTRY_INTR_INFO, 0);
    }
    vmw(VMCS_GUEST_RFLAGS, entry_rflags);

    /* The guest owns CR0/CR4, so no CR access causes an exit. */
    vmw(VMCS_CR0_GUEST_HOST_MASK, 0);
    vmw(VMCS_CR4_GUEST_HOST_MASK, 0);
    vmw(VMCS_CR0_READ_SHADOW, v.sregs.cr0);
    vmw(VMCS_CR4_READ_SHADOW, v.sregs.cr4);

    if VMW_FAIL_FIELD.get() != 0 {
        notice_hex("hv: guest launch: VMCS write rejected, field ", VMW_FAIL_FIELD.get());
    }

    /* Guest GPRs are the host's at entry (VMX saves none), so load the
     * vCPU's set right before VMLAUNCH; RSP/RIP/RFLAGS come from the VMCS.
     * Order matches cact_vmx_launch_regs. */
    let gpr = [
        v.regs.rax, v.regs.rbx, v.regs.rcx, v.regs.rdx,
        v.regs.rsi, v.regs.rdi, v.regs.rbp,
        v.regs.r8, v.regs.r9, v.regs.r10, v.regs.r11,
        v.regs.r12, v.regs.r13, v.regs.r14, v.regs.r15,
    ];

    /* Launch.  On success this only returns after the guest has exited. */
    if cpu::vmx_launch_regs(&gpr) != 0 {
        let mut err = 0u64;
        let _ = cpu::vmread(VMCS_VM_INSTRUCTION_ERROR, &mut err);
        notice_hex("hv: guest launch: VMLAUNCH failed, instruction error ", err);
        let _ = cpu::vmclear(vmcs_phys);
        cpu::vmx_ept_free();
        free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
        return 1;
    }
    /* The entry consumed the injected interrupt, if any. */
    VCPU.with(|vc| vc.pending_irq = -1);

    notice_hex("hv: guest ran, VM-exit reason ", EXIT_REASON.get());
    notice_hex("hv: guest I/O exits ", IO_EXITS.get());
    notice_hex("hv: guest CPUID exits ", CPUID_EXITS.get());
    if INTR_WINDOW_EXITS.get() > 0 {
        notice_hex("hv: interrupt-window exits ", INTR_WINDOW_EXITS.get());
    }
    if MEM_PAGES_USED.get() > 0 {
        notice_hex("hv: guest memory slots mapped, pages ", MEM_PAGES_USED.get() as u64);
    }
    if real_mode {
        notice("hv: guest launched in 16-bit real mode (unrestricted guest)");
    }

    /* The fixture's line went out as COM1 data writes; its length is how
     * many data-register exits we expect to have relayed. */
    let line_len = if real_mode { RM_GUEST_LINE.len() } else { GUEST_LINE.len() };
    if IO_EXITS.get() >= line_len as u64 {
        notice("hv: guest spoke over emulated COM1 (I/O exits relayed)");
    }

    /* The store through the mapped GPA must have landed in the *host* frame
     * that GPA names — the guest never wrote that physical address, so
     * reading the magic back is the translation proof. */
    if real_mode {
        let stored = data.read_u16(0);
        if stored == RM_MAGIC {
            notice("hv: EPT translation OK — real-mode mapped-GPA store reached the host frame");
        } else {
            notice_hex("hv: EPT translation FAILED (real mode) — host frame holds ", stored as u64);
        }
    } else {
        let stored = data.read_u32(0);
        if stored == GUEST_MAGIC {
            notice("hv: EPT translation OK — mapped-GPA store reached the host frame");
        } else {
            notice_hex("hv: EPT translation FAILED — host frame holds ", stored as u64);
        }
    }

    if SAW_EPT.get() {
        notice_hex("hv: EPT violation (skipped as MMIO): guest-physical ", LAST_GPA.get());
        notice_hex("hv:   qualification ", LAST_QUAL.get());
        notice_hex("hv:   guest-linear  ", LAST_GLA.get());
        if LAST_GPA.get() == GPA_TRAP && (LAST_QUAL.get() & 0x2) != 0 {
            notice("hv: EPT violation names the unmapped trap GPA on a write, as intended");
        }
    }

    if EXIT_REASON.get() == EXIT_HLT {
        notice("hv: guest hlt -> exit reason 12 (HLT)");
    }

    // Drop the VMCS and hand every page back: a run must not leak its own
    // pages, the EPT tables, or the VMCS.
    let _ = cpu::vmclear(vmcs_phys);
    cpu::vmx_ept_free();
    free_guest_pages([vmcs, code, data, idt, stack, gdt, pml4, pdpt, pd, pt, tss]);
    0
}
