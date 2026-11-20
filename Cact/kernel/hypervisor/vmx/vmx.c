/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "vmx.h"
#include "vmx_insn.h"
#include "kernel.h"
#include "cpu_msr.h"
#include "cpu_cr.h"
#include "memory.h"

/* Intel VT-x model-specific registers. */
#define IA32_FEATURE_CONTROL  0x0000003Au
#define IA32_VMX_BASIC        0x00000480u

/* IA32_FEATURE_CONTROL bits. */
#define FEATURE_CONTROL_LOCK          (1u << 0)  /* [0] — the MSR is locked   */
#define FEATURE_CONTROL_VMXON_SMX     (1u << 1)  /* [1] — VMXON inside SMX    */
#define FEATURE_CONTROL_VMXON_OUT_SMX (1u << 2)  /* [2] — VMXON outside SMX   */

/* CR0/CR4 bits VMX needs: CR4.VMXE enables the instruction set, and VMX
 * requires CR0.NE=1 (it is a fixed bit — IA32_VMX_CR0_FIXED0 pins it, and a
 * CPU with CR0.NE=0 faults VMXON with #GP).  CactOS runs with NE clear, so
 * host mode sets it and restores the original value on the way out. */
#define CR0_NE  (1ull << 5)
#define CR4_VMXE (1ull << 13)

/* IA32_VMX_BASIC[30:0] — the VMCS revision identifier a VMXON/VMCS region
 * must carry in its first dword. */
static uint32_t vmx_revision_id(void) {
    return (uint32_t)(cpu_rdmsr(IA32_VMX_BASIC) & 0x7FFFFFFFu);
}

/* The live VMXON region on this CPU, or NULL when not in VMX operation. */
static void *g_vmxon_region = NULL;
static uint64_t g_cr0_saved = 0;   /* CR0/CR4 as they were before host mode, */
static uint64_t g_cr4_saved = 0;   /* so leaving restores them exactly.      */

void vmx_detect(vmx_caps_t *caps) {
    caps->supported = (cpu_features_ecx() & CPU_FEATURE_VMX) != 0;
    if (!caps->supported)
        return;

    caps->feature_control = cpu_rdmsr(IA32_FEATURE_CONTROL);
    caps->enabled = (caps->feature_control & FEATURE_CONTROL_VMXON_OUT_SMX) != 0;

    caps->basic = cpu_rdmsr(IA32_VMX_BASIC);
    caps->revision_id = (uint32_t)(caps->basic & 0x7FFFFFFFu);
    caps->region_size = (uint32_t)((caps->basic >> 32) & 0x1FFFu);
}

int vmx_host_enable(void) {
    if (g_vmxon_region)
        return 0;   /* already in VMX operation on this CPU */

    uint64_t fc  = cpu_rdmsr(IA32_FEATURE_CONTROL);
    if (!(fc & FEATURE_CONTROL_LOCK)) {
        fc |= FEATURE_CONTROL_VMXON_OUT_SMX;
        cpu_wrmsr(IA32_FEATURE_CONTROL, fc);
    } else if (!(fc & FEATURE_CONTROL_VMXON_OUT_SMX)) {
        return -1;   /* firmware locked VMX off and we cannot re-enable it */
    }

    g_cr0_saved = cpu_read_cr0();
    g_cr4_saved = cpu_read_cr4();
    cpu_write_cr0(g_cr0_saved | CR0_NE);
    cpu_write_cr4(g_cr4_saved | CR4_VMXE);

    void *region = kalloc();
    if (!region) {
        cpu_write_cr4(g_cr4_saved);
        cpu_write_cr0(g_cr0_saved);
        return -1;
    }
    /* The first dword of both the VMXON and VMCS regions is the VMCS revision
     * identifier; a mismatch is VMfailValid. */
    *(volatile uint32_t *)region = vmx_revision_id();

    if (vmx_on(vmm_v2p(region)) != 0) {
        free_page(region);
        cpu_write_cr4(g_cr4_saved);
        cpu_write_cr0(g_cr0_saved);
        return -1;
    }

    g_vmxon_region = region;
    return 0;
}

void vmx_host_disable(void) {
    if (!g_vmxon_region)
        return;

    vmx_off();
    free_page(g_vmxon_region);
    g_vmxon_region = NULL;

    /* Drop CR4.VMXE before lowering CR0.NE.  While in VMX operation CR0/CR4
     * must keep the VMX fixed bits (CR0.NE=1, CR4.VMXE=1); the VMXOFF above
     * ends that, and unwinding in this order keeps the CPU valid at every
     * step. */
    cpu_write_cr4(g_cr4_saved);
    cpu_write_cr0(g_cr0_saved);
}
