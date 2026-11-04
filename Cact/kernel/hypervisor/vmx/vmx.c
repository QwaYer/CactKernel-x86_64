/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "vmx.h"
#include "kernel.h"
#include "cpu_msr.h"

/* Intel VT-x model-specific registers. */
#define IA32_FEATURE_CONTROL  0x0000003Au
#define IA32_VMX_BASIC        0x00000480u

/* IA32_FEATURE_CONTROL bits. */
#define FEATURE_CONTROL_LOCK          (1u << 0)  /* [0] — the MSR is locked   */
#define FEATURE_CONTROL_VMXON_SMX     (1u << 1)  /* [1] — VMXON inside SMX    */
#define FEATURE_CONTROL_VMXON_OUT_SMX (1u << 2)  /* [2] — VMXON outside SMX   */

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
