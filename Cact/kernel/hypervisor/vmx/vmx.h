/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMX_H
#define CACT_HV_VMX_H

#include <stdint.h>

/* Intel VT-x capability snapshot (read-only; Phase H1). */
typedef struct {
    int      supported;        /* CPUID.1:ECX[5] — VMX available */
    int      enabled;          /* IA32_FEATURE_CONTROL allows VMXON outside SMX */
    uint32_t revision_id;      /* IA32_VMX_BASIC[30:0] — VMCS revision identifier */
    uint32_t region_size;      /* IA32_VMX_BASIC[44:32] — VMXON/VMCS region size, bytes */
    uint64_t feature_control;  /* raw IA32_FEATURE_CONTROL */
    uint64_t basic;            /* raw IA32_VMX_BASIC */
} vmx_caps_t;

/* Fill `caps` from CPUID/MSRs.  Reads only; leaves the CPU in host mode. */
void vmx_detect(vmx_caps_t *caps);

/*
 * Enter VMX root operation on the calling CPU (Phase H2): allow VMXON in
 * IA32_FEATURE_CONTROL, set CR4.VMXE, hand the CPU a 4 KiB VMXON region whose
 * first dword carries the VMCS revision identifier, and issue VMXON.
 * Returns 0 on success, -1 when the firmware locked VMX off or VMXON failed.
 * Idempotent per CPU.
 */
int  vmx_host_enable(void);

/* Leave VMX root operation on the calling CPU and release the VMXON region. */
void vmx_host_disable(void);

#endif
