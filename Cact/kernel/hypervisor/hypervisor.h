/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HYPERVISOR_H
#define CACT_HYPERVISOR_H

#include <stdint.h>

/*
 * CactOS as a hypervisor (host).
 *
 * This is the backend-neutral core: it owns the VM/vCPU model and dispatches
 * to one of the hardware backends (`vmx/` for Intel VT-x, `svm/` for AMD-V).
 * Nothing above this layer — the rest of the kernel, and the userspace uAPI —
 * is allowed to see backend specifics.
 *
 * Phase H1 only detects what the CPU offers and publishes the capability bits;
 * it never enters host mode.
 */

/* Hardware virtualization extensions this machine offers. */
#define HV_CAP_NONE 0u
#define HV_CAP_VMX  (1u << 0)   /* Intel VT-x */
#define HV_CAP_SVM  (1u << 1)   /* AMD-V      */

/*
 * Detect the CPU virtualization extensions and log what was found.  Runs from
 * the boot path right after `cpudev_init()`, so the CPUID feature registers it
 * relies on are already populated.  Returns 0 always (a machine without either
 * extension is not an error — it simply cannot host guests).
 */
int hypervisor_init(void);

/* OR of HV_CAP_* as detected at boot. */
uint32_t hv_capabilities(void);

/* Non-zero when CactOS itself runs as a guest (CPUID.1:ECX[31]) — the case
 * where a backend is only usable from the "nested" half of the stack. */
int hv_running_as_guest(void);

#endif
