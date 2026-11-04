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
 * Language split: this C layer holds the low-level primitives (MSR/CR access,
 * the VMX/SVM instructions and regions).  The VM/vCPU model and the exit
 * dispatch move to a Rust crate once the primitives exist — the same split the
 * rest of the kernel uses (`sched`, `rust_mm`, `rust_drm`, `rust_vfs`).
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

/*
 * Bring-up probe for host mode (Phase H2): enter and immediately leave VMX root
 * (Intel) and/or SVM host mode (AMD) on the boot CPU.  Runs once the kernel
 * heap exists, since the VMXON and VM_HSAVE_PA regions come from `kalloc()`.
 * Always returns 0; a backend that cannot be entered is logged and skipped.
 */
int hypervisor_host_init(void);

/* OR of HV_CAP_* as detected at boot. */
uint32_t hv_capabilities(void);

/* Non-zero when CactOS itself runs as a guest (CPUID.1:ECX[31]) — the case
 * where a backend is only usable from the "nested" half of the stack. */
int hv_running_as_guest(void);

#endif
