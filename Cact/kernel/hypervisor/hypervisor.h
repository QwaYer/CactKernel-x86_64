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

/* OR of HV_CAP_* as detected at boot. */
uint32_t hv_capabilities(void);

/* 4 KiB page tables the hypervisor physically holds: the host EPT hierarchy on
 * Intel plus a live guest's own 4-level tables.  Reported by /proc/meminfo as
 * part of PageTables and as HypervisorTables; normally 0, since guests are run
 * on demand.  The guest's tables also count in hv_guest_memory_pages(): the
 * same frames are both its page tables and its RAM. */
uint32_t hv_ptable_pages(void);

/* 4 KiB guest frames the hypervisor currently backs as the guest's physical
 * memory (EPT leaves, the guest's own page tables included).  Reported by
 * /proc/meminfo as GuestMemory; normally 0, since guests are run on demand. */
uint32_t hv_guest_memory_pages(void);

/* Non-zero when CactOS itself runs as a guest (CPUID.1:ECX[31]) — the case
 * where a backend is only usable from the "nested" half of the stack. */
int hv_running_as_guest(void);

/* The Rust vCPU model's guest-run entry point (crate `cact_hv`, linked via
 * kernel_rust).  Enter VMX root, launch the model's guest, leave VMX root
 * again, and report the VM-exit reason through `out_exit_reason` (caller-owned,
 * may be NULL).  Returns 0 once the guest exited, -1 when host mode is
 * unavailable.  Called on demand from the `/dev/chv` device — never at boot. */
int hv_run_guest(uint64_t *out_exit_reason);

/* Register the /dev/chv ("Cact Hypervisor") character device.  Called from
 * devfs_init() once the VFS is up; returns 0 on success, -1 if the node could
 * not be registered. */
int chv_devfs_init(void);

#endif
