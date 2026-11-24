/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HYPERVISOR_H
#define CACT_HYPERVISOR_H

#include <stdint.h>
#include "ioctl_abi.h"

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

/*
 * The vCPU state, exposed to userspace (crate `cact_hv`, same door as
 * hv_run_guest).  The model owns one persistent vCPU: `hv_get_*` fills the
 * caller's struct from it, `hv_set_*` adopts the caller's, and the state is
 * applied to the guest on the next RUN (and the guest's state is written back
 * after each exit).  `hv_inject_irq` queues one external interrupt for the next
 * entry.  All return 0 on success, non-zero on a bad argument.
 */
int hv_get_regs(cact_chv_regs_t *out);
int hv_set_regs(const cact_chv_regs_t *in);
int hv_get_sregs(cact_chv_sregs_t *out);
int hv_set_sregs(const cact_chv_sregs_t *in);
int hv_get_msrs(cact_chv_msrs_t *io);
int hv_set_msrs(const cact_chv_msrs_t *in);
int hv_inject_irq(uint32_t vector);

/*
 * Guest memory slots (the /dev/chv MAP/UNMAP_MEMORY uAPI).  `hv_add_memory_region`
 * resolves [hva, hva+size) in the calling process's page tables (`pd`), pins the
 * frames so swap cannot move them, and records them to be installed into the
 * guest's EPT at `gpa` on the next RUN; a MAP with an existing slot id replaces
 * it.  `hv_del_memory_region` unpins a slot (only `slot` matters).  Both return
 * 0 on success, non-zero on a bad argument (bad alignment, overlap, or a page
 * that cannot be backed).
 */
int hv_add_memory_region(const cact_chv_memory_t *in, uint64_t *pd);
int hv_del_memory_region(const cact_chv_memory_t *in);

/* Register the /dev/chv ("Cact Hypervisor") character device.  Called from
 * devfs_init() once the VFS is up; returns 0 on success, -1 if the node could
 * not be registered. */
int chv_devfs_init(void);

#endif
