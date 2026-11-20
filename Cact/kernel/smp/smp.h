/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_SMP_H
#define CACT_SMP_H

#include <stdint.h>

/* C-facing ABI for the Rust SMP bring-up (sched/src/smp.rs). The per-CPU
 * GDT/TSS environment, trampoline staging and INIT-SIPI sequence live in
 * Rust; this header only declares the stable entry points. */

int smp_init(void);
int smp_self_cpu(void);
int smp_cpu_online(uint32_t cpu);

/* ACPI S3: park every worker core before the machine sleeps, and bring them
 * back afterwards.  smp_suspend_workers() returns 0 when all workers are
 * parked, -1 when one is busy — in which case nothing is changed and the
 * caller must abort the suspend.  smp_resume_workers() is a no-op when nothing
 * was parked. */
int  smp_suspend_workers(void);
void smp_resume_workers(void);

#endif
