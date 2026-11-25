/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef IRQSTAT_H
#define IRQSTAT_H

#include <stdint.h>

/* Per-vector interrupt accounting for /proc/interrupts.
 *
 * One counter per (CPU, vector): an interrupt is noted on the CPU that took
 * it, which is exactly the per-CPU column /proc/interrupts shows.  A vector's
 * total is summed on read, so there is no shared counter to race on. */

#define IRQSTAT_MAX_CPUS 64
#define IRQSTAT_VECTORS  256

void        irqstat_init(void);
void        irqstat_note(unsigned int vector);        /* count on this CPU   */
void        irqstat_name(unsigned int vector, const char *name);
void        irqstat_set_sci(unsigned int vector);     /* register the SCI     */
void        irqstat_note_sci(void);                   /* count the SCI vector */

uint32_t    irqstat_cpu(unsigned int cpu, unsigned int vector);
uint32_t    irqstat_vector_total(unsigned int vector);
uint64_t    irqstat_total(void);
const char *irqstat_name_of(unsigned int vector);

#endif
