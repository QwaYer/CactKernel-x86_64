/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_TIMER_TICK_H
#define CACT_TIMER_TICK_H

#include <stdint.h>

/* Scheduler tick counter ("jiffies"): advanced once per LAPIC timer
 * interrupt (LAPIC_TIMER_VECTOR) and used as the kernel's coarse time base
 * for timeouts and sleep deadlines. */
void     timer_tick(void);
uint32_t timer_ticks_get(void);

/* Per-CPU tick accounting for /proc/stat.  timer_account_tick() is called from
 * timer_isr with the interrupted frame's CS; the getters return one CPU's
 * bucket.  tick_cpu_count() is the table size, not the number of online CPUs. */
void     timer_account_tick(uint64_t cs);
int      tick_cpu_count(void);
uint64_t tick_cpu_user(int cpu);
uint64_t tick_cpu_system(int cpu);
uint64_t tick_cpu_idle(int cpu);

#endif
