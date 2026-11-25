/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include <stdint.h>
#include "tick.h"
#include "smp.h"
#include "kernel.h"
#include "task.h"
#include "irqstat.h"
#include "thermal.h"

#define TICK_MAX_CPUS 64

static volatile uint32_t timer_ticks = 0;

/* Per-CPU tick split for /proc/stat: the LAPIC tick is attributed to user
 * (the interrupted code was ring 3), idle (the interrupted task is this CPU's
 * idle context — pid 0) or system (kernel-mode work).  Each CPU fills only its
 * own row, so no element is shared. */
static volatile uint64_t cpu_user_ticks[TICK_MAX_CPUS];
static volatile uint64_t cpu_system_ticks[TICK_MAX_CPUS];
static volatile uint64_t cpu_idle_ticks[TICK_MAX_CPUS];

int tick_cpu_count(void) { return TICK_MAX_CPUS; }

uint64_t tick_cpu_user(int cpu) {
    if (cpu < 0 || cpu >= TICK_MAX_CPUS) return 0;
    return cpu_user_ticks[cpu];
}
uint64_t tick_cpu_system(int cpu) {
    if (cpu < 0 || cpu >= TICK_MAX_CPUS) return 0;
    return cpu_system_ticks[cpu];
}
uint64_t tick_cpu_idle(int cpu) {
    if (cpu < 0 || cpu >= TICK_MAX_CPUS) return 0;
    return cpu_idle_ticks[cpu];
}

/* Attribute one timer interrupt to a CPU-time bucket, from the interrupted
 * CS (RPL 3 = user).  Called from timer_isr with the frame's CS. */
void timer_account_tick(uint64_t cs) {
    int cpu = smp_self_cpu();
    if (cpu < 0 || cpu >= TICK_MAX_CPUS) cpu = 0;

    struct task_struct *cur = current_task;
    if ((cs & 3u) == 3u) {
        cpu_user_ticks[cpu]++;
    } else if (cur && cur->pid == 0) {
        cpu_idle_ticks[cpu]++;
    } else {
        cpu_system_ticks[cpu]++;
    }
}

void timer_tick(void)
{
    /* Count the LAPIC timer on every core (per-CPU /proc/interrupts column) and
     * sample this core's DTS (per-CPU /proc/sensors), then advance the global
     * tick on the master only: workers share the timer vector, but counting
     * every core's tick toward the clock would make it run N times too fast. */
    int cpu = smp_self_cpu();
    irqstat_note(LAPIC_TIMER_VECTOR);
    thermal_cpu_sample(cpu);
    if (cpu != 0)
        return;
    timer_ticks++;
}

uint32_t timer_ticks_get(void)
{
    return timer_ticks;
}
