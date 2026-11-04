/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_CPU_MSR_H
#define CACT_CPU_MSR_H

#include <stdint.h>

/*
 * Shared MSR access for kernel code that has to touch model-specific
 * registers.  The kernel used to carry a file-local `static inline` copy of
 * this in every translation unit that needed it (cpudev, apic, gdt, pat); new
 * code includes this header instead.  The instruction pair is the same in both
 * cases, so the two styles coexist without ABI concerns.
 */
static inline uint64_t cpu_rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpu_wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

#endif
