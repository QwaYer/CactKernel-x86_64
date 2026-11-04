/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_CPU_CR_H
#define CACT_CPU_CR_H

#include <stdint.h>

/*
 * Control-register access for kernel code that has to read or write CR0/CR2/
 * CR3/CR4.  Long mode only encodes the 64-bit `mov` forms, so every accessor is
 * a 64-bit register move.  A write carries a "memory" clobber: a CR change
 * takes effect for subsequent memory accesses (CR3 reload, CR0/CR4 paging and
 * cache bits), which the compiler must not reorder around.
 */
static inline uint64_t cpu_read_cr0(void) {
    uint64_t v; __asm__ __volatile__("mov %%cr0, %0" : "=r"(v)); return v;
}
static inline void cpu_write_cr0(uint64_t v) {
    __asm__ __volatile__("mov %0, %%cr0" :: "r"(v) : "memory");
}
static inline uint64_t cpu_read_cr2(void) {
    uint64_t v; __asm__ __volatile__("mov %%cr2, %0" : "=r"(v)); return v;
}
static inline uint64_t cpu_read_cr3(void) {
    uint64_t v; __asm__ __volatile__("mov %%cr3, %0" : "=r"(v)); return v;
}
static inline void cpu_write_cr3(uint64_t v) {
    __asm__ __volatile__("mov %0, %%cr3" :: "r"(v) : "memory");
}
static inline uint64_t cpu_read_cr4(void) {
    uint64_t v; __asm__ __volatile__("mov %%cr4, %0" : "=r"(v)); return v;
}
static inline void cpu_write_cr4(uint64_t v) {
    __asm__ __volatile__("mov %0, %%cr4" :: "r"(v) : "memory");
}

#endif
