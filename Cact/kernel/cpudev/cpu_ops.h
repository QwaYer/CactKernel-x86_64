/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_CPU_OPS_H
#define CACT_CPU_OPS_H

#include <stdint.h>

/*
 * MSR access behind a plain C ABI, for code (the Rust vCPU model, driver
 * crates) that needs `rdmsr`/`wrmsr` without including the inline header.
 * Same instructions as cpu_msr.h.
 */
uint64_t cact_rdmsr(uint32_t msr);
void     cact_wrmsr(uint32_t msr, uint64_t value);

#endif
