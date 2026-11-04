/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "cpu_ops.h"
#include "cpu_msr.h"

uint64_t cact_rdmsr(uint32_t msr) { return cpu_rdmsr(msr); }

void cact_wrmsr(uint32_t msr, uint64_t value) { cpu_wrmsr(msr, value); }
