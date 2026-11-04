/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMX_OPS_H
#define CACT_HV_VMX_OPS_H

#include <stdint.h>

/*
 * VMX operation entry points for the model layer (Rust).
 *
 * The instructions themselves live in vmx_insn.h as `static inline`; these are
 * the same operations behind a plain C ABI so the Rust vCPU model can call
 * them without re-emitting the opcodes.  Each returns 0 on success and non-zero
 * on VMfail (Invalid or Valid) — see vmx_insn.h.
 */
int cact_vmclear(uint64_t vmcs_phys);
int cact_vmptrld(uint64_t vmcs_phys);
int cact_vmread(uint64_t field, uint64_t *value);
int cact_vmwrite(uint64_t field, uint64_t value);
int cact_vmlaunch(void);
int cact_vmresume(void);

#endif
