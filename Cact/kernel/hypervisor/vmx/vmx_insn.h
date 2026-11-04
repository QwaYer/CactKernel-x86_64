/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMX_INSN_H
#define CACT_HV_VMX_INSN_H

#include <stdint.h>

/*
 * Raw VMX instruction wrappers — the only place in the tree that emits a VMX
 * opcode.  Every VMX instruction reports failure in RFLAGS: CF=1 is
 * VMfailInvalid (no current VMCS / bad operand) and ZF=1 is VMfailValid (the
 * VMCS error field says why); `setna` (CF | ZF) folds both into a 0/1 return.
 *
 * The flag consumer is a *byte* (uint8_t, "=qm") on purpose: `setcc` writes one
 * byte, so widening it to `int` would read whatever the upper three bytes held
 * and turn a success into a phantom failure — and, worse, send the caller down
 * an unwind path while it is really in VMX operation.
 *
 * VMXON and VMCLEAR/VMPTRLD/VMPTRST take the address of the VMXON/VMCS region
 * (a *physical* address, hence the memory operand).  Their forms are legal only
 * once the CPU is in VMX operation, which VMXON itself establishes.
 */

static inline int vmx_on(uint64_t phys) {
    uint8_t f;
    __asm__ __volatile__("vmxon %[pa]; setna %[f]"
        : [f] "=qm"(f) : [pa] "m"(phys) : "cc", "memory");
    return f;
}

static inline int vmx_off(void) {
    uint8_t f;
    __asm__ __volatile__("vmxoff; setna %[f]"
        : [f] "=qm"(f) :: "cc", "memory");
    return f;
}

static inline int vmclear(uint64_t phys) {
    uint8_t f;
    __asm__ __volatile__("vmclear %[pa]; setna %[f]"
        : [f] "=qm"(f) : [pa] "m"(phys) : "cc", "memory");
    return f;
}

static inline int vmptrld(uint64_t phys) {
    uint8_t f;
    __asm__ __volatile__("vmptrld %[pa]; setna %[f]"
        : [f] "=qm"(f) : [pa] "m"(phys) : "cc", "memory");
    return f;
}

static inline int vmptrst(uint64_t *phys) {
    uint8_t f;
    __asm__ __volatile__("vmptrst %[pa]; setna %[f]"
        : [pa] "=m"(*phys), [f] "=qm"(f) : : "cc", "memory");
    return f;
}

/* VMREAD/VMWRITE name the VMCS field encoding as a register operand.  The Intel
 * forms are asymmetric — VMREAD(dest, field) but VMWRITE(field, value) — so the
 * reversed AT&T order is `vmread field, dest` yet `vmwrite value, field`. */
static inline int vmread(uint64_t field, uint64_t *value) {
    uint8_t f;
    __asm__ __volatile__("vmread %2, %0; setna %1"
        : "=r"(*value), "=qm"(f)
        : "r"(field)
        : "cc");
    return f;
}

static inline int vmwrite(uint64_t field, uint64_t value) {
    uint8_t f;
    __asm__ __volatile__("vmwrite %2, %1; setna %0"
        : "=qm"(f)
        : "r"(field), "r"(value)
        : "cc");
    return f;
}

/* VMLAUNCH/VMRESUME run the guest from the current VMCS; control returns to the
 * host only through a VM exit (never as a normal return), so a 0 return means
 * the launch failed (VMfail) and the guest never started. */
static inline int vmlaunch(void) {
    uint8_t f;
    __asm__ __volatile__("vmlaunch; setna %[f]"
        : [f] "=qm"(f) :: "cc", "memory");
    return f;
}

static inline int vmresume(void) {
    uint8_t f;
    __asm__ __volatile__("vmresume; setna %[f]"
        : [f] "=qm"(f) :: "cc", "memory");
    return f;
}

#endif
