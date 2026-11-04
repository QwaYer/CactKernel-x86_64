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

/* VMREAD/VMWRITE name the VMCS field encoding as the first AT&T operand. */
static inline int vmread(uint64_t field, uint64_t *value) {
    uint8_t f;
    __asm__ __volatile__("vmread %1, %0; setna %2"
        : "=r"(*value), "=qm"(f)
        : "r"(field)
        : "cc");
    return f;
}

static inline int vmwrite(uint64_t field, uint64_t value) {
    uint8_t f;
    __asm__ __volatile__("vmwrite %1, %2; setna %0"
        : "=qm"(f)
        : "r"(field), "r"(value)
        : "cc");
    return f;
}

#endif
