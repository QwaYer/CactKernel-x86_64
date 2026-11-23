/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "vmx_launch.h"
#include "cpu_msr.h"
#include "cpu_cr.h"

/* Saved by cact_vmx_launch so the VM-exit stub can return to its caller and
 * restore the launch-time RFLAGS (the CPU clears RFLAGS to 2 on VM exit). */
uint64_t g_hv_launch_rsp;
uint64_t g_hv_launch_rflags;

extern int  hv_vmx_exit_entry(void *regs);
extern void vmx_exit_stub(void);

__asm__(
".text\n"
"\n"
".globl cact_vmx_launch\n"
".type cact_vmx_launch, @function\n"
"cact_vmx_launch:\n"
"    movq %rsp, g_hv_launch_rsp(%rip)\n"
"    pushfq\n"
"    popq %rax\n"
"    movq %rax, g_hv_launch_rflags(%rip)\n"
"    vmlaunch\n"
/* VMLAUNCH reaches here only on failure (VMfailInvalid/Valid). */
"    setna %al\n"
"    movzbl %al, %eax\n"
"    ret\n"
".size cact_vmx_launch, .-cact_vmx_launch\n"
"\n"
".globl vmx_exit_stub\n"
".type vmx_exit_stub, @function\n"
"vmx_exit_stub:\n"
/* Hardware does not save GPRs on VM exit; save them into a frame for the
 * model's handler. */
"    pushq %r15\n    pushq %r14\n    pushq %r13\n    pushq %r12\n"
"    pushq %r11\n    pushq %r10\n    pushq %r9\n     pushq %r8\n"
"    pushq %rbp\n    pushq %rdi\n    pushq %rsi\n    pushq %rdx\n"
"    pushq %rcx\n    pushq %rbx\n    pushq %rax\n"
"    movq %rsp, %rdi\n"
"    subq $8, %rsp\n"          /* keep the call site 16-byte aligned */
"    call hv_vmx_exit_entry\n"
"    addq $8, %rsp\n"
"    testl %eax, %eax\n"
"    je 1f\n"                  /* 0 -> the model is done with the guest */
/* Non-zero: the model handled the exit and asked to continue.  The frame is
 * live, so pop it back (the handler may have edited it, e.g. CPUID results or
 * an IN value) and re-enter the guest with VMRESUME.  VM exits land here again
 * on HOST_RIP/HOST_RSP, so this is a loop, not a one-shot. */
"    popq %rax\n    popq %rbx\n    popq %rcx\n    popq %rdx\n"
"    popq %rsi\n    popq %rdi\n    popq %rbp\n    popq %r8\n"
"    popq %r9\n     popq %r10\n    popq %r11\n    popq %r12\n"
"    popq %r13\n    popq %r14\n    popq %r15\n"
"    vmresume\n"
/* VMRESUME reaches here only on failure (VMfail); fall through and finish. */
/* Return to cact_vmx_launch's caller as if it had returned 0. */
"1:\n"
"    movq g_hv_launch_rsp(%rip), %rsp\n"
"    pushq g_hv_launch_rflags(%rip)\n"
"    popfq\n"
"    xorl %eax, %eax\n"
"    ret\n"
".size vmx_exit_stub, .-vmx_exit_stub\n"
);

uint64_t cact_vmx_exit_stub_addr(void) {
    return (uint64_t)(uintptr_t)vmx_exit_stub;
}

void cact_cpu_state_snapshot(uint64_t *out) {
    uint16_t cs, ss, ds, es, fs, gs, tr;

    __asm__ __volatile__("mov %%cs, %0" : "=r"(cs));
    __asm__ __volatile__("mov %%ss, %0" : "=r"(ss));
    __asm__ __volatile__("mov %%ds, %0" : "=r"(ds));
    __asm__ __volatile__("mov %%es, %0" : "=r"(es));
    __asm__ __volatile__("mov %%fs, %0" : "=r"(fs));
    __asm__ __volatile__("mov %%gs, %0" : "=r"(gs));
    __asm__ __volatile__("str %0"       : "=r"(tr));

    out[0] = cs;  out[1] = ss;  out[2] = ds;  out[3] = es;
    out[4] = fs;  out[5] = gs;  out[6] = tr;

    out[7] = cpu_rdmsr(0xC0000100u);   /* IA32_FS_BASE */
    out[8] = cpu_rdmsr(0xC0000101u);   /* IA32_GS_BASE */

    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) gdtr, idtr;
    __asm__ __volatile__("sgdt %0" : "=m"(gdtr));
    __asm__ __volatile__("sidt %0" : "=m"(idtr));

    /* TSS base out of the GDT descriptor the TR selects. */
    uint64_t sel = (uint64_t)(tr & ~7u);
    uint64_t d   = *(const uint64_t *)(uintptr_t)(gdtr.base + sel);
    out[9]  = ((d >> 16) & 0xFFFFFFu) | (((d >> 56) & 0xFFu) << 24);
    out[10] = gdtr.base;
    out[11] = idtr.base;

    out[12] = cpu_read_cr0();
    out[13] = cpu_read_cr3();
    out[14] = cpu_read_cr4();

    uint64_t rfl;
    __asm__ __volatile__("pushfq; popq %0" : "=r"(rfl));
    out[15] = rfl;
}
