; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

; acpi_suspend_lowlevel — the kernel half of an ACPI S3 suspend.
;
; It saves just enough state to be resumable (the callee-saved registers and
; the resume point), programs the wake trampoline's info block with the current
; stack pointer and the resume label, then calls acpi_enter_sleep(), which
; writes the SLP_TYP/SLP_EN bits and stops the machine.
;
; The trampoline (drivers/acpi/wake.asm, staged at 0xA000) brings the core back
; to long mode and jumps to .resume_point on the *same* stack — so the sleep
; call simply "returns" on wake, and this function returns to its C caller as
; if nothing had happened.  acpi_resume_finish() first re-establishes the
; machine (GDT/IDT, LAPIC, timebase, ACPI GPEs) with interrupts still off.
;
; If the sleep did not take (the firmware ignored SLP_EN), acpi_enter_sleep()
; returns normally and the same epilogue runs — power.c tells the two apart
; with a flag.

[bits 64]

global acpi_suspend_lowlevel
extern acpi_enter_sleep
extern acpi_resume_finish

%define INFO_BASE 0xAF00        ; identity-mapped trampoline page (paging.rs)
%define OFF_RSP   0x0F40        ; must match wake.asm's info block layout
%define OFF_RIP   0x0F48

section .text

acpi_suspend_lowlevel:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                  ; keep rsp 16-byte aligned for the ABI

    mov rax, INFO_BASE
    mov [rax + OFF_RSP], rsp
    lea rcx, [rel .resume_point]
    mov [rax + OFF_RIP], rcx

    call acpi_enter_sleep       ; returns only when the sleep did not happen

.resume_point:
    call acpi_resume_finish

    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
