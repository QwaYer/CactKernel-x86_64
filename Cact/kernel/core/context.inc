; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

; ---------------------------------------------------------------------------
; Interrupt-frame save/restore, shared by every entry stub.
;
; Long mode has no pusha/popa, so the fifteen general-purpose registers go on
; the stack one at a time — in the order that makes the stack look like
; `struct context_frame` (Cact/kernel/proc/task.h).  The stack grows down, so
; the *last* push is the *first* field of the structure: r15 first, rdi last.
;
; The entry stub is responsible for having the vector and the error code (or a
; zero in its place) on the stack below the registers, followed by what the CPU
; pushed itself: rip, cs, rflags, and rsp/ss when the interrupted code was less
; privileged.
;
; Both macros preserve every register they touch, so a stub may use rbp as its
; frame pointer between them.
; ---------------------------------------------------------------------------

%macro ISR_SAVE 0
    push rdi
    push rsi
    push rdx
    push rcx
    push rax
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro ISR_RESTORE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rax
    pop rcx
    pop rdx
    pop rsi
    pop rdi
%endmacro

; ---------------------------------------------------------------------------
; swapgs discipline.
;
; In kernel mode %gs is this CPU's per-CPU block; in user mode it is the user's
; (always zero) base, and IA32_KERNEL_GS_BASE holds the other one.  An entry
; from ring 3 therefore has to `swapgs` in, and its return `swapgs` out — but an
; entry that interrupted the kernel must not swap at all, so the swap is keyed
; on the interrupted CS.RPL.
;
; SWAPGS_IN takes the distance from rsp to the interrupted CS at the point it is
; used: 8 for a plain frame (rip then cs), and 16 when the exception pushed an
; error code first (errcode, rip, cs) — vectors 8, 10-14, 17, 21, 29, 30.  The
; macros are expanded where that frame is at the top of the stack: at a stub's
; first instruction, or right after the frame has been popped back on the way
; out.  `test [rsp+disp], 3` is therefore "the interrupted code was ring 3".
; (syscall_entry does not use these: it is reached only from ring 3, so it swaps
; unconditionally.)
; ---------------------------------------------------------------------------

%macro SWAPGS_IN 1
    test byte [rsp+%1], 3
    jz %%keep
    swapgs
%%keep:
%endmacro

%macro SWAPGS_OUT 0
    test byte [rsp+8], 3
    jz %%keep
    ; The swap and the iretq must not be interruptible: an interrupt taken
    ; between them enters through a stub that sees an interrupted CS.RPL of 0
    ; (this is kernel code), so it does not swap, and the kernel would then run
    ; on the *user* %gs base — the first %gs access faults, and the #PF handler
    ; faults on its own %gs read and recurses until the kernel stack overruns.
    ; IRETQ restores the frame's RFLAGS, so masking here is transparent.
    cli
    swapgs
%%keep:
%endmacro
