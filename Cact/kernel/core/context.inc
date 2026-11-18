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

; ---------------------------------------------------------------------------
; FP/SIMD state across a handler.
;
; The kernel is compiled with SSE2 — memcpy/memset and the ABI's movd/movq
; through XMM — so any handler *will* clobber xmm0-15.  That is not merely
; untidy: an exception the handler returns to re-executes the faulting
; instruction, so a `movdqu` store that faulted is retried with xmm0 already
; overwritten by the handler and writes garbage.  (Seen concretely as 16 zero
; bytes at the start of every page a user memcpy first touches — the handler's
; zero_page leaves xmm0 zero.)  It is also why a syscall or IRQ may not quietly
; trash the *user's* vector registers: the kernel's own SSE use sits between the
; user's instructions.
;
; The save area lives in the per-CPU block (`%gs`, see CpuSched.fpu_scratch),
; NOT on the stack: a stub's frame IS `struct context_frame`, so anything pushed
; between the GPR block and the vector/error slots would shift int_no/err_code/
; rip/cs and the handler would read garbage.  `movdqu` also needs no alignment,
; so a plain `%gs` displacement serves.
;
; x87/MMX are not saved: no C or Rust in this kernel emits them, so nothing here
; can have clobbered them.  CR0.TS is never set (the lazy-FPU handler in idt/fpu
; only clears it), so the vector file is always live and can never trap.
;
; Known limit: this is one slot per CPU, so it assumes entries do not nest.  The
; exception and IRQ gates clear IF and no handler here re-enables it, so they do
; not.  An entry taken inside a *syscall* handler — which runs with IF set —
; would overwrite the slot; making that case exact needs a per-task save, not a
; per-CPU one.
; ---------------------------------------------------------------------------

%define PERCPU_FPU_SCRATCH 16

%macro FPU_SAVE 0
    movdqu [gs:PERCPU_FPU_SCRATCH+0],   xmm0
    movdqu [gs:PERCPU_FPU_SCRATCH+16],  xmm1
    movdqu [gs:PERCPU_FPU_SCRATCH+32],  xmm2
    movdqu [gs:PERCPU_FPU_SCRATCH+48],  xmm3
    movdqu [gs:PERCPU_FPU_SCRATCH+64],  xmm4
    movdqu [gs:PERCPU_FPU_SCRATCH+80],  xmm5
    movdqu [gs:PERCPU_FPU_SCRATCH+96],  xmm6
    movdqu [gs:PERCPU_FPU_SCRATCH+112], xmm7
    movdqu [gs:PERCPU_FPU_SCRATCH+128], xmm8
    movdqu [gs:PERCPU_FPU_SCRATCH+144], xmm9
    movdqu [gs:PERCPU_FPU_SCRATCH+160], xmm10
    movdqu [gs:PERCPU_FPU_SCRATCH+176], xmm11
    movdqu [gs:PERCPU_FPU_SCRATCH+192], xmm12
    movdqu [gs:PERCPU_FPU_SCRATCH+208], xmm13
    movdqu [gs:PERCPU_FPU_SCRATCH+224], xmm14
    movdqu [gs:PERCPU_FPU_SCRATCH+240], xmm15
%endmacro

%macro FPU_RESTORE 0
    movdqu xmm0,  [gs:PERCPU_FPU_SCRATCH+0]
    movdqu xmm1,  [gs:PERCPU_FPU_SCRATCH+16]
    movdqu xmm2,  [gs:PERCPU_FPU_SCRATCH+32]
    movdqu xmm3,  [gs:PERCPU_FPU_SCRATCH+48]
    movdqu xmm4,  [gs:PERCPU_FPU_SCRATCH+64]
    movdqu xmm5,  [gs:PERCPU_FPU_SCRATCH+80]
    movdqu xmm6,  [gs:PERCPU_FPU_SCRATCH+96]
    movdqu xmm7,  [gs:PERCPU_FPU_SCRATCH+112]
    movdqu xmm8,  [gs:PERCPU_FPU_SCRATCH+128]
    movdqu xmm9,  [gs:PERCPU_FPU_SCRATCH+144]
    movdqu xmm10, [gs:PERCPU_FPU_SCRATCH+160]
    movdqu xmm11, [gs:PERCPU_FPU_SCRATCH+176]
    movdqu xmm12, [gs:PERCPU_FPU_SCRATCH+192]
    movdqu xmm13, [gs:PERCPU_FPU_SCRATCH+208]
    movdqu xmm14, [gs:PERCPU_FPU_SCRATCH+224]
    movdqu xmm15, [gs:PERCPU_FPU_SCRATCH+240]
%endmacro

%macro ISR_SAVE_NOFPU 0
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

%macro ISR_RESTORE_NOFPU 0
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

%macro ISR_SAVE 0
    FPU_SAVE
    ISR_SAVE_NOFPU
%endmacro

%macro ISR_RESTORE 0
    ISR_RESTORE_NOFPU
    FPU_RESTORE
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
