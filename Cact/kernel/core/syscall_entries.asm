; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

[BITS 64]
%include "context.inc"

global syscall_entry

extern syscall_handler

section .text

; ---------------------------------------------------------------------------
; Fast syscall entry (the IA32_LSTAR target of the `syscall` instruction).
;
; User convention (set by the CactLib stub rebuilt in Phase 6 of
; PORTING-x86_64.md):
;   rax = syscall number
;   rdi = arg1, rsi = arg2, rdx = arg3
;   rcx = return RIP   (CPU-saved; `syscall` writes it there)
;   r11 = user RFLAGS  (CPU-saved)
;   rsp = user RSP     (`syscall` does NOT switch stacks)
;
; FMASK clears IF (and DF) on entry, so the entry runs to completion with
; interrupts off.  The entry then builds a `struct context_frame` (byte-identical
; to `struct syscall_frame`) on this CPU's kernel stack, dispatches, and returns
; through the same epilogue as an exception stub: restore the registers, drop
; int_no/err_code, `iretq`.  IRET is used rather than SYSRET because SYSRET's
; selector arithmetic (SS = CS - 8) does not match this GDT's
; user-code-then-user-data ordering; the round trip is otherwise identical and
; IRET keeps one return path for syscalls, faults and IRQs.
;
; The user stack is never written: `syscall` does not switch stacks, but
; reaching this CPU's kernel entry stack is a single %gs-relative load and r10
; is spare in our 3-argument ABI, so there is nothing to spill anywhere — and in
; particular nothing lands at [user_rsp - 8], which would sit inside the SysV
; red zone of the calling frame (every userspace leaf function is free to keep a
; local there, and x86_64 code compiled without -mno-red-zone does).
; ---------------------------------------------------------------------------
syscall_entry:
    ; `syscall` is only ever entered from ring 3, so the per-CPU %gs swap is
    ; unconditional here (the exception/IRQ stubs key theirs on CS.RPL instead).
    swapgs
    mov r10, rsp                    ; r10 = user RSP (restored by the frame below)
    mov rsp, [gs:8]                 ; this CPU's kernel entry stack (%gs:esp0)

    ; Build the frame, lowest address last: the pushes run in reverse field
    ; order so the last one lands as `r15`, the frame's first field.
    push qword 0x23                 ; ss   (user data | RPL3)
    push r10                        ; rsp  (user)
    push r11                        ; rflags (user; CPU-saved into r11)
    push qword 0x1B                 ; cs   (user code | RPL3)
    push rcx                        ; rip  (user; CPU-saved into rcx)
    push qword 0                    ; err_code (unused for a syscall)
    push qword 0                    ; int_no
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

    ; Long mode ignores ds/es, so there is no kernel data segment to load.
    sti                             ; on the kernel stack now — the frame is whole
    mov rdi, rsp                    ; arg: struct context_frame*
    call syscall_handler

    ISR_RESTORE
    add rsp, 16                     ; drop int_no / err_code
    cli                             ; nothing may interrupt between the swapgs
                                    ; and the iretq: the stub of an interrupt
                                    ; taken there sees the interrupted CS.RPL=0,
                                    ; so it does not swap, and the kernel would
                                    ; then run with the *user* %gs base — the
                                    ; first %gs access would fault and recurse
                                    ; in the #PF handler.
    swapgs                          ; back to the user %gs base before returning
    iretq
