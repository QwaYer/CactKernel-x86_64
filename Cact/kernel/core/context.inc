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
