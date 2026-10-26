[bits 64]
%include "context.inc"

global isr0
global isr1
global isr2
global isr3
global isr4
global isr5
global isr6
global isr8
global isr9
global isr10
global isr11
global isr12
global isr13
global isr14
global isr15
global isr16
global isr17
global isr18
global isr19
global isr20
global isr21
global isr22
global isr23
global isr24
global isr25
global isr26
global isr27
global isr28
global isr29
global isr30
global isr31
global isr_common_stub

extern exception_handler
extern page_fault_handler

section .text

; The exceptions in the CPU's "pushes an error code" group leave it on the
; stack; the rest get a zero in its place so that every frame has the same
; shape.  The vector is pushed after it, which puts int_no below err_code in
; `struct context_frame` — the order ISR_SAVE expects.
%macro ISR_NOERR 1
global isr%1
isr%1:
    push qword 0
    push qword %1
    jmp isr_common_stub
%endmacro

%macro ISR_ERR 1
global isr%1
isr%1:
    push qword %1
    jmp isr_common_stub
%endmacro

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

; #PF has a handler of its own (it resolves the fault instead of reporting it).
isr14:
    push qword 14
    jmp isr_pf_stub

; Save the registers, hand the frame over, put everything back and return with
; iretq.  rbp is the frame pointer here: its interrupted value was pushed by
; ISR_SAVE, so it is free, and `and rsp, -16` makes the stack 16-byte aligned
; at the call as the SysV ABI requires — an interrupt can arrive with rsp at
; any alignment.
isr_pf_stub:
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16
    mov rdi, rbp
    call page_fault_handler
    mov rsp, rbp
    ISR_RESTORE
    add rsp, 16                 ; drop the vector and the error code
    iretq

isr_common_stub:
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16
    mov rdi, rbp
    call exception_handler
    mov rsp, rbp
    ISR_RESTORE
    add rsp, 16
    iretq
