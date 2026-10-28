[bits 64]
%include "context.inc"

; ---------------------------------------------------------------------------
; Device interrupt stubs (vectors 0x30–0xEF). Each pushes an error-code slot
; and the vector, then dispatches — MSI and MSI-X share these, since both
; deliver a LAPIC message carrying the vector.
;
; The error-code slot is a zero: device interrupts have none, but pushing it
; makes the frame the stubs leave on the stack exactly a `struct context_frame`
; (the CPU's own pushes, then int_no/err_code, then the registers), so the
; dispatcher can publish the interrupted context as-is — see get_irq_regs().
; ---------------------------------------------------------------------------
extern msidev_dispatch
extern irq_apic_eoi

section .text

%macro msidev_entry 1
global msidev_stub_%1
msidev_stub_%1:
    SWAPGS_IN 8
    push qword 0
    push qword %1
    jmp msidev_common_dispatch
%endmacro

%assign msidev_vec 0x30
%rep 192
msidev_entry msidev_vec
%assign msidev_vec msidev_vec+1
%endrep

global msidev_common_dispatch
msidev_common_dispatch:
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16

    ; The frame is `rbp`; the vector the stub pushed is int_no, which sits
    ; directly below the fifteen saved registers (15 * 8).
    mov edi, [rbp + 120]
    mov rsi, rbp
    call msidev_dispatch
    call irq_apic_eoi

    mov rsp, rbp
    ISR_RESTORE
    add rsp, 16                 ; drop the vector and the error-code slot
    SWAPGS_OUT
    iretq

section .rodata
global msidev_stub_table
msidev_stub_table:
%assign msidev_j 0x30
%rep 192
    dq msidev_stub_%+msidev_j
%assign msidev_j msidev_j+1
%endrep
