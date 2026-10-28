[bits 64]
%include "context.inc"

global isr7_nm_stub
global clear_xmm_regs
extern handle_lazy_fpu

; #NM: the lazy-FPU handler needs no frame of its own — it works from
; current_task — so this stub only has to preserve the interrupted registers.
isr7_nm_stub:
    SWAPGS_IN 8
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16
    call handle_lazy_fpu
    mov rsp, rbp
    ISR_RESTORE
    SWAPGS_OUT
    iretq

clear_xmm_regs:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    pxor xmm8, xmm8
    pxor xmm9, xmm9
    pxor xmm10, xmm10
    pxor xmm11, xmm11
    pxor xmm12, xmm12
    pxor xmm13, xmm13
    pxor xmm14, xmm14
    pxor xmm15, xmm15
    ret
