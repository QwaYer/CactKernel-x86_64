; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

[bits 64]

; Control-register helpers.  CR0/CR2/CR3 are 64-bit registers in long mode and
; only the 64-bit forms are encodable, so every access is full-width even where
; the C declaration is still pointer-width-agnostic.

global load_page_directory
global enable_paging
global read_cr2

; void load_page_directory(uint32_t* directory)
load_page_directory:
    mov cr3, rdi
    ret

; void enable_paging(void)
;
; `bts` rather than `or rax, 0x80000000`: the immediate form of OR sign-extends
; its 32-bit operand in long mode, which would set every bit above 31 as well,
; and writing a reserved CR0 bit set raises #GP.
enable_paging:
    mov rax, cr0
    bts rax, 31
    mov cr0, rax
    ret

; uintptr_t read_cr2(void)
read_cr2:
    mov rax, cr2
    ret
