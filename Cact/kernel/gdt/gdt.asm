; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

[bits 64]

global gdt_flush
global tss_flush
global gdt_load_fs

; void gdt_flush(uint64_t gdt_ptr)
; Loads a new GDT and reloads every segment register.  CS can only be reloaded
; by a control transfer, and in long mode the only encodable form for an
; arbitrary target is a far return — hence the push/retfq pair instead of the
; far jump the 32-bit build used.
gdt_flush:
    lgdt [rdi]              ; rdi = pointer to the 80-bit GDTR descriptor

    mov ax, 0x10            ; Data segment selector (index 2, RPL 0)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    push qword 0x08         ; Code segment selector (index 1, RPL 0)
    lea rax, [rel .reloaded]
    push rax
    retfq
.reloaded:
    ret

; void tss_flush(void)
; Loads the Task State Segment selector into the TR register.  Slot 5 holds the
; descriptor's first half (see write_tss in gdt.c).
tss_flush:
    mov ax, 0x28
    ltr ax
    ret

; void gdt_load_fs(uint16_t sel)
; Loads a data selector into %fs — the user TLS segment.  In long mode this does
; *not* carry a base — gdt_write_tls() programs IA32_FS_BASE — so a caller that
; wants a new thread pointer writes the MSR and leaves the selector alone.
gdt_load_fs:
    mov eax, edi
    mov fs, ax
    ret
