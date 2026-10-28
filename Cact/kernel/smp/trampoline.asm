; AP trampoline — copied to low memory (0x8000) and executed by worker cores
; after an INIT-SIPI wake.  Runs in real mode, brings the core up into IA-32e
; (long mode) with the kernel's own page tables, then jumps to the C entry
; smp_ap_entry, which lives in the higher half.
;
; The SIPI vector is TRAMP_ADDR >> 12, so a woken core always lands on the first
; byte of this page and starts fetching instructions there.  Offset 0 must
; therefore be the entry instruction: the info block below is data, and an AP
; that begins executing it never reaches the entry code (the values patched
; here are addresses, and a byte pair like 0xF0 0xC3 decodes as `lock ret`).
; The block is parked at a fixed offset near the top of the page instead and is
; reached only through absolute addresses (org 0x8000).
;
;   +0x0000              AP entry (real mode)
;   +0x0F00 info_cr3     physical address of the kernel PML4
;   +0x0F08 info_stack   per-CPU idle stack top (64-bit, higher half)
;   +0x0F10 info_entry   smp_ap_entry() (64-bit, higher half)
;   +0x0F18 info_cpu     logical cpu index this AP should take
;   +0x0F1C info_ack     set by the AP to 1 after it consumed the info block

[bits 16]
org 0x8000

; Must match the INFO_* offsets in proc/sched/src/smp.rs.
%define INFO_BASE 0x8F00

section .text

ap_start16:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x8000 + 0x0E00

    lgdt [gdt_desc]

    mov eax, cr0
    or al, 1
    mov cr0, eax

    jmp dword 0x08:ap_start32

[bits 32]
ap_start32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; PAE is required by the four-level tables; OSFXSR/OSXMMEXCPT bring SSE live
    ; before the first line of Rust runs (the x86-64 SysV ABI relies on it).
    mov eax, cr4
    or eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov cr4, eax

    mov eax, [info_cr3]             ; kernel PML4 (physical, below 4 GiB)
    mov cr3, eax

    mov ecx, 0xC0000080             ; IA32_EFER
    rdmsr
    or eax, 1 << 8                  ; LME
    wrmsr

    mov eax, cr0
    or eax, 0x80000001              ; PG | PE
    mov cr0, eax

    jmp 0x18:ap_start64             ; 64-bit code segment -> long mode

[bits 64]
ap_start64:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, [abs info_stack]       ; this core's idle stack (higher half)
    mov rax, [abs info_entry]
    jmp rax

align 16
gdt_start:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF           ; 0x08 — 32-bit kernel code (D=1, L=0)
    dq 0x00CF92000000FFFF           ; 0x10 — kernel data
    dq 0x00AF9A000000FFFF           ; 0x18 — 64-bit kernel code (L=1, D=0)
gdt_end:

align 2
gdt_desc:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Info block.  The fill keeps these words out of the instruction stream and
; turns a trampoline that grows into INFO_BASE into a build error instead of a
; silently overwritten (BSP-patched) value.
align 16
info_block:
    times (INFO_BASE - 0x8000 - ($ - $$)) db 0
info_cr3:    dq 0
info_stack:  dq 0
info_entry:  dq 0
info_cpu:    dd 0
info_ack:    dd 0
info_pad:    dd 0
