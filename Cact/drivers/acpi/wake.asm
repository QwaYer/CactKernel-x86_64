; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

; ACPI S3 wake trampoline — copied to the identity-mapped page at 0xA000 and
; entered by the platform in *real mode* when the machine wakes from
; suspend-to-RAM.  Its physical address is what power.c programs into
; FACS.FirmwareWakingVector; the wake vector is a plain linear address, so the
; very first byte of the page must be the entry instruction.
;
; It brings the core from real mode back into IA-32e long mode with the
; kernel's page tables, restores the machine state the sleep reset (segment
; bases, XCR0, CR0/CR4) from the info block, and jumps to the saved resume RIP
; — the point inside acpi_suspend_lowlevel() just after the sleep call, on the
; suspended task's own kernel stack.  Everything else (GDT/IDT, LAPIC,
; timebase, PAT, ACPI GPEs) is restored by acpi_resume_finish() in C;
; IA32_PAT in particular belongs to pat_init() (the PAT driver,
; memory/rust_mm/src/vmm/pat.rs: "an S3 resume resets the MSR, so pat_init()
; sets it explicitly on every (re)initialisation").
;
; The layout mirrors kernel/smp/trampoline.asm: the info block lives at a fixed
; offset near the top of the page (INFO_BASE) so it can never be reached by
; falling through the entry code.  power.c writes those fields through its
; low-half alias before the sleep.
;
;   +0x0000              wake entry (real mode)
;   +0x0E00              real-mode stack top (grows down, below the info block)
;   +0x0F00 info_cr0     saved CR0
;   +0x0F08 info_cr3     kernel PML4 (physical)
;   +0x0F10 info_cr4     saved CR4
;   +0x0F18 info_pat     saved IA32_PAT
;   +0x0F20 info_xcr0    saved XCR0
;   +0x0F28 info_fs_base saved IA32_FS_BASE
;   +0x0F30 info_gs_base saved IA32_GS_BASE
;   +0x0F38 info_kgs_base saved IA32_KERNEL_GS_BASE
;   +0x0F40 info_rsp     kernel stack pointer to resume on
;   +0x0F48 info_rip     acpi_suspend_lowlevel's resume label (higher half)
;
; EFER is not carried: the trampoline re-establishes the only bits the kernel
; uses (LME | NXE | SCE) itself.

[bits 16]
org 0xA000

%define WAKE_BASE 0xA000
%define INFO_BASE 0xAF00

section .text

wake_start16:
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, WAKE_BASE + 0x0E00

    lgdt [gdt_desc]

    mov eax, cr0
    or al, 1                        ; PE
    mov cr0, eax

    jmp dword 0x08:wake_start32

[bits 32]
wake_start32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; The minimum CR4 needed to run the compiler's SSE code after long mode is
    ; reached (OSFXSR/OSXMMEXCPT); the exact value follows in 64-bit mode.
    mov eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov cr4, eax

    mov eax, dword [info_cr3]
    mov cr3, eax

    mov ecx, 0xC0000080             ; IA32_EFER
    rdmsr
    or eax, (1 << 8) | (1 << 11) | (1 << 0)   ; LME | NXE | SCE
    wrmsr

    mov eax, dword [info_cr0]       ; paging among the saved bits
    mov cr0, eax

    jmp 0x18:wake_start64           ; 64-bit code segment -> long mode

[bits 64]
wake_start64:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; In long mode a segment base is an MSR, not a descriptor: put %fs/%gs
    ; back before any kernel code that walks them (TLS and the per-CPU block).
    mov ecx, 0xC0000100             ; IA32_FS_BASE
    mov rax, [abs info_fs_base]
    wrmsr
    mov ecx, 0xC0000101             ; IA32_GS_BASE
    mov rax, [abs info_gs_base]
    wrmsr
    mov ecx, 0xC0000102             ; IA32_KERNEL_GS_BASE
    mov rax, [abs info_kgs_base]
    wrmsr

    ; Exact CR4/CR0 (the 32-bit writes were only the minimum to get here).
    mov rax, [abs info_cr4]
    mov cr4, rax
    mov rax, [abs info_cr0]
    mov cr0, rax

    ; XCR0 comes back only if the kernel actually uses the XSAVE feature set.
    test qword [abs info_cr4], (1 << 18)     ; OSXSAVE
    jz .no_xsave
    mov ecx, 0
    mov rax, [abs info_xcr0]
    mov rdx, [abs info_xcr0 + 8]
    xsetbv
.no_xsave:

    mov rsp, [abs info_rsp]
    mov rax, [abs info_rip]
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

; Info block.  The fill turns a trampoline that grows into INFO_BASE into a
; build error instead of a silently clobbered (power.c-filled) field.
align 16
info_block:
    times (INFO_BASE - WAKE_BASE - ($ - $$)) db 0
info_cr0:      dq 0
info_cr3:      dq 0
info_cr4:      dq 0
info_pat:      dq 0
info_xcr0:     dq 0
info_fs_base:  dq 0
info_gs_base:  dq 0
info_kgs_base: dq 0
info_rsp:      dq 0
info_rip:      dq 0
