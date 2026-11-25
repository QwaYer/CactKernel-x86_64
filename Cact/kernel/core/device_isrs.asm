; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 CactOS Project

[bits 64]
%include "context.inc"

global timer_isr
global xhci_isr
global acpi_sci_isr
global pci_isr
global spurious_apic_isr
global ipi_halt_isr
global ipi_wake_isr

extern acpi_sci_callback
extern on_timer_tick
extern timer_tick
extern timer_account_tick
extern irq_apic_eoi
extern xhci_irq_handler
extern spurious_apic_handler
extern energy_ipi_halt_handle
extern energy_ipi_wake_handle
extern irqstat_note
extern irqstat_note_sci

section .text

; These vectors carry no frame the C side inspects — a driver that wants the
; interrupted context publishes it itself (see msidev_dispatch) — so they only
; have to keep the interrupted registers intact around the handler call.  The
; kernel data segments they used to load do not exist as a concern in long
; mode: DS/ES are ignored for data access.

%macro IRQ_BEGIN 0
    SWAPGS_IN 8
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16
%endmacro

%macro IRQ_END 0
    mov rsp, rbp
    ISR_RESTORE
    SWAPGS_OUT
    iretq
%endmacro

timer_isr:
    IRQ_BEGIN
    mov edi, [rbp + 144]        ; interrupted CS (RPL 3 => user time)
    call timer_account_tick
    call timer_tick
    call irq_apic_eoi
    call on_timer_tick
    IRQ_END

xhci_isr:
    IRQ_BEGIN
    call xhci_irq_handler
    call irq_apic_eoi
    IRQ_END

acpi_sci_isr:
    IRQ_BEGIN
    call irqstat_note_sci
    call acpi_sci_callback
    call irq_apic_eoi
    IRQ_END

; ---------------------------------------------------------------------------
; Generic PCI INTx ISR (vectors 0xF0+). Just EOIs.
; ---------------------------------------------------------------------------
pci_isr:
    IRQ_BEGIN
    call irq_apic_eoi
    IRQ_END

; ---------------------------------------------------------------------------
; APIC spurious interrupt handler.  The spec says a spurious delivery sets no
; in-service bit and therefore needs no EOI, but this hardware does set the
; bit: left in service it pins PPR at 0xF0 and blocks the LAPIC timer (0xFE)
; along with every MSI-X vector (0x30-0xEF).  The handler therefore retires
; the bit itself — see spurious_apic_handler().
; ---------------------------------------------------------------------------
spurious_apic_isr:
    IRQ_BEGIN
    mov edi, 0xFF
    call irqstat_note
    call spurious_apic_handler
    IRQ_END

; ---------------------------------------------------------------------------
; Energy C-state controller IPIs (vectors 0xF8/0xF9): master -> worker halt /
; wakeup protocol. Dispatch handlers live in the Rust energy/cstate modules.
; ---------------------------------------------------------------------------
ipi_halt_isr:
    IRQ_BEGIN
    mov edi, 0xF8
    call irqstat_note
    call energy_ipi_halt_handle
    call irq_apic_eoi
    IRQ_END

ipi_wake_isr:
    IRQ_BEGIN
    mov edi, 0xF9
    call irqstat_note
    call energy_ipi_wake_handle
    call irq_apic_eoi
    IRQ_END

; ---------------------------------------------------------------------------
; Generic ISA-IRQ / PCI-INTx stubs (vectors 0x21-0x2F and 0xF0-0xF7).  The
; shared pci_isr could not be counted per line because it never learns which
; vector fired; these push the vector and jump to a common dispatcher that
; notes it for /proc/interrupts and EOIs — the same work pci_isr did.
; ---------------------------------------------------------------------------
%macro irq_count_entry 1
global irq_count_stub_%1
irq_count_stub_%1:
    SWAPGS_IN 8
    push qword 0
    push qword %1
    jmp irq_count_common
%endmacro

%assign irq_count_v 0x21
%rep 15
irq_count_entry irq_count_v
%assign irq_count_v irq_count_v+1
%endrep

%assign irq_count_v 0xF0
%rep 8
irq_count_entry irq_count_v
%assign irq_count_v irq_count_v+1
%endrep

irq_count_common:
    ISR_SAVE
    mov rbp, rsp
    and rsp, -16
    mov edi, [rbp + 120]        ; int_no, below the fifteen saved registers
    call irqstat_note
    call irq_apic_eoi
    mov rsp, rbp
    ISR_RESTORE
    add rsp, 16
    SWAPGS_OUT
    iretq

section .rodata
; Addresses of the counting stubs, in vector order: entry i is vector 0x21+i
; (i < 15) then 0xF0+(i-15) (i < 23).
global irq_count_stub_table
irq_count_stub_table:
%assign irq_count_v 0x21
%rep 15
    dq irq_count_stub_%+irq_count_v
%assign irq_count_v irq_count_v+1
%endrep
%assign irq_count_v 0xF0
%rep 8
    dq irq_count_stub_%+irq_count_v
%assign irq_count_v irq_count_v+1
%endrep
