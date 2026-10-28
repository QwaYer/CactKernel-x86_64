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
extern irq_apic_eoi
extern xhci_irq_handler
extern spurious_apic_handler
extern energy_ipi_halt_handle
extern energy_ipi_wake_handle

section .text

; These vectors carry no frame the C side inspects — a driver that wants the
; interrupted context publishes it itself (see msidev_dispatch) — so they only
; have to keep the interrupted registers intact around the handler call.  The
; kernel data segments they used to load do not exist as a concern in long
; mode: DS/ES are ignored for data access.

%macro IRQ_BEGIN 0
    SWAPGS_IN
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
    call spurious_apic_handler
    IRQ_END

; ---------------------------------------------------------------------------
; Energy C-state controller IPIs (vectors 0xF8/0xF9): master -> worker halt /
; wakeup protocol. Dispatch handlers live in the Rust energy/cstate modules.
; ---------------------------------------------------------------------------
ipi_halt_isr:
    IRQ_BEGIN
    call energy_ipi_halt_handle
    call irq_apic_eoi
    IRQ_END

ipi_wake_isr:
    IRQ_BEGIN
    call energy_ipi_wake_handle
    call irq_apic_eoi
    IRQ_END
