#include "idt.h"
#include "kernel.h"
#include "memory.h"
#include "klib.h"
#include "gdt.h"

// Exception handlers (ISRs 0-31)
extern void isr0();  extern void isr1();  extern void isr2();
extern void isr3();  extern void isr4();  extern void isr5();
extern void isr6();  extern void isr7_nm_stub();  extern void isr8();
extern void isr9();  extern void isr10(); extern void isr11();
extern void isr12(); extern void isr13(); extern void isr14();
extern void isr15(); extern void isr16(); extern void isr17();
extern void isr18(); extern void isr19(); extern void isr20();
extern void isr21(); extern void isr22(); extern void isr23();
extern void isr24(); extern void isr25(); extern void isr26();
extern void isr27(); extern void isr28(); extern void isr29();
extern void isr30(); extern void isr31();

// IRQ handlers
extern void timer_isr();
extern void usb_isr();
extern void uhci_isr();
extern void ohci_isr();
extern void pci_isr();

static struct idt_entry idt[256];
static struct idt_ptr   idtp;

// Install a gate.  `ist` is the IST index the CPU switches to on entry; the
// ordinary case is 0, which means "keep using the current stack".
static void set_idt_gate_ist_internal(int n, uint64_t handler, uint8_t ist) {
    if (n < 0 || n > 255)
        return;
    idt[n].offset_low  = (uint16_t)(handler & 0xFFFF);
    idt[n].sel         = 0x08;              // Kernel code segment
    idt[n].ist         = ist & 0x7u;
    idt[n].flags       = 0x8E;              // Present, ring0, 64-bit interrupt gate
    idt[n].offset_mid  = (uint16_t)((handler >> 16) & 0xFFFF);
    idt[n].offset_high = (uint32_t)(handler >> 32);
    idt[n].zero        = 0;
}

void set_idt_gate(int n, uint64_t handler) {
    set_idt_gate_ist_internal(n, handler, 0);
}

void set_idt_gate_ist(int n, uint64_t handler, uint8_t ist) {
    set_idt_gate_ist_internal(n, handler, ist);
}

// Initialize IDT and load it
int init_idt(void) {
    idtp.limit = (sizeof(struct idt_entry) * 256) - 1;
    idtp.base  = (uint64_t)(uintptr_t)&idt;
    memory_set(&idt, 0, sizeof(struct idt_entry) * 256);

    // Install CPU exception gates (0-31).  #DF gets IST1 and NMI IST2: a double
    // fault is usually "the stack is what broke", so it must not run on it.
    set_idt_gate(0,  (uint64_t)(uintptr_t)isr0);
    set_idt_gate(1,  (uint64_t)(uintptr_t)isr1);
    set_idt_gate_ist(2, (uint64_t)(uintptr_t)isr2, IST_NMI);
    set_idt_gate(3,  (uint64_t)(uintptr_t)isr3);
    set_idt_gate(4,  (uint64_t)(uintptr_t)isr4);
    set_idt_gate(5,  (uint64_t)(uintptr_t)isr5);
    set_idt_gate(6,  (uint64_t)(uintptr_t)isr6);
    set_idt_gate(7,  (uint64_t)(uintptr_t)isr7_nm_stub);
    set_idt_gate_ist(8, (uint64_t)(uintptr_t)isr8, IST_DOUBLE_FAULT);
    set_idt_gate(9,  (uint64_t)(uintptr_t)isr9);
    set_idt_gate(10, (uint64_t)(uintptr_t)isr10);
    set_idt_gate(11, (uint64_t)(uintptr_t)isr11);
    set_idt_gate(12, (uint64_t)(uintptr_t)isr12);
    set_idt_gate(13, (uint64_t)(uintptr_t)isr13);
    set_idt_gate(14, (uint64_t)(uintptr_t)isr14);
    set_idt_gate(15, (uint64_t)(uintptr_t)isr15);
    set_idt_gate(16, (uint64_t)(uintptr_t)isr16);
    set_idt_gate(17, (uint64_t)(uintptr_t)isr17);
    set_idt_gate(18, (uint64_t)(uintptr_t)isr18);
    set_idt_gate(19, (uint64_t)(uintptr_t)isr19);
    set_idt_gate(20, (uint64_t)(uintptr_t)isr20);
    set_idt_gate(21, (uint64_t)(uintptr_t)isr21);
    set_idt_gate(22, (uint64_t)(uintptr_t)isr22);
    set_idt_gate(23, (uint64_t)(uintptr_t)isr23);
    set_idt_gate(24, (uint64_t)(uintptr_t)isr24);
    set_idt_gate(25, (uint64_t)(uintptr_t)isr25);
    set_idt_gate(26, (uint64_t)(uintptr_t)isr26);
    set_idt_gate(27, (uint64_t)(uintptr_t)isr27);
    set_idt_gate(28, (uint64_t)(uintptr_t)isr28);
    set_idt_gate(29, (uint64_t)(uintptr_t)isr29);
    set_idt_gate(30, (uint64_t)(uintptr_t)isr30);
    set_idt_gate(31, (uint64_t)(uintptr_t)isr31);

    // Install IRQ handlers (hardware interrupts)
    // ISA IRQ vectors 1-15: safe stubs (IOAPIC still routes here, any
    // stray interrupt must have a valid gate to avoid #GP).  Vector 0x20
    // (legacy IRQ0/PIT) is deliberately left unpopulated: IRQ0 is never
    // routed (masked in apic_init) and LINT0 is masked in lapic_init, so the
    // 8259 PIC cannot deliver it either.
    for (int i = 1; i < 16; i++)
        set_idt_gate(0x20 + i, (uint64_t)(uintptr_t)pci_isr);
    // ACPI SCI vector set dynamically by AcpiOsInstallInterruptHandler.

    // IOAPIC PCI INTx vectors (GSI 16+ mapped to 0xF0+)
    set_idt_gate(0xF0, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF1, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF2, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF3, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF4, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF5, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF6, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(0xF7, (uint64_t)(uintptr_t)pci_isr);
    // Reserved PCI range 0xF8-0xFD (0xF8/0xF9 become the C-state IPI gates),
    // the dedicated LAPIC timer vector 0xFE, and the spurious vector 0xFF.
    for (int i = 0xF8; i < LAPIC_TIMER_VECTOR; i++)
        set_idt_gate(i, (uint64_t)(uintptr_t)pci_isr);
    set_idt_gate(LAPIC_TIMER_VECTOR, (uint64_t)(uintptr_t)timer_isr);
    extern void spurious_apic_isr();
    set_idt_gate(0xFF, (uint64_t)(uintptr_t)spurious_apic_isr);

    // Load IDT into IDTR
    __asm__ __volatile__("lidt (%0)" : : "r"(&idtp));
    return 0;
}

// Reload the (shared) IDT on the current CPU. Called by AP startup.
void idt_reload(void) {
    __asm__ __volatile__("lidt (%0)" : : "r"(&idtp));
}

uint64_t idt_gate_handler(int n) {
    if (n < 0 || n > 255) return 0;
    return (uint64_t)idt[n].offset_low
         | ((uint64_t)idt[n].offset_mid << 16)
         | ((uint64_t)idt[n].offset_high << 32);
}
