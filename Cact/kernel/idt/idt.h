#ifndef IDT_H
#define IDT_H

#include <stdint.h>

// IDT entry (16 bytes in long mode): the handler address is a full 64-bit
// linear address, split 16/16/32 around the selector and the attributes, and
// the byte that used to be "always zero" is now the IST index.
struct idt_entry {
    uint16_t offset_low;   // Handler address bits 15..0
    uint16_t sel;          // Code segment selector (kernel CS = 0x08)
    uint8_t  ist;          // 0 = stay on the current stack, 1..7 = IST index
    uint8_t  flags;        // Gate type, DPL, present flag
    uint16_t offset_mid;   // Handler address bits 31..16
    uint32_t offset_high;  // Handler address bits 63..32
    uint32_t zero;         // Reserved, must be 0
} __attribute__((packed));

// IDTR structure (80-bit pseudo-descriptor)
struct idt_ptr {
    uint16_t limit;        // Size of IDT - 1
    uint64_t base;         // Linear address of IDT
} __attribute__((packed));

void set_idt_gate(int n, uint64_t handler);
/* Same, but on IST `ist` — for the exceptions that cannot trust the stack they
 * interrupted (see IST_* in gdt.h). */
void set_idt_gate_ist(int n, uint64_t handler, uint8_t ist);
int  init_idt(void);
void idt_reload(void);

/* Handler address currently installed in gate `n` (0 if out of range). */
uint64_t idt_gate_handler(int n);

#endif
