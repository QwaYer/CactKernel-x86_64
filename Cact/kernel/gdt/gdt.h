#ifndef GDT_H
#define GDT_H

#include <stdint.h>

// GDT entry (8 bytes, packed)
struct gdt_entry {
    uint16_t limit_low;     // Bits 0-15 of segment limit
    uint16_t base_low;      // Bits 0-15 of base address
    uint8_t  base_middle;   // Bits 16-23 of base address
    uint8_t  access;        // Access flags (P, DPL, S, Type)
    uint8_t  granularity;   // Limit high (4 bits) + G, DB, L flags
    uint8_t  base_high;     // Bits 24-31 of base address
} __attribute__((packed));

// GDTR structure — 80 bits in long mode: limit plus a full 64-bit base
struct gdt_ptr {
    uint16_t limit;         // Size of GDT - 1
    uint64_t base;          // Linear address of GDT
} __attribute__((packed));

// 64-bit Task State Segment.  Long mode has no hardware task switching left to
// save registers for, so the whole register image is gone and what remains is
// the stack the CPU uses on a privilege change (rsp0) and the seven IST stacks.
// No ss0 either: the stack segment for a ring-3 -> ring-0 transition is fixed
// (null selector, base 0) and cannot be configured.  The I/O permission bitmap
// is unused, so iomap_base points past the limit.
struct tss_entry_struct {
    uint32_t reserved0;
    uint64_t rsp0;          // Stack for interrupts while the CPU is in ring 3
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist[7];        // IST1..IST7
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} __attribute__((packed));

/* IST indices: the exceptions that cannot run on whatever stack is current.
 * A #DF is usually "the stack is broken", so it must have one of its own. */
#define IST_DOUBLE_FAULT 1
#define IST_NMI          2

// GDT initialization
void init_gdt();
void set_gdt_gate(int num, uint64_t base, uint32_t limit, uint8_t access, uint8_t gran);
void write_tss(int num, uint64_t rsp0);
void tss_set_ist(int index, uint64_t rsp);

/* Per-task TLS lives in %fs: in long mode a segment's base is in an MSR
 * (IA32_FS_BASE), not in the descriptor, so gdt_write_tls() programs the MSR and
 * gdt_load_fs() only loads a selector.  The descriptor keeps its slot so the
 * selector value stays valid.  %gs is left for the per-CPU kernel state a later
 * phase reaches through swapgs. */
#define GDT_TSS_SLOT    5
#define GDT_TSS_SLOTS   2       /* a 64-bit TSS descriptor is 16 bytes */
#define GDT_TLS_SLOT    (GDT_TSS_SLOT + GDT_TSS_SLOTS * 64)   /* TSS_SLOT + 2 * MAX_CPUS */
#define GDT_TLS_SEL     ((uint16_t)(GDT_TLS_SLOT * 8 + 3))    /* RPL 3: ring 3 may load it */
#define GDT_ENTRIES     (GDT_TLS_SLOT + 1)

/* Rewrite the per-task %fs base (the boot GDT; APs program their own MSR). */
void gdt_write_tls(uint64_t base);
/* Load a data selector into %fs. */
extern void gdt_load_fs(uint16_t sel);

// External assembly functions
extern struct tss_entry_struct tss_entry;
extern void gdt_flush(uint64_t);  // Load GDTR and reload CS/SS
extern void tss_flush(void);      // Load Task Register (LTR)

#endif
