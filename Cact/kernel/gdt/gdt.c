#include "gdt.h"
#include "klib.h"
#include "kernel.h"

// GDT: null, kernel code, data, user code, data, the BSP TSS (two slots — a
// 64-bit TSS descriptor is 16 bytes), then the per-CPU TSS slots a per-CPU GDT
// reserves (two slots each) and the TLS descriptor at GDT_TLS_SLOT.  The array
// has to reach GDT_TLS_SLOT so the TLS selector means the same thing on the BSP
// as on an AP.
struct gdt_entry gdt[GDT_ENTRIES];
struct gdt_ptr   gp;
struct tss_entry_struct tss_entry;
uint8_t early_kernel_stack[4096] __attribute__((aligned(16)));

// #DF and NMI get stacks of their own: the current one may be exactly what is
// broken when they arrive.
static uint8_t double_fault_stack[8192] __attribute__((aligned(16)));
static uint8_t nmi_stack[8192] __attribute__((aligned(16)));

// Set GDT entry at index 'num' with base, limit, access flags, and granularity
void set_gdt_gate(int num, uint64_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[num].base_low    = (uint16_t)(base & 0xFFFF);
    gdt[num].base_middle = (uint8_t)((base >> 16) & 0xFF);
    gdt[num].base_high   = (uint8_t)((base >> 24) & 0xFF);
    gdt[num].limit_low   = (uint16_t)(limit & 0xFFFF);
    gdt[num].granularity = (uint8_t)((limit >> 16) & 0x0F);
    gdt[num].granularity |= gran & 0xF0;  // Merge granularity bits (G, DB, L)
    gdt[num].access      = access;
}

// Write the BSP's TSS descriptor: a system descriptor of type 9 spanning two
// GDT slots, whose second slot carries bits 63..32 of the base.
void write_tss(int num, uint64_t rsp0) {
    uint64_t base  = (uint64_t)(uintptr_t)&tss_entry;
    uint32_t limit = sizeof(tss_entry) - 1;

    memory_set(&tss_entry, 0, sizeof(tss_entry));
    tss_entry.rsp0       = rsp0;                // Kernel stack for ring 3 -> ring 0
    tss_entry.iomap_base = sizeof(tss_entry);   // No I/O permission bitmap

    struct gdt_entry *lo = &gdt[num];
    struct gdt_entry *hi = &gdt[num + 1];

    lo->limit_low   = (uint16_t)(limit & 0xFFFF);
    lo->base_low    = (uint16_t)(base & 0xFFFF);
    lo->base_middle = (uint8_t)((base >> 16) & 0xFF);
    lo->access      = 0x89;   // Present, DPL 0, system, type 9 = available 64-bit TSS
    lo->granularity = (uint8_t)((limit >> 16) & 0x0F);   // G=0: the limit is in bytes
    lo->base_high   = (uint8_t)((base >> 24) & 0xFF);

    hi->limit_low   = (uint16_t)((base >> 32) & 0xFFFF);
    hi->base_low    = (uint16_t)((base >> 48) & 0xFFFF);
    hi->base_middle = 0;
    hi->access      = 0;
    hi->granularity = 0;
    hi->base_high   = 0;
}

void tss_set_ist(int index, uint64_t rsp) {
    if (index < 1 || index > 7)
        return;
    tss_entry.ist[index - 1] = rsp;
}

// Initialize GDT: null, kernel code/data, user code/data, TSS, TLS
void init_gdt() {
    gp.limit = (sizeof(struct gdt_entry) * GDT_ENTRIES) - 1;
    gp.base  = (uint64_t)(uintptr_t)&gdt;

    // Null segment (required by x86)
    set_gdt_gate(0, 0, 0, 0, 0);

    // Kernel code: L=1 makes it a 64-bit code segment (D must be 0), G=1 so the
    // limit still spans the whole address space.
    set_gdt_gate(1, 0, 0xFFFFF, 0x9A, 0xAF);
    // Kernel data segment: G=1, D=1 (ignored for data in long mode)
    set_gdt_gate(2, 0, 0xFFFFF, 0x92, 0xCF);
    // User code (L=1) and data
    set_gdt_gate(3, 0, 0xFFFFF, 0xFA, 0xAF);
    set_gdt_gate(4, 0, 0xFFFFF, 0xF2, 0xCF);

    write_tss(GDT_TSS_SLOT,
              (uint64_t)(uintptr_t)early_kernel_stack + sizeof(early_kernel_stack));

    tss_set_ist(IST_DOUBLE_FAULT,
                (uint64_t)(uintptr_t)double_fault_stack + sizeof(double_fault_stack));
    tss_set_ist(IST_NMI,
                (uint64_t)(uintptr_t)nmi_stack + sizeof(nmi_stack));

    // The per-task TLS descriptor: a ring-3 data segment whose slot is what the
    // selector names.  Its base is done through IA32_FS_BASE, not the
    // descriptor (see gdt_write_tls), so it is written as zero.
    set_gdt_gate(GDT_TLS_SLOT, 0, 0xFFFFF, 0xF2, 0xCF);

    // Load GDT into GDTR and reload segment registers
    gdt_flush((uint64_t)(uintptr_t)&gp);

    // Load Task Register with TSS selector
    tss_flush();
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

#define IA32_FS_BASE 0xC0000100u

void gdt_write_tls(uint64_t base) {
    wrmsr(IA32_FS_BASE, base);
}
