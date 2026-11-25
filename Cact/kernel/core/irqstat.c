/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "irqstat.h"
#include "smp.h"
#include "klib.h"

static uint32_t     irq_cpu_counts[IRQSTAT_MAX_CPUS][IRQSTAT_VECTORS];
static char         irq_names[IRQSTAT_VECTORS][32];
static unsigned int irq_sci_vector = 0;   /* 0 = no SCI installed */

void irqstat_init(void) {
    memset(irq_cpu_counts, 0, sizeof(irq_cpu_counts));
    memset(irq_names, 0, sizeof(irq_names));
    irq_sci_vector = 0;

    irqstat_name(0xFE, "timer");
    irqstat_name(0xF8, "IPI halt");
    irqstat_name(0xF9, "IPI wake");
    irqstat_name(0xFF, "spurious");

    /* ISA IRQ 1-15 live at 0x21-0x2F, the IO-APIC PCI INTx pins (GSI 16-23)
     * at 0xF0-0xF7.  The vectors are fixed by init_idt(). */
    for (int irq = 1; irq <= 15; irq++) {
        char b[32];
        snprintf(b, sizeof(b), "IO-APIC  IRQ%d", irq);
        irqstat_name(0x20 + irq, b);
    }
    for (int i = 0; i < 8; i++)
        irqstat_name(0xF0 + i, "PCI INTx");
}

void irqstat_note(unsigned int vector) {
    if (vector >= IRQSTAT_VECTORS) return;
    int cpu = smp_self_cpu();
    if (cpu < 0 || cpu >= IRQSTAT_MAX_CPUS) cpu = 0;
    irq_cpu_counts[cpu][vector]++;
}

void irqstat_name(unsigned int vector, const char *name) {
    if (vector >= IRQSTAT_VECTORS || !name) return;
    int i = 0;
    for (; name[i] && i < 31; i++) irq_names[vector][i] = name[i];
    irq_names[vector][i] = '\0';
}

void irqstat_set_sci(unsigned int vector) {
    if (vector == 0 || vector >= IRQSTAT_VECTORS) return;
    irq_sci_vector = vector;
    irqstat_name(vector, "ACPI SCI");
}

void irqstat_note_sci(void) {
    if (irq_sci_vector) irqstat_note(irq_sci_vector);
}

uint32_t irqstat_cpu(unsigned int cpu, unsigned int vector) {
    if (cpu >= IRQSTAT_MAX_CPUS || vector >= IRQSTAT_VECTORS) return 0;
    return irq_cpu_counts[cpu][vector];
}

uint32_t irqstat_vector_total(unsigned int vector) {
    if (vector >= IRQSTAT_VECTORS) return 0;
    uint32_t t = 0;
    for (int c = 0; c < IRQSTAT_MAX_CPUS; c++) t += irq_cpu_counts[c][vector];
    return t;
}

uint64_t irqstat_total(void) {
    uint64_t t = 0;
    for (unsigned int v = 0; v < IRQSTAT_VECTORS; v++) t += irqstat_vector_total(v);
    return t;
}

const char *irqstat_name_of(unsigned int vector) {
    if (vector >= IRQSTAT_VECTORS) return "";
    return irq_names[vector];
}
