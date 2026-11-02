/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * Per-machine quirk blacklist — the one place a hardware workaround is
 * declared.
 *
 * A row matches either a machine (by SMBIOS vendor / product substring, via
 * dmi_matches()) or a PCI device (by vendor / device ID).  Both DMI fields are
 * substrings, so a row may pin a whole board family or a single part; a
 * machine or device may match several rows, and their bits are ORed together.
 *
 * Nothing here is board- or part-specific *code*: the drivers only read the
 * bits they define in quirks.h.
 */

#include "quirks.h"
#include "dmi.h"
#include "kernel.h"

enum quirk_match_kind {
    QUIRK_MATCH_DMI,   /* SMBIOS system vendor / product */
    QUIRK_MATCH_PCI,   /* PCI vendor / device ID */
};

struct quirk_entry {
    enum quirk_match_kind kind;
    union {
        struct { const char *vendor; const char *product; } dmi;
        struct { uint16_t vendor; uint16_t device; }        pci;
    } m;
    uint32_t    flags;   /* OR of QUIRK_* bits to apply */
    const char *note;    /* what the row is, for the log line */
};

#define QUIRK_BOARD(vendor, product, bits, text)                       \
    { .kind = QUIRK_MATCH_DMI,                                         \
      .m.dmi = { (vendor), (product) },                                \
      .flags = (bits), .note = (text) }

#define QUIRK_DEVICE(vendor, device, bits, text)                       \
    { .kind = QUIRK_MATCH_PCI,                                         \
      .m.pci = { (vendor), (device) },                                 \
      .flags = (bits), .note = (text) }

static const struct quirk_entry quirk_blacklist[] = {
    /* HP 290 G1 SFF / microtower (Intel B360, BIOS F.31): evaluating
     * \_SB.PCI0._OSC runs broken AML that references an unresolvable symbol
     * ([\_SB.PCI0._OSC.TBTS]) and trips ACPICA.  Every other board evaluates
     * _OSC normally.  SMBIOS reports this board as vendor "HP" / product
     * containing "290 G1"; a machine that spells its vendor differently gets
     * its own row here rather than a change in any driver. */
    QUIRK_BOARD("HP", "290 G1", QUIRK_ACPI_DISABLE_OSC,
                "HP 290 G1: broken _OSC AML"),

    /* Intel 300-series PCH (B360/H370/Z390) + Cannon Lake-LP: a spurious host
     * system error would trip a chipset reboot — keep HSEE masked. */
    QUIRK_DEVICE(0x8086, 0xA36D,
                 QUIRK_XHCI_INTEL_HOST | QUIRK_XHCI_SPURIOUS_REBOOT,
                 "Intel 300-series xHCI"),
    QUIRK_DEVICE(0x8086, 0x9DED,
                 QUIRK_XHCI_INTEL_HOST | QUIRK_XHCI_SPURIOUS_REBOOT,
                 "Intel 300-series xHCI"),
    QUIRK_DEVICE(0x8086, 0x8CA2,
                 QUIRK_XHCI_INTEL_HOST | QUIRK_XHCI_SPURIOUS_REBOOT,
                 "Intel 300-series xHCI"),
};

#define QUIRK_COUNT (sizeof(quirk_blacklist) / sizeof(quirk_blacklist[0]))

uint32_t quirks_for_board(void)
{
    uint32_t flags = 0;

    for (unsigned int i = 0; i < QUIRK_COUNT; i++) {
        const struct quirk_entry *e = &quirk_blacklist[i];

        if (e->kind != QUIRK_MATCH_DMI)
            continue;
        if (!dmi_matches(e->m.dmi.vendor, e->m.dmi.product))
            continue;

        pr_notice("%s: applied — %s (0x%x)\n", "quirk", e->note,
                  (unsigned)e->flags);
        flags |= e->flags;
    }
    return flags;
}

uint32_t quirks_for_pci(uint16_t vendor, uint16_t device)
{
    uint32_t flags = 0;

    for (unsigned int i = 0; i < QUIRK_COUNT; i++) {
        const struct quirk_entry *e = &quirk_blacklist[i];

        if (e->kind != QUIRK_MATCH_PCI)
            continue;
        if (e->m.pci.vendor != vendor || e->m.pci.device != device)
            continue;

        pr_notice("%s: applied — %s (%04x:%04x, 0x%x)\n", "quirk", e->note,
                  (unsigned)vendor, (unsigned)device, (unsigned)e->flags);
        flags |= e->flags;
    }
    return flags;
}
