/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_QUIRKS_H
#define CACT_QUIRKS_H

#include <stdint.h>

/*
 * Per-machine quirk blacklist.
 *
 * The single place in the tree where a hardware workaround is declared.  A
 * driver carries no machine-specific knowledge of its own: it asks for the
 * quirk bits that apply to the board it runs on (quirks_for_board()) or to a
 * PCI device it just bound (quirks_for_pci()), then acts on the bits it
 * understands.
 *
 * Adding a workaround for a new machine — or fixing one for a machine whose
 * firmware reports itself differently — is a one-row change in quirks.c.  No
 * driver source is touched.
 */

/* ACPI: do not evaluate \_SB.PCI0._OSC — the board's AML is broken. */
#define QUIRK_ACPI_DISABLE_OSC       (1u << 0)

/* xHCI: host controller needs the extra settle after reset. */
#define QUIRK_XHCI_INTEL_HOST        (1u << 1)

/* xHCI: a spurious host-system-error must not be allowed to reset the chipset. */
#define QUIRK_XHCI_SPURIOUS_REBOOT   (1u << 2)

/* Quirk bits for the board we are running on: the OR of every DMI-keyed row
 * that matches this machine's SMBIOS identity (0 when SMBIOS is unavailable or
 * no row matches). */
uint32_t quirks_for_board(void);

/* Quirk bits for a PCI device, given its vendor and device ID: the OR of every
 * PCI-keyed row that matches (0 when no row matches). */
uint32_t quirks_for_pci(uint16_t vendor, uint16_t device);

#endif
