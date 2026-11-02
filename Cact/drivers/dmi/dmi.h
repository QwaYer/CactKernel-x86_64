/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_DMI_H
#define CACT_DMI_H

/*
 * SMBIOS/DMI board identification.
 *
 * Firmware-provided SMBIOS tables are the only reliable way to tell which
 * physical board we are running on; PCI/ACPI only identify chipsets and
 * AML blobs, not the product.
 *
 * This layer only *reports* identity — it knows no board by name.  A caller
 * that cares about a particular machine asks dmi_matches() with the vendor and
 * product substrings it is looking for; the decision of what workaround to
 * apply to that board lives in the quirk blacklist (drivers/quirks).
 *
 * dmi_matches() returns 1 when SMBIOS identifies a board whose system vendor
 * and product name both contain the given substrings (a NULL argument matches
 * any value), and 0 otherwise — including any machine that does not expose
 * SMBIOS at all.
 */
int dmi_matches(const char *vendor_sub, const char *product_sub);

/*
 * Raw SMBIOS identity (system vendor / product name / BIOS version) as the
 * firmware reported it, for /proc/dmi.  Each returns a NUL-terminated string
 * that lives for the kernel lifetime, or NULL when the firmware exposes no
 * SMBIOS.  The first call runs the one-shot probe, so no separate init step is
 * needed.
 */
const char *dmi_vendor_string(void);
const char *dmi_product_string(void);
const char *dmi_bios_string(void);

#endif
