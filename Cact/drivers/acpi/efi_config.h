#ifndef CACT_EFI_CONFIG_H
#define CACT_EFI_CONFIG_H

#include <stdint.h>

/*
 * EFI configuration table access.
 *
 * UEFI firmware does not put the firmware tables in the F-segment the way a
 * legacy BIOS does; it publishes them from the EFI configuration table instead
 * (a GUID -> physical address list hanging off the EFI system table).  GRUB
 * hands us the physical address of that system table in the Multiboot2 EFI64
 * tag, so this is how a UEFI-booted machine is reached:
 *
 *   SMBIOS3_TABLE_GUID -> 64-bit SMBIOS entry point   (dmi.c)
 *   SMBIOS_TABLE_GUID  -> 32-bit SMBIOS entry point   (dmi.c)
 *   ACPI_20_TABLE_GUID -> RSDP, ACPI 2.0+             (osl.c)
 *   ACPI_TABLE_GUID    -> RSDP, ACPI 1.0 fallback     (osl.c)
 *
 * The tables live in firmware memory that the direct map does not cover, so
 * both the system table and the entry array are read through the ACPI OSL
 * temporary-map window (that shared window is why this lives under drivers/
 * acpi).  efi_config_lookup() returns 0 when the machine was not booted under
 * UEFI, when the window is not up yet, or when the GUID is not published.
 */
int efi_config_lookup(const uint8_t guid[16], uint64_t *phys_out);

/* GUIDs in EFI wire order (first three fields little-endian). */
extern const uint8_t EFI_GUID_ACPI20[16];
extern const uint8_t EFI_GUID_ACPI[16];
extern const uint8_t EFI_GUID_SMBIOS3[16];
extern const uint8_t EFI_GUID_SMBIOS[16];

#endif
