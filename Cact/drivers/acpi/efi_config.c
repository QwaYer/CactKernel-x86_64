/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/* EFI configuration table lookup — see efi_config.h. */

#include "kernel.h"
#include "klib.h"
#include "cact_acpi.h"
#include "multiboot2.h"
#include "efi_config.h"

#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249ull  /* "IBI SYST" */

/* Enough for any real firmware: an EDK2 system table carries a few dozen
 * entries at most.  Guards against walking a bogus count. */
#define EFI_CONFIG_TABLE_MAX 256u

/* EFI table header: 24 bytes shared by every EFI table structure. */
struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} __attribute__((packed));

/* Only the tail of EFI_SYSTEM_TABLE is needed to reach the configuration
 * table; the console/boot-services pointers in between are unread.  Offsets
 * are fixed by the UEFI spec for the 64-bit architecture (sizeof = 120). */
struct efi_system_table {
    struct efi_table_header hdr;            /* 0x00 */
    uint64_t firmware_vendor;               /* 0x18 */
    uint32_t firmware_revision;             /* 0x20 */
    uint8_t  reserved[4];                   /* 0x24 */
    uint64_t console_in_handle;             /* 0x28 */
    uint64_t console_in;                    /* 0x30 */
    uint64_t console_out_handle;            /* 0x38 */
    uint64_t console_out;                   /* 0x40 */
    uint64_t std_err_handle;                /* 0x48 */
    uint64_t std_err;                       /* 0x50 */
    uint64_t runtime_services;              /* 0x58 */
    uint64_t boot_services;                 /* 0x60 */
    uint64_t number_of_table_entries;       /* 0x68 */
    uint64_t configuration_table;           /* 0x70 */
} __attribute__((packed));

_Static_assert(sizeof(struct efi_system_table) == 120,
               "EFI_SYSTEM_TABLE is 120 bytes on the 64-bit ABI");

struct efi_config_table_entry {
    uint8_t  guid[16];
    uint64_t table;
} __attribute__((packed));

const uint8_t EFI_GUID_ACPI20[16] = {
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11,
    0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81
};
const uint8_t EFI_GUID_ACPI[16] = {
    0x30, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11,
    0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d
};
const uint8_t EFI_GUID_SMBIOS3[16] = {
    0x44, 0x15, 0xfd, 0xf2, 0x94, 0x97, 0x2c, 0x4a,
    0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94
};
const uint8_t EFI_GUID_SMBIOS[16] = {
    0x31, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11,
    0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d
};

int efi_config_lookup(const uint8_t guid[16], uint64_t *phys_out)
{
    if (!guid || !phys_out)
        return 0;
    *phys_out = 0;

    /* No EFI64/EFI32 tag: a legacy/CSM boot, nothing to look up here. */
    if (mb2_efi_systab == 0)
        return 0;

    /* The temp-map window is created in AcpiOsInitialize(); before that the
     * base VA is still 0 and mapping would clobber low memory. */
    if (!acpi_temp_map_ready())
        return 0;

    struct efi_system_table *st =
        acpi_temp_map(mb2_efi_systab, sizeof(struct efi_system_table));
    if (!st)
        return 0;

    if (st->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE) {
        static int warned;
        if (!warned) {
            warned = 1;
            pr_warn("%s: EFI system table at 0x%llx has signature 0x%llx — "
                    "not an EFI system table, ignoring\n", "efi-config",
                    (unsigned long long)mb2_efi_systab,
                    (unsigned long long)st->hdr.signature);
        }
        acpi_temp_unmap(st, sizeof(struct efi_system_table));
        return 0;
    }

    uint64_t nr  = st->number_of_table_entries;
    uint64_t cfg = st->configuration_table;
    acpi_temp_unmap(st, sizeof(struct efi_system_table));

    if (cfg == 0 || nr == 0 || nr > EFI_CONFIG_TABLE_MAX)
        return 0;

    uint32_t bytes = (uint32_t)(nr * sizeof(struct efi_config_table_entry));
    struct efi_config_table_entry *tbl = acpi_temp_map(cfg, bytes);
    if (!tbl)
        return 0;

    int found = 0;
    for (uint64_t i = 0; i < nr; i++) {
        if (memcmp(tbl[i].guid, guid, 16) == 0 && tbl[i].table != 0) {
            *phys_out = tbl[i].table;
            found = 1;
            break;
        }
    }

    acpi_temp_unmap(tbl, bytes);
    return found;
}
