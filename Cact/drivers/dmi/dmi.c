/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * SMBIOS/DMI probing (board identification).
 *
 * The SMBIOS entry point comes from one of two places, depending on how the
 * machine was booted:
 *
 *   UEFI    the firmware publishes it through the EFI configuration table
 *           (SMBIOS3_TABLE_GUID, else SMBIOS_TABLE_GUID) — see efi_config.h.
 *           UEFI firmware does *not* keep the entry point in the F-segment, so
 *           a scan limited to that range finds nothing at all on such a
 *           machine.
 *   legacy  the entry point lives in the firmware BIOS area between 0xF0000
 *           and 0xFFFFF, exactly like the ACPI RSDP.
 *
 * Both entry point formats are accepted:
 *
 *   2.1+  anchor "_SM_"  (32-bit structure table address, 16-bit length)
 *   3.x   anchor "_SM3_" (64-bit table address; length from the maximum
 *         structure-table size field)
 *
 * Structure types 0 (BIOS information) and 1 (system information) are walked
 * out of the table so the vendor, product name and BIOS version can be matched
 * against the firmware a board quirk was written for.
 */

#include "kernel.h"
#include "klib.h"
#include "cact_acpi.h"
#include "efi_config.h"
#include "dmi.h"

#define DMI_STR_MAX         64u

#define SMBIOS_SCAN_START   0x000F0000u
#define SMBIOS_SCAN_LEN     0x00010000u   /* 0xF0000..0xFFFFF */
#define SMBIOS_SCAN_STEP    16u
#define SMBIOS_EPS_MAX      32u           /* longest entry point structure */
/* Mapping cap for the structure table (not a validity test): it bounds how
 * much of the shared temp-map window one probe can claim.  Types 0 and 1 sit
 * at the front of the table, so a firmware that reports more than this is
 * still identified from the first 64 KiB. */
#define SMBIOS_TABLE_MAX    0x00010000u

#define SMBIOS_END_TYPE     127u

/* Entry point candidates tried in order; a handful covers every board seen
 * (EFI 64/32-bit, then the F-segment scan). */
#define DMI_MAX_CAND        8

static char dmi_vendor[DMI_STR_MAX];
static char dmi_product[DMI_STR_MAX];
static char dmi_bios_version[DMI_STR_MAX];
static int  dmi_state;                    /* 0 = unprobed, 1 = ok, -1 = absent */

static int dmi_checksum(const uint8_t *p, unsigned int n)
{
    unsigned int sum = 0;
    for (unsigned int i = 0; i < n; i++)
        sum += p[i];
    return (sum & 0xFF) == 0;
}

static uint16_t dmi_get16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t dmi_get32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t dmi_get64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int dmi_prefix(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s++ != *prefix++)
            return 0;
    }
    return 1;
}

static int dmi_contains(const char *haystack, const char *needle)
{
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*n && *h && *h == *n) {
            h++;
            n++;
        }
        if (!*n)
            return 1;
    }
    return 0;
}

/* Copy the idx-th string (1-based) of a structure into @out.  Index 0 or a
 * missing string yields an empty string.  Reads never leave the table. */
static void dmi_struct_string(const uint8_t *st, const uint8_t *end,
                              uint8_t idx, char *out, uint32_t cap)
{
    const uint8_t *s = st + st[1];
    uint32_t n = 0;

    out[0] = '\0';
    if (idx == 0 || s >= end || cap == 0)
        return;

    for (uint8_t i = 1; i < idx; i++) {
        while (s < end && *s)
            s++;
        if (s >= end)
            return;
        s++;                                /* skip the string's NUL */
    }

    while (s < end && *s && n + 1 < cap) {
        out[n++] = (char)*s;
        s++;
    }
    out[n] = '\0';
}

/* Advance past the formatted area and the NUL-terminated string set (ending
 * in a double NUL), rounded up to the next word boundary. */
static const uint8_t *dmi_next_structure(const uint8_t *st, const uint8_t *end)
{
    const uint8_t *q = st + st[1];
    if (q >= end)
        return end;

    while (q < end) {
        if (*q == 0) {
            q++;
            break;
        }
        while (q < end && *q != 0)
            q++;
        if (q >= end)
            break;
        q++;                                /* skip the string's NUL */
    }
    if (q >= end)
        return end;

    q = (const uint8_t *)(((uintptr_t)q + 1u) & ~(uintptr_t)1u);
    return (q > end) ? end : q;
}

/* A located SMBIOS entry point: where its structure table is, how long the
 * firmware says that table is, and which of the two formats carried it. */
struct dmi_eps {
    uint64_t table;      /* physical address of the structure table */
    uint32_t len;        /* structure table length in bytes */
    int      smbios3;    /* 64-bit (SMBIOS 3.x) entry point */
};

/* Validate one entry point structure (@p, 32 bytes) and pull the structure
 * table address out of it.  Returns 1 when accepted, 0 otherwise. */
static int dmi_parse_eps(const uint8_t *p, struct dmi_eps *out)
{
    uint8_t len;

    if (p[0] != '_' || p[1] != 'S' || p[2] != 'M')
        return 0;

    if (p[3] == '3' && p[4] == '_') {
        /* SMBIOS 3.x: "_SM3_" anchor, checksum at 0x05, entry point length at
         * 0x06, maximum structure-table size at 0x0C, 64-bit table address at
         * 0x10.  The table address is genuinely 64-bit — firmware is free to
         * keep the table above 4 GiB, and the mapping window accepts it. */
        len = p[6];
        if (len < 0x18 || len > SMBIOS_EPS_MAX || !dmi_checksum(p, len))
            return 0;

        uint32_t size = dmi_get32(p + 0x0C);
        uint64_t addr = dmi_get64(p + 0x10);
        if (addr == 0 || size == 0)
            return 0;

        out->table   = addr;
        out->len     = size;
        out->smbios3 = 1;
        return 1;
    }

    if (p[3] == '_') {
        /* SMBIOS 2.1+: "_SM_" anchor, entry point length at 0x05 and the
         * legacy DMI header ("_DMI_") embedded at 0x10. */
        len = p[5];
        if (len < 0x1E || len > SMBIOS_EPS_MAX || !dmi_checksum(p, len))
            return 0;

        if (p[0x10] != '_' || p[0x11] != 'D' || p[0x12] != 'M' ||
            p[0x13] != 'I' || p[0x14] != '_')
            return 0;
        if (!dmi_checksum(p + 0x10, 15))
            return 0;

        uint16_t size = dmi_get16(p + 0x16);
        uint32_t addr = dmi_get32(p + 0x18);
        if (addr == 0 || size == 0)
            return 0;

        out->table   = addr;
        out->len     = size;
        out->smbios3 = 0;
        return 1;
    }

    return 0;
}

/* Collect the entry point candidates, most preferred first: the EFI
 * configuration table (64-bit form first, per SMBIOS 3.0 §5.2), then every
 * 16-byte-aligned candidate in the F-segment, 64-bit ones before 32-bit ones.
 * Up to @max candidates are written; returns the number found. */
static int dmi_locate(struct dmi_eps *out, const char **src, int max)
{
    int n = 0;
    uint8_t buf[SMBIOS_EPS_MAX];
    uint64_t phys = 0;

    /* 1. EFI configuration table — the only place UEFI publishes this. */
    for (int i = 0; i < 2 && n < max; i++) {
        const uint8_t *guid = i == 0 ? EFI_GUID_SMBIOS3 : EFI_GUID_SMBIOS;
        const char    *name = i == 0 ? "EFI/SMBIOS3" : "EFI/SMBIOS";

        if (!efi_config_lookup(guid, &phys))
            continue;

        void *m = acpi_temp_map(phys, SMBIOS_EPS_MAX);
        if (!m) {
            pr_warn("%s: EFI %s entry point at 0x%llx does not map\n",
                    "smbios", name, (unsigned long long)phys);
            continue;
        }
        memcpy(buf, m, SMBIOS_EPS_MAX);
        acpi_temp_unmap(m, SMBIOS_EPS_MAX);

        if (dmi_parse_eps(buf, &out[n])) {
            src[n++] = name;
        } else {
            pr_warn("%s: EFI %s entry point at 0x%llx did not validate\n",
                    "smbios", name, (unsigned long long)phys);
        }
    }

    /* 2. F-segment scan (legacy BIOS boot, or a UEFI machine that also keeps a
     *    legacy copy).  The whole window is scanned rather than stopping at
     *    the first structurally valid entry point: firmware that ships a stale
     *    or unreadable legacy entry point next to a working 64-bit one must not
     *    have the latter shadowed. */
    void *seg = acpi_temp_map(SMBIOS_SCAN_START, SMBIOS_SCAN_LEN);
    if (!seg)
        return n;

    const uint8_t *p = seg;

    for (int pass = 0; pass < 2 && n < max; pass++) {
        for (uint32_t off = 0; off + SMBIOS_EPS_MAX <= SMBIOS_SCAN_LEN;
             off += SMBIOS_SCAN_STEP) {
            if (p[off] != '_' || p[off + 1] != 'S' || p[off + 2] != 'M')
                continue;
            if ((p[off + 3] == '3') != (pass == 0))
                continue;

            memcpy(buf, p + off, SMBIOS_EPS_MAX);
            if (dmi_parse_eps(buf, &out[n])) {
                src[n] = out[n].smbios3 ? "F-segment _SM3_" : "F-segment _SM_";
                n++;
                break;                       /* at most one per pass */
            }
        }
    }

    acpi_temp_unmap(seg, SMBIOS_SCAN_LEN);
    return n;
}

static int dmi_parse_table(const uint8_t *table, uint32_t len)
{
    const uint8_t *p = table;
    const uint8_t *end = table + len;
    int got_type0 = 0, got_type1 = 0;

    while ((uint32_t)(end - p) >= 4u) {
        uint8_t type = p[0];
        uint8_t fmt  = p[1];

        if (type == SMBIOS_END_TYPE || fmt < 4u || (uint32_t)(end - p) < fmt)
            break;

        if (type == 1 && fmt >= 6u && !got_type1) {
            /* System information: 0x04 manufacturer, 0x05 product name. */
            dmi_struct_string(p, end, p[4], dmi_vendor, DMI_STR_MAX);
            dmi_struct_string(p, end, p[5], dmi_product, DMI_STR_MAX);
            got_type1 = 1;
        }
        if (type == 0 && fmt >= 6u && !got_type0) {
            /* BIOS information: 0x05 BIOS version. */
            dmi_struct_string(p, end, p[5], dmi_bios_version, DMI_STR_MAX);
            got_type0 = 1;
        }
        if (got_type1 && got_type0)
            break;

        p = dmi_next_structure(p, end);
        if (p >= end)
            break;
    }

    return got_type1 && dmi_product[0] != '\0' && dmi_vendor[0] != '\0';
}

static int dmi_collect_once(void)
{
    if (dmi_state != 0)
        return dmi_state;

    /* The probe reads firmware memory through the ACPI OSL window, which only
     * exists once AcpiOsInitialize() has run.  Report "not yet" without
     * caching it, so a late caller still gets a real answer. */
    if (!acpi_temp_map_ready())
        return 0;

    dmi_state = -1;

    struct dmi_eps eps[DMI_MAX_CAND];
    const char *src[DMI_MAX_CAND];
    int n = dmi_locate(eps, src, DMI_MAX_CAND);

    for (int i = 0; i < n; i++) {
        uint32_t len = eps[i].len;
        if (len > SMBIOS_TABLE_MAX) {
            pr_info("%s: %s table is %u B — reading the first %u B\n",
                    "smbios", src[i], (unsigned)len, (unsigned)SMBIOS_TABLE_MAX);
            len = SMBIOS_TABLE_MAX;
        }

        void *m = acpi_temp_map(eps[i].table, len);
        if (!m) {
            pr_warn("%s: %s table at 0x%llx does not map\n", "smbios", src[i],
                    (unsigned long long)eps[i].table);
            continue;
        }

        int ok = dmi_parse_table((const uint8_t *)m, len);
        acpi_temp_unmap(m, len);

        if (ok) {
            pr_info("dmi: %s / %s (BIOS %s) [%s]",
                    dmi_vendor, dmi_product, dmi_bios_version, src[i]);
            dmi_state = 1;
            break;
        }
        pr_info("%s: %s table at 0x%llx carries no usable type 1 structure\n",
                "smbios", src[i], (unsigned long long)eps[i].table);
    }

    if (dmi_state != 1)
        pr_info("dmi: no usable SMBIOS table (%d candidate(s) tried)\n", n);

    return dmi_state;
}

int dmi_is_hp_290g1(void)
{
    if (dmi_collect_once() <= 0)
        return 0;

    /* Manufacturer is "HP" / "HP Inc." on modern boards, "Hewlett-Packard"
     * on older ones. */
    if (strcmp(dmi_vendor, "Hewlett-Packard") != 0 &&
        !dmi_prefix(dmi_vendor, "HP"))
        return 0;

    /* HP 290 G1 SFF / Microtower (Intel B360). */
    if (!dmi_contains(dmi_product, "290 G1"))
        return 0;

    return 1;
}

/* Raw SMBIOS identity for /proc/dmi — see dmi.h.  The probe result is cached
 * in `dmi_state`, so repeated calls cost a load. */
const char *dmi_vendor_string(void)
{
    return dmi_collect_once() > 0 ? dmi_vendor : 0;
}

const char *dmi_product_string(void)
{
    return dmi_collect_once() > 0 ? dmi_product : 0;
}

const char *dmi_bios_string(void)
{
    return dmi_collect_once() > 0 ? dmi_bios_version : 0;
}
