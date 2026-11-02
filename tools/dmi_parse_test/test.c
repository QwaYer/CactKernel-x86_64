/*
 * Host-side test for the SMBIOS entry-point discovery in
 * Cact/drivers/dmi/dmi.c (+ the EFI configuration-table lookup in
 * Cact/drivers/acpi/efi_config.c).
 *
 * Both files are compiled *unmodified* against the stub headers in ./stub;
 * this harness emulates the physical address space the probe walks.  That is
 * the only way to reach the cases that matter for the real-hardware bug this
 * covers: a 64-bit SMBIOS 3.x table placed above 4 GiB, and a stale legacy
 * entry point sitting next to a working one.  QEMU firmware (SeaBIOS and OVMF
 * alike) produces neither.
 *
 * Run it with ./run.sh (or `ninja -C build-meson dmi-parse-test`).  Each case
 * runs in a forked child, because dmi.c caches its probe result in a static.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dmi.h"            /* the real Cact/drivers/dmi/dmi.h */
#include "efi_config.h"     /* the real Cact/drivers/acpi/efi_config.h */

/* --- emulated physical address space ------------------------------------- */

#define LOW_LIMIT  (64u * 1024u * 1024u)      /* RAM the harness simulates */
#define HIGH_BASE  0x100000000ull              /* strictly above 4 GiB */
#define HIGH_LEN   0x10000u

#define FSEG       0xF0000u                    /* where the scan looks */
#define SYSTAB     0x80000u                    /* fake EFI system table */
#define CFGTAB     0x80100u                    /* fake configuration table */
#define TABLE_A    0xA0000u                    /* synthetic structure table */
#define TABLE_B    0xA8000u                    /* a second one */

static uint8_t lowmem[LOW_LIMIT];
static uint8_t himem[HIGH_LEN];

uint64_t mb2_efi_systab;                       /* stub/multiboot2.h */

void *acpi_temp_map(uint64_t phys, uint32_t size)
{
    if (phys >= HIGH_BASE) {
        if (phys - HIGH_BASE + size > HIGH_LEN)
            return NULL;
        return himem + (phys - HIGH_BASE);
    }
    if (phys + size > LOW_LIMIT)
        return NULL;
    return lowmem + phys;
}

void acpi_temp_unmap(void *virt, uint32_t size) { (void)virt; (void)size; }
int  acpi_temp_map_ready(void) { return 1; }

static uint32_t cact_mmio_base = 0xC0000000u;
uint32_t cact_mmio_window_base(void) { return cact_mmio_base; }

static int failures;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; }           \
    } while (0)

/* --- EFI fixtures -------------------------------------------------------- */

/* Offsets from efi_config.c (UEFI 64-bit ABI, sizeof == 120): if that layout
 * changes, these fixtures stop matching and the EFI cases fail loudly. */
static void put_systab(uint64_t phys, uint64_t nr, uint64_t cfg_phys)
{
    uint8_t *st = acpi_temp_map(phys, 120);
    memset(st, 0, 120);
    memcpy(st, "IBI SYST", 8);
    memcpy(st + 0x68, &nr, 8);                 /* NumberOfTableEntries */
    memcpy(st + 0x70, &cfg_phys, 8);           /* ConfigurationTable */
    acpi_temp_unmap(st, 120);
}

static void put_cfg_entry(uint32_t idx, const uint8_t guid[16], uint64_t table)
{
    uint8_t *e = acpi_temp_map(CFGTAB + (uint64_t)idx * 24u, 24);
    memcpy(e, guid, 16);
    memcpy(e + 16, &table, 8);
    acpi_temp_unmap(e, 24);
}

/* --- synthetic SMBIOS pieces -------------------------------------------- */

/* Make the checksum byte at @at zero the byte sum over @[from, from+len). */
static void fix_checksum(uint8_t *p, unsigned from, unsigned len, unsigned at)
{
    uint8_t s = 0;
    for (unsigned i = from; i < from + len; i++)
        s += p[i];
    p[at] = (uint8_t)(p[at] - s);
}

/* "_SM_" (SMBIOS 2.1+) entry point at @p: 32-bit table address. */
static void make_sm(uint8_t *p, uint32_t table_addr, uint16_t table_len)
{
    memset(p, 0, 32);
    memcpy(p, "_SM_", 4);
    p[5] = 0x1F;                               /* entry point length */
    p[6] = 2; p[7] = 6;                        /* version 2.6 */
    memcpy(p + 0x10, "_DMI_", 5);
    p[0x16] = (uint8_t)(table_len & 0xFF);
    p[0x17] = (uint8_t)(table_len >> 8);
    memcpy(p + 0x18, &table_addr, 4);
    p[0x1C] = 1;                               /* structure count */
    p[0x1E] = 0x26;                            /* BCD revision */
    fix_checksum(p, 0x10, 15, 0x15);           /* inside the "_DMI_" block */
    fix_checksum(p, 0, p[5], 4);               /* whole entry point */
}

/* "_SM3_" (SMBIOS 3.x) entry point at @p: 64-bit table address. */
static void make_sm3(uint8_t *p, uint64_t table_addr, uint32_t max_size)
{
    memset(p, 0, 32);
    memcpy(p, "_SM3_", 5);
    p[6] = 0x18;                               /* entry point length */
    p[7] = 3; p[8] = 0;                        /* version 3.0 */
    memcpy(p + 0x0C, &max_size, 4);
    memcpy(p + 0x10, &table_addr, 8);
    fix_checksum(p, 0, p[6], 5);
}

/* Minimal structure table: type 1 ("ACME"/"Widget"), type 0, end-of-table. */
static uint32_t make_table(uint64_t phys, uint32_t cap)
{
    uint8_t *t = acpi_temp_map(phys, cap);
    uint32_t i = 0;
    memset(t, 0, cap);

    t[i++] = 1;  t[i++] = 8;                   /* type 1, formatted length */
    t[i++] = 0;  t[i++] = 0;                   /* handle */
    t[i++] = 1;  t[i++] = 2;                   /* manufacturer / product idx */
    t[i++] = 0;  t[i++] = 0;                   /* version / serial idx */
    memcpy(t + i, "ACME\0Widget\0", 12); i += 12;
    t[i++] = 0;                                /* terminate the string set */

    t[i++] = 0;  t[i++] = 0x12;                /* type 0, formatted length */
    t[i++] = 0;  t[i++] = 0;
    t[i++] = 1;  t[i++] = 2;                   /* vendor / version idx */
    memset(t + i, 0, 12); i += 12;
    static const char bios[] = "BIOSVEND\0" "9.9.9";   /* 16 B incl. final NUL */
    memcpy(t + i, bios, sizeof(bios)); i += sizeof(bios);
    t[i++] = 0;

    t[i++] = 127; t[i++] = 4;                  /* end of table */
    t[i++] = 0; t[i++] = 0;
    t[i++] = 0; t[i++] = 0;

    acpi_temp_unmap(t, cap);
    return i;
}

/* --- cases --------------------------------------------------------------- */

static void expect(const char *want_vendor, const char *want_product)
{
    const char *v = dmi_vendor_string();
    const char *p = dmi_product_string();

    if (want_vendor == NULL) {
        CHECK(v == NULL && p == NULL, "expected no SMBIOS identity");
        return;
    }
    CHECK(v != NULL && !strcmp(v, want_vendor), "vendor name");
    CHECK(p != NULL && !strcmp(p, want_product), "product name");
}

static void case_sm3_high(void)
{
    uint32_t len = make_table(HIGH_BASE + 0x1000, HIGH_LEN - 0x1000);
    make_sm3(acpi_temp_map(FSEG, 32), HIGH_BASE + 0x1000, len);
    expect("ACME", "Widget");
}

static void case_sm3_stale_sm(void)
{
    /* A structurally valid "_SM_" whose table is zeroed memory, then a working
     * "_SM3_": the stale one must not shadow it. */
    make_sm(acpi_temp_map(FSEG, 32), TABLE_A, 0x40);
    uint32_t len = make_table(TABLE_B, 0x1000);
    make_sm3(acpi_temp_map(FSEG + 0x1000, 32), TABLE_B, len);
    expect("ACME", "Widget");
}

static void case_sm_legacy(void)
{
    uint32_t len = make_table(TABLE_A, 0x1000);
    make_sm(acpi_temp_map(FSEG, 32), TABLE_A, (uint16_t)len);
    expect("ACME", "Widget");
}

static void case_sm3_oversize(void)
{
    /* Reported table size past the 64 KiB mapping cap: accepted, capped. */
    make_table(TABLE_A, 0x1000);
    make_sm3(acpi_temp_map(FSEG, 32), TABLE_A, 0x00020000u);
    expect("ACME", "Widget");
}

static void case_efi_sm3(void)
{
    /* Nothing in the F-segment; the entry point comes from the EFI
     * configuration table (the path a UEFI boot needs). */
    uint32_t len = make_table(TABLE_A, 0x1000);
    make_sm3(acpi_temp_map(TABLE_A + 0x800, 32), TABLE_A, len);
    put_systab(SYSTAB, 1, CFGTAB);
    put_cfg_entry(0, EFI_GUID_SMBIOS3, TABLE_A + 0x800);
    mb2_efi_systab = SYSTAB;
    expect("ACME", "Widget");
}

static void case_efi_sm(void)
{
    /* Only the 32-bit GUID is published (what OVMF does). */
    uint32_t len = make_table(TABLE_A, 0x1000);
    make_sm(acpi_temp_map(TABLE_A + 0x800, 32), TABLE_A, (uint16_t)len);
    put_systab(SYSTAB, 2, CFGTAB);
    put_cfg_entry(0, EFI_GUID_ACPI20, TABLE_A + 0x800);   /* unrelated entry */
    put_cfg_entry(1, EFI_GUID_SMBIOS, TABLE_A + 0x800);
    mb2_efi_systab = SYSTAB;
    expect("ACME", "Widget");
}

static void case_none(void)
{
    expect(NULL, NULL);
}

static const struct {
    const char *name;
    void (*fn)(void);
} cases[] = {
    { "sm3-high",      case_sm3_high },
    { "sm3-stale-sm",  case_sm3_stale_sm },
    { "sm-legacy",     case_sm_legacy },
    { "sm3-oversize",  case_sm3_oversize },
    { "efi-sm3",       case_efi_sm3 },
    { "efi-sm",        case_efi_sm },
    { "none",          case_none },
};

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--list")) {
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            printf("%s\n", cases[i].name);
        return 0;
    }
    if (argc > 1) {
        printf("usage: %s [--list]\n", argv[0]);
        return 2;
    }

    unsigned ncase = sizeof(cases) / sizeof(cases[0]);
    int failed = 0;

    for (unsigned i = 0; i < ncase; i++) {
        /* A fresh child per case: dmi.c caches its probe in a static. */
        pid_t pid = fork();
        if (pid == 0) {
            failures = 0;
            printf("--- %s\n", cases[i].name);
            cases[i].fn();
            fflush(NULL);
            _exit(failures ? 1 : 0);
        }
        if (pid < 0) {
            printf("fork failed\n");
            return 2;
        }

        int status = 0;
        if (waitpid(pid, &status, 0) != pid)
            return 2;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("=> %s FAILED\n", cases[i].name);
            failed++;
        }
    }

    if (failed) {
        printf("\n%d/%u case(s) FAILED\n", failed, ncase);
        return 1;
    }
    printf("\nall %u smbios discovery cases passed\n", ncase);
    return 0;
}
