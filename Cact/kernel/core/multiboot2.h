/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef MULTIBOOT2_H
#define MULTIBOOT2_H

#include <stdint.h>

/*
 * Multiboot2 magic values and tag types.
 * See: https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html
 */

#define MB2_BOOTLOADER_MAGIC 0x36D76289u   // Passed in EAX
#define MB2_HEADER_MAGIC     0xE85250D6u   // Kernel header magic

// Tag type identifiers
#define MB2_TAG_END           0
#define MB2_TAG_CMDLINE       1
#define MB2_TAG_BOOT_LOADER   2
#define MB2_TAG_MODULE        3
#define MB2_TAG_BASIC_MEMINFO 4
#define MB2_TAG_BOOTDEV       5
#define MB2_TAG_MMAP          6
#define MB2_TAG_VBE           7
#define MB2_TAG_FRAMEBUFFER   8
#define MB2_TAG_ELF_SECTIONS  9
#define MB2_TAG_APM           10
#define MB2_TAG_EFI32         11
#define MB2_TAG_EFI64         12
#define MB2_TAG_ACPI_OLD      14
#define MB2_TAG_ACPI_NEW      15
#define MB2_TAG_NETWORK       16

// Memory region types (from MMAP tag)
#define MB2_MMAP_TYPE_AVAILABLE 1
#define MB2_MMAP_TYPE_RESERVED  2
#define MB2_MMAP_TYPE_ACPI      3
#define MB2_MMAP_TYPE_NVS       4
#define MB2_MMAP_TYPE_BADRAM    5

#define MB2_MMAP_MAX_ENTRIES 128

// Generic tag header
struct mb2_tag {
    uint32_t type;
    uint32_t size;
} __attribute__((packed));

// Basic memory info tag (type 4)
struct mb2_tag_basic_meminfo {
    uint32_t type;
    uint32_t size;
    uint32_t mem_lower;   // Conventional memory in KB (0-640)
    uint32_t mem_upper;   // Extended memory in KB (1MB+)
} __attribute__((packed));

// Memory map entry
struct mb2_mmap_entry {
    uint64_t addr;   // Base address
    uint64_t len;    // Length in bytes
    uint32_t type;   // Region type (available, reserved, etc.)
    uint32_t zero;   // Reserved, must be zero
} __attribute__((packed));

// MMAP tag (type 6)
struct mb2_tag_mmap {
    uint32_t type;
    uint32_t size;
    uint32_t entry_size;     // Size of each entry
    uint32_t entry_version;  // Version (must be 0)
    struct mb2_mmap_entry entries[];
} __attribute__((packed));

// EFI system table pointer tag (type 12 = EFI64, type 11 = EFI32).  Present
// only when the bootloader itself ran under UEFI; the target machine's
// firmware tables (SMBIOS, and the ACPI RSDP on boards that keep it out of the
// F-segment) are reachable through the EFI configuration table this points at.
struct mb2_tag_efi64 {
    uint32_t type;
    uint32_t size;
    uint64_t pointer;    // physical address of the EFI system table
} __attribute__((packed));

struct mb2_tag_efi32 {
    uint32_t type;
    uint32_t size;
    uint32_t pointer;    // physical address of the EFI system table
} __attribute__((packed));

// ACPI RSDP tag (type 14 = RSDP v1, type 15 = RSDP v2).  The payload is a copy
// of the firmware RSDP as the bootloader found it.
struct mb2_tag_acpi {
    uint32_t type;
    uint32_t size;
    uint8_t  rsdp[];     // copy of the RSDP (>= 20 bytes)
} __attribute__((packed));

// Framebuffer tag (type 8)
struct mb2_tag_framebuffer {
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t  framebuffer_bpp;
    uint8_t  framebuffer_type;   // 0=indexed, 1=RGB, 2=EGA
    uint16_t reserved;
    // Type 1 (RGB direct color) appends the bit layout of each channel.
    // Absent for type 0 (palette follows instead) and type 2 (EGA).
    uint8_t  red_field_position;
    uint8_t  red_mask_size;
    uint8_t  green_field_position;
    uint8_t  green_mask_size;
    uint8_t  blue_field_position;
    uint8_t  blue_mask_size;
} __attribute__((packed));

// Size of the fixed part of the tag, before the type-dependent color/palette
// info.  A type-2 (EGA) tag is exactly this size; a type-1 tag is 6 bytes more.
#define MB2_FB_TAG_BASE_SIZE 32u
#define MB2_FB_TAG_RGB_SIZE  (MB2_FB_TAG_BASE_SIZE + 6u)

// String tag (type 1,2, etc.)
struct mb2_tag_string {
    uint32_t type;
    uint32_t size;
    char     string[];
} __attribute__((packed));

// Flat memory map entry, built here and read by the PMM's Rust side.
//
// Deliberately *not* packed: with `packed` an entry is 20 bytes while the Rust
// mirror (`Mb2MmapFlat`, a plain `#[repr(C)]` struct) is 24, so the two arrays
// stride differently and `count` — which C writes at the end of its table and
// Rust reads at the end of its own — lands past the written data and reads back
// as zero.  The PMM then saw an empty map and fell back to guessing where RAM
// ends.  The asserts below pin the layout on both sides.
typedef struct {
    uint64_t base;   // Base address (preserved from MB2, may be >4 GB on PAE systems)
    uint64_t len;    // Length in bytes (preserved from MB2)
    uint32_t type;   // Region type
} mb2_mmap_flat_t;

_Static_assert(sizeof(mb2_mmap_flat_t) == 24,
               "mb2_mmap_flat_t must match Mb2MmapFlat in rust_mm/ffi.rs");

// Flat MMAP table passed to physical memory manager
typedef struct {
    mb2_mmap_flat_t entries[MB2_MMAP_MAX_ENTRIES];
    uint32_t        count;
} mb2_mmap_table_t;

_Static_assert(sizeof(mb2_mmap_table_t) == MB2_MMAP_MAX_ENTRIES * 24u + 8u,
               "mb2_mmap_table_t must match Mb2MmapTable in rust_mm/ffi.rs");

// Multiboot2 module tag (type 3) — one per `module2` line in grub.cfg.
struct mb2_tag_module {
    uint32_t type;        // == MB2_TAG_MODULE
    uint32_t size;
    uint32_t mod_start;   // physical address of module start
    uint32_t mod_end;     // physical address of module end (exclusive)
    char     string[];    // NUL-terminated cmdline / identifier
} __attribute__((packed));

// Captured module info passed back from multiboot2_parse(); the first module
// whose cmdline starts with "localbinrepo" is recorded, and the first starting with
// "firmrepo" is recorded separately.
#define MB2_MODULE_NAME_MAX 32
typedef struct {
    uint32_t mod_start;     // 0 when no matching module was found
    uint32_t mod_size;
    char     name[MB2_MODULE_NAME_MAX];
} mb2_module_info_t;

// localbinrepo staging module captured during multiboot2_parse() (defined in multiboot2.c)
extern mb2_module_info_t mb2_localbinrepo_module;

// firmrepo.tar.zst captured during multiboot2_parse().  It is NOT staged: it
// stays in place in physical memory (RAM is identity-mapped) and /dev/firmrepo
// hands it to userspace, because the image is far too big to copy.
extern mb2_module_info_t mb2_firmrepo_module;

// Highest end address over every MB2 module tag (0 when there were none).  The
// RAM below it holds the modules loaded by GRUB — available RAM per the memory
// map, but in use — so init() reserves it in the PMM before the heap exists.
extern uint32_t mb2_modules_end;

// EFI system table physical address from the Multiboot2 EFI64/EFI32 tag; 0 when
// the bootloader was not running under UEFI (a legacy/CSM boot passes no such
// tag, and the firmware tables then have to come from the F-segment scan).
extern uint64_t mb2_efi_systab;

#endif  