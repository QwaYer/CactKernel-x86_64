/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "kernel.h"
#include "klib.h"
#include "multiboot2.h"

// Flags for which fields are valid in multiboot_info_t
#define MB2_FLAG_MEMINFO     (1u << 0)
#define MB2_FLAG_MMAP        (1u << 6)
#define MB2_FLAG_FRAMEBUFFER (1u << 12)

#define MB2_TAG_HDR_SIZE  8u
#define MB2_ALIGN         8u

// Module info captured from MB2_TAG_MODULE; written by multiboot2_parse(),
// consumed by init() to stage the localbinrepo image into kernel .bss.
mb2_module_info_t mb2_localbinrepo_module;
mb2_module_info_t mb2_firmrepo_module;
mb2_module_info_t mb2_netdrvrepo_module;
mb2_module_info_t mb2_drvrepo_module;
mb2_module_info_t mb2_grubrepo_module;

// Highest end address over all MB2 module tags: the RAM the bootloader loaded
// images into.  It is ordinary "available" RAM as far as the memory map says,
// so the PMM has to reserve it explicitly — init() passes this to
// pmm_reserve_boot_images() before the memory managers come up.
uint32_t mb2_modules_end;

// EFI system table physical address (MB2_TAG_EFI64/EFI32); 0 on a legacy boot.
uint64_t mb2_efi_systab;

// Kernel command line (MB2_TAG_CMDLINE); empty when none.
//
// The tag's string lives in the bootloader's Multiboot2 info buffer — which the
// kernel reaches only while the identity map is up, i.e. during this parse —
// and that buffer is not reserved after boot.  So the string is COPIED here,
// into kernel .bss, exactly like the module names; consumers (zram=/zswap=, see
// kernel_setup_hardware) run after `init_paging` and would fault on the raw
// physical pointer.
#define MB2_CMDLINE_MAX 256
static char g_cmdline_buf[MB2_CMDLINE_MAX];
const char *mb2_cmdline = g_cmdline_buf;

static int starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

// Command-line token lookup.  `mb2_cmdline` is a space-separated list of
// "key" or "key=value" tokens; `key` must match the whole key, so
// "zram" never matches the "xzram=..." token.  The returned value points into
// the command line and ends at the next whitespace or NUL, not at a NUL of its
// own — callers parse it as a token.
const char *mb2_cmdline_get(const char *key) {
    if (!key || !key[0])
        return 0;
    const char *s = mb2_cmdline;
    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == '\n') s++;
        const char *tok = s;
        while (*s && *s != ' ' && *s != '\t' && *s != '\n') s++;
        const char *k = key, *t = tok;
        while (*k && t < s && *t == *k) { t++; k++; }
        if (*k == '\0' && t < s && *t == '=')
            return t + 1;
    }
    return 0;
}

// Bounded, NUL-terminated copy of a value, for callers (the Rust zswap hook)
// that want a safe buffer rather than a pointer into the command line.
int mb2_cmdline_value(const char *key, char *buf, int cap) {
    const char *v = mb2_cmdline_get(key);
    if (!v)
        return 0;
    if (!buf || cap <= 0)
        return -1;
    int i = 0;
    while (i < cap - 1 && v[i] && v[i] != ' ' && v[i] != '\t' && v[i] != '\n') {
        buf[i] = v[i];
        i++;
    }
    buf[i] = '\0';
    if (v[i] && v[i] != ' ' && v[i] != '\t' && v[i] != '\n')
        return -1;  // truncated
    return 1;
}

// Parse "512", "512K", "512M", "2G" (case-insensitive suffix, optional trailing
// 'B'/'b').  A value with trailing junk is rejected rather than half-parsed.
int mb2_cmdline_parse_size(const char *val, uint64_t *out_bytes) {
    if (!val || !out_bytes)
        return 0;
    uint64_t n = 0;
    int digits = 0;
    while (*val >= '0' && *val <= '9') {
        n = n * 10u + (uint64_t)(*val - '0');
        val++;
        digits++;
    }
    if (!digits)
        return 0;
    uint64_t mult = 1;
    char c = *val;
    if (c == 'k' || c == 'K') { mult = 1024ull; val++; }
    else if (c == 'm' || c == 'M') { mult = 1024ull * 1024; val++; }
    else if (c == 'g' || c == 'G') { mult = 1024ull * 1024 * 1024; val++; }
    if (*val == 'b' || *val == 'B')
        val++;
    if (*val != '\0' && *val != ' ' && *val != '\t' && *val != '\n')
        return 0;
    *out_bytes = n * mult;
    return 1;
}

static void copy_module_name(char* dst, const char* src, uint32_t max) {
    uint32_t i = 0;
    while (i + 1 < max && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

// Fallback direct-color layout for a type-1 tag that omits the channel info,
// keyed off the pixel depth.  Covers the layouts VBE/GRUB actually hand over.
static void fb_default_color_layout(multiboot_info_t* out) {
    switch (out->framebuffer_bpp) {
    case 32:
    case 24:  // XRGB8888 / BGR888
        out->framebuffer_red_pos = 16; out->framebuffer_red_size = 8;
        out->framebuffer_green_pos = 8; out->framebuffer_green_size = 8;
        out->framebuffer_blue_pos = 0;  out->framebuffer_blue_size = 8;
        break;
    case 16:  // RGB565
        out->framebuffer_red_pos = 11; out->framebuffer_red_size = 5;
        out->framebuffer_green_pos = 5; out->framebuffer_green_size = 6;
        out->framebuffer_blue_pos = 0;  out->framebuffer_blue_size = 5;
        break;
    case 15:  // RGB555
        out->framebuffer_red_pos = 10; out->framebuffer_red_size = 5;
        out->framebuffer_green_pos = 5; out->framebuffer_green_size = 5;
        out->framebuffer_blue_pos = 0;  out->framebuffer_blue_size = 5;
        break;
    case 8:   // RGB332
        out->framebuffer_red_pos = 5;  out->framebuffer_red_size = 3;
        out->framebuffer_green_pos = 2; out->framebuffer_green_size = 3;
        out->framebuffer_blue_pos = 0;  out->framebuffer_blue_size = 2;
        break;
    default:
        break;
    }
}

// Parse multiboot2 tag list into simplified kernel structure
void multiboot2_parse(uint32_t mb2_info_addr,
                      multiboot_info_t*  out,
                      mb2_mmap_table_t*  mmap_out)
{
    mb2_localbinrepo_module.mod_start = 0;
    mb2_localbinrepo_module.mod_size  = 0;
    mb2_localbinrepo_module.name[0]   = '\0';
    mb2_firmrepo_module.mod_start = 0;
    mb2_firmrepo_module.mod_size  = 0;
    mb2_firmrepo_module.name[0]   = '\0';
    mb2_netdrvrepo_module.mod_start = 0;
    mb2_netdrvrepo_module.mod_size  = 0;
    mb2_netdrvrepo_module.name[0]   = '\0';
    mb2_drvrepo_module.mod_start = 0;
    mb2_drvrepo_module.mod_size  = 0;
    mb2_drvrepo_module.name[0]   = '\0';
    mb2_grubrepo_module.mod_start = 0;
    mb2_grubrepo_module.mod_size  = 0;
    mb2_grubrepo_module.name[0]   = '\0';
    mb2_modules_end = 0;
    mb2_efi_systab  = 0;
    g_cmdline_buf[0] = '\0';

    // Zero output structures
    out->flags             = 0;
    out->mem_lower         = 0;
    out->mem_upper         = 0;
    out->mem_total_bytes   = 0;
    out->framebuffer_addr  = 0;
    out->framebuffer_pitch = 0;
    out->framebuffer_width = 0;
    out->framebuffer_height= 0;
    out->framebuffer_bpp   = 0;
    out->framebuffer_type  = 0;
    out->framebuffer_red_pos   = 0;
    out->framebuffer_red_size  = 0;
    out->framebuffer_green_pos = 0;
    out->framebuffer_green_size= 0;
    out->framebuffer_blue_pos  = 0;
    out->framebuffer_blue_size = 0;

    if (mmap_out) {
        mmap_out->count = 0;
    }

    // Validate input address
    if (mb2_info_addr == 0) return;
    if (mb2_info_addr & (MB2_ALIGN - 1u)) return;  // Not aligned

    uint32_t total_size = *(volatile uint32_t*)(uintptr_t)mb2_info_addr;
    if (total_size < 16u) return;
    if (mb2_info_addr > (0xFFFFFFFFu - total_size)) return;  // Wraparound

    uint32_t cursor = mb2_info_addr + MB2_ALIGN;  // Skip total_size field
    uint32_t end    = mb2_info_addr + total_size;

    while (1) {
        // Bounds check
        if (cursor > end || (end - cursor) < MB2_TAG_HDR_SIZE) break;

        // Align cursor to 8-byte boundary
        if (cursor & (MB2_ALIGN - 1u)) {
            cursor = (cursor + MB2_ALIGN - 1u) & ~(MB2_ALIGN - 1u);
            continue;
        }

        struct mb2_tag* tag = (struct mb2_tag*)(uintptr_t)cursor;

        // Validate tag header
        if (tag->size < MB2_TAG_HDR_SIZE) break;
        if (cursor > end || (end - cursor) < tag->size) break;

        // End tag -> terminate parsing
        if (tag->type == MB2_TAG_END) break;

        switch (tag->type) {

        case MB2_TAG_BASIC_MEMINFO: {
            if (tag->size < sizeof(struct mb2_tag_basic_meminfo)) break;
            struct mb2_tag_basic_meminfo* t =
                (struct mb2_tag_basic_meminfo*)(uintptr_t)cursor;
            out->mem_lower = t->mem_lower;
            out->mem_upper = t->mem_upper;
            out->flags |= MB2_FLAG_MEMINFO;
            break;
        }

        case MB2_TAG_MMAP: {
            if (tag->size < 16u) break;
            struct mb2_tag_mmap* t = (struct mb2_tag_mmap*)(uintptr_t)cursor;

            // entry_size must be at least sizeof(mb2_mmap_entry)
            if (t->entry_size < sizeof(struct mb2_mmap_entry)) break;

            uint32_t payload_bytes = tag->size - 16u;
            uint32_t count = payload_bytes / t->entry_size;
            uint64_t total_avail = 0;

            for (uint32_t i = 0; i < count; i++) {
                uint64_t entry_off64 = 16ull + (uint64_t)i * t->entry_size;
                if (entry_off64 > 0xFFFFFFFFu) break;
                uint32_t entry_off = (uint32_t)entry_off64;
                if (entry_off + sizeof(struct mb2_mmap_entry) > tag->size) break;

                struct mb2_mmap_entry* e =
                    (struct mb2_mmap_entry*)((uint8_t*)(uintptr_t)cursor + entry_off);

                // Sum available RAM for total memory count
                if (e->type == MB2_MMAP_TYPE_AVAILABLE) {
                    total_avail += e->len;
                }

                // Build flat mmap table for PMM.
                if (mmap_out && mmap_out->count < MB2_MMAP_MAX_ENTRIES) {
                    // Keep the full 64-bit values: the PMM is 64-bit and manages
                    // RAM above 4 GiB too (below the 32-bit hole it is device
                    // MMIO, above it is RAM again).
                    if (e->len == 0) continue;

                    mb2_mmap_flat_t* fe =
                        &mmap_out->entries[mmap_out->count++];
                    fe->base = e->addr;
                    fe->len  = e->len;
                    fe->type = e->type;
                }
            }

            out->mem_total_bytes = total_avail;
            out->flags |= MB2_FLAG_MMAP;
            break;
        }

        case MB2_TAG_MODULE: {
            if (tag->size <= sizeof(struct mb2_tag_module)) break;
            struct mb2_tag_module* t =
                (struct mb2_tag_module*)(uintptr_t)cursor;
            if (t->mod_end <= t->mod_start) break;

            // Highest module end over the whole tag list: see mb2_modules_end.
            if (t->mod_end > mb2_modules_end) mb2_modules_end = t->mod_end;

            // Where the bootloader put it.  firmrepo, netdrvrepo, drvrepo and
            // grubrepo are served *in place* (RAM is identity-mapped), so this
            // physical range is the only address the module ever has; it lies
            // inside the boot reservation the PMM logs right after this parse.
            pr_info("%s: module %s at phys 0x%x-0x%x (%u B, %u KiB)\n",
                    "multiboot2", t->string,
                    (unsigned)t->mod_start, (unsigned)t->mod_end,
                    (unsigned)(t->mod_end - t->mod_start),
                    (unsigned)((t->mod_end - t->mod_start) / 1024));

            // Only record the first module of each kind; any later ones ignored.
            if (mb2_localbinrepo_module.mod_start == 0 &&
                starts_with(t->string, "localbinrepo"))
            {
                mb2_localbinrepo_module.mod_start = t->mod_start;
                mb2_localbinrepo_module.mod_size  = t->mod_end - t->mod_start;
                copy_module_name(mb2_localbinrepo_module.name, t->string,
                                 MB2_MODULE_NAME_MAX);
            }
            if (mb2_firmrepo_module.mod_start == 0 &&
                starts_with(t->string, "firmrepo"))
            {
                mb2_firmrepo_module.mod_start = t->mod_start;
                mb2_firmrepo_module.mod_size  = t->mod_end - t->mod_start;
                copy_module_name(mb2_firmrepo_module.name, t->string,
                                 MB2_MODULE_NAME_MAX);
            }
            if (mb2_netdrvrepo_module.mod_start == 0 &&
                starts_with(t->string, "netdrvrepo"))
            {
                mb2_netdrvrepo_module.mod_start = t->mod_start;
                mb2_netdrvrepo_module.mod_size  = t->mod_end - t->mod_start;
                copy_module_name(mb2_netdrvrepo_module.name, t->string,
                                 MB2_MODULE_NAME_MAX);
            }
            if (mb2_drvrepo_module.mod_start == 0 &&
                starts_with(t->string, "drvrepo"))
            {
                mb2_drvrepo_module.mod_start = t->mod_start;
                mb2_drvrepo_module.mod_size  = t->mod_end - t->mod_start;
                copy_module_name(mb2_drvrepo_module.name, t->string,
                                 MB2_MODULE_NAME_MAX);
            }
            if (mb2_grubrepo_module.mod_start == 0 &&
                starts_with(t->string, "grubrepo"))
            {
                mb2_grubrepo_module.mod_start = t->mod_start;
                mb2_grubrepo_module.mod_size  = t->mod_end - t->mod_start;
                copy_module_name(mb2_grubrepo_module.name, t->string,
                                 MB2_MODULE_NAME_MAX);
            }
            break;
        }

        case MB2_TAG_EFI64: {
            if (tag->size < sizeof(struct mb2_tag_efi64)) break;
            struct mb2_tag_efi64* t = (struct mb2_tag_efi64*)(uintptr_t)cursor;
            if (t->pointer == 0) break;
            mb2_efi_systab = t->pointer;
            pr_info("%s: EFI system table at phys 0x%llx (EFI64)\n",
                    "multiboot2", (unsigned long long)mb2_efi_systab);
            break;
        }

        case MB2_TAG_EFI32: {
            if (tag->size < sizeof(struct mb2_tag_efi32)) break;
            struct mb2_tag_efi32* t = (struct mb2_tag_efi32*)(uintptr_t)cursor;
            if (t->pointer == 0) break;
            mb2_efi_systab = t->pointer;
            pr_info("%s: EFI system table at phys 0x%llx (EFI32)\n",
                    "multiboot2", (unsigned long long)mb2_efi_systab);
            break;
        }

        case MB2_TAG_ACPI_OLD:
        case MB2_TAG_ACPI_NEW: {
            // The bootloader hands over its own copy of the firmware RSDP.
            // Logged only: ACPI keeps reading the RSDP the firmware exposes
            // (osl.c), so nothing here depends on the lifetime of this buffer.
            // It is still the fastest way to see *on a real board* whether the
            // firmware has an RSDP the bootloader could reach at all.
            if (tag->size < sizeof(struct mb2_tag_acpi) + 20u) break;
            struct mb2_tag_acpi* t = (struct mb2_tag_acpi*)(uintptr_t)cursor;
            const uint8_t* r = t->rsdp;
            uint8_t csum = 0;
            uint64_t xsdt = 0;
            for (unsigned i = 0; i < 20u; i++) csum += r[i];
            if (t->size >= sizeof(struct mb2_tag_acpi) + 36u && r[15] >= 2u)
                memcpy(&xsdt, r + 24, sizeof(xsdt));
            pr_info("%s: ACPI RSDP copy (tag %u, rev %u, xSDT 0x%llx, "
                    "checksum %s)\n", "multiboot2", (unsigned)tag->type,
                    (unsigned)r[15], (unsigned long long)xsdt,
                    csum == 0 ? "ok" : "BAD");
            break;
        }

        case MB2_TAG_CMDLINE: {
            if (tag->size <= sizeof(struct mb2_tag_string)) break;
            struct mb2_tag_string* t = (struct mb2_tag_string*)(uintptr_t)cursor;
            copy_module_name(g_cmdline_buf, t->string, MB2_CMDLINE_MAX);
            pr_info("%s: cmdline: \"%s\"\n", "multiboot2", mb2_cmdline);
            break;
        }

        case MB2_TAG_FRAMEBUFFER: {
            if (tag->size < MB2_FB_TAG_BASE_SIZE) break;
            struct mb2_tag_framebuffer* t =
                (struct mb2_tag_framebuffer*)(uintptr_t)cursor;
            out->framebuffer_addr   = t->framebuffer_addr;
            out->framebuffer_pitch  = t->framebuffer_pitch;
            out->framebuffer_width  = t->framebuffer_width;
            out->framebuffer_height = t->framebuffer_height;
            out->framebuffer_bpp    = t->framebuffer_bpp;
            out->framebuffer_type   = t->framebuffer_type;
            // Direct-color tags carry the channel layout; use it verbatim,
            // otherwise fall back to the standard layout for this depth.
            if (t->framebuffer_type == 1 && tag->size >= MB2_FB_TAG_RGB_SIZE) {
                out->framebuffer_red_pos    = t->red_field_position;
                out->framebuffer_red_size   = t->red_mask_size;
                out->framebuffer_green_pos  = t->green_field_position;
                out->framebuffer_green_size = t->green_mask_size;
                out->framebuffer_blue_pos   = t->blue_field_position;
                out->framebuffer_blue_size  = t->blue_mask_size;
            } else {
                fb_default_color_layout(out);
            }
            out->flags |= MB2_FLAG_FRAMEBUFFER;
            break;
        }

        default:
            break;
        }

        // Align tag size to 8 bytes, advance cursor
        uint32_t adv = (tag->size + (MB2_ALIGN - 1u)) & ~(MB2_ALIGN - 1u);
        if (adv < MB2_TAG_HDR_SIZE) break;  // Would loop forever
        if (cursor > end - adv) break;       // Would overflow
        cursor += adv;
    }
}