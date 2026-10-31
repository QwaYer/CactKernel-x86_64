/*
 * Loadable USB driver-module loader (multi-slot).
 *
 * Mirrors fs_mod.c — the other non-PCI module class.  A USB driver module is
 * an ET_REL image (e.g. rt2800usb.cctk) that exports usb_driver_init(), which
 * typically calls the ksym-exported usb_driver_register() with a static
 * usb_driver_t.  The loader verifies the module's ECDSA P-256 signature +
 * vermagic tag, relocates it into a private image, resolves undefined symbols
 * through ksym_resolve(), and calls the entry point.
 */

#include "usb_mod.h"
#include "usb.h"
#include "initfs_modblob.h"
#include "ksym.h"
#include "klib.h"
#include "memory.h"
#include "kernel.h"
#include "mod_tag.h"
#include "elf.h"

// Linux i386 errno values, returned negated so the /dev/sys module ioctl can
// report a real reason (see kmod.c).
#ifndef EPERM
#define EPERM  1
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef EEXIST
#define EEXIST 17
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif

// ELF constants live in elf.h (ELF64 / SHT_RELA).

typedef int (*usb_init_fn_t)(void);
typedef void (*usb_exit_fn_t)(void);

typedef struct {
    int          used;
    char         instance[64];
    uint8_t     *image;
    uint32_t     size;
    usb_exit_fn_t exit;
    // Driver-list head as it was before init() ran.  usb_driver_register()
    // prepends, so the drivers this module registered are exactly the nodes
    // above it — that prefix answers "how many devices does this module use".
    const usb_driver_t *drv_baseline;
} usb_slot_t;

static usb_slot_t slots[USB_MOD_MAX];

static Elf64_Shdr *get_shdr(Elf64_Ehdr *eh, uint16_t idx) {
    if (idx >= eh->e_shnum)
        return NULL;
    return (Elf64_Shdr *)((uint8_t *)eh + eh->e_shoff + idx * eh->e_shentsize);
}

static const char *get_str(Elf64_Ehdr *eh, uint16_t strtab_idx, uint32_t off) {
    Elf64_Shdr *sh = get_shdr(eh, strtab_idx);
    if (!sh)
        return NULL;
    return (const char *)((uint8_t *)eh + sh->sh_offset + off);
}

// Instance name: path basename with a trailing ".cctk" stripped.
static void instance_name(const char *path, char *out, int out_sz) {
    const char *base = path;
    for (const char *p = path; p && *p; p++)
        if (*p == '/') base = p + 1;

    int i = 0;
    for (; base[i] && i < out_sz - 1; i++) {
        char c = base[i];
        if (c == ' ')
            c = '_';
        if (c == '.' && base[i + 1] == 'c' && base[i + 2] == 'c' &&
            base[i + 3] == 't' && base[i + 4] == 'k')
            break;
        out[i] = c;
    }
    out[i] = '\0';
}

// Locate an exported global function symbol by name.  Returns 0 if absent.
static uintptr_t find_func_sym(Elf64_Ehdr *eh, Elf64_Sym *syms, uint32_t sym_cnt,
                               uint16_t strtab_idx, uint8_t *image,
                               const char *want) {
    for (uint32_t s = 0; s < sym_cnt; s++) {
        if (ELF64_ST_BIND(syms[s].st_info) != STB_GLOBAL) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC)   continue;
        if (syms[s].st_shndx == SHN_UNDEF)                continue;
        const char *sym_name = get_str(eh, strtab_idx, syms[s].st_name);
        if (!sym_name || strcmp((char *)sym_name, (char *)want) != 0) continue;
        Elf64_Shdr *sym_sh = get_shdr(eh, syms[s].st_shndx);
        if (!sym_sh) continue;
        return (uintptr_t)(image + sym_sh->sh_addr + syms[s].st_value);
    }
    return 0;
}

// Load, verify and relocate the module; resolve usb_driver_init/_exit.
static int load_module_image(const char *path, uint8_t **image_out,
                             uint32_t *size_out, usb_init_fn_t *init_out,
                             usb_exit_fn_t *exit_out) {
    const uint8_t *blob_data = NULL;
    uint32_t       blob_size = 0;
    if (initfs_modblob_get(path, &blob_data, &blob_size) != 0 || !blob_size) {
        pr_err("usbmod: module not found: %s\n", path);
        return -ENOENT;
    }

    uint8_t *elf_data = (uint8_t *)kmalloc(blob_size);
    if (!elf_data) return -ENOMEM;
    memcpy(elf_data, blob_data, blob_size);
    uint32_t file_size = blob_size;

    if (mod_tag_verify(elf_data, &file_size) != 0) {
        kfree(elf_data);
        return -EACCES;
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf_data;
    if (!elf64_is_rel_object(eh)) {
        pr_err("usbmod: not a valid ELF64 relocatable (class=%u type=%u machine=%u): %s\n",
               (unsigned)eh->e_ident[EI_CLASS], (unsigned)eh->e_type,
               (unsigned)eh->e_machine, path);
        kfree(elf_data);
        return -2;
    }

    uint64_t sh_tab_end;
    if (__builtin_mul_overflow(eh->e_shnum, eh->e_shentsize, &sh_tab_end) ||
        __builtin_add_overflow(eh->e_shoff, sh_tab_end, &sh_tab_end) ||
        eh->e_shentsize < sizeof(Elf64_Shdr) || sh_tab_end > (uint64_t)file_size) {
        pr_err("usbmod: corrupted section header table (shoff=%llu shnum=%u "
               "shentsize=%u file=%u): %s\n",
               (unsigned long long)eh->e_shoff, (unsigned)eh->e_shnum,
               (unsigned)eh->e_shentsize, (unsigned)file_size, path);
        kfree(elf_data);
        return -3;
    }

    // First pass: total image size and section addresses.
    uint64_t total = 0;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!sh || !(sh->sh_flags & SHF_ALLOC)) continue;
        uint64_t align = sh->sh_addralign ? sh->sh_addralign : 1;
        if (align & (align - 1)) align = 1;
        total = (total + align - 1) & ~(align - 1);
        sh->sh_addr = total;
        total += sh->sh_size;
    }
    if (total == 0 || total > 0xFFFFFFFFull) {
        pr_err("usbmod: bad module image size (%llu bytes): %s\n",
               (unsigned long long)total, path);
        kfree(elf_data);
        return -8;
    }

    uint8_t *image = (uint8_t *)kmalloc((size_t)total);
    if (!image) { kfree(elf_data); return -ENOMEM; }
    memset(image, 0, (size_t)total);

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!sh || !(sh->sh_flags & SHF_ALLOC) || sh->sh_type != SHT_PROGBITS) continue;
        if (sh->sh_offset + sh->sh_size > (uint64_t)file_size) {
            pr_err("usbmod: section %u exceeds file (off=0x%llx size=0x%llx file=0x%x): %s\n",
                   (unsigned)i, (unsigned long long)sh->sh_offset,
                   (unsigned long long)sh->sh_size, (unsigned)file_size, path);
            kfree(image); kfree(elf_data);
            return -8;
        }
        memcpy(image + sh->sh_addr, elf_data + sh->sh_offset, (size_t)sh->sh_size);
    }

    // Symbol table + its string table.
    Elf64_Shdr *symtab_sh = NULL;
    uint16_t    strtab_idx = 0;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (sh && sh->sh_type == SHT_SYMTAB) {
            symtab_sh  = sh;
            strtab_idx = (uint16_t)sh->sh_link;
            break;
        }
    }
    if (!symtab_sh) {
        pr_err("usbmod: no .symtab in %s\n", path);
        kfree(image); kfree(elf_data);
        return -4;
    }
    if (symtab_sh->sh_offset + symtab_sh->sh_size > (uint64_t)file_size) {
        kfree(image); kfree(elf_data);
        return -8;
    }
    Elf64_Shdr *strtab_sh = get_shdr(eh, strtab_idx);
    if (!strtab_sh || strtab_sh->sh_offset + strtab_sh->sh_size > (uint64_t)file_size) {
        kfree(image); kfree(elf_data);
        return -8;
    }
    Elf64_Sym *syms    = (Elf64_Sym *)(elf_data + symtab_sh->sh_offset);
    uint32_t   sym_cnt = (uint32_t)(symtab_sh->sh_size / sizeof(Elf64_Sym));

    // Relocations: ELF64 SHT_RELA, the direct relocations a GOT/PLT-free
    // (-mcmodel=kernel) object emits — intra-module and against ksym exports.
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!sh || sh->sh_type != SHT_RELA) continue;
        Elf64_Shdr *target_sh = get_shdr(eh, sh->sh_info);
        if (!target_sh || !(target_sh->sh_flags & SHF_ALLOC)) continue;
        Elf64_Rela *rels    = (Elf64_Rela *)(elf_data + sh->sh_offset);
        uint32_t    rel_cnt = (uint32_t)(sh->sh_size / sizeof(Elf64_Rela));
        for (uint32_t r = 0; r < rel_cnt; r++) {
            uint32_t sym_idx = ELF64_R_SYM(rels[r].r_info);
            uint32_t type    = ELF64_R_TYPE(rels[r].r_info);
            uint32_t width   = elf64_rela_width(type);
            if (sym_idx >= sym_cnt) {
                pr_err("usbmod: relocation symbol index %u >= %u: %s\n",
                       (unsigned)sym_idx, (unsigned)sym_cnt, path);
                kfree(image); kfree(elf_data);
                return -7;
            }
            if (width == 0) {
                pr_err("usbmod: unsupported relocation type %u: %s\n",
                       (unsigned)type, path);
                kfree(image); kfree(elf_data);
                return -7;
            }
            Elf64_Sym *sym = &syms[sym_idx];
            uint64_t   S;
            if (sym->st_shndx == SHN_UNDEF) {
                const char *sym_name = get_str(eh, strtab_idx, sym->st_name);
                if (!sym_name) { kfree(image); kfree(elf_data); return -7; }
                S = (uint64_t)ksym_resolve(sym_name);
                if (S == 0 && ELF64_ST_BIND(sym->st_info) != STB_WEAK) {
                    pr_err("usbmod: unresolved symbol '%s': %s\n", sym_name, path);
                    kfree(image); kfree(elf_data);
                    return -7;
                }
            } else {
                Elf64_Shdr *sym_sh = get_shdr(eh, sym->st_shndx);
                if (!sym_sh || !(sym_sh->sh_flags & SHF_ALLOC)) {
                    pr_err("usbmod: symbol in non-ALLOC section %u: %s\n",
                           (unsigned)sym->st_shndx, path);
                    kfree(image); kfree(elf_data);
                    return -7;
                }
                S = (uint64_t)(uintptr_t)(image + sym_sh->sh_addr + sym->st_value);
            }
            if (rels[r].r_offset + width > target_sh->sh_size) {
                pr_err("usbmod: relocation offset 0x%llx >= section size 0x%llx: %s\n",
                       (unsigned long long)rels[r].r_offset,
                       (unsigned long long)target_sh->sh_size, path);
                kfree(image); kfree(elf_data);
                return -7;
            }
            uint8_t *patch = image + target_sh->sh_addr + rels[r].r_offset;
            elf64_apply_rela(type, patch, S, rels[r].r_addend);
        }
    }

    uintptr_t init_addr = find_func_sym(eh, syms, sym_cnt, strtab_idx, image,
                                        "usb_driver_init");
    if (!init_addr) {
        pr_err("usbmod: symbol 'usb_driver_init' not found in %s\n", path);
        kfree(image); kfree(elf_data);
        return -5;
    }
    uintptr_t exit_addr = find_func_sym(eh, syms, sym_cnt, strtab_idx, image,
                                        "usb_driver_exit");

    kfree(elf_data);
    *image_out = image;
    *size_out  = (uint32_t)total;
    *init_out  = (usb_init_fn_t)init_addr;
    *exit_out  = exit_addr ? (usb_exit_fn_t)exit_addr : NULL;
    return 0;
}

static int usb_mod_image_errno(int rc) {
    switch (rc) {
    case -ENOENT: return -ENOENT;   // no such module in the cctkfs image
    case -ENOMEM: return -ENOMEM;   // relocation image too large
    case -EACCES: return -EACCES;   // HMAC signature rejected
    default:      return -EINVAL;   // not ET_REL / corrupt / unresolved symbol
    }
}

int usb_mod_load(const char *path) {
    if (!path) return -EINVAL;

    int free_slot = -1;
    for (int i = 0; i < USB_MOD_MAX; i++)
        if (!slots[i].used) { free_slot = i; break; }
    if (free_slot < 0) {
        pr_err("usbmod: no free USB-module slot (max %d) for %s\n",
               (int)USB_MOD_MAX, path);
        return -ENOSPC;
    }

    char inst[64];
    instance_name(path, inst, sizeof(inst));
    for (int i = 0; i < USB_MOD_MAX; i++) {
        if (slots[i].used && strcmp(slots[i].instance, inst) == 0) {
            pr_warn("usbmod: module already loaded: %s\n", inst);
            return -EEXIST;
        }
    }

    uint8_t      *image = NULL;
    uint32_t      size  = 0;
    usb_init_fn_t init  = NULL;
    usb_exit_fn_t exit  = NULL;
    int rc = load_module_image(path, &image, &size, &init, &exit);
    if (rc != 0)
        return usb_mod_image_errno(rc);

    // Publish the slot before calling init: init registers drivers whose
    // probe may fire immediately, and those must see the module as resident.
    usb_slot_t *s = &slots[free_slot];
    memset(s, 0, sizeof(*s));
    strlcpy(s->instance, inst, sizeof(s->instance));
    s->used  = 1;
    s->image = image;
    s->size  = size;
    s->exit  = exit;
    s->drv_baseline = usb_driver_list_head();

    int irc = init();
    if (irc != 0) {
        pr_err("usbmod: usb_driver_init failed: %d\n", irc);
        memset(s, 0, sizeof(*s));
        kfree(image);
        return irc;
    }

    pr_info("usbmod: module loaded: %s (slot %d)\n", inst, free_slot);
    return 0;
}

static usb_slot_t *slot_by_instance(const char *instance) {
    if (!instance)
        return 0;
    for (int i = 0; i < USB_MOD_MAX; i++)
        if (slots[i].used && strcmp(slots[i].instance, instance) == 0)
            return &slots[i];
    return 0;
}

int usb_mod_unload(const char *instance) {
    usb_slot_t *s = slot_by_instance(instance);
    if (!s)
        return -ENOENT;
    if (s->exit)
        s->exit();
    if (s->image)
        kfree(s->image);
    memset(s, 0, sizeof(*s));
    pr_info("usbmod: module unloaded: %s\n", instance);
    return 0;
}

int usb_mod_loaded(const char *instance) {
    return slot_by_instance(instance) != 0;
}

const char *usb_mod_instance(int slot) {
    if (slot < 0 || slot >= USB_MOD_MAX || !slots[slot].used)
        return 0;
    return slots[slot].instance;
}

// Resident image size reported by /proc/modules (0 when the slot is free).
uint32_t usb_mod_size(int slot) {
    if (slot < 0 || slot >= USB_MOD_MAX || !slots[slot].used)
        return 0;
    return slots[slot].size;
}

// User count reported by /proc/modules: the devices the drivers this module
// registered currently claim (0 when the slot is free).
int usb_mod_refs(int slot) {
    if (slot < 0 || slot >= USB_MOD_MAX || !slots[slot].used)
        return 0;
    return usb_driver_users_since(slots[slot].drv_baseline);
}

// Non-destructive probe: scan the ELF symbol table for an exported global FUNC
// named 'usb_driver_init'.  Used by modload to route a .cctk to this loader.
int usb_mod_detect(const char *path) {
    if (!path) return -1;

    const uint8_t *blob = NULL;
    uint32_t       size = 0;
    if (initfs_modblob_get(path, &blob, &size) != 0 || !blob || !size)
        return -1;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)blob;
    if (!elf64_is_rel_object(eh))
        return 0;

    uint64_t sh_tab_end;
    if (__builtin_mul_overflow(eh->e_shnum, eh->e_shentsize, &sh_tab_end) ||
        __builtin_add_overflow(eh->e_shoff, sh_tab_end, &sh_tab_end) ||
        eh->e_shentsize < sizeof(Elf64_Shdr) || sh_tab_end > (uint64_t)size)
        return 0;

    Elf64_Shdr *symtab_sh = NULL;
    uint16_t    strtab_idx = 0;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (sh && sh->sh_type == SHT_SYMTAB) {
            symtab_sh  = sh;
            strtab_idx = (uint16_t)sh->sh_link;
            break;
        }
    }
    if (!symtab_sh)
        return 0;
    if (symtab_sh->sh_offset + symtab_sh->sh_size > (uint64_t)size)
        return 0;
    Elf64_Shdr *strtab_sh = get_shdr(eh, strtab_idx);
    if (!strtab_sh || strtab_sh->sh_offset + strtab_sh->sh_size > (uint64_t)size)
        return 0;

    Elf64_Sym *syms    = (Elf64_Sym *)(blob + symtab_sh->sh_offset);
    uint32_t   sym_cnt = (uint32_t)(symtab_sh->sh_size / sizeof(Elf64_Sym));

    for (uint32_t s = 0; s < sym_cnt; s++) {
        if (ELF64_ST_BIND(syms[s].st_info) != STB_GLOBAL) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC)   continue;
        if (syms[s].st_shndx == SHN_UNDEF)                continue;
        const char *sym_name = get_str(eh, strtab_idx, syms[s].st_name);
        if (sym_name && strcmp((char *)sym_name, "usb_driver_init") == 0)
            return 1;
    }
    return 0;
}
