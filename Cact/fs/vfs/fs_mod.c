/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * Loadable filesystem-module loader (multi-slot).
 *
 * Mirrors pci_load_module() but for non-PCI filesystems: it loads an ET_REL
 * module (typically `ext4.cctk`) from the staged localbinrepo image, verifies its
 * ECDSA P-256 signature + vermagic tag, relocates it, and resolves the generic
 * `fs_mount` / `fs_unmount` entry symbols.  Up to FS_MOD_MAX modules can be resident at
 * once; mntfs and the /dev/sys mount ioctl select a module by instance name
 * or probe them in registration order.
 *
 * Undefined kernel symbols referenced by the module are resolved through
 * ksym_resolve(), exactly like PCI modules do.
 */

#include "fs_mod.h"
#include "initfs_modblob.h"
#include "ksym.h"
#include "klib.h"
#include "memory.h"
#include "kernel.h"
#include "mod_image.h"
#include "mod_tag.h"
#include "elf.h"

// Linux i386 errno values, returned negated to the /dev/sys module ioctl so
// that modload/modunload can report a real reason (see kmod.c).  The userspace
// wrapper folds a negative result into errno.
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
#ifndef EBUSY
#define EBUSY  16
#endif
#ifndef EEXIST
#define EEXIST 17
#endif
#ifndef ENODEV
#define ENODEV 19
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif

// ELF constants live in elf.h (ELF64 / SHT_RELA).

// Resident module slot
typedef struct {
    int             used;
    char            instance[64];
    uint8_t        *image;
    uint32_t        size;
    fs_mount_fn_t   mount;
    fs_unmount_fn_t unmount;

    char            mounted[FS_MOD_MAX_MOUNTS][BLKDEV_NAME_MAX];
    uint32_t        mount_count;
} fs_slot_t;

static fs_slot_t slots[FS_MOD_MAX];

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
        // strip ".cctk" / ".so" style suffix
        if (c == '.' &&
            (base[i+1] == 'c' || base[i+1] == 's') &&
            base[i+2] == 'c' && base[i+3] == 't' && base[i+4] == 'k')
            break;
        out[i] = c;
    }
    out[i] = '\0';
}

// Shared relocation/entry-point lookup. Returns a freshly kmalloc'd image
// (must be freed by caller on error) or NULL.
static int load_module_image(const char *path, uint8_t **image_out,
                             uint32_t *size_out, fs_mount_fn_t *mount_out,
                             fs_unmount_fn_t *unmount_out) {
    const uint8_t *blob_data = NULL;
    uint32_t       blob_size = 0;
    if (initfs_modblob_get(path, &blob_data, &blob_size) != 0 || !blob_size) {
        pr_err("fsmod: module not found: %s\n", path);
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
        pr_err("fsmod: not a valid ELF64 relocatable (class=%u type=%u machine=%u): %s\n",
               (unsigned)eh->e_ident[EI_CLASS], (unsigned)eh->e_type,
               (unsigned)eh->e_machine, path);
        kfree(elf_data);
        return -2;
    }

    uint64_t sh_tab_end;
    if (__builtin_mul_overflow(eh->e_shnum, eh->e_shentsize, &sh_tab_end) ||
        __builtin_add_overflow(eh->e_shoff, sh_tab_end, &sh_tab_end) ||
        eh->e_shentsize < sizeof(Elf64_Shdr) || sh_tab_end > (uint64_t)file_size) {
        pr_err("fsmod: corrupted section header table (shoff=%llu shnum=%u "
               "shentsize=%u file=%u): %s\n",
               (unsigned long long)eh->e_shoff, (unsigned)eh->e_shnum,
               (unsigned)eh->e_shentsize, (unsigned)file_size, path);
        kfree(elf_data);
        return -3;
    }

    // First pass: calculate total image size and assign section addresses
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
        pr_err("fsmod: bad module image size (%llu bytes): %s\n",
               (unsigned long long)total, path);
        kfree(elf_data);
        return -8;
    }

    // The image lives in the module window (±2 GiB of the kernel), not the heap:
    // its code and data are relocated with 32-bit signed fields.
    uint8_t *image = (uint8_t *)module_image_alloc((size_t)total);
    if (!image) { kfree(elf_data); return -ENOMEM; }
    memset(image, 0, (size_t)total);

    // Copy PROGBITS sections into image
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!sh || !(sh->sh_flags & SHF_ALLOC) || sh->sh_type != SHT_PROGBITS) continue;
        if (sh->sh_offset + sh->sh_size > (uint64_t)file_size) {
            pr_err("fsmod: section %u exceeds file (off=0x%llx size=0x%llx file=0x%x): %s\n",
                   (unsigned)i, (unsigned long long)sh->sh_offset,
                   (unsigned long long)sh->sh_size, (unsigned)file_size, path);
            module_image_free(image, (size_t)total); kfree(elf_data);
            return -8;
        }
        memcpy(image + sh->sh_addr, elf_data + sh->sh_offset, (size_t)sh->sh_size);
    }

    // Locate symbol table and its string table
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
        pr_err("fsmod: no .symtab in %s\n", path);
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -4;
    }
    if (symtab_sh->sh_offset + symtab_sh->sh_size > (uint64_t)file_size) {
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -8;
    }
    Elf64_Shdr *strtab_sh = get_shdr(eh, strtab_idx);
    if (!strtab_sh || strtab_sh->sh_offset + strtab_sh->sh_size > (uint64_t)file_size) {
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -8;
    }
    Elf64_Sym *syms    = (Elf64_Sym *)(elf_data + symtab_sh->sh_offset);
    uint32_t   sym_cnt = (uint32_t)(symtab_sh->sh_size / sizeof(Elf64_Sym));

    // Apply relocations: ELF64 SHT_RELA, the direct relocations a GOT/PLT-free
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
                pr_err("fsmod: relocation symbol index %u >= %u: %s\n",
                       (unsigned)sym_idx, (unsigned)sym_cnt, path);
                module_image_free(image, (size_t)total); kfree(elf_data);
                return -7;
            }
            if (width == 0) {
                pr_err("fsmod: unsupported relocation type %u: %s\n",
                       (unsigned)type, path);
                module_image_free(image, (size_t)total); kfree(elf_data);
                return -7;
            }
            Elf64_Sym *sym = &syms[sym_idx];
            uint64_t   S;
            if (sym->st_shndx == SHN_UNDEF) {
                const char *sym_name = get_str(eh, strtab_idx, sym->st_name);
                if (!sym_name) { module_image_free(image, (size_t)total); kfree(elf_data); return -7; }
                S = (uint64_t)ksym_resolve(sym_name);
                if (S == 0 && ELF64_ST_BIND(sym->st_info) != STB_WEAK) {
                    pr_err("fsmod: unresolved symbol '%s': %s\n", sym_name, path);
                    module_image_free(image, (size_t)total); kfree(elf_data);
                    return -7;
                }
            } else {
                Elf64_Shdr *sym_sh = get_shdr(eh, sym->st_shndx);
                if (!sym_sh || !(sym_sh->sh_flags & SHF_ALLOC)) {
                    pr_err("fsmod: symbol in non-ALLOC section %u: %s\n",
                           (unsigned)sym->st_shndx, path);
                    module_image_free(image, (size_t)total); kfree(elf_data);
                    return -7;
                }
                S = (uint64_t)(uintptr_t)(image + sym_sh->sh_addr + sym->st_value);
            }
            if (rels[r].r_offset + width > target_sh->sh_size) {
                pr_err("fsmod: relocation offset 0x%llx >= section size 0x%llx: %s\n",
                       (unsigned long long)rels[r].r_offset,
                       (unsigned long long)target_sh->sh_size, path);
                module_image_free(image, (size_t)total); kfree(elf_data);
                return -7;
            }
            uint8_t *patch = image + target_sh->sh_addr + rels[r].r_offset;
            elf64_apply_rela(type, patch, S, rels[r].r_addend);
        }
    }

    // Find exported symbols "fs_mount" (required) and "fs_unmount" (optional)
    fs_mount_fn_t   mnt = NULL;
    fs_unmount_fn_t unm = NULL;
    for (uint32_t s = 0; s < sym_cnt; s++) {
        if (ELF64_ST_BIND(syms[s].st_info) != STB_GLOBAL) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC)   continue;
        if (syms[s].st_shndx == SHN_UNDEF) continue;
        const char *sym_name = get_str(eh, strtab_idx, syms[s].st_name);
        if (!sym_name) continue;
        Elf64_Shdr *sym_sh = get_shdr(eh, syms[s].st_shndx);
        if (!sym_sh) continue;
        uintptr_t addr = (uintptr_t)(image + sym_sh->sh_addr + syms[s].st_value);
        if (strcmp((char *)sym_name, "fs_mount") == 0)
            mnt = (fs_mount_fn_t)addr;
        else if (strcmp((char *)sym_name, "fs_unmount") == 0)
            unm = (fs_unmount_fn_t)addr;
    }
    if (!mnt) {
        pr_err("fsmod: symbol 'fs_mount' not found in %s\n", path);
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -5;
    }

    kfree(elf_data);
    *image_out  = image;
    *size_out   = (uint32_t)total;
    *mount_out  = mnt;
    *unmount_out = unm;
    return 0;
}

// load_module_image() codes -> errno for the /dev/sys module ioctl.
static int fs_mod_image_errno(int rc) {
    switch (rc) {
    case -ENOENT: return -ENOENT;   // no such module in the localbinrepo image
    case -ENOMEM: return -ENOMEM;   // relocation image too large
    case -EACCES: return -EACCES;   // HMAC signature rejected
    default:      return -EINVAL;   // not ET_REL / corrupt / unresolved symbol
    }
}

int fs_mod_load(const char *path) {
    if (!path) return -EINVAL;

    int free_slot = -1;
    for (int i = 0; i < FS_MOD_MAX; i++) {
        if (!slots[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
    }
    if (free_slot < 0) {
        pr_err("fsmod: no free filesystem-module slot (max %d) for %s\n",
               (int)FS_MOD_MAX, path);
        return -ENOSPC;
    }

    char inst[64];
    instance_name(path, inst, sizeof(inst));
    for (int i = 0; i < FS_MOD_MAX; i++) {
        if (slots[i].used && strcmp(slots[i].instance, inst) == 0) {
            pr_warn("fsmod: filesystem module already loaded: %s\n", inst);
            return -EEXIST;
        }
    }

    uint8_t        *image = NULL;
    uint32_t        size  = 0;
    fs_mount_fn_t   mnt   = NULL;
    fs_unmount_fn_t unm   = NULL;
    int rc = load_module_image(path, &image, &size, &mnt, &unm);
    if (rc != 0)
        return fs_mod_image_errno(rc);

    fs_slot_t *s = &slots[free_slot];
    memset(s, 0, sizeof(*s));
    strlcpy(s->instance, inst, sizeof(s->instance));
    s->used    = 1;
    s->image   = image;
    s->size    = size;
    s->mount   = mnt;
    s->unmount = unm;
    s->mount_count = 0;

    pr_info("fsmod: module loaded: %s (slot %d)\n", inst, free_slot);
    return 0;
}

static fs_slot_t *slot_by_instance(const char *instance) {
    if (!instance)
        return 0;
    for (int i = 0; i < FS_MOD_MAX; i++)
        if (slots[i].used && strcmp(slots[i].instance, (char *)instance) == 0)
            return &slots[i];
    return 0;
}

static int slot_unload(fs_slot_t *s) {
    if (!s || !s->used)
        return -EINVAL;
    if (s->mount_count > 0) {
        pr_warn("fsmod: module busy (still mounted), not unloading: %s\n",
                s->instance);
        return -EBUSY;
    }
    if (s->image)
        module_image_free(s->image, s->size);
    memset(s, 0, sizeof(*s));
    return 0;
}

int fs_mod_unload(const char *instance) {
    fs_slot_t *s = slot_by_instance(instance);
    if (!s)
        return -ENOENT;
    int rc = slot_unload(s);
    if (rc == 0) {
        pr_info("fsmod: module unloaded: %s\n", instance);
    }
    return rc;
}

int fs_mod_loaded(const char *instance) {
    return slot_by_instance(instance) != 0;
}

const char *fs_mod_instance(int slot) {
    if (slot < 0 || slot >= FS_MOD_MAX || !slots[slot].used)
        return 0;
    return slots[slot].instance;
}

// The two per-module numbers /proc/modules reports: the resident image size
// and the module's user count (devices it currently has mounted).
uint32_t fs_mod_size(int slot) {
    if (slot < 0 || slot >= FS_MOD_MAX || !slots[slot].used)
        return 0;
    return slots[slot].size;
}

int fs_mod_refs(int slot) {
    if (slot < 0 || slot >= FS_MOD_MAX || !slots[slot].used)
        return 0;
    return (int)slots[slot].mount_count;
}

// Remember a successful mount so an unload can be refused while in use.
static void slot_note_mount(fs_slot_t *s, const char *devname) {
    if (!s || !devname)
        return;
    for (uint32_t i = 0; i < s->mount_count; i++)
        if (strcmp(s->mounted[i], (char *)devname) == 0)
            return;
    if (s->mount_count >= FS_MOD_MAX_MOUNTS)
        return;
    strlcpy(s->mounted[s->mount_count], devname, BLKDEV_NAME_MAX);
    s->mount_count++;
}

vfs_node_t *fs_mod_mount_type(blkdev_t *dev, const char *fstype) {
    if (!dev)
        return NULL;

    if (!fstype || fstype[0] == '\0' ||
        strcmp((char *)fstype, "auto") == 0 || strcmp((char *)fstype, "*") == 0)
        return fs_mod_mount(dev);

    fs_slot_t *s = slot_by_instance(fstype);
    if (!s)
        return NULL;
    vfs_node_t *root = s->mount ? s->mount(dev) : NULL;
    if (root)
        slot_note_mount(s, dev->name);
    return root;
}

vfs_node_t *fs_mod_mount(blkdev_t *dev) {
    if (!dev)
        return NULL;
    for (int i = 0; i < FS_MOD_MAX; i++) {
        fs_slot_t *s = &slots[i];
        if (!s->used || !s->mount)
            continue;
        vfs_node_t *root = s->mount(dev);
        if (root) {
            slot_note_mount(s, dev->name);
            return root;
        }
    }
    return NULL;
}

int fs_mod_unmount_dev(blkdev_t *dev) {
    if (!dev)
        return -1;
    int rc = -1;
    for (int i = 0; i < FS_MOD_MAX; i++) {
        fs_slot_t *s = &slots[i];
        if (!s->used)
            continue;
        int removed = 0;
        for (uint32_t m = 0; m < s->mount_count; m++) {
            if (strcmp(s->mounted[m], (char *)dev->name) == 0) {
                // compact
                for (uint32_t k = m; k + 1 < s->mount_count; k++)
                    strlcpy(s->mounted[k], s->mounted[k + 1], BLKDEV_NAME_MAX);
                s->mount_count--;
                removed = 1;
                break;
            }
        }
        if (removed) {
            if (s->unmount)
                s->unmount();
            rc = 0;
        }
    }
    return rc;
}

// Non-destructive probe: scan the ELF symbol table of the module at 'path'
// for an exported global FUNC named 'fs_mount'. Used to auto-detect whether
// modload should treat a .cctk as a filesystem module.
int fs_mod_detect(const char *path) {
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
        if (!sym_name) continue;
        if (strcmp((char *)sym_name, "fs_mount") == 0)
            return 1;
    }
    return 0;
}
