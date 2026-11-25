/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "pci_loader.h"
#include "pci_loader_internal.h"
#include "pci_driver.h"
#include "pci_enum.h"
#include "initfs_modblob.h"
#include "tarmod.h"
#include "localbinrepo.h"
#include "vfs.h"
#include "memory.h"
#include "kernel.h"
#include "klib.h"
#include "ksym.h"
#include "mod_image.h"
#include "mod_tag.h"

static void module_proc_name(const char *path, char *out, int out_sz) {
    const char *base = path;
    for (const char *p = path; p && *p; p++)
        if (*p == '/') base = p + 1;

    int i = 0;
    while (base[i] && i < out_sz - 1) {
        out[i] = (base[i] == ' ') ? '_' : base[i];
        i++;
    }
    out[i] = '\0';
}

// Return pointer to section header 'idx'
Elf64_Shdr *get_shdr(Elf64_Ehdr *eh, uint16_t idx) {
    if (idx >= eh->e_shnum)
        return NULL;
    return (Elf64_Shdr *)((uint8_t *)eh + eh->e_shoff + idx * eh->e_shentsize);
}

// Return string from string table 'strtab_idx' at offset 'off'
const char *get_str(Elf64_Ehdr *eh, uint16_t strtab_idx, uint32_t off) {
    Elf64_Shdr *sh = get_shdr(eh, strtab_idx);
    if (!sh)
        return NULL;
    return (const char *)((uint8_t *)eh + sh->sh_offset + off);
}

uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

// Read ET_REL file from VFS into kmalloc'd buffer; validate header.
// In-memory blobs (objcopy'd from LocalRepoCactOS/lib) take priority so that
// modules can load before VFS is up.
// Returns 0 on success; -1 open/read/alloc; -2 bad ELF.
int read_rel_elf_from_path(const char *path, uint8_t **elf_data, uint32_t *file_size) {
    const uint8_t *blob_data = NULL;
    uint32_t       blob_size = 0;

    if (modsrc_get(path, &blob_data, &blob_size) == 0) {
        if (!blob_size)
            return -1;
        uint8_t *buf = (uint8_t *)kmalloc(blob_size);
        if (!buf)
            return -1;
        memcpy(buf, blob_data, blob_size);

        Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
        if (!elf64_is_rel_object(eh)) {
            kfree(buf);
            return -2;
        }
        *elf_data  = buf;
        *file_size = blob_size;
        return 0;
    }

    struct vfs_node *node = vfs_resolve_path(path);
    if (!node)
        return -1;

    uint32_t fsz = node->size;
    if (!fsz) {
        vfs_node_unref(node);
        return -1;
    }

    uint8_t *buf = (uint8_t *)kmalloc(fsz);
    if (!buf) {
        vfs_node_unref(node);
        return -1;
    }

    int br = read_vfs(node, 0, fsz, (char *)buf);
    if (br <= 0) {
        kfree(buf);
        vfs_node_unref(node);
        return -1;
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (!elf64_is_rel_object(eh)) {
        kfree(buf);
        vfs_node_unref(node);
        return -2;
    }

    *elf_data   = buf;
    *file_size  = fsz;
    vfs_node_unref(node);
    return 0;
}

// Load a relocatable ELF module, relocate it into a private image,
// find the exported symbol "pci_driver_probe", and wire it into 'drv'.
int pci_load_module(const char *path, struct pci_driver *drv) {

    pr_debug("pciloader: loading module: %s", path);

    uint8_t *elf_data = NULL;
    uint32_t file_size = 0;
    int      rr        = read_rel_elf_from_path(path, &elf_data, &file_size);
    if (rr == -1) {
        pr_err("pciloader: module file not found: %s\n", path);
        return -1;
    }
    if (rr == -2) {
        pr_err("pciloader: not an ELF64 relocatable: %s\n", path);
        return -2;
    }
    if (mod_tag_verify(elf_data, &file_size) != 0) {
        pr_err("pciloader: signature/ABI check failed: %s\n", path);
        kfree(elf_data);
        return -8;
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf_data;

    // Validate section header table fits in file
    uint64_t sh_tab_end;
    if (__builtin_mul_overflow(eh->e_shnum, eh->e_shentsize, &sh_tab_end) ||
        __builtin_add_overflow(eh->e_shoff, sh_tab_end, &sh_tab_end) ||
        eh->e_shentsize < sizeof(Elf64_Shdr) || sh_tab_end > (uint64_t)file_size) {
        pr_err("pciloader: corrupted module ELF: %s\n", path);
        kfree(elf_data);
        return -8;
    }

    // First pass: calculate total image size and assign section addresses
    uint64_t total = 0;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!(sh->sh_flags & SHF_ALLOC)) continue;
        uint64_t align = sh->sh_addralign ? sh->sh_addralign : 1;
        if (align & (align - 1)) align = 1;
        total = (total + align - 1) & ~(align - 1);
        sh->sh_addr = total;
        total += sh->sh_size;
    }
    if (total == 0 || total > 0xFFFFFFFFull) {
        pr_err("pciloader: bad module image size (%llu bytes): %s\n",
               (unsigned long long)total, path);
        kfree(elf_data);
        return -8;
    }

    // Allocate and zero the module private image.  It is mapped in the module
    // window (within ±2 GiB of the kernel image), not the heap: its code and
    // data are relocated with 32-bit signed fields the direct map cannot reach.
    uint8_t *image = (uint8_t *)module_image_alloc((size_t)total);
    if (!image) {
        pr_err("pciloader: module image alloc failed (%llu bytes)",
               (unsigned long long)total);
        kfree(elf_data); return -3;
    }
    memset(image, 0, (size_t)total);

    // Copy PROGBITS sections into image
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type != SHT_PROGBITS) continue;
        if (sh->sh_offset + sh->sh_size > (uint64_t)file_size) {
            pr_err("pciloader: section %u exceeds file (off=0x%llx size=0x%llx file=0x%x): %s\n",
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
        if (sh->sh_type == SHT_SYMTAB) {
            symtab_sh  = sh;
            strtab_idx = (uint16_t)sh->sh_link;
            break;
        }
    }
    if (!symtab_sh) {
        pr_err("pciloader: no .symtab in %s\n", path);
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -4;
    }

    if (symtab_sh->sh_offset + symtab_sh->sh_size > (uint64_t)file_size) {
        pr_err("pciloader: symtab exceeds file (off=0x%llx size=0x%llx file=0x%x): %s\n",
               (unsigned long long)symtab_sh->sh_offset,
               (unsigned long long)symtab_sh->sh_size, (unsigned)file_size, path);
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -8;
    }
    Elf64_Shdr *strtab_sh = get_shdr(eh, strtab_idx);
    if (!strtab_sh || strtab_sh->sh_offset + strtab_sh->sh_size > (uint64_t)file_size) {
        pr_err("pciloader: strtab exceeds file (idx=%u file=0x%x): %s\n",
               (unsigned)strtab_idx, (unsigned)file_size, path);
        module_image_free(image, (size_t)total); kfree(elf_data);
        return -8;
    }

    Elf64_Sym *syms    = (Elf64_Sym *)(elf_data + symtab_sh->sh_offset);
    uint32_t   sym_cnt = (uint32_t)(symtab_sh->sh_size / sizeof(Elf64_Sym));

    // Apply relocations: ELF64 SHT_RELA, the direct relocations a GOT/PLT-free
    // (-mcmodel=kernel) object emits — intra-module and against ksym exports.
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *sh = get_shdr(eh, i);
        if (sh->sh_type != SHT_RELA) continue;
        Elf64_Shdr *target_sh = get_shdr(eh, sh->sh_info);
        if (!target_sh || !(target_sh->sh_flags & SHF_ALLOC)) continue;
        Elf64_Rela *rels    = (Elf64_Rela *)(elf_data + sh->sh_offset);
        uint32_t    rel_cnt = (uint32_t)(sh->sh_size / sizeof(Elf64_Rela));
        for (uint32_t r = 0; r < rel_cnt; r++) {
            uint32_t   sym_idx = ELF64_R_SYM(rels[r].r_info);
            uint32_t   type    = ELF64_R_TYPE(rels[r].r_info);
            uint32_t   width   = elf64_rela_width(type);
            if (sym_idx >= sym_cnt) {
                pr_err("pciloader: relocation symbol index %u >= %u: %s\n",
                       (unsigned)sym_idx, (unsigned)sym_cnt, path);
                module_image_free(image, (size_t)total);
                kfree(elf_data);
                return -7;
            }
            if (width == 0) {
                pr_err("pciloader: unsupported relocation type %u: %s\n",
                       (unsigned)type, path);
                module_image_free(image, (size_t)total);
                kfree(elf_data);
                return -7;
            }
            Elf64_Sym *sym = &syms[sym_idx];
            uint64_t   S;

            if (sym->st_shndx == SHN_UNDEF) {
                const char *sym_name = get_str(eh, strtab_idx, sym->st_name);
                if (!sym_name) {
                    pr_err("pciloader: bad string table index (name %u): %s\n",
                           (unsigned)sym->st_name, path);
                    module_image_free(image, (size_t)total);
                    kfree(elf_data);
                    return -7;
                }
                S = (uint64_t)ksym_resolve(sym_name);
                if (S == 0 && ELF64_ST_BIND(sym->st_info) != STB_WEAK) {
                    pr_err("pciloader: unresolved symbol '%s': %s", (char *)sym_name, path);
                    module_image_free(image, (size_t)total);
                    kfree(elf_data);
                    return -7;
                }
            } else {
                Elf64_Shdr *sym_sh = get_shdr(eh, sym->st_shndx);
                if (!sym_sh) {
                    pr_err("pciloader: symbol section index %u out of bounds: %s\n",
                           (unsigned)sym->st_shndx, path);
                    module_image_free(image, (size_t)total);
                    kfree(elf_data);
                    return -7;
                }
                if (!(sym_sh->sh_flags & SHF_ALLOC)) {
                    pr_err("pciloader: symbol in non-ALLOC section %u: %s\n",
                           (unsigned)sym->st_shndx, path);
                    module_image_free(image, (size_t)total);
                    kfree(elf_data);
                    return -7;
                }
                S = (uint64_t)(uintptr_t)(image + sym_sh->sh_addr + sym->st_value);
            }
            if (rels[r].r_offset + width > target_sh->sh_size) {
                pr_err("pciloader: relocation offset 0x%llx >= section size 0x%llx: %s\n",
                       (unsigned long long)rels[r].r_offset,
                       (unsigned long long)target_sh->sh_size, path);
                module_image_free(image, (size_t)total);
                kfree(elf_data);
                return -7;
            }
            uint8_t *patch = image + target_sh->sh_addr + rels[r].r_offset;
            elf64_apply_rela(type, patch, S, rels[r].r_addend);
        }
    }

    // Find exported symbol "pci_driver_probe" (STB_GLOBAL, STT_FUNC)
    typedef int (*probe_fn_t)(pci_device_t *);
    probe_fn_t found_probe = NULL;

    for (uint32_t s = 0; s < sym_cnt; s++) {
        if (ELF64_ST_BIND(syms[s].st_info) != STB_GLOBAL) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC)   continue;
        const char *sym_name = get_str(eh, strtab_idx, syms[s].st_name);
        if (!sym_name || strcmp((char *)sym_name, "pci_driver_probe") != 0) continue;
        if (syms[s].st_shndx == SHN_UNDEF) continue;
        Elf64_Shdr *sym_sh = get_shdr(eh, syms[s].st_shndx);
        if (!sym_sh) continue;
        found_probe = (probe_fn_t)(image + sym_sh->sh_addr + syms[s].st_value);
        break;
    }

    if (!found_probe) {
        pr_err("pciloader: symbol 'pci_driver_probe' not found in %s\n", path);
        module_image_free(image, (size_t)total);
        kfree(elf_data);
        return -5;
    }

    drv->probe = found_probe;

    typedef void (*remove_fn_t)(pci_device_t *);
    remove_fn_t found_remove = NULL;
    for (uint32_t s = 0; s < sym_cnt; s++) {
        if (ELF64_ST_BIND(syms[s].st_info) != STB_GLOBAL) continue;
        if (ELF64_ST_TYPE(syms[s].st_info) != STT_FUNC)   continue;
        const char *sym_name = get_str(eh, strtab_idx, syms[s].st_name);
        if (!sym_name || strcmp((char *)sym_name, "pci_driver_remove") != 0) continue;
        if (syms[s].st_shndx == SHN_UNDEF) continue;
        Elf64_Shdr *sym_sh = get_shdr(eh, syms[s].st_shndx);
        if (!sym_sh) continue;
        found_remove = (remove_fn_t)(image + sym_sh->sh_addr + syms[s].st_value);
        break;
    }
    drv->remove = found_remove;

    // Bookkeeping: store image pointer so it can be freed on unload
    mod_mem_t *mm  = (mod_mem_t *)kmalloc(sizeof(mod_mem_t));
    if (!mm) {
        pr_err("pciloader: module bookkeeping alloc failed for %s", path);
        module_image_free(image, (size_t)total);
        kfree(elf_data);
        drv->probe = NULL;
        return -6;
    }
    mm->image      = image;
    mm->image_size = (uint32_t)total;
    module_proc_name(path, mm->proc_name, sizeof(mm->proc_name));
    drv->priv      = mm;
    drv->flags    |= PCI_DRV_F_RELOC_MODULE;

    kfree(elf_data);   // ELF header no longer needed
    printk("pciloader: module ready: "); printk(mm->proc_name);

    return 0;
}

// Unload a previously loaded module: call remove (if any), free image and bookkeeping
void pci_unload_module(struct pci_driver *drv) {
    if (!drv || !drv->priv) return;
    mod_mem_t *mm = (mod_mem_t *)drv->priv;
    if (drv->remove) drv->remove(NULL);
    module_image_free(mm->image, mm->image_size);
    kfree(mm);
    drv->priv   = NULL;
    drv->probe  = NULL;
    drv->remove = NULL;
    drv->flags &= ~PCI_DRV_F_RELOC_MODULE;
    pr_info("pciloader: module unloaded: %s", drv->name);
}

// Resident image size reported by /proc/modules.  Built-in drivers carry no
// image, so they read as 0.
uint32_t pci_module_image_size(const struct pci_driver *drv) {
    if (!drv || !drv->priv)
        return 0;
    if (!(drv->flags & PCI_DRV_F_RELOC_MODULE))
        return 0;
    const mod_mem_t *mm = (const mod_mem_t *)drv->priv;
    return mm->image_size;
}
