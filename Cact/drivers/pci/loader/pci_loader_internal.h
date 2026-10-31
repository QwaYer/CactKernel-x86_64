#ifndef PCI_LOADER_INTERNAL_H
#define PCI_LOADER_INTERNAL_H

#include <stdint.h>
#include "elf.h"

// Wildcard ID — must match PCI_ANY_ID in pci_driver.h
#define LDR_PCI_ANY_ID 0xFFFFu

// Bookkeeping for a loaded module image
typedef struct {
    uint8_t  *image;
    uint32_t  image_size;
    char      proc_name[64];
} mod_mem_t;

// pci_loader.c — file/section readers shared with the manifest pass.
int  read_rel_elf_from_path(const char *path, uint8_t **elf_data, uint32_t *file_size);
Elf64_Shdr *get_shdr(Elf64_Ehdr *eh, uint16_t idx);
const char *get_str(Elf64_Ehdr *eh, uint16_t strtab_idx, uint32_t off);
uint16_t read_le16(const uint8_t *p);

#endif
