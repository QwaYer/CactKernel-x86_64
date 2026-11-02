/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>
#include "multiboot2.h"

#define PAGE_SIZE 4096

/* Kernel load address */
#define MEM_START 0x00100000u

/*
 * PCI_HOLE_START is the default physical MMIO base (a board's real RAM/MMIO
 * boundary is discovered at boot), and the floor below which the fixed kernel
 * MMIO windows are placed so they sit in the shared kernel half, clear of every
 * user mapping.
 */
#define PCI_HOLE_START  0xC0000000u

/* The PMM is 64-bit and sizes its free-frame bitmap / refcount arrays at boot
 * from the Multiboot2 map (rust_mm pmm.rs), so there are no compile-time frame
 * counts here any more: RAM above 4 GiB is managed like any other. */

/*
 * Fixed kernel windows (ACPI temp map + PCIe ECAM) live in the shared kernel
 * half (VA >= PCI_HOLE_START), so any mapping there is valid under any CR3.
 * Because of that sharing, two subsystems that pick the same VA silently alias
 * each other's physical pages, so the windows are laid out from one base.
 *
 * The base is chosen at boot by the PMM: max(RAM top, PCI_HOLE_START), 2 MiB
 * aligned — at or above PCI_HOLE_START the windows land in the shared kernel
 * half, where no user VA can collide with them.
 */
uint32_t cact_mmio_window_base(void);               /* rust_mm: pmm.rs */
#define KERNEL_MMIO_WINDOW_SIZE (256u * PAGE_SIZE)  /* 1 MB */

/*
 * Heap window.  The heap allocator starts right after the hard-reserved
 * low-memory zone so kmalloc() never overlaps kernel-reserved pages.
 *
 * HEAP_START/RESERVED_END are the *floor*.  The PMM raises the boundary past
 * the Multiboot2 module images at boot (GRUB loads them into ordinary available
 * RAM, and the localrepo archive is served to userspace in place out of it), so
 * the heap window starts directly above whatever the boot reservation covers.
 * These macros are therefore only valid before pmm_reserve_boot_images() runs;
 * ask the PMM (pmm.rs reserved_end/heap_start/heap_end) for the live values.
 */
#define HEAP_START (512u * 1024u * 1024u)   /* 0x20000000 */
#define HEAP_SIZE  (16u * 1024u * 1024u)   /* 16 MB heap window */
#define HEAP_MAGIC 0xDEADBEEFu

/* Hard reservation floor: nothing below RESERVED_END is given to kalloc() or
 * the heap, whatever the boot reservation turns out to be.  It clears the
 * whole kernel image including the cctkfs staging buffer in .bss
 * (INITFS_MODBLOB_MAX_IMAGE, 24 MiB) *and* the low user VA region
 * (USER_HEAP_START … the reachable brk end, i.e. the ELF image + heap), which
 * overlaps the reservation. */
#define RESERVED_END (512u * 1024u * 1024u)

#define PAGE_PRESENT 0x1
#define PAGE_RW      0x2
#define PAGE_USER    0x4
#define PAGE_PWT     0x8   /* write-through cache policy for MMIO mappings */
#define PAGE_PCD     0x10  /* cache-disable for MMIO/device memory          */
#define PAGE_PAT     0x80  /* PAT bit (selects PAT entry 4 = WC when PCD|PWT=0) */


void      pmm_init_from_mmap(const mb2_mmap_table_t* mmap);
/* rust_mm: pmm.rs — reserve the bootloader's module RAM, returns the boundary. */
uint32_t  pmm_reserve_boot_images(uint32_t end);
void      init_memory_manager(void);
void*     kalloc(void);
void      free_page(void* ptr);
void      init_paging(void);
void      init_heap(void);
void*     kmalloc(uint32_t size);
void*     kmalloc_aligned(uint32_t size, uint32_t align);
void      kfree(void* ptr);
void      kfree(void* ptr);
uint32_t  get_free_heap_memory(void);
uint32_t  pmm_total_frames(void);
uint32_t  pmm_free_frames(void);
void      vmm_map(uint64_t* pd, uint64_t virtual_addr, uint64_t physical_addr, int flags);
uint64_t  vmm_get_phys(uint64_t* pd, uint64_t virtual_addr);
/* Physical address behind a pointer the kernel can dereference (rust_mm
 * paging.rs: v2p).  The kernel addresses its own frames through the direct map,
 * so a `kalloc`'d frame — or anything else it holds a pointer to — has to come
 * back through here before its numeric value goes into a page-table entry. */
uint64_t  vmm_v2p(const void* ptr);
/* Virtual address at which physical `phys` is reachable (rust_mm paging.rs:
 * p2v — DIRECT_MAP_BASE + phys).  An address read out of a page-table entry, or
 * out of vmm_get_phys(), is dereferenceable only after this translation. */
void*     vmm_p2v(uint64_t phys);
/* Low flag bits of the mapping for `virt` (0 when unmapped); the fault and
 * diagnostic paths need the permission bits, not the frame. */
uint32_t  vmm_pte_flags(uint64_t* pd, uint64_t virt);
/* Clear the 4 KiB mapping for `virt`; returns the frame it named (0 if none). */
uint64_t  vmm_unmap(uint64_t* pd, uint64_t virt);
void      vmm_sync_kernel_mmio_mappings(uint64_t* pd);
/* Set/clear cache-attribute bits on the kernel's own mapping for `va`
 * (rust_mm: paging.rs).  The kernel maps with 2 MiB pages, so this reaches the
 * page-directory entry when there is no PTE; pat.c uses it for write-combining
 * framebuffer pages. */
void      vmm_set_kernel_cache(uint64_t va, uint64_t set, uint64_t clear);
uint64_t* vmm_create_address_space(void);
void      vmm_free_address_space(uint64_t* pd);
void      vmm_copy_address_space(uint64_t* src_pd, uint64_t* dst_pd);
extern void load_page_directory(uint64_t* directory);
extern void enable_paging(void);

#endif
