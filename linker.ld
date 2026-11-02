/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/* The image is loaded by GRUB at 1 MiB and entered in 32-bit protected mode,
   so .boot -- the multiboot2 header and the code that builds the page tables
   and turns long mode on -- is linked at that physical address.  Everything
   after it is linked for the top 2 GiB, where the bootstrap's page tables map
   it, with the load address left where GRUB put it.  See Cact/kernel/core/
   kernel.asm for the two views of memory this produces, and PORTING-x86_64.md
   decision 4 for why the kernel lives high. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_LMA = 1M;
KERNEL_VMA = 0xFFFFFFFF80000000;

SECTIONS {
    . = KERNEL_LMA;

    .boot BLOCK(4K) : ALIGN(4K) {
        *(.multiboot)
        *(.boot)
    }

    /* Everything the bootstrap reads or writes after the tables are built:
       the temporary GDT and the 64-bit pointers into the higher half.  Its own
       page, so the loader does not have to merge it into the code segment as
       read-write-execute. */
    .boot.data BLOCK(4K) : ALIGN(4K) {
        *(.boot.data)
    }

    /* Page tables: written before they are used, so they never need to be
       loaded from the file. */
    .boot.bss BLOCK(4K) (NOLOAD) : ALIGN(4K) {
        *(.boot.bss)
    }

    /* Same physical offset, higher-half address: the load address stays
       contiguous while the location counter jumps. */
    . += KERNEL_VMA;

    .text BLOCK(4K) : AT(ADDR(.text) - KERNEL_VMA) ALIGN(4K) {
        *(.text)
    }

    .rodata BLOCK(4K) : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4K) {
        *(.rodata)
    }

    .data BLOCK(4K) : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4K) {
        *(.data)
    }

    .bss BLOCK(4K) : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4K) {
        *(COMMON)
        *(.bss)
    }

    /* The bootstrap zeroes this range itself: a multiboot2 loader is only
       obliged to load file-backed bytes, and the kernel assumes .bss starts as
       zero (page tables, allocator bitmaps, the log ring). */
    __bss_start = ADDR(.bss);
    __bss_end   = ADDR(.bss) + SIZEOF(.bss);
}
