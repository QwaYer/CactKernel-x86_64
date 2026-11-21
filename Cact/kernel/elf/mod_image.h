/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef MOD_IMAGE_H
#define MOD_IMAGE_H

#include <stddef.h>

/* The window a `.cctk` module image is relocated and mapped into: the 1 GiB at
 * the top of the kernel's PML4[511] half, directly above the kernel image's own
 * 1 GiB (PDPT[510]).
 *
 * A module has to live within ±2 GiB of KERNEL_VMA (`0xFFFFFFFF80000000`).  The
 * `-mcmodel=kernel` object the loader expects turns every call to a kernel
 * symbol into a signed 32-bit PC-relative `call rel32` (R_X86_64_PLT32) and
 * every absolute reference to module data into a sign-extended 32-bit immediate
 * (R_X86_64_32S), so both fields only encode across a short distance.  The
 * direct map (`0xFFFF800000000000`) is ~140 TB away, so a heap-resident image
 * cannot be relocated against them at all — the displacement wraps and the call
 * jumps into unbacked physical memory (KVM reports it as an emulation failure).
 * Living under PML4[511] also means the image is mapped under every CR3, so a
 * module probe or IRQ handler runs correctly while any process is current. */
#define MODULE_IMAGE_BASE 0xFFFFFFFFC0000000ull
#define MODULE_IMAGE_END  0xFFFFFFFFFFFFF000ull

/* Reserve `size` bytes in the window and map zeroed, writable supervisor pages
 * for them.  Returns the module VA (page-aligned) or NULL when the window or the
 * frame allocator is exhausted. */
void *module_image_alloc(size_t size);

/* Unmap and free the frames of an image returned by `module_image_alloc`. */
void  module_image_free(void *va, size_t size);

#endif
