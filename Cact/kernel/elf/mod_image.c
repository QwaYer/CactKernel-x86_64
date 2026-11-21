/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "mod_image.h"
#include "memory.h"
#include "kernel.h"
#include "klib.h"
#include "sync.h"

/* See mod_image.h for why module images live in this window.
 *
 * The allocator is a bump pointer that never reissues a range: a released range
 * would still be in another CPU's TLB (the kernel has no cross-CPU shootdown),
 * and handing it to a different module could send that CPU to the frames the
 * old module owned.  Frames are freed on unload; only the window's VA is
 * consumed, which takes tens of thousands of unloads to exhaust.
 *
 * `image_lock` is a plain zero-initialised spinlock — the unlocked state — and
 * `image_next` starts at the window base, so no init hook is needed and a module
 * can be loaded as early as the kernel likes. */
static uint64_t   image_next = MODULE_IMAGE_BASE;
static spinlock_t image_lock;

void *module_image_alloc(size_t size) {
    if (size == 0)
        return 0;
    if ((uint64_t)size > MODULE_IMAGE_END - MODULE_IMAGE_BASE)
        return 0;

    uint64_t pages = ((uint64_t)size + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t bytes = pages * PAGE_SIZE;

    spin_lock(&image_lock);
    uint64_t va = image_next;
    if (bytes > MODULE_IMAGE_END - va) {
        spin_unlock(&image_lock);
        pr_err("modimg: module image window exhausted (%u bytes)", (unsigned)size);
        return 0;
    }
    image_next = va + bytes;   /* the range is never reissued */
    spin_unlock(&image_lock);

    for (uint64_t off = 0; off < bytes; off += PAGE_SIZE) {
        void *frame = kalloc();
        if (!frame) {
            /* Unwind the pages already mapped and fail the load. */
            for (uint64_t un = 0; un < off; un += PAGE_SIZE) {
                uint64_t phys = vmm_unmap(get_current_pd(), va + un);
                if (phys) free_page(vmm_p2v(phys));
            }
            pr_err("modimg: out of frames for a %u-byte module image",
                   (unsigned)size);
            return 0;
        }
        uint8_t *dst = (uint8_t *)(uintptr_t)(va + off);
        vmm_map(get_current_pd(), va + off, vmm_v2p(frame),
                PAGE_PRESENT | PAGE_RW);
        memset(dst, 0, (unsigned)PAGE_SIZE);
    }
    return (void *)(uintptr_t)va;
}

void module_image_free(void *va, size_t size) {
    if (!va || size == 0)
        return;

    uint64_t base  = (uint64_t)(uintptr_t)va;
    uint64_t pages = ((uint64_t)size + PAGE_SIZE - 1) / PAGE_SIZE;
    for (uint64_t off = 0; off < pages * PAGE_SIZE; off += PAGE_SIZE) {
        uint64_t phys = vmm_unmap(get_current_pd(), base + off);
        if (phys) free_page(vmm_p2v(phys));
    }
}
