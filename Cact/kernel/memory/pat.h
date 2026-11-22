/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef PAT_H
#define PAT_H

#include <stdint.h>

/*
 * Page Attribute Table (PAT) driver — per-page memory type via the PAT bit.
 *
 * The implementation lives in Rust (memory/rust_mm/src/vmm/pat.rs, exported with
 * C linkage); this header is the C-side declaration of its two entry points.
 * PAT entry 4 (WC) is the one the framebuffer mapping selects — the encoding
 * table, the MSR programming and the resume rationale are documented there.
 *
 * Usage:
 *   1. Call pat_init() early during boot to program the IA32_PAT MSR.
 *   2. Call pat_enable_wc_for_framebuffer() to set PAT|~PCD|~PWT on FB PTEs.
 */

/*
 * Detect PAT support via CPUID, program PAT entry 4 to Write-Combining, and
 * log the capability once.  Safe to call before any framebuffer activity, and
 * again after a resume (which silently restores the MSR).
 */
void pat_init(void);

/*
 * Mark the framebuffer range as Write-Combining by setting the PAT bit
 * and clearing PCD|PWT on every page in
 * [fb_va, fb_va + pitch*height).  That selects PAT entry 4, which
 * pat_init() programs to WC.
 *
 * `fb_va` is the framebuffer's *virtual* address (the direct-map VA
 * fb_get_buffer() returns), not its physical address: the mapping the kernel
 * itself uses is the one whose cache policy matters.
 *
 * Also used after a resume to re-apply the bits and flush the stale
 * translations, so the framebuffer is not left write-back.
 *
 * Returns 0 on success, negative on error:
 *   -1  PAT not supported
 *   -2  invalid arguments
 */
int  pat_enable_wc_for_framebuffer(uint64_t fb_va,
                                    uint32_t fb_pitch,
                                    uint32_t fb_height);

#endif
