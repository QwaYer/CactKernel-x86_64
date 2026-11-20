/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMX_EPT_H
#define CACT_HV_VMX_EPT_H

#include <stdint.h>

/*
 * Intel EPT (Extended Page Tables) — Phase H4.
 *
 * A guest that runs with its own 4-level paging is translated twice: GVA -> GPA
 * by the guest's CR3, and GPA -> HPA by EPT, which the host alone controls.
 * Without EPT the guest's "physical" addresses are host physical addresses and
 * a guest can touch any frame the host did not hand it; with EPT the host owns
 * the second translation and can hand out GPAs that name, or refuse, whatever
 * it likes.
 *
 * These are the low-level pieces: the capability probe, the 4-level hierarchy
 * builder, its teardown, and INVEPT.  What to map — which GPA names which frame
 * — is the model layer's call (Rust), which then writes the returned EPTP into
 * the VMCS.
 */

/* Leaf/intermediate permission bits (SDM Table 28-1). */
#define VMX_EPT_R 0x1u
#define VMX_EPT_W 0x2u
#define VMX_EPT_X 0x4u

typedef struct {
    uint64_t gpa;     /* guest-physical page base (4 KiB aligned) */
    uint64_t hpa;     /* host-physical page backing it (4 KiB aligned) */
    uint32_t flags;   /* VMX_EPT_R | VMX_EPT_W | VMX_EPT_X */
} vmx_ept_map_t;

/* Non-zero when the CPU offers EPT with the pieces this module needs: WB EPT
 * memory and INVEPT single-context.  (INVEPT is not optional: the EPT TLB is
 * tagged by EPTP, and reusing an EPTP value across runs would otherwise serve
 * stale GPA -> HPA translations.) */
int vmx_ept_supported(void);

/*
 * Build a 4-level EPT hierarchy mapping each `maps[i]` GPA -> HPA and return the
 * EPTP to store in VMCS_EPT_POINTER.  Returns 0 on failure (out of memory, or a
 * misaligned GPA).  The tables stay live until vmx_ept_free(); a second build
 * without a free leaks the first.
 */
uint64_t vmx_ept_build(const vmx_ept_map_t *maps, unsigned count);

/* Release the tables built by vmx_ept_build().  Safe with none built. */
void vmx_ept_free(void);

/* 4 KiB pages currently held by the live EPT hierarchy (0 when none is built).
 * Reported by /proc/meminfo as part of PageTables. */
uint32_t vmx_ept_table_pages(void);

/* 4 KiB guest frames the live EPT maps into the guest's physical address space
 * (one per distinct GPA leaf).  This is the guest's RAM as the hypervisor backs
 * it — reported by /proc/meminfo as GuestMemory. */
uint32_t vmx_ept_leaf_pages(void);

/* Invalidate cached EPT translations for `eptp` (INVEPT single-context).
 * Returns 0 on success. */
int vmx_ept_invept_single(uint64_t eptp);

#endif
