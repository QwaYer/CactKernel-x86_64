/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "ept.h"
#include "vmx_insn.h"
#include "cpu_msr.h"
#include "memory.h"

/* IA32_VMX_PROCBASED_CTLS2 (secondary-controls capability, "allowed" bits in
 * the high dword) and IA32_VMX_EPT_VPID_CAP. */
#define IA32_VMX_PROCBASED_CTLS2 0x0000048Bu
#define IA32_VMX_EPT_VPID_CAP    0x0000048Cu

/* IA32_VMX_EPT_VPID_CAP bits (SDM Table 24-7). */
#define EPT_CAP_WB            (1ull << 14)
#define EPT_CAP_INVEPT        (1ull << 20)
#define EPT_CAP_INVEPT_SINGLE (1ull << 25)

/* Secondary processor-based control "enable EPT" (bit 1). */
#define SECONDARY_EXEC_ENABLE_EPT (1ull << 1)

/* INVEPT invalidation types (SDM 30.3): 1 = single-context.  The descriptor is
 * 16 bytes; its EPTP qword is only read for the single-context type. */
#define INVEPT_SINGLE_CONTEXT 1ull

/* EPTP encoding (SDM Table 28-6): bits 2:0 = EPT paging-structure memory type
 * (6 = write-back), bits 5:3 = page-walk length minus one. */
#define EPTP_MEMTYPE_WB 6ull
#define EPTP_WALK_LEN_4 3ull

#define EPT_PAGE_MASK 0x000ffffffffff000ull
#define EPT_PERM_MASK 0x7ull

/* The tables of the live EPT hierarchy, so one teardown returns them all. */
static void *g_ept_pages[64];
static unsigned g_ept_page_count;

/* A zeroed table page, recorded for vmx_ept_free().  kalloc() does not zero. */
static void *ept_alloc(void) {
    if (g_ept_page_count >= sizeof(g_ept_pages) / sizeof(g_ept_pages[0]))
        return 0;
    void *p = kalloc();
    if (!p)
        return 0;
    volatile uint8_t *b = p;
    for (unsigned i = 0; i < 4096; i++)
        b[i] = 0;
    g_ept_pages[g_ept_page_count++] = p;
    return p;
}

/* Next-level table named by `parent[idx]`, allocated and linked on first use.
 * EPT presence is "any of R/W/X set", and the intermediate entry's own
 * permissions are ignored (only the leaf's matter), so 0x7 is safe there. */
static uint64_t *ept_walk(uint64_t *parent, unsigned idx) {
    uint64_t e = parent[idx];
    if (e & EPT_PERM_MASK)
        return vmm_p2v(e & EPT_PAGE_MASK);
    void *t = ept_alloc();
    if (!t)
        return 0;
    parent[idx] = vmm_v2p(t) | EPT_PERM_MASK;
    return t;
}

int vmx_ept_supported(void) {
    uint64_t cap = cpu_rdmsr(IA32_VMX_EPT_VPID_CAP);
    uint64_t want = EPT_CAP_WB | EPT_CAP_INVEPT | EPT_CAP_INVEPT_SINGLE;
    if ((cap & want) != want)
        return 0;
    return (cpu_rdmsr(IA32_VMX_PROCBASED_CTLS2) >> 32) & SECONDARY_EXEC_ENABLE_EPT
               ? 1 : 0;
}

uint64_t vmx_ept_build(const vmx_ept_map_t *maps, unsigned count) {
    void *pml4_page = ept_alloc();
    if (!pml4_page)
        return 0;
    uint64_t *pml4 = pml4_page;

    for (unsigned m = 0; m < count; m++) {
        uint64_t gpa = maps[m].gpa;
        if (gpa & 0xFFFull)
            return 0;
        uint64_t *pdpt = ept_walk(pml4, (unsigned)((gpa >> 39) & 0x1FF));
        if (!pdpt)
            return 0;
        uint64_t *pd = ept_walk(pdpt, (unsigned)((gpa >> 30) & 0x1FF));
        if (!pd)
            return 0;
        uint64_t *pt = ept_walk(pd, (unsigned)((gpa >> 21) & 0x1FF));
        if (!pt)
            return 0;
        unsigned i = (unsigned)((gpa >> 12) & 0x1FF);
        if (pt[i] & EPT_PERM_MASK)
            continue;   /* already mapped; the first mapping wins */
        pt[i] = (maps[m].hpa & EPT_PAGE_MASK) | (maps[m].flags & EPT_PERM_MASK);
    }

    /* Write-back is the only memory type the CPU offers for EPT tables here
     * (vmx_ept_supported() checked the bit), and the hierarchy is 4 levels. */
    return vmm_v2p(pml4_page) | (EPTP_WALK_LEN_4 << 3) | EPTP_MEMTYPE_WB;
}

void vmx_ept_free(void) {
    for (unsigned i = 0; i < g_ept_page_count; i++)
        free_page(g_ept_pages[i]);
    g_ept_page_count = 0;
}

int vmx_ept_invept_single(uint64_t eptp) {
    struct vmx_invept_desc desc = { eptp, 0 };
    return invept(INVEPT_SINGLE_CONTEXT, &desc);
}
