/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "hypervisor.h"
#include "vmx.h"
#include "ept.h"
#include "svm.h"
#include "kernel.h"

static uint32_t g_caps  = HV_CAP_NONE;
static int      g_guest = 0;

int hypervisor_init(void) {
    uint32_t eax, ebx, ecx, edx;

    /* CPUID.1:ECX[31] — some hypervisor is hosting us (the nested case). */
    cact_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    g_guest = (ecx & CPU_FEATURE_HYPERVISOR) != 0;

    vmx_caps_t vmx;
    svm_caps_t svm;
    vmx_detect(&vmx);
    svm_detect(&svm);

    if (vmx.supported)
        g_caps |= HV_CAP_VMX;
    if (svm.supported)
        g_caps |= HV_CAP_SVM;

    if (g_guest)
        pr_info("%s: running as a guest under a hypervisor\n", "hv");

    if (vmx.supported) {
        pr_info("%s: vmx present (VMCS rev 0x%08x, region %u B, feature_control 0x%08x)%s\n",
                "hv", vmx.revision_id, vmx.region_size,
                (unsigned)(vmx.feature_control & 0xFFFFFFFFu),
                vmx.enabled ? "" : " — VMXON locked out");
    }

    if (svm.supported) {
        pr_info("%s: svm present (npt=%u, asid=%u, vm_cr 0x%08x)%s%s\n",
                "hv", (unsigned)svm.npt, svm.asid_count,
                (unsigned)(svm.vm_cr & 0xFFFFFFFFu),
                svm.locked ? " locked" : "",
                svm.svm_dis ? " svm-disabled" : "");
    }

    if (g_caps == HV_CAP_NONE)
        pr_info("%s: no hardware virtualization extension — host mode unavailable\n",
                "hv");

    return 0;
}

uint32_t hv_capabilities(void) { return g_caps; }

uint32_t hv_ptable_pages(void) {
    /* Host-side nested page tables: the EPT hierarchy on Intel (SVM/NPT will
     * add its own when built).  The guest's own page tables are guest memory,
     * not host page tables — see hv_guest_memory_pages(). */
    return vmx_ept_table_pages();
}

uint32_t hv_guest_memory_pages(void) {
    /* Guest-physical frames the hypervisor currently backs (EPT leaves). */
    return vmx_ept_leaf_pages();
}

int hv_running_as_guest(void) { return g_guest; }
