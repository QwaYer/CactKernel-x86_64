/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "svm.h"
#include "kernel.h"
#include "cpu_msr.h"
#include "memory.h"

/* AMD long-mode / SVM MSRs. */
#define AMD_EFER        0xC0000080u
#define AMD_EFER_SVME   (1u << 12)
#define AMD_VM_CR       0xC0010114u
#define AMD_VM_HSAVE_PA 0xC0010117u

/* VM_CR bits. */
#define VM_CR_LOCK   (1u << 3)  /* [3] — VM_CR is read-only       */
#define VM_CR_SVMDIS (1u << 4)  /* [4] — SVM disabled by firmware */

/* CPUID.8000000Ah:EDX feature bits. */
#define SVM_FEATURE_NPT (1u << 0)  /* nested paging */

/* The host-save area VM_HSAVE_PA points at, or NULL when not an SVM host. */
static void *g_hsave_area = NULL;

void svm_detect(svm_caps_t *caps) {
    uint32_t eax, ebx, ecx, edx;

    /* CPUID.80000001h:ECX[2] — SVM is available. */
    ecx = 0;
    cact_cpuid(0x80000001u, 0, &eax, &ebx, &ecx, &edx);
    caps->supported = (ecx & (1u << 2)) != 0;
    if (!caps->supported)
        return;

    /* EFER.SVME — set once a hypervisor has put this CPU into SVM host mode. */
    caps->enabled = (cpu_rdmsr(AMD_EFER) & AMD_EFER_SVME) != 0;

    /* CPUID.8000000Ah — SVM capabilities: EBX = ASID count, EDX = features. */
    cact_cpuid(0x8000000Au, 0, &eax, &ebx, &ecx, &caps->features);
    caps->asid_count = ebx;
    caps->npt = (caps->features & SVM_FEATURE_NPT) != 0;

    caps->vm_cr = cpu_rdmsr(AMD_VM_CR);
    caps->locked = (caps->vm_cr & VM_CR_LOCK) != 0;
    caps->svm_dis = (caps->vm_cr & VM_CR_SVMDIS) != 0;
}

int svm_host_enable(void) {
    if (g_hsave_area)
        return 0;   /* already an SVM host on this CPU */

    uint64_t efer = cpu_rdmsr(AMD_EFER);
    if (efer & AMD_EFER_SVME)
        return 0;   /* already enabled out-of-band */

    uint64_t vmcr = cpu_rdmsr(AMD_VM_CR);
    if (vmcr & VM_CR_LOCK) {
        if (vmcr & VM_CR_SVMDIS)
            return -1;   /* firmware disabled SVM and locked the MSR */
    } else if (vmcr & VM_CR_SVMDIS) {
        cpu_wrmsr(AMD_VM_CR, vmcr & ~VM_CR_SVMDIS);
    }

    /* EFER.SVME may only be set while VM_HSAVE_PA holds a valid page. */
    void *hsave = kalloc();
    if (!hsave)
        return -1;
    cpu_wrmsr(AMD_VM_HSAVE_PA, vmm_v2p(hsave));
    cpu_wrmsr(AMD_EFER, efer | AMD_EFER_SVME);

    g_hsave_area = hsave;
    return 0;
}

void svm_host_disable(void) {
    if (!g_hsave_area)
        return;

    cpu_wrmsr(AMD_EFER, cpu_rdmsr(AMD_EFER) & ~AMD_EFER_SVME);
    free_page(g_hsave_area);
    g_hsave_area = NULL;
}

int svm_host_self_test(void) {
    if (svm_host_enable() != 0)
        return -1;
    if (!(cpu_rdmsr(AMD_EFER) & AMD_EFER_SVME)) {
        svm_host_disable();
        return -1;
    }
    svm_host_disable();
    return 0;
}
