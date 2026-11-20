/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_SVM_H
#define CACT_HV_SVM_H

#include <stdint.h>

/* AMD-V (SVM) capability snapshot (read-only; Phase H1). */
typedef struct {
    int      supported;   /* CPUID.80000001h:ECX[2] — SVM available */
    int      enabled;     /* EFER.SVME — already an SVM host */
    int      npt;         /* CPUID.8000000Ah:EDX[0] — nested paging */
    int      locked;      /* VM_CR[3] — VM_CR is read-only */
    int      svm_dis;     /* VM_CR[4] — SVM disabled by firmware */
    uint32_t asid_count;  /* CPUID.8000000Ah:EBX — address space identifiers */
    uint32_t features;    /* CPUID.8000000Ah:EDX — SVM feature flags */
    uint64_t vm_cr;       /* raw MSR 0xC0010114 */
} svm_caps_t;

/* Fill `caps` from CPUID/MSRs.  Reads only; leaves the CPU in host mode. */
void svm_detect(svm_caps_t *caps);

/*
 * Enter SVM host mode on the calling CPU (Phase H2): clear VM_CR.SVMDIS when it
 * is writable, point VM_HSAVE_PA at a scratch page, and set EFER.SVME.  Returns
 * 0 on success, -1 when firmware disabled SVM under lock.  Idempotent per CPU.
 */
int  svm_host_enable(void);

/* Leave SVM host mode on the calling CPU and release the host-save page. */
void svm_host_disable(void);

#endif
