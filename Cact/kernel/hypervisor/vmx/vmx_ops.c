/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "vmx_ops.h"
#include "vmx_insn.h"

int cact_vmclear(uint64_t vmcs_phys) { return vmclear(vmcs_phys); }

int cact_vmptrld(uint64_t vmcs_phys) { return vmptrld(vmcs_phys); }

int cact_vmread(uint64_t field, uint64_t *value) { return vmread(field, value); }

int cact_vmwrite(uint64_t field, uint64_t value) { return vmwrite(field, value); }

int cact_vmlaunch(void) { return vmlaunch(); }

int cact_vmresume(void) { return vmresume(); }
