/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMX_LAUNCH_H
#define CACT_HV_VMX_LAUNCH_H

#include <stdint.h>

/*
 * The guest-launch primitive and the VM-exit entry point (Phase H3.2).
 *
 * `cact_vmx_launch` runs VMLAUNCH on the current VMCS.  VMLAUNCH never returns
 * normally on success: the first VMLAUNCH exit is a VM exit, which the CPU
 * delivers to HOST_RIP (the stub below) on HOST_RSP.  The stub saves the guest
 * GPRs, calls the model's `hv_vmx_exit_entry()`, and acts on its verdict:
 *
 *   0 — the run is over; return to `cact_vmx_launch`'s caller as if the launch
 *       had returned 0.
 *   1 — the exit was handled and the guest is to continue; restore the (possibly
 *       edited) GPR frame and re-enter with VMRESUME.  The next VM exit lands on
 *       the same HOST_RIP/HOST_RSP, so one VMLAUNCH drives a whole run.
 */

/* Run the guest.  Returns 0 once a VM exit has been handled and the model
 * asked to finish; non-zero when VMLAUNCH itself failed (the guest never ran,
 * and the reason is in the VMCS VM-instruction-error field). */
int cact_vmx_launch(void);

/* Like cact_vmx_launch(), but first loads the guest's initial general-purpose
 * registers from `regs`, an array of 15 uint64_t in the order
 *   rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 * (RSP and the rest come from the VMCS).  Same return contract. */
int cact_vmx_launch_regs(const uint64_t *regs);

/* Address of the VM-exit stub, for HOST_RIP. */
uint64_t cact_vmx_exit_stub_addr(void);

/* Snapshot the host CPU state the VMCS host-state area needs.  `out` needs
 * room for 16 uint64_t:
 *   [0]cs [1]ss [2]ds [3]es [4]fs [5]gs [6]tr
 *   [7]fs_base [8]gs_base [9]tr_base [10]gdtr_base [11]idtr_base
 *   [12]cr0 [13]cr3 [14]cr4 [15]rflags
 */
void cact_cpu_state_snapshot(uint64_t *out);

#endif
