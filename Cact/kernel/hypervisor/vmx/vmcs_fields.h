/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_HV_VMCS_FIELDS_H
#define CACT_HV_VMCS_FIELDS_H

/*
 * VMCS field encodings (Intel SDM Vol. 3C, Table 24-1) — the 32-bit values
 * VMREAD/VMWRITE take as their field selector.  Kept in one header so the model
 * layer never spells a magic number.
 *
 * The encoding packs the access width in bits 15:13 and the field index in
 * bits 14:0, which is why the constants below look strided (0x0802, 0x6802, …).
 */

/* ---- 16-bit fields ---------------------------------------------------- */
#define VMCS_VIRTUAL_PROCESSOR_ID      0x0000u

#define VMCS_GUEST_ES_SELECTOR         0x0800u
#define VMCS_GUEST_CS_SELECTOR         0x0802u
#define VMCS_GUEST_SS_SELECTOR         0x0804u
#define VMCS_GUEST_DS_SELECTOR         0x0806u
#define VMCS_GUEST_FS_SELECTOR         0x0808u
#define VMCS_GUEST_GS_SELECTOR         0x080Au
#define VMCS_GUEST_LDTR_SELECTOR       0x080Cu
#define VMCS_GUEST_TR_SELECTOR         0x080Eu

#define VMCS_HOST_ES_SELECTOR          0x0C00u
#define VMCS_HOST_CS_SELECTOR          0x0C02u
#define VMCS_HOST_SS_SELECTOR          0x0C04u
#define VMCS_HOST_DS_SELECTOR          0x0C06u
#define VMCS_HOST_FS_SELECTOR          0x0C08u
#define VMCS_HOST_GS_SELECTOR          0x0C0Au
#define VMCS_HOST_TR_SELECTOR          0x0C0Cu

/* ---- 64-bit fields ---------------------------------------------------- */
#define VMCS_IO_BITMAP_A               0x2000u
#define VMCS_IO_BITMAP_B               0x2002u
#define VMCS_MSR_BITMAP                0x2004u
#define VMCS_TSC_OFFSET                0x2010u
#define VMCS_VM_FUNCTION_CONTROL       0x2018u
#define VMCS_EPT_POINTER               0x201Au

#define VMCS_GUEST_PHYSICAL_ADDRESS    0x2400u

#define VMCS_VMCS_LINK_POINTER         0x2800u
#define VMCS_GUEST_IA32_DEBUGCTL       0x2802u
#define VMCS_GUEST_IA32_PAT            0x2804u
#define VMCS_GUEST_IA32_EFER           0x2806u

#define VMCS_HOST_IA32_PAT             0x2C00u
#define VMCS_HOST_IA32_EFER            0x2C02u

/* ---- 32-bit control fields -------------------------------------------- */
#define VMCS_PIN_BASED_VM_EXEC_CTRL    0x4000u
#define VMCS_PRIMARY_PROC_BASED_CTRL   0x4002u
#define VMCS_EXCEPTION_BITMAP          0x4004u
#define VMCS_PF_ERROR_CODE_MASK        0x4006u
#define VMCS_PF_ERROR_CODE_MATCH       0x4008u
#define VMCS_CR3_TARGET_COUNT          0x400Au
#define VMCS_VM_EXIT_CTRLS             0x400Cu
#define VMCS_VM_EXIT_MSR_STORE_COUNT   0x400Eu
#define VMCS_VM_EXIT_MSR_LOAD_COUNT    0x4010u
#define VMCS_VM_ENTRY_CTRLS            0x4012u
#define VMCS_VM_ENTRY_MSR_LOAD_COUNT   0x4014u
#define VMCS_VM_ENTRY_INTR_INFO        0x4016u
#define VMCS_VM_ENTRY_EXCEPTION_ERR    0x4018u
#define VMCS_VM_ENTRY_INSTRUCTION_LEN  0x401Au
#define VMCS_SECONDARY_PROC_BASED_CTRL 0x401Eu

/* ---- 32-bit read-only fields ------------------------------------------ */
#define VMCS_VM_INSTRUCTION_ERROR      0x4400u
#define VMCS_VM_EXIT_REASON            0x4402u
#define VMCS_VM_EXIT_INTR_INFO         0x4404u
#define VMCS_VM_EXIT_INTR_ERROR_CODE   0x4406u
#define VMCS_IDT_VECTORING_INFO        0x4408u
#define VMCS_VM_EXIT_INSTRUCTION_LEN   0x440Cu
#define VMCS_VMX_INSTRUCTION_INFO      0x440Eu

/* ---- 32-bit guest-state fields ---------------------------------------- */
#define VMCS_GUEST_ES_LIMIT            0x4800u
#define VMCS_GUEST_CS_LIMIT            0x4802u
#define VMCS_GUEST_SS_LIMIT            0x4804u
#define VMCS_GUEST_DS_LIMIT            0x4806u
#define VMCS_GUEST_FS_LIMIT            0x4808u
#define VMCS_GUEST_GS_LIMIT            0x480Au
#define VMCS_GUEST_LDTR_LIMIT          0x480Cu
#define VMCS_GUEST_TR_LIMIT            0x480Eu
#define VMCS_GUEST_GDTR_LIMIT          0x4810u
#define VMCS_GUEST_IDTR_LIMIT          0x4812u
#define VMCS_GUEST_ES_AR_BYTES         0x4814u
#define VMCS_GUEST_CS_AR_BYTES         0x4816u
#define VMCS_GUEST_SS_AR_BYTES         0x4818u
#define VMCS_GUEST_DS_AR_BYTES         0x481Au
#define VMCS_GUEST_FS_AR_BYTES         0x481Cu
#define VMCS_GUEST_GS_AR_BYTES         0x481Eu
#define VMCS_GUEST_LDTR_AR_BYTES       0x4820u
#define VMCS_GUEST_TR_AR_BYTES         0x4822u
#define VMCS_GUEST_INTERRUPTIBILITY    0x4824u
#define VMCS_GUEST_ACTIVITY_STATE      0x4826u
#define VMCS_GUEST_SMBASE              0x4828u
#define VMCS_GUEST_IA32_SYSENTER_CS    0x482Au

/* ---- 32-bit host-state fields ----------------------------------------- */
#define VMCS_HOST_IA32_SYSENTER_CS     0x4C00u

/* ---- natural-width control fields ------------------------------------- */
#define VMCS_CR0_GUEST_HOST_MASK       0x6000u
#define VMCS_CR4_GUEST_HOST_MASK       0x6002u
#define VMCS_CR0_READ_SHADOW           0x6004u
#define VMCS_CR4_READ_SHADOW           0x6006u

/* ---- natural-width read-only fields ----------------------------------- */
#define VMCS_EXIT_QUALIFICATION        0x6400u
#define VMCS_IO_RCX                    0x6402u
#define VMCS_IO_RSI                    0x6404u
#define VMCS_IO_RDI                    0x6406u
#define VMCS_IO_RIP                    0x6408u
#define VMCS_GUEST_LINEAR_ADDRESS      0x640Au

/* ---- natural-width guest-state fields --------------------------------- */
#define VMCS_GUEST_CR0                 0x6800u
#define VMCS_GUEST_CR3                 0x6802u
#define VMCS_GUEST_CR4                 0x6804u
#define VMCS_GUEST_ES_BASE             0x6806u
#define VMCS_GUEST_CS_BASE             0x6808u
#define VMCS_GUEST_SS_BASE             0x680Au
#define VMCS_GUEST_DS_BASE             0x680Cu
#define VMCS_GUEST_FS_BASE             0x680Eu
#define VMCS_GUEST_GS_BASE             0x6810u
#define VMCS_GUEST_LDTR_BASE           0x6812u
#define VMCS_GUEST_TR_BASE             0x6814u
#define VMCS_GUEST_GDTR_BASE           0x6816u
#define VMCS_GUEST_IDTR_BASE           0x6818u
#define VMCS_GUEST_DR7                 0x681Au
#define VMCS_GUEST_RSP                  0x681Cu
#define VMCS_GUEST_RIP                  0x681Eu
#define VMCS_GUEST_RFLAGS               0x6820u
#define VMCS_GUEST_PENDING_DBG_EXC     0x6822u
#define VMCS_GUEST_IA32_SYSENTER_ESP   0x6824u
#define VMCS_GUEST_IA32_SYSENTER_EIP   0x6826u

/* ---- natural-width host-state fields ---------------------------------- */
#define VMCS_HOST_CR0                  0x6C00u
#define VMCS_HOST_CR3                  0x6C02u
#define VMCS_HOST_CR4                  0x6C04u
#define VMCS_HOST_FS_BASE              0x6C06u
#define VMCS_HOST_GS_BASE              0x6C08u
#define VMCS_HOST_TR_BASE              0x6C0Au
#define VMCS_HOST_GDTR_BASE            0x6C0Cu
#define VMCS_HOST_IDTR_BASE            0x6C0Eu
#define VMCS_HOST_IA32_SYSENTER_ESP    0x6C10u
#define VMCS_HOST_IA32_SYSENTER_EIP    0x6C12u
#define VMCS_HOST_RSP                  0x6C14u
#define VMCS_HOST_RIP                  0x6C16u

#endif
