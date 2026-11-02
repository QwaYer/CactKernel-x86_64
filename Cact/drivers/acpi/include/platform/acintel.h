/* SPDX-License-Identifier: (BSD-2-Clause-Patent OR GPL-2.0-only) AND GPL-3.0-or-later */
/* Copyright (c) 1999-2026 Intel Corporation */
/* Copyright (C) 2026 CactOS Project */

/*
 * Adapted from Intel ACPICA (source/include/platform/acenv.h|acintel.h);
 * CactOS uses the BSD-2-Clause-Patent option.  Upstream: https://github.com/acpica/acpica
 * See Cact/drivers/acpi/include/platform/UPSTREAM.md.
 */

#ifndef __ACINTEL_H__
#define __ACINTEL_H__

#define ACPI_INTERNAL_VAR_XFACE
#define ACPI_EXTERNAL_VAR_XFACE

#define ACPI_CACHE_LINE_SIZE  64

#define acpi_restore_flags(flags)      __asm__ __volatile__("pushfq ; pop %0" : "=rm"(flags) :: "memory")
#define acpi_save_flags(flags)         __asm__ __volatile__("pushfq ; pop %0" : "=rm"(flags) :: "memory")
#define acpi_disable_int()             __asm__ __volatile__("cli" ::: "memory")
#define acpi_enable_int()              __asm__ __volatile__("sti" ::: "memory")

#define ACPI_ASM_MACROS
#define BREAKPOINT3                    __asm__ __volatile__("int3" ::: "memory")
#define BREAKPOINT

#endif
