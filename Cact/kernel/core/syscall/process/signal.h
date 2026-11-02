/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef SC_PROC_SIGNAL_H
#define SC_PROC_SIGNAL_H

#include "kernel.h"
#include "task.h"
#include "mod.h"

// Signal constants (if not already defined in task.h)
#ifndef SIG_DFL
#define SIG_DFL 0u
#endif
#ifndef SIG_IGN
#define SIG_IGN 1u
#endif
#ifndef SIG_UNCATCHABLE
#define SIG_UNCATCHABLE 0x00000003u  // SIGKILL | SIGSTOP
#endif
#ifndef NSIG
#define NSIG 32
#endif

// Signal syscalls
sysret_t sys_sigreturn(struct syscall_frame* regs);

#endif 