/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "proc.h"
#include "proc_mm.h"
#include "vfs.h"
#include "validate.h"
#include "tty.h"

// Maximum number of argv/envp entries to validate (prevents runaway loops)
#define EXEC_VALIDATE_MAX 256

// fork() — create a child process that is a copy of the caller
sysret_t sys_fork(struct syscall_frame* regs) {
    // The syscall frame is field for field a context_frame (mod.c asserts it),
    // so the child's saved context is the parent's, with `rax` zeroed later by
    // task_fork so fork() returns 0 in the child.
    struct context_frame cf = { 0 };
    cf.rdi    = regs->rdi;      cf.rsi      = regs->rsi;
    cf.rbp    = regs->rbp;      cf.rbx      = regs->rbx;
    cf.rdx    = regs->rdx;      cf.rcx      = regs->rcx;
    cf.rax    = regs->rax;
    cf.rip    = regs->rip;      cf.cs       = regs->cs;
    cf.rflags = regs->rflags;
    cf.rsp    = regs->rsp;      cf.ss       = regs->ss;
    struct task_struct* child = task_fork(&cf);
    if (!child) {
        return -1;
    }
    task_comm_inherit((uint32_t)child->pid, current_task->pid);
    return (int)child->pid;   // child sees 0, parent sees child PID
}

// exec() — replace the current process image with a new program
sysret_t sys_exec(struct syscall_frame* regs) {
    char* path = (char*)regs->rdi;

    char** argv = (char**)regs->rsi;
    char** envp = (char**)regs->rdx;

    // Validate argv array and each string pointer. The array ends at its first
    // NULL entry, so only the slots up to that terminator may be required to
    // live in userspace: a fixed-length window would reject a perfectly valid
    // argv sitting near the top of the user stack (which ends at KERNEL_BASE).
    if (argv) {
        for (int i = 0; i < EXEC_VALIDATE_MAX; i++) {
            if ((uintptr_t)&argv[i] < USER_SPACE_START || (uintptr_t)&argv[i] >= KERNEL_BASE) return -1;
            if (!argv[i]) break;
            if (!validate_user_str(argv[i])) return -1;
        }
    }

    // Validate envp array and each string pointer (same NULL-terminated rule).
    if (envp) {
        for (int i = 0; i < EXEC_VALIDATE_MAX; i++) {
            if ((uintptr_t)&envp[i] < USER_SPACE_START || (uintptr_t)&envp[i] >= KERNEL_BASE) return -1;
            if (!envp[i]) break;
            if (!validate_user_str(envp[i])) return -1;
        }
    }

    // Check execute permission on the file — uses kernel copy of path
    char *kpath = copy_path_from_user(path);
    if (!kpath) return -1;

    vfs_node_t* exec_node = vfs_resolve_path(kpath);
    if (!exec_node || vfs_check_perm(exec_node, VFS_PERM_EXEC) < 0) {
        kfree(kpath);
        return -1;
    }

    struct context_frame cf = { 0 };
    cf.rip    = regs->rip;
    cf.cs     = regs->cs;
    cf.rflags = regs->rflags;
    cf.rsp    = regs->rsp;
    cf.ss     = regs->ss;
    task_comm_set_path(current_task->pid, kpath);
    int ret = task_exec(kpath, argv, envp, &cf);   // never returns on success
    kfree(kpath);
    return ret;
}

// exit() — terminate the calling process
sysret_t sys_exit(struct syscall_frame* regs) {
    if (!current_task) return -1;

    // Drop the console's foreground process group once its last member is gone.
    // A stale pgid would swallow ^C (the line discipline only hands the byte
    // through to a raw-mode reader when no foreground group is set) instead of
    // letting the shell's line editor see it.
    if (terminal_fg_pgid != 0 && current_task->proc &&
        terminal_fg_pgid == current_task->proc->pgid) {
        int still_alive = 0;
        for (struct task_struct *it = task_list_head; it; it = it->next) {
            if (it == current_task || !it->proc) continue;
            if (it->proc->pgid == terminal_fg_pgid) { still_alive = 1; break; }
        }
        if (!still_alive) terminal_fg_pgid = 0;
    }

    // Drop the process's controlling-terminal assignment
    tty_clear_ctty(current_task->pid);

    // exit() ends the whole process, not just the calling thread: ask every
    // other thread of the group to die too.  pthread_exit() uses the separate
    // CACT_PROCCTL_THREAD_EXIT path, which ends only the caller.
    task_signal_group(current_task->pid, SIGKILL);

    sched_task_exit((int)regs->rdi);   // sets zombie state, reschedules

    // Safety net: if schedule() returns, spin forever in HLT
    for (;;)
        __asm__ volatile ("hlt");
}

// waitpid() — wait for a child process to change state
sysret_t sys_waitpid(struct syscall_frame* regs) {
    int  target_pid = (int)regs->rdi;
    int* status     = (int*)regs->rsi;
    int  options    = (int)regs->rdx;

    if (!current_task) return -1;
    if (status && !validate_user_ptr(status, sizeof(int))) return -1;

    return sched_waitpid(target_pid, status, options);
}