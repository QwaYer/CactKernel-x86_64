#ifndef SC_PROC_PROC_H
#define SC_PROC_PROC_H

#include "kernel.h"
#include "task.h"
#include "mod.h"

// Scheduler functions used by proc syscalls
extern void sched_sleep_ticks(uint32_t ticks);
extern void sched_task_exit(int exit_code);
extern int  sched_waitpid(int target_pid, int* status, int options);

// Process management syscalls
sysret_t sys_fork(struct syscall_frame* regs);
sysret_t sys_exec(struct syscall_frame* regs);
sysret_t sys_exit(struct syscall_frame* regs);
sysret_t sys_waitpid(struct syscall_frame* regs);

#endif 