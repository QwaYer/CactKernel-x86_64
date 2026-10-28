#ifndef SC_MOD_H
#define SC_MOD_H

#include "kernel.h"

// The register frame the syscall entry leaves on the kernel stack.
//
// Long mode's fast-syscall ABI is `rax` = number, `rdi`/`rsi`/`rdx` =
// arguments; the entry (syscall_entries.asm) saves the whole general-purpose
// set plus the return context, so handlers that need the full snapshot (fork,
// exec, signals, sigreturn) can read and rewrite it.  The layout is field for
// field `struct context_frame` in task.h — mod.c asserts the match — which is
// what lets the same epilogue an exception stub uses (restore the registers,
// drop int_no/err_code, `iretq`) return to user mode, and what lets fork hand
// this frame straight to task_fork().
struct syscall_frame {
    uint64_t r15, r14, r13, r12;
    uint64_t rbp, rbx;
    uint64_t r11, r10, r9, r8;
    uint64_t rax, rcx, rdx, rsi, rdi;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip, cs, rflags;
    uint64_t rsp, ss;
};

// SYS_SIGRETURN number — exported to the Rust trampoline via FFI
extern const uint32_t sys_sigreturn_num;

// Called from the syscall entry (syscall_entries.asm), with the frame pointer.
void syscall_handler(struct syscall_frame* regs);

#endif
