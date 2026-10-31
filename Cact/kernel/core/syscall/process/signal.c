#include "signal.h"
#include "validate.h"
#include "helper.h"
#include "klib.h"
#include "ioctl_abi.h"   // CACT_SS_ONSTACK

// The kernel keeps exactly one signal-related trap: sigreturn, which restores
// the user context saved on the signal frame stack.  All signal *control*
// (sigaction/procmask/kill/alarm/setitimer/sigsuspend/...) is served by the
// /proc/self/ctl node ioctls (CACT_PROCCTL_*).

// sigreturn() — restore user context from the signal frame on the stack
/* Queue `signal` for `pid` and remember what it came from, so an SA_SIGINFO
 * handler gets a truthful si_code (and, for a hardware fault, the address that
 * faulted).  A plain task_signal() leaves the default, SI_USER.
 *
 * `signal` is the bit (SIGSEGV = 1<<8, as the kernel's own headers define it);
 * the per-signal arrays are indexed by the bit *number*. */
void task_signal_code(uint32_t pid, uint32_t signal, uint32_t code, uint64_t addr) {
    if (current_task && current_task->proc && current_task->pid == pid) {
        int bit = 0;
        uint32_t m = signal;
        while (bit < NSIG && !(m & 1u)) { m >>= 1; bit++; }
        if (bit < NSIG) {
            current_task->proc->signal_codes[bit] = code;
            current_task->proc->signal_addr      = addr;
        }
    }
    task_signal(pid, signal);
}

static int sys_sigreturn_impl(struct syscall_frame* regs) {
    if (!current_task || current_task->is_kernel) return -1;

    uint64_t user_rsp = regs->rsp;
    if (user_rsp < USER_SPACE_START || user_rsp >= KERNEL_BASE) return -1;

    uint64_t page_off = user_rsp & 0xFFFu;
    if (page_off + sizeof(signal_frame_t) > PAGE_SIZE) return -1;

    signal_frame_t frame_buf;

    // Read frame with double-check of page tables to prevent TOCTOU
    for (int attempt = 0; attempt < 2; attempt++) {
        // Resolve the frame's page through the memory layer's four-level walk
        // rather than indexing the tables with a two-level layout.
        uint64_t* pd = current_task->page_directory;
        if (!pd) return -1;
        if (!(vmm_pte_flags(pd, user_rsp) & PAGE_PRESENT)) return -1;

        uint64_t frame = vmm_get_phys(pd, user_rsp);
        if (!frame) return -1;
        uint64_t phys = frame & ~0xFFFULL;

        // vmm_get_phys answers with a physical address; the frame is read
        // through the direct map.
        memory_copy(&frame_buf, (signal_frame_t*)((uint8_t*)vmm_p2v(phys) + page_off),
                    sizeof(frame_buf));

        // Re-validate: the mapping must still resolve to the same frame
        if ((vmm_get_phys(pd, user_rsp) & ~0xFFFULL) == phys)
            break;

        if (attempt == 1) return -1;
    }

    // Restore the full 64-bit register set the frame saved at delivery, so the
    // interrupted program resumes exactly where it left off.
    regs->rax    = frame_buf.rax;
    regs->rbx    = frame_buf.rbx;
    regs->rcx    = frame_buf.rcx;
    regs->rdx    = frame_buf.rdx;
    regs->rsi    = frame_buf.rsi;
    regs->rdi    = frame_buf.rdi;
    regs->rbp    = frame_buf.rbp;
    regs->r8     = frame_buf.r8;
    regs->r9     = frame_buf.r9;
    regs->r10    = frame_buf.r10;
    regs->r11    = frame_buf.r11;
    regs->r12    = frame_buf.r12;
    regs->r13    = frame_buf.r13;
    regs->r14    = frame_buf.r14;
    regs->r15    = frame_buf.r15;
    regs->rip    = frame_buf.rip;
    regs->rflags = frame_buf.rflags;
    regs->rsp    = frame_buf.rsp;

    // Put back the mask the handler interrupted — delivery blocked the signal
    // itself (unless SA_NODEFER), and any signal that arrived meanwhile must
    // become deliverable again.
    current_task->proc->signal_mask = (uint32_t)frame_buf.saved_mask;

    // The handler is leaving, so the alternate signal stack is free again: a
    // later SA_ONSTACK delivery may use it (and sigaltstack() should stop
    // reporting SS_ONSTACK).
    current_task->proc->altstack_flags &= ~(uint32_t)CACT_SS_ONSTACK;

    return 0;
}

sysret_t sys_sigreturn(struct syscall_frame* regs) { return sys_sigreturn_impl(regs); }
