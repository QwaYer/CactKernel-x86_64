#include "helper.h"
#include "validate.h"
#include "memory.h"
#include "ioctl_abi.h"

// Find a free file descriptor slot (starting from 3) and install the file.
int alloc_fd(vfs_node_t *node) {
    if (!node || !current_task) return -1;
    file_t *f = file_alloc(node);
    if (!f) return -1;
    for (int i = 3; i < MAX_FD; i++) {
        if (!current_task->proc->fds->files[i]) {
            current_task->proc->fds->files[i] = f;
            return i;
        }
    }
    // No free slot — undo the allocation
    file_unref(f);
    return -1;
}

// Would a signal frame at `rsp` fit inside one page and in the user window?
static int frame_fits(uint64_t rsp) {
    if (rsp < USER_SPACE_START || rsp >= KERNEL_BASE) return 0;
    uint64_t page_off = rsp & 0xFFFu;
    return page_off + sizeof(signal_frame_t) <= PAGE_SIZE;
}

// Is the page holding `rsp` a present, user, writable page of this task?
static int frame_mapped(struct task_struct *t, uint64_t rsp) {
    uint64_t *pd = t->page_directory;
    if (!pd) return 0;
    // The permission bits come straight from the memory layer's four-level walk.
    uint32_t flags = vmm_pte_flags(pd, rsp);
    if (!(flags & PAGE_PRESENT)) return 0;
    if (!(flags & PAGE_USER))    return 0;
    if (!(flags & PAGE_RW))      return 0;
    return 1;
}

// Deliver a pending signal to a task by constructing a signal frame on its
// user stack and redirecting EIP to the signal handler.
// Called from syscall_handler before returning to userspace.
void deliver_pending_signal(struct task_struct *t, struct syscall_frame *regs) {
    uint32_t deliverable = t->proc->pending_signals & ~t->proc->signal_mask;
    if (!deliverable) return;

    for (int bit = 0; bit < NSIG; bit++) {
        uint32_t mask = (1u << bit);
        if (!(deliverable & mask)) continue;
        uint32_t handler = t->proc->signal_handlers[bit];
        if (handler <= SIG_IGN) continue;
        if (handler < USER_SPACE_START || handler >= KERNEL_BASE) continue;

        uint64_t new_rsp = 0;
        int on_alt = 0;

        // SA_ONSTACK: build the frame on the alternate signal stack when this
        // disposition asked for it, one is registered, and we are not already
        // running on it (POSIX: only one handler at a time uses it — a fault
        // inside the handler must not clobber the frame it is running on).
        // The frame still records the interrupted rsp, which sigreturn
        // restores, so the handler returns to the original stack.
        if ((t->proc->signal_flags[bit] & CACT_SA_ONSTACK) &&
            t->proc->altstack_sp != 0 &&
            !(t->proc->altstack_flags & (CACT_SS_DISABLE | CACT_SS_ONSTACK))) {
            uint64_t cand = (uint64_t)t->proc->altstack_sp + t->proc->altstack_size
                            - sizeof(signal_frame_t);
            cand = ((cand - 8u) & ~0xFu) + 8u;        // where a `call` would leave rsp
            if (cand >= (uint64_t)t->proc->altstack_sp && frame_fits(cand) && frame_mapped(t, cand)) {
                new_rsp = cand;
                on_alt  = 1;
            }
            // An unmapped or too-small alternate stack falls through to the
            // interrupted stack: delivering it somewhere beats stranding it.
        }

        if (!on_alt) {
            new_rsp = regs->rsp - sizeof(signal_frame_t);

            // The handler is entered with `new_rsp` as its stack pointer (iretq, no
            // call), and clang may emit aligned SSE stores into its frame, so place
            // the frame where a `call` would leave rsp — ≡ 8 (mod 16).  Rounding
            // down only adds a ≤15-byte gap below the interrupted rsp.
            new_rsp = ((new_rsp - 8u) & ~0xFu) + 8u;

            if (!frame_fits(new_rsp)) {
                // The frame would straddle a page boundary (user rsp lies within
                // sizeof(signal_frame_t) of a page start).  Only the single page
                // holding `new_rsp` is walked below, so park the frame at the end
                // of the previous page instead — the user stack is mapped as a
                // whole, so that page is present for any task that has not
                // overrun it.  Bailing out here instead would strand the signal:
                // the tty read path returns -EINTR while a catchable signal is
                // pending, so the interrupted syscall could never progress again.
                new_rsp = (regs->rsp & ~0xFFFu) - sizeof(signal_frame_t);
                new_rsp = ((new_rsp - 8u) & ~0xFu) + 8u;
                if (!frame_fits(new_rsp)) continue;
            }
            if (!frame_mapped(t, new_rsp)) continue;
        }

        signal_frame_t *frame = (signal_frame_t *)(uintptr_t)new_rsp;
        uint64_t frame_base = new_rsp;

        frame->ret_addr = t->proc->sigreturn_trampoline;
        // The whole 64-bit register set is saved so sigreturn resumes the
        // interrupted program exactly; the handler receives its three arguments
        // in rdi/rsi/rdx below, not from the stack.
        frame->rax    = regs->rax;
        frame->rbx    = regs->rbx;
        frame->rcx    = regs->rcx;
        frame->rdx    = regs->rdx;
        frame->rsi    = regs->rsi;
        frame->rdi    = regs->rdi;
        frame->rbp    = regs->rbp;
        frame->r8     = regs->r8;
        frame->r9     = regs->r9;
        frame->r10    = regs->r10;
        frame->r11    = regs->r11;
        frame->r12    = regs->r12;
        frame->r13    = regs->r13;
        frame->r14    = regs->r14;
        frame->r15    = regs->r15;
        frame->rip    = regs->rip;
        frame->rflags = regs->rflags;
        frame->rsp    = regs->rsp;

        // siginfo: the signal path carries the source code recorded when it was
        // queued (SI_USER for a kill, SI_KERNEL plus the fault address for a
        // fault), and consuming it leaves the default for the next delivery.
        // si_value is sigqueue()'s payload, and si_signo is the same mask value
        // the handler is entered with.
        frame->siginfo.si_signo = (int32_t)(1u << bit);
        frame->siginfo.si_code  = (int32_t)t->proc->signal_codes[bit];
        frame->siginfo.si_addr  = t->proc->signal_addr;
        frame->siginfo.si_value = t->proc->signal_value;
        t->proc->signal_codes[bit] = CACT_SI_USER;
        t->proc->signal_addr       = 0;
        t->proc->signal_value      = 0;

        // ucontext: the interrupted register state, in the libc's REG_* order.
        frame->ucontext.uc_link  = 0;
        frame->ucontext.uc_flags = 0;
        {
            uint64_t *g = frame->ucontext.uc_mcontext.gregs;
            for (int i = 0; i < 19; i++) g[i] = 0;
            g[SF_REG_ES]   = 0;                       // long mode has no es/ds to save
            g[SF_REG_DS]   = 0;
            g[SF_REG_EDI]  = regs->rdi;
            g[SF_REG_ESI]  = regs->rsi;
            g[SF_REG_EBP]  = regs->rbp;
            g[SF_REG_ESP]  = regs->rsp;
            g[SF_REG_EBX]  = regs->rbx;
            g[SF_REG_EDX]  = regs->rdx;
            g[SF_REG_ECX]  = regs->rcx;
            g[SF_REG_EAX]  = regs->rax;
            g[SF_REG_EIP]  = regs->rip;
            g[SF_REG_CS]   = regs->cs;
            g[SF_REG_EFL]  = regs->rflags;
            g[SF_REG_UESP] = regs->rsp;
            g[SF_REG_SS]   = regs->ss;
        }

        // POSIX: the delivered signal is blocked while its handler runs, so a
        // fault cannot re-enter the same handler; SA_NODEFER opts out.  Whatever
        // the disposition itself asked to block (sa_mask) applies on top.  The
        // old mask travels in the frame and sigreturn() puts it back.
        frame->saved_mask = t->proc->signal_mask;
        if (!(t->proc->signal_flags[bit] & CACT_SA_NODEFER))
            t->proc->signal_mask |= mask;
        t->proc->signal_mask |= t->proc->signal_masks[bit];

        // Enter the handler the SysV AMD64 way: its three arguments are passed
        // in registers, with rsi/rdx pointing at the payloads carried in the
        // same frame (nothing has to be kept alive elsewhere).
        regs->rdi = (uint64_t)(1u << bit);
        regs->rsi = frame_base + __builtin_offsetof(signal_frame_t, siginfo);
        regs->rdx = frame_base + __builtin_offsetof(signal_frame_t, ucontext);
        regs->rsp = new_rsp;
        regs->rip = handler;

        if (on_alt) t->proc->altstack_flags |= CACT_SS_ONSTACK;

        t->proc->pending_signals &= ~mask;
        return;
    }
}
