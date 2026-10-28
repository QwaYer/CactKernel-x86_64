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

// Would a signal frame at `esp` fit inside one page and in the user window?
static int frame_fits(uint32_t esp) {
    if (esp < USER_SPACE_START || esp >= KERNEL_BASE) return 0;
    uint32_t page_off = esp & 0xFFFu;
    return page_off + sizeof(signal_frame_t) <= PAGE_SIZE;
}

// Is the page holding `esp` a present, user, writable page of this task?
static int frame_mapped(struct task_struct *t, uint32_t esp) {
    uint32_t *pd = t->page_directory;
    if (!pd) return 0;
    uint32_t pdi = PD_INDEX(esp);
    uint32_t pti = PT_INDEX(esp);
    if (!(pd[pdi] & PAGE_PRESENT)) return 0;
    uint32_t *pt = (uint32_t *)(pd[pdi] & ~0xFFFu);
    uint32_t pte = pt[pti];
    if (!(pte & PAGE_PRESENT)) return 0;
    if (!(pte & PAGE_USER))    return 0;
    if (!(pte & PAGE_RW))      return 0;
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

        uint32_t new_esp = 0;
        int on_alt = 0;

        // SA_ONSTACK: build the frame on the alternate signal stack when this
        // disposition asked for it, one is registered, and we are not already
        // running on it (POSIX: only one handler at a time uses it — a fault
        // inside the handler must not clobber the frame it is running on).
        // The frame still records the interrupted esp, which sigreturn
        // restores, so the handler returns to the original stack.
        if ((t->proc->signal_flags[bit] & CACT_SA_ONSTACK) &&
            t->proc->altstack_sp != 0 &&
            !(t->proc->altstack_flags & (CACT_SS_DISABLE | CACT_SS_ONSTACK))) {
            uint32_t cand = t->proc->altstack_sp + t->proc->altstack_size - sizeof(signal_frame_t);
            cand = ((cand - 12u) & ~0xFu) + 12u;      // where a `call` would leave esp
            if (cand >= t->proc->altstack_sp && frame_fits(cand) && frame_mapped(t, cand)) {
                new_esp = cand;
                on_alt  = 1;
            }
            // An unmapped or too-small alternate stack falls through to the
            // interrupted stack: delivering it somewhere beats stranding it.
        }

        if (!on_alt) {
            new_esp = (uint32_t)regs->rsp - sizeof(signal_frame_t);

            // The handler is entered with `new_esp` as its stack pointer (iretd, no
            // call), and clang may emit aligned SSE stores into its frame, so place
            // the frame where a `call` would leave esp — ≡ 12 (mod 16).  Rounding
            // down only adds a ≤15-byte gap below the interrupted esp.
            new_esp = ((new_esp - 12u) & ~0xFu) + 12u;

            if (!frame_fits(new_esp)) {
                // The frame would straddle a page boundary (user ESP lies within
                // sizeof(signal_frame_t) of a page start).  Only the single page
                // holding `new_esp` is walked below, so park the frame at the end
                // of the previous page instead — the user stack is mapped as a
                // whole, so that page is present for any task that has not
                // overrun it.  Bailing out here instead would strand the signal:
                // the tty read path returns -EINTR while a catchable signal is
                // pending, so the interrupted syscall could never progress again.
                new_esp = ((uint32_t)regs->rsp & ~0xFFFu) - sizeof(signal_frame_t);
                new_esp = ((new_esp - 12u) & ~0xFu) + 12u;
                if (!frame_fits(new_esp)) continue;
            }
            if (!frame_mapped(t, new_esp)) continue;
        }

        signal_frame_t *frame = (signal_frame_t *)new_esp;
        uint32_t frame_base = new_esp;

        frame->ret_addr = t->proc->sigreturn_trampoline;
        /* The handler's first argument is the signal *mask*, which is the value
         * this libc's <signal.h> gives SIGINT and friends — so `case SIGINT:` in
         * a handler and the number sigwait() returns are the same thing. */
        frame->signum   = (1u << bit);
        // The signal_frame_t is the 32-bit user ABI (rebuilt together with
        // userspace in Phase 6); the 64-bit frame's argument registers map onto
        // the legacy slots the 32-bit stub used: ebx=arg1, ecx/esi=arg2,
        // edx/edi=arg3.
        frame->eax      = (uint32_t)regs->rax;
        frame->ecx      = (uint32_t)regs->rsi;
        frame->edx      = (uint32_t)regs->rdx;
        frame->ebx      = (uint32_t)regs->rdi;
        frame->esp      = (uint32_t)regs->rsp;
        frame->ebp      = (uint32_t)regs->rbp;
        frame->esi      = (uint32_t)regs->rsi;
        frame->edi      = (uint32_t)regs->rdx;
        frame->eip      = (uint32_t)regs->rip;
        frame->eflags   = (uint32_t)regs->rflags;

        // The two extra handler arguments point at the payloads carried in the
        // same frame, so nothing has to be kept alive elsewhere.
        frame->siginfo_ptr  = frame_base +
            (uint32_t)((uintptr_t)&frame->siginfo  - (uintptr_t)frame);
        frame->ucontext_ptr = frame_base +
            (uint32_t)((uintptr_t)&frame->ucontext - (uintptr_t)frame);

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
            uint32_t *g = frame->ucontext.uc_mcontext.gregs;
            for (int i = 0; i < 19; i++) g[i] = 0;
            g[SF_REG_ES]   = 0;                       // long mode has no es/ds to save
            g[SF_REG_DS]   = 0;
            g[SF_REG_EDI]  = (uint32_t)regs->rdx;     // edi held arg3 in the 32-bit stub
            g[SF_REG_ESI]  = (uint32_t)regs->rsi;     // esi held arg2
            g[SF_REG_EBP]  = (uint32_t)regs->rbp;
            g[SF_REG_ESP]  = (uint32_t)regs->rsp;
            g[SF_REG_EBX]  = (uint32_t)regs->rdi;     // ebx held arg1
            g[SF_REG_EDX]  = (uint32_t)regs->rdx;
            g[SF_REG_ECX]  = (uint32_t)regs->rsi;
            g[SF_REG_EAX]  = (uint32_t)regs->rax;
            g[SF_REG_EIP]  = (uint32_t)regs->rip;
            g[SF_REG_CS]   = (uint32_t)regs->cs;
            g[SF_REG_EFL]  = (uint32_t)regs->rflags;
            g[SF_REG_UESP] = (uint32_t)regs->rsp;
            g[SF_REG_SS]   = (uint32_t)regs->ss;
        }

        // POSIX: the delivered signal is blocked while its handler runs, so a
        // fault cannot re-enter the same handler; SA_NODEFER opts out.  Whatever
        // the disposition itself asked to block (sa_mask) applies on top.  The
        // old mask travels in the frame and sigreturn() puts it back.
        frame->saved_mask = t->proc->signal_mask;
        if (!(t->proc->signal_flags[bit] & CACT_SA_NODEFER))
            t->proc->signal_mask |= mask;
        t->proc->signal_mask |= t->proc->signal_masks[bit];

        regs->rsp = new_esp;
        regs->rip = handler;

        if (on_alt) t->proc->altstack_flags |= CACT_SS_ONSTACK;

        t->proc->pending_signals &= ~mask;
        return;
    }
}
