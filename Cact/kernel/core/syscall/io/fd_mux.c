/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "fd.h"
#include "validate.h"
#include "helper.h"
#include "kernel.h"   // terminal_winsize

extern void sched_sleep_ticks(uint32_t ticks);

#ifndef EINTR
#define EINTR 4
#endif

/* SIGCHLD (bit 6) | SIGWINCH (bit 9): job-control notifications are *reported*
   to the application, not delivered, so they must not abort a poll wait
   (the same rule the tty read path follows). */
#define SC_JC_MASK (~((1u << 6) | (1u << 9)))

sysret_t sys_poll(struct syscall_frame *regs) {
    struct pollfd *fds_user   = (struct pollfd *)regs->rdi;
    int            nfds       = (int)regs->rsi;
    int            timeout_ms = (int)regs->rdx;

    if (!current_task) return -1;

    // poll(NULL, 0, timeout) — pure sleep (nfds == 0).
    if (nfds <= 0) {
        if (timeout_ms == 0) return 0;
        int      sleep_infinite = (timeout_ms < 0);
        uint32_t ticks = sleep_infinite
                             ? 0u
                             : (uint32_t)((timeout_ms + (1000 / 100) - 1) / (1000 / 100));
        uint32_t sleep_deadline = timer_ticks_get() + ticks;
        // Sleep on the timer wheel in one-tick slices rather than busy-yielding
        // on the tick, and stay interruptible: a bare sleep must still honour
        // Ctrl+C.
        for (;;) {
            if (task_signal_pending_current() & SC_JC_MASK) return -EINTR;
            if (!sleep_infinite &&
                (int32_t)(timer_ticks_get() - sleep_deadline) >= 0) return 0;
            sched_sleep_ticks(1);
        }
    }
    if ((uint32_t)nfds > UINT32_MAX / sizeof(struct pollfd)) return -1;
    if (!validate_user_ptr(fds_user, (uint32_t)nfds * sizeof(struct pollfd))) return -1;

    // Copy fds from user to kernel buffer for safe access across schedule()
    struct pollfd *fds = (struct pollfd *)kmalloc((uint32_t)nfds * sizeof(struct pollfd));
    if (!fds) return -1;
    if (copy_from_user(fds, fds_user, (uint32_t)nfds * sizeof(struct pollfd)) != 0) {
        kfree(fds);
        return -1;
    }

#define TIMER_HZ_POLL 100
    int      infinite    = (timeout_ms < 0);
    int      nonblocking = (timeout_ms == 0);
    uint32_t deadline    = 0;
    if (!infinite && !nonblocking) {
        uint32_t ticks = (uint32_t)((timeout_ms + (1000 / TIMER_HZ_POLL) - 1) /
                                    (1000 / TIMER_HZ_POLL));
        deadline = timer_ticks_get() + ticks;
    }
#undef TIMER_HZ_POLL

    struct task_struct *t = current_task;

    for (;;) {
        int ready = 0;

        for (int i = 0; i < nfds; i++) {
            fds[i].revents = 0;
            int fd = fds[i].fd;
            if (fd < 0 || fd >= MAX_FD) { fds[i].revents = POLLNVAL; continue; }
            file_t *f = t->proc->fds->files[fd];
            if (!f || !f->node) { fds[i].revents = POLLNVAL; continue; }

            uint32_t events = 0;
            if (fds[i].events & POLLIN)  events |= VFS_POLLIN;
            if (fds[i].events & POLLOUT) events |= VFS_POLLOUT;

            uint32_t revents = (uint32_t)poll_file_vfs(f, events);

            short ev = 0;
            if (revents & VFS_POLLIN)  ev |= POLLIN;
            if (revents & VFS_POLLOUT) ev |= POLLOUT;
            if (revents & VFS_POLLHUP) ev |= POLLHUP;
            if (revents & VFS_POLLERR) ev |= POLLERR;
            if (revents & VFS_POLLNVAL) ev |= POLLNVAL;

            fds[i].revents = ev;
            if (ev) ready++;
        }

        if (ready > 0 || nonblocking ||
                (!infinite && (int32_t)(timer_ticks_get() - deadline) >= 0)) {
            copy_to_user(fds_user, fds, (uint32_t)nfds * sizeof(struct pollfd));
            kfree(fds);
            return ready;
        }

        /* Interruptible wait.  A blocking poll() used to busy-yield on
         * schedule(), burning a core and ignoring Ctrl+C (the pending signal
         * never reached a syscall-return). */
        if (task_signal_pending_current() & SC_JC_MASK) {
            kfree(fds);
            return -EINTR;
        }
        sched_sleep_ticks(1);
    }
}
