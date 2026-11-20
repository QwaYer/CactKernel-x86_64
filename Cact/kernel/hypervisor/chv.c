/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

// chv.c — /dev/chv, the "Cact Hypervisor" control node.
//
// The hypervisor model lives in the Rust crate `cact_hv` (linked into
// kernel.bin) and in the C/asm primitives under this directory; this file is
// only the userspace door to it.  It used to be reached by a boot-time
// self-test that ran a throwaway guest before the VFS existed and — worse —
// left the CPU in VMX root for the rest of the kernel's life (CR4.VMXE set, a
// live VMCS, a leaked VMXON region).  The guest is now run on demand, when
// userspace asks, and host mode is left again before the ioctl returns.
//
//   /dev/chv  ioctl  -> capabilities, run the model's guest
//   CACT_CHVCTL_* = 0x4100 (Cact/kernel/core/syscall/ioctl_abi.h)

#include "hypervisor.h"
#include "devfs.h"
#include "validate.h"
#include "kernel.h"
#include "sync.h"
#include "ioctl_abi.h"

#define EFAULT 14
#define ENODEV 19
#define EINVAL 22
#define EIO    5

/* The model runs one guest on the calling CPU: `hv_run_guest()` enters VMX
 * root, launches, and leaves again.  The host state it uses (the VMXON region,
 * the current VMCS) is still a single instance, so two concurrent runs would
 * collide — serialise them here until that state is per-CPU. */
static mutex_t g_chv_lock;

static int _chv_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;

    switch (cmd) {
    case CACT_CHVCTL_CAPS: {
        cact_chv_caps_t *a = (cact_chv_caps_t *)arg;
        if (!validate_user_ptr(a, sizeof(*a))) return -EFAULT;
        cact_chv_caps_t out;
        out.caps             = hv_capabilities();
        out.running_as_guest = (uint32_t)hv_running_as_guest();
        out.reserved         = 0;
        return copy_to_user(a, &out, sizeof(out)) == 0 ? 0 : -EFAULT;
    }

    case CACT_CHVCTL_RUN: {
        cact_chv_run_arg_t *a = (cact_chv_run_arg_t *)arg;
        if (!validate_user_ptr(a, sizeof(*a))) return -EFAULT;

        uint64_t reason = 0;
        mutex_lock(&g_chv_lock);
        int rc = hv_run_guest(&reason);
        mutex_unlock(&g_chv_lock);

        cact_chv_run_arg_t out;
        out.exit_reason = reason;
        out.status      = (rc == 0) ? 0u : 1u;
        if (copy_to_user(a, &out, sizeof(out)) != 0) return -EFAULT;

        if (rc == 0) return 0;                 /* the guest ran */
        return (rc < 0) ? -ENODEV : -EIO;      /* no host mode / launch failed */
    }

    default:
        return -EINVAL;
    }
}

static devfs_driver_t drv_chv = { .ioctl = _chv_ioctl };

int chv_devfs_init(void) {
    mutex_init(&g_chv_lock);
    if (!register_chrdev("chv", DEVFS_F_CHAR, &drv_chv, 0))
        return -1;
    pr_info("%s: /dev/chv ready (cact hypervisor)\n", "hv");
    return 0;
}
