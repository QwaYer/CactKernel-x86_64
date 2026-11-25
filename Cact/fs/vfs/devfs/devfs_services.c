/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "devfs.h"
#include "devfs_internal.h"
#include "vfs.h"
#include "memory.h"
#include "klib.h"
#include "kernel.h"
#include "task.h"
#include "pipe.h"
#include "socket.h"
#include "unix_sock.h"
#include "rust_net_ffi.h"
#include "validate.h"
#include "helper.h"
#include "ioctl_abi.h"
#include "module/kmod.h"
#include "klog.h"
#include "memfd.h"
#include "eventfd.h"
#include "timerfd.h"
#include "signalfd.h"
#include "epoll.h"
#include "blkdev.h"
#include "part.h"
#include "vfsdev.h"
#include "procfs.h"
#include "cact_acpi.h"
#include "tty.h"
#include "rtc.h"
#include "zram.h"
#include "zswap.h"
#include "swap.h"

// devfs_services.c — kernel-service devices exposed through devfs.
//
// These turn "everything else" (console output, mount/reboot, module loading,
// socket creation, pipe creation) into plain VFS nodes so the kernel only
// needs the minimal core syscall set.  All handlers run in the calling
// process context (ioctl/write/read on the device), so current_task and its
// fd table are available.
//
//   /dev/console  write  -> kernel console (replaces sys_print / tty print)
//   /dev/sys      ioctl  -> mount/umount/reboot/module load/clock set (root only)
//   /dev/net      ioctl  -> socket()/ping/dns/netcfg
//   /dev/pipe     ioctl  -> pipe() creation
//   /dev/memfd    ioctl  -> memfd_create()

#ifndef EPERM
#define EPERM 1
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef ENODEV
#define ENODEV 19
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EMFILE
#define EMFILE 24
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef EBUSY
#define EBUSY 16
#endif

static int _root_only(void) {
    if (!current_task || !current_task->proc) return -1;
    return current_task->proc->euid != 0 ? -EPERM : 0;
}

// ── /dev/console ──────────────────────────────────────────────────────────

static int _console_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;(void)off;(void)size;(void)buf;
    return 0;   // console has no input
}

static int _console_write(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    /* Kernel console == the active VT (Linux /dev/console lands on the console
     * terminal).  Routing through tty_write() keeps the VT scrollback in sync
     * and draws straight to the framebuffer without re-entering the kernel
     * message log — a reader echoing /dev/kmsg must not re-log its own output. */
    return tty_write(0, off, size, buf);
}

static int _console_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    /* /dev/console is the active VT (see _console_write), so terminal ioctls
     * go to the tty driver: this is what makes isatty(/dev/console) true while
     * any non-terminal node returns -ENOTTY instead. */
    return tty_ioctl(0, cmd, arg);
}

devfs_driver_t drv_console = { .read = _console_read, .write = _console_write,
                               .ioctl = _console_ioctl };

// ── /dev/kmsg ─────────────────────────────────────────────────────────────
// Kernel message log.  Records are stored in the Linux /dev/kmsg read format
// ("<level>,<seq>,<usec>,<flags>;<text>\n"); reads are offset-based, so
// cat /dev/kmsg dumps the whole transcript.  Writes append a record from
// userspace (KLOG_F_USER); the level comes from the leading "<N>" or
// "N,seq,usec,flags,facility;" prefix.

static int _kmsg_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    return klog_read(off, size, buf);
}

static int _kmsg_write(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p; (void)off;
    if (!buf || !validate_user_ptr(buf, size)) return -1;
    return klog_write_user(buf, size);
}

devfs_driver_t drv_kmsg = {
    .read = _kmsg_read, .write = _kmsg_write
};

// ── /dev/sys ──────────────────────────────────────────────────────────────

// Mount a block device by name onto an explicit target directory (Linux-style
// mount /dev/<dev> <dir>). Dispatch handled by vfsdev_mount().
static int _sys_mount_ioctl(cact_mount_arg_t *a) {
    int r = _root_only();
    if (r) return r;

    char *ksrc = copy_path_from_user(a->src);
    if (!ksrc) return -EFAULT;
    char *ktgt = NULL;
    if (a->target) {
        if (!validate_user_str(a->target)) { kfree(ksrc); return -EFAULT; }
        ktgt = copy_path_from_user(a->target);
        if (!ktgt) { kfree(ksrc); return -EFAULT; }
    }
    char *kfs = NULL;
    if (a->fstype) {
        if (!validate_user_str(a->fstype)) { kfree(ksrc); return -EFAULT; }
        kfs = copy_path_from_user(a->fstype);
        if (!kfs) { kfree(ksrc); if (ktgt) kfree(ktgt); return -EFAULT; }
    }

    // Device mount: mount(src=<name|/dev/name>, target=<dir>, fstype=<module>).
    if (kfs && kfs[0]) {
        if (!ktgt || !ktgt[0]) {
            kfree(ksrc); kfree(kfs);
            return -EINVAL;
        }
        r = vfsdev_mount(ksrc, ktgt, kfs);
        kfree(ksrc);
        if (ktgt) kfree(ktgt);
        if (kfs)  kfree(kfs);
        return r;
    }

    // Legacy semantics: alias an already-mounted VFS path at target.
    vfs_node_t *src_node = vfs_resolve_path(ksrc);
    kfree(ksrc);
    if (!src_node) { if (ktgt) kfree(ktgt); if (kfs) kfree(kfs); return -1; }

    if (!ktgt) { if (kfs) kfree(kfs); return -EINVAL; }
    char basename[128];
    vfs_node_t *parent = vfs_resolve_parent(ktgt, basename, 128);
    if (kfs) kfree(kfs);
    kfree(ktgt);
    if (!parent || !basename[0]) return -1;

    return vfs_mount(parent, basename, src_node);
}

static int _sys_umount_ioctl(char *target) {
    int r = _root_only();
    if (r) return r;

    char *ktgt = copy_path_from_user(target);
    if (!ktgt) return -EFAULT;

    // Managed device mount first (target path or device name), then a plain
    // VFS alias mount.
    int rr = vfsdev_umount(ktgt);
    if (rr == 0) {
        kfree(ktgt);
        return 0;
    }

    char basename[128];
    vfs_node_t *parent = vfs_resolve_parent(ktgt, basename, 128);
    rr = -1;
    if (parent && basename[0])
        rr = vfs_umount(parent, basename);
    kfree(ktgt);
    return rr;
}

static int _do_reboot(uint32_t cmd) {
    int pid = current_task ? current_task->pid : 0;

    switch (cmd) {
    case CACT_REBOOT_POWEROFF:
        pr_notice("%s: poweroff requested by pid %d\n", "power", pid);
        acpi_power_off();
        break;

    case CACT_REBOOT_HALT:
        pr_notice("%s: halt requested by pid %d\n", "power", pid);
        acpi_halt();
        break;

    case CACT_REBOOT_SUSPEND:
        /* Unlike the one-way paths, this one comes back: the call returns when
         * the machine wakes (or reports why it did not suspend). */
        pr_notice("%s: suspend requested by pid %d\n", "power", pid);
        return acpi_suspend();

    case CACT_REBOOT_RESTART:
    default:
        pr_notice("%s: reboot requested by pid %d\n", "power", pid);
        acpi_reboot();
        break;
    }
    return 0;   // unreachable: the paths above never return
}

static int _sys_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;

    switch (cmd) {
    case CACT_SYSCTL_MOUNT: {
        cact_mount_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return _sys_mount_ioctl(&a);
    }

    case CACT_SYSCTL_UMOUNT: {
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        return _sys_umount_ioctl((char *)arg);
    }

    case CACT_SYSCTL_REBOOT: {
        uint32_t c;
        if (!arg) return -EINVAL;
        if (copy_from_user(&c, arg, sizeof(c)) != 0) return -EFAULT;
        int r = _root_only();
        if (r) return r;

        return _do_reboot(c);
    }

    case CACT_SYSCTL_MODULE_LOAD: {
        cact_module_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        int r = _root_only();
        if (r) return r;
        char *kpath = copy_path_from_user(a.path);
        if (!kpath) return -EFAULT;
        int rc = kmod_load_kpath(kpath, a.vendor_id, a.device_id);
        kfree(kpath);
        return rc;
    }

    case CACT_SYSCTL_MODULE_UNLOAD: {
        int r = _root_only();
        if (r) return r;
        if (!arg) return kmod_unload_kname(0);
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((const char *)arg);
        if (!kname) return -EFAULT;
        int rc = kmod_unload_kname(kname);
        kfree(kname);
        return rc;
    }

    case CACT_SYSCTL_BLKDEV_RESCAN: {
        int r = _root_only();
        if (r) return r;
        if (!arg) return -EINVAL;
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((const char *)arg);
        if (!kname) return -EFAULT;
        blkdev_t *disk = blkdev_find(kname);
        if (!disk || disk->parent) { kfree(kname); return -1; }
        // Refuse to rescan while the disk itself or any of its partitions
        // has a mounted filesystem.
        if (vfsdev_device_mounted(kname)) { kfree(kname); return -1; }
        for (int i = 0; i < blkdev_part_count(disk); i++) {
            blkdev_t *p = blkdev_part_at(disk, i);
            if (p && vfsdev_device_mounted(p->name)) { kfree(kname); return -1; }
        }
        int n = part_rescan(kname);
        kfree(kname);
        return n;   // >= 0: number of partitions exposed
    }

    case CACT_SYSCTL_SETHOSTNAME: {
        int r = _root_only();
        if (r) return r;
        if (!arg) return -EINVAL;
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((const char *)arg);
        if (!kname) return -EFAULT;
        size_t n = strlen(kname);
        if (n == 0 || n > 64) { kfree(kname); return -EINVAL; }
        procfs_set_nodename(kname);
        kfree(kname);
        return 0;
    }

    case CACT_SYSCTL_GET_CONSOLE_LOGLEVEL: {
        if (!arg) return -EINVAL;
        int lv = console_loglevel_get();
        if (copy_to_user(arg, &lv, sizeof(lv)) != 0) return -EFAULT;
        return lv;
    }

    case CACT_SYSCTL_SET_CONSOLE_LOGLEVEL: {
        int r = _root_only();
        if (r) return r;
        if (!arg) return -EINVAL;
        int lv;
        if (copy_from_user(&lv, arg, sizeof(lv)) != 0) return -EFAULT;
        if (lv < 0 || lv > 7) return -EINVAL;
        console_loglevel_set(lv);
        return 0;
    }

    case CACT_SYSCTL_SETWALLCLOCK: {
        int r = _root_only();
        if (r) return r;
        if (!arg) return -EINVAL;
        cact_time_t t;
        if (copy_from_user(&t, arg, sizeof(t)) != 0) return -EFAULT;
        if (t.usec > 999999) return -EINVAL;
        rtc_set_epoch_usec((uint64_t)t.sec * 1000000ull + t.usec);
        return 0;
    }

    default:
        return -EINVAL;
    }
}

devfs_driver_t drv_sys = { .ioctl = _sys_ioctl };

// A device name may be given bare ("zram0", what blkdev_find() keys on) or as a
// /dev path ("/dev/zram0", what a user types and what swapon(8)-style tools
// pass); strip the optional prefix.
static const char *zmem_blkdev_name(const char *p) {
    static const char pfx[] = "/dev/";
    int i = 0;
    while (pfx[i] && p[i] == pfx[i])
        i++;
    return pfx[i] ? p : p + i;
}

// ── /dev/zmem ─────────────────────────────────────────────────────────────
// The single atomic control node for the compressed-memory backends (zram and
// zswap).  Root only, like /dev/sys: these change how the whole system's memory
// behaves.  Each ioctl configures *and* enables in one call.

static int _zmem_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    int r = _root_only();
    if (r) return r;

    switch (cmd) {
    case CACT_ZMEM_ZSWAP_SET: {
        cact_zmem_zswap_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (!a.enabled)
            return zswap_disable();
        // zswap_enable validates the percentage and returns a negated errno
        // (-EINVAL / -ENOMEM) or 0.  A raised limit *grows* the pool; a lower one
        // is refused (handles live in page tables).
        int rc = zswap_enable(a.max_pool_pct, (int)a.compress_level,
                              (int)a.writeback);
        return rc < 0 ? rc : 0;
    }

    case CACT_ZMEM_ZRAM_CREATE: {
        cact_zmem_zram_create_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (a.name[sizeof(a.name) - 1] != '\0') return -EINVAL;
        if (zram_create(a.name, a.size_bytes, (int)a.compress_level) != 0)
            return -EINVAL;   // name in use, size below a page, or out of memory
        return 0;
    }

    case CACT_ZMEM_ZRAM_DESTROY: {
        if (!arg) return -EINVAL;
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((char *)arg);
        if (!kname) return -EFAULT;
        int rc = zram_destroy(kname);
        kfree(kname);
        if (rc == ZRAM_DESTROY_OK)   return 0;
        if (rc == ZRAM_DESTROY_BUSY) return -EBUSY;
        return -ENODEV;
    }

    case CACT_ZMEM_SWAP_ATTACH: {
        if (!arg) return -EINVAL;
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((char *)arg);
        if (!kname) return -EFAULT;
        blkdev_t *dev = blkdev_find(zmem_blkdev_name(kname));
        kfree(kname);
        if (!dev) return -ENODEV;
        // A partition attaches through its own table (the partition layer does
        // that itself); this is for whole devices like zramN.
        if (dev->parent) return -EINVAL;
        return swap_enable_device(dev) == 0 ? 0 : -EINVAL;
    }

    case CACT_ZMEM_SWAP_DETACH: {
        if (!arg) return -EINVAL;
        if (!validate_user_str((const char *)arg)) return -EFAULT;
        char *kname = copy_path_from_user((char *)arg);
        if (!kname) return -EFAULT;
        blkdev_t *dev = blkdev_find(zmem_blkdev_name(kname));
        kfree(kname);
        if (!dev) return -ENODEV;
        if (!swap_is_backing_device(dev)) return -EINVAL;
        // Refuse while pages are still swapped out: CactOS has no swapoff
        // migration, so releasing the device would strand them.
        if (swap_get_stats().used_slots != 0) return -EBUSY;
        swap_detach_device(dev);
        return 0;
    }

    default:
        return -EINVAL;
    }
}

devfs_driver_t drv_zmem = { .ioctl = _zmem_ioctl };

// ── /dev/net ──────────────────────────────────────────────────────────────

static int _net_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;

    switch (cmd) {
    case CACT_NETCTL_SOCKET: {
        cact_socket_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (!current_task) return -1;
        vfs_node_t *node;
        if ((int)a.domain == AF_UNIX)
            node = unix_sock_create((int)a.type, (int)a.proto);
        else
            node = ksock_create((int)a.domain, (int)a.type, (int)a.proto);
        if (!node) return -1;
        return alloc_fd(node);
    }

    case CACT_NETCTL_SOCKETPAIR: {
        cact_socketpair_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        int fds[2];
        int r = unix_socketpair((int)a.type, fds);
        if (r < 0) return r;
        a.fds[0] = (uint32_t)fds[0];
        a.fds[1] = (uint32_t)fds[1];
        return copy_to_user(arg, &a, sizeof(a));
    }

    case CACT_NETCTL_PING: {
        cact_ping_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_ping_echo_host(a.dst_ip, (uint16_t)a.id, (uint16_t)a.seq);
    }

    case CACT_NETCTL_PING_WAIT: {
        cact_ping_wait_arg_t a;
        int rtt;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        rtt = rust_net_ping_wait(a.dst_ip, (uint16_t)a.id, (uint16_t)a.seq,
                                 a.timeout_ms, &a.src_ip_out, &a.bytes_out);
        a.rtt_us_out = (rtt < 0) ? 0u : (uint32_t)rtt;
        if (copy_to_user(arg, &a, sizeof(a)) != 0) return -EFAULT;
        return rtt;
    }

    case CACT_NETCTL_PING6: {
        cact_ping6_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_ping_echo6(a.dst, (uint16_t)a.id, (uint16_t)a.seq);
    }

    case CACT_NETCTL_PING_WAIT6: {
        cact_ping6_wait_arg_t a;
        int rtt;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        rtt = rust_net_ping_wait6(a.dst, (uint16_t)a.id, (uint16_t)a.seq,
                                  a.timeout_ms, a.src_out, &a.bytes_out);
        a.rtt_us_out = (rtt < 0) ? 0u : (uint32_t)rtt;
        if (copy_to_user(arg, &a, sizeof(a)) != 0) return -EFAULT;
        return rtt;
    }

    case CACT_NETCTL_DNS_RESOLVE: {
        cact_dns_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (!validate_user_str(a.name)) return -EFAULT;
        if (!validate_user_ptr(a.out_ip, sizeof(uint32_t))) return -EFAULT;
        return rust_net_dns_resolve_a(a.name, a.out_ip);
    }

    case CACT_NETCTL_DNS_RESOLVE_AAAA: {
        cact_dns6_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (!validate_user_str(a.name)) return -EFAULT;
        if (!validate_user_ptr(a.out_addr, 16)) return -EFAULT;
        return rust_net_dns_resolve_aaaa(a.name, a.out_addr);
    }

    case CACT_NETCTL_NETCFG: {
        int r = _root_only();
        if (r) return r;
        cact_netcfg_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_set_ipv4_config(a.ip_host, a.netmask_host,
                                        a.gateway_host, a.dns_host);
    }

    case CACT_NETCTL_NETCFG_GET: {
        if (!arg) return -EINVAL;
        if (!validate_user_ptr(arg, sizeof(cact_netcfg_get_t))) return -EFAULT;
        cact_netcfg_get_t g;
        memset(&g, 0, sizeof(g));
        rust_net_get_ipv4_config(&g.ip_host, &g.netmask_host,
                                 &g.gateway_host, &g.dns_host);
        g.link_up = (rust_net_link_is_up() > 0) ? 1u : 0u;
        if (g.link_up)
            rust_net_get_mac(g.mac);
        return copy_to_user(arg, &g, sizeof(g));
    }

    case CACT_NETCTL_IFNAME: {
        char name[CACT_IFNAME_MAX];
        if (!arg) return -EINVAL;
        if (!validate_user_ptr(arg, CACT_IFNAME_MAX)) return -EFAULT;
        memset(name, 0, sizeof(name));
        if (rust_net_get_ifname(name, sizeof(name)) < 0) return -ENODEV;
        return copy_to_user(arg, name, sizeof(name));
    }

    case CACT_NETCTL_IFACE_COUNT: {
        return rust_net_iface_count();
    }

    case CACT_NETCTL_IFACE_GET: {
        cact_iface_get_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        cact_iface_info_t info;
        memset(&info, 0, sizeof(info));
        if (rust_net_iface_get(a.index, &info) < 0) return -ENODEV;
        a.info = info;
        if (copy_to_user(arg, &a, sizeof(a)) != 0) return -EFAULT;
        return 0;
    }

    case CACT_NETCTL_ARP_COUNT: {
        return rust_net_arp_count();
    }

    case CACT_NETCTL_ARP_GET: {
        cact_arp_get_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (rust_net_arp_get(a.index, &a.entry) < 0) return -ENODEV;
        return copy_to_user(arg, &a, sizeof(a));
    }

    case CACT_NETCTL_IFACE_SETCFG: {
        int r = _root_only();
        if (r) return r;
        cact_iface_setcfg_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_iface_set_cfg(a.index, a.ip_host, a.netmask_host,
                                      a.gateway_host, a.dns_host);
    }

    case CACT_NETCTL_NETCFG6: {
        int r = _root_only();
        if (r) return r;
        cact_netcfg6_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_set_ipv6_config(a.addr, a.prefix, a.gateway, a.dns);
    }

    case CACT_NETCTL_IFACE_SETCFG6: {
        int r = _root_only();
        if (r) return r;
        cact_iface_setcfg6_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_iface_set_cfg6(a.index, a.addr, a.prefix, a.gateway, a.dns);
    }

    case CACT_NETCTL_FW_RULE_ADD: {
        int r = _root_only();
        if (r) return r;
        cact_fw_rule_t rule;
        if (!arg) return -EINVAL;
        if (copy_from_user(&rule, arg, sizeof(rule)) != 0) return -EFAULT;
        return rust_net_fw_rule_add(&rule);
    }

    case CACT_NETCTL_FW_RULE_DEL: {
        int r = _root_only();
        if (r) return r;
        cact_fw_idx_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_fw_rule_del(a.chain, a.index);
    }

    case CACT_NETCTL_FW_RULE_COUNT: {
        cact_fw_chain_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_fw_rule_count(a.chain);
    }

    case CACT_NETCTL_FW_RULE_GET: {
        cact_fw_get_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (rust_net_fw_rule_get(a.chain, a.index, &a.rule) != 0) return -ENODEV;
        return copy_to_user(arg, &a, sizeof(a));
    }

    case CACT_NETCTL_FW_FLUSH: {
        int r = _root_only();
        if (r) return r;
        cact_fw_chain_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_fw_flush(a.chain);
    }

    case CACT_NETCTL_FW_POLICY_SET: {
        int r = _root_only();
        if (r) return r;
        cact_fw_policy_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_fw_policy_set(a.chain, a.policy);
    }

    case CACT_NETCTL_FW_POLICY_GET: {
        cact_fw_chain_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        return rust_net_fw_policy_get(a.chain);
    }

    case CACT_NETCTL_FW_RESET: {
        int r = _root_only();
        if (r) return r;
        return rust_net_fw_reset();
    }

    case CACT_NETCTL_FW_CONN_COUNT: {
        return rust_net_fw_conn_count();
    }

    case CACT_NETCTL_FW_CONN_GET: {
        cact_fw_conn_get_arg_t a;
        if (!arg) return -EINVAL;
        if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
        if (rust_net_fw_conn_get(a.index, &a.conn) != 0) return -ENODEV;
        return copy_to_user(arg, &a, sizeof(a));
    }

    case CACT_NETCTL_FW_CONN_FLUSH: {
        int r = _root_only();
        if (r) return r;
        return rust_net_fw_conn_flush();
    }

    default:
        return -EINVAL;
    }
}

devfs_driver_t drv_net = { .ioctl = _net_ioctl };

// ── /dev/pipe ─────────────────────────────────────────────────────────────

static int _pipe_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_PIPECTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    if (!validate_user_ptr(arg, sizeof(uint32_t) * 2)) return -EFAULT;
    if (!current_task) return -1;

    vfs_node_t *pipefd[2];
    if (pipe_create(pipefd, 0) != 0) return -1;

    file_t *rf = file_alloc(pipefd[0]);
    file_t *wf = file_alloc(pipefd[1]);
    if (!rf || !wf) {
        // Close each end exactly once: an opened end via file_unref, an end
        // whose file_alloc failed via a direct close_vfs.  (Calling both, as
        // the original did, double-decremented and leaked the pipe.)
        if (rf) file_unref(rf); else close_vfs(pipefd[0]);
        if (wf) file_unref(wf); else close_vfs(pipefd[1]);
        return -ENOMEM;
    }

    int rfd = -1, wfd = -1;
    for (int i = 3; i < MAX_FD && (rfd < 0 || wfd < 0); i++) {
        if (!current_task->proc->fds->files[i]) {
            if (rfd < 0) rfd = i;
            else         wfd = i;
        }
    }

    if (rfd < 0 || wfd < 0) {
        file_unref(rf);
        file_unref(wf);
        return -EMFILE;
    }

    current_task->proc->fds->files[rfd] = rf;
    current_task->proc->fds->files[wfd] = wf;

    uint32_t fds[2] = { (uint32_t)rfd, (uint32_t)wfd };
    return copy_to_user(arg, fds, sizeof(fds));
}

devfs_driver_t drv_pipe = { .ioctl = _pipe_ioctl };

// ── /dev/memfd ────────────────────────────────────────────────────────────

static int _memfd_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_MEMFDCTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    cact_memfd_create_arg_t a;
    if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
    if (!current_task) return -1;

    char name[128];
    name[0] = 0;
    if (a.name) {
        if (!validate_user_str(a.name)) return -EFAULT;
        if (copy_from_user(name, a.name, sizeof(name) - 1) != 0) return -EFAULT;
        name[sizeof(name) - 1] = 0;
    }

    vfs_node_t *node = memfd_create_vnode(name[0] ? name : "memfd", (int)a.flags);
    if (!node) return -ENOMEM;

    int fd = alloc_fd(node);
    if (fd < 0) return -EMFILE;   // alloc_fd released the node again

    current_task->proc->fds->files[fd]->cloexec =
        (a.flags & CACT_MFD_CLOEXEC) ? 1 : 0;
    return fd;
}

devfs_driver_t drv_memfd = { .ioctl = _memfd_ioctl };

// ── /dev/eventfd ──────────────────────────────────────────────────────────

static int _eventfd_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_EVENTFDCTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    cact_eventfd_create_arg_t a;
    if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
    if (!current_task) return -1;

    vfs_node_t *node = eventfd_create_vnode(a.initval, a.flags);
    if (!node) return -ENOMEM;

    int fd = alloc_fd(node);
    if (fd < 0) return -EMFILE;   // alloc_fd released the node again

    current_task->proc->fds->files[fd]->cloexec =
        (a.flags & CACT_EFD_CLOEXEC) ? 1 : 0;
    return fd;
}

devfs_driver_t drv_eventfd = { .ioctl = _eventfd_ioctl };

// ── /dev/timerfd ──────────────────────────────────────────────────────────

static int _timerfd_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_TIMERFDCTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    cact_timerfd_create_arg_t a;
    if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
    if (!current_task) return -1;

    vfs_node_t *node = timerfd_create_vnode(a.clockid, a.flags);
    if (!node) return -ENOMEM;

    int fd = alloc_fd(node);
    if (fd < 0) return -EMFILE;   // alloc_fd released the node again

    current_task->proc->fds->files[fd]->cloexec =
        (a.flags & CACT_TFD_CLOEXEC) ? 1 : 0;
    return fd;
}

devfs_driver_t drv_timerfd = { .ioctl = _timerfd_ioctl };

// ── /dev/signalfd ─────────────────────────────────────────────────────────

static int _signalfd_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_SIGNALFDCTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    cact_signalfd_create_arg_t a;
    if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
    if (!current_task) return -1;

    vfs_node_t *node = signalfd_create_vnode(a.mask, a.flags);
    if (!node) return -ENOMEM;

    int fd = alloc_fd(node);
    if (fd < 0) return -EMFILE;   // alloc_fd released the node again

    current_task->proc->fds->files[fd]->cloexec =
        (a.flags & CACT_SFD_CLOEXEC) ? 1 : 0;
    return fd;
}

devfs_driver_t drv_signalfd = { .ioctl = _signalfd_ioctl };

// ── /dev/epoll ────────────────────────────────────────────────────────────

static int _epoll_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if (cmd != CACT_EPOLLCTL_CREATE) return -EINVAL;
    if (!arg) return -EINVAL;
    cact_epoll_create_arg_t a;
    if (copy_from_user(&a, arg, sizeof(a)) != 0) return -EFAULT;
    if (!current_task) return -1;

    vfs_node_t *node = epoll_create_vnode(a.flags);
    if (!node) return -ENOMEM;

    int fd = alloc_fd(node);
    if (fd < 0) return -EMFILE;   // alloc_fd released the node again

    current_task->proc->fds->files[fd]->cloexec =
        (a.flags & CACT_EPOLL_CLOEXEC) ? 1 : 0;
    return fd;
}

devfs_driver_t drv_epoll = { .ioctl = _epoll_ioctl };

// Register this file's service devices (see devfs_devices_init for the
// convention).  These are the kernel-service nodes that turn console output,
// mount/reboot, module loading, socket/pipe/memfd/fd creation into plain VFS
// nodes.
void devfs_services_init(void) {
    register_chrdev("console", DEVFS_F_CHAR, &drv_console, 0);
    register_chrdev("sys",     DEVFS_F_CHAR, &drv_sys,     0);
    register_chrdev("zmem",    DEVFS_F_CHAR, &drv_zmem,    0);
    register_chrdev("net",     DEVFS_F_CHAR, &drv_net,     0);
    register_chrdev("pipe",    DEVFS_F_CHAR, &drv_pipe,    0);
    register_chrdev("memfd",   DEVFS_F_CHAR, &drv_memfd,   0);
    register_chrdev("eventfd", DEVFS_F_CHAR, &drv_eventfd, 0);
    register_chrdev("timerfd", DEVFS_F_CHAR, &drv_timerfd, 0);
    register_chrdev("signalfd",DEVFS_F_CHAR, &drv_signalfd,0);
    register_chrdev("epoll",   DEVFS_F_CHAR, &drv_epoll,   0);
    register_chrdev("kmsg",    DEVFS_F_CHAR, &drv_kmsg,    0);
}
