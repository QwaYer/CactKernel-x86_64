/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "ksym.h"
#include "klib.h"
#include "memory.h"
#include "kernel.h"
#include "net.h"
#include "pci.h"
#include "sync.h"
#include "devfs.h"
#include "blkdev.h"
#include "pagecache.h"
#include "msi.h"
#include "drm_drv.h"
#include "validate.h"
#include "usb.h"
#include "firmware.h"
#include "ktime.h"
#include "proc.h"

/* 64-bit signed division (compiler runtime).  An i386 module doing int64_t
 * arithmetic — e.g. the i915 WRPLL calculator — resolves these here; the
 * kernel already provides them. */
extern long long __divdi3(long long, long long);
extern long long __moddi3(long long, long long);
extern unsigned long long __udivdi3(unsigned long long, unsigned long long);

/* In-kernel 802.11 station engine (Rust, cact80211): a Wi-Fi module registers
 * its radio ops and hands received MPDUs to cact80211_rx. */
int  cact80211_register(void *hw);
void cact80211_unregister(void *hw);
void cact80211_rx(void *hw, const unsigned char *frame, int len);

typedef struct {
    const char* name;
    uintptr_t   addr;
} ksym_entry_t;

/*
 * Static export list — extend as driver modules need more kernel entry points.
 * Keep sorted by name if you switch to binary search; linear scan is fine
 * for a small table.
 */
static const ksym_entry_t ksym_table[] = {
    { "kmalloc_aligned", (uintptr_t)kmalloc_aligned },
    { "compare_string",  (uintptr_t)compare_string },
    { "copy_string",     (uintptr_t)copy_string },
    { "memory_copy",     (uintptr_t)memory_copy },
    { "memory_set",      (uintptr_t)memory_set },
    { "irq_spinlock_init",    (uintptr_t)irq_spinlock_init },
    { "irq_spinlock_acquire", (uintptr_t)irq_spinlock_acquire },
    { "irq_spinlock_release", (uintptr_t)irq_spinlock_release },
    { "free_page",      (uintptr_t)free_page },
    { "kalloc",         (uintptr_t)kalloc },
    { "kfree",          (uintptr_t)kfree },
    { "kmalloc",        (uintptr_t)kmalloc },

    /* User-memory access.  A driver module decodes its own ioctl payloads
     * (DRM_COMMAND_BASE and above are passed through to it untouched), so it
     * needs the same validate/copy primitives the core uses.  Modules are
     * HMAC-verified at load time, i.e. trusted kernel code. */
    { "validate_user_ptr", (uintptr_t)validate_user_ptr },
    { "copy_from_user",     (uintptr_t)copy_from_user },
    { "copy_to_user",       (uintptr_t)copy_to_user },
    { "snprintf",       (uintptr_t)snprintf },
    { "memcpy",         (uintptr_t)memcpy },
    { "memcmp",         (uintptr_t)memcmp },
    { "memset",         (uintptr_t)memset },
    { "sema_init",      (uintptr_t)sema_init },
    { "down",           (uintptr_t)down },
    { "up",             (uintptr_t)up },
    { "mutex_init",     (uintptr_t)mutex_init },
    { "mutex_lock",     (uintptr_t)mutex_lock },
    { "mutex_unlock",   (uintptr_t)mutex_unlock },
    { "spin_lock_init", (uintptr_t)spin_lock_init },
    { "spin_lock",      (uintptr_t)spin_lock },
    { "spin_unlock",    (uintptr_t)spin_unlock },
    { "spin_lock_irqsave",    (uintptr_t)spin_lock_irqsave },
    { "spin_unlock_irqrestore", (uintptr_t)spin_unlock_irqrestore },
    { "register_chrdev",      (uintptr_t)register_chrdev },
    { "unregister_chrdev",    (uintptr_t)unregister_chrdev },
    { "register_blkdev",       (uintptr_t)register_blkdev },
    { "unregister_blkdev",     (uintptr_t)unregister_blkdev },
    { "blkdev_set_ident",      (uintptr_t)blkdev_set_ident },
    { "blkdev_read_sector",    (uintptr_t)blkdev_read_sector },
    { "blkdev_write_sector",   (uintptr_t)blkdev_write_sector },
    { "blkdev_read",           (uintptr_t)blkdev_read },
    { "blkdev_write",          (uintptr_t)blkdev_write },
    { "blkdev_by_id",          (uintptr_t)blkdev_by_id },
    { "pc_get_page",           (uintptr_t)pc_get_page },
    { "pc_put_page",           (uintptr_t)pc_put_page },
    { "pc_mark_dirty",         (uintptr_t)pc_mark_dirty },
    { "pc_flush_dev",          (uintptr_t)pc_flush_dev },

    /* Generic inode address space (page cache) — an fs module points an
     * (owner, ino) object at its own disk backing and then reads, writes and
     * maps the file through the page cache.  Only the calls a filesystem
     * module makes are exported; vfs_as_truncate/flush/release/flush_fd/stats
     * stay kernel-internal. */
    { "vfs_as_set_backing",    (uintptr_t)vfs_as_set_backing },
    { "vfs_as_setsize",        (uintptr_t)vfs_as_setsize },
    { "vfs_as_size",           (uintptr_t)vfs_as_size },
    { "vfs_as_read",           (uintptr_t)vfs_as_read },
    { "vfs_as_write",          (uintptr_t)vfs_as_write },
    { "vfs_as_backing",        (uintptr_t)vfs_as_backing },
    { "vfs_as_flush_all",      (uintptr_t)vfs_as_flush_all },

    { "printk",         (uintptr_t)printk },
    { "printk_color",   (uintptr_t)printk_color },
    { "printk_hex",     (uintptr_t)printk_hex },
    { "netif_rx",         (uintptr_t)netif_rx },
    { "net_receive_packet",  (uintptr_t)net_receive_packet },
    { "net_driver_irq_wake", (uintptr_t)net_driver_irq_wake },
    { "active_nic",          (uintptr_t)&active_nic },
    { "register_netdev",   (uintptr_t)register_netdev },
    { "unregister_netdev", (uintptr_t)unregister_netdev },
    /* In-kernel 802.11 station engine: a Wi-Fi module is a dumb radio that
     * registers its ops and hands received MPDUs to cact80211_rx. */
    { "cact80211_register",   (uintptr_t)cact80211_register },
    { "cact80211_unregister", (uintptr_t)cact80211_unregister },
    { "cact80211_rx",         (uintptr_t)cact80211_rx },
    { "msidev_alloc_vector",  (uintptr_t)msidev_alloc_vector },
    { "msidev_free_vector",   (uintptr_t)msidev_free_vector },
    { "msidev_register_handler", (uintptr_t)msidev_register_handler },
    { "msidev_unregister_handler", (uintptr_t)msidev_unregister_handler },
    { "msidev_register",      (uintptr_t)msidev_register },
    { "msidev_unregister",    (uintptr_t)msidev_unregister },
    { "pci_msix_support",     (uintptr_t)pci_msix_support },
    { "pci_msix_table_map",   (uintptr_t)pci_msix_table_map },
    { "pci_msix_pba_map",     (uintptr_t)pci_msix_pba_map },
    { "pci_msix_enable",      (uintptr_t)pci_msix_enable },
    { "pci_msi_support",      (uintptr_t)pci_msi_support },
    { "pci_msi_enable",       (uintptr_t)pci_msi_enable },
    { "pci_set_master", (uintptr_t)pci_set_master },
    { "pci_read_config_dword",            (uintptr_t)pci_read_config_dword },
    { "pci_read_config_long",  (uintptr_t)pci_read_config_long },
    { "pci_write_config_dword",           (uintptr_t)pci_write_config_dword },
    { "pci_write_config_long", (uintptr_t)pci_write_config_long },
    { "inb",   (uintptr_t)inb },
    { "outb",  (uintptr_t)outb },
    { "inl",   (uintptr_t)inl },
    { "outl",  (uintptr_t)outl },
    { "inw",   (uintptr_t)inw },
    { "outw",  (uintptr_t)outw },
    { "strcmp",         (uintptr_t)strcmp },
    { "strlen",         (uintptr_t)strlen },
    { "strncmp",        (uintptr_t)strncmp },
    { "strncpy",        (uintptr_t)strncpy },
    { "streq",          (uintptr_t)streq },
    { "strlcpy",        (uintptr_t)strlcpy },
    { "skb_alloc",      (uintptr_t)skb_alloc },
    { "skb_data",       (uintptr_t)skb_data },
    { "kfree_skb",       (uintptr_t)kfree_skb },
    { "skb_len",        (uintptr_t)skb_len },
    { "skb_push",       (uintptr_t)skb_push },
    { "skb_put",        (uintptr_t)skb_put },
    { "vmm_get_phys",   (uintptr_t)vmm_get_phys },
    { "vmm_map",        (uintptr_t)vmm_map },

    /* DRM/KMS core — the generic API a GPU module (e.g. virtio-gpu) drives.
     * Everything behind these entry points is hardware-agnostic: the module
     * builds KMS objects, GEM buffers and framebuffers, and implements the
     * drm_driver_ops_t callbacks; ioctl decoding stays in the kernel. */
    { "drm_dev_alloc",               (uintptr_t)drm_dev_alloc },
    { "drm_dev_free",                (uintptr_t)drm_dev_free },
    { "drm_dev_priv",                (uintptr_t)drm_dev_priv },
    { "drm_dev_ops",                 (uintptr_t)drm_dev_ops },
    { "drm_dev_register",            (uintptr_t)drm_dev_register },
    { "drm_dev_unregister",          (uintptr_t)drm_dev_unregister },
    { "drm_dev_create",              (uintptr_t)drm_dev_create },
    { "drm_mode_crtc_init",          (uintptr_t)drm_mode_crtc_init },
    { "drm_mode_encoder_init",       (uintptr_t)drm_mode_encoder_init },
    { "drm_mode_connector_init",     (uintptr_t)drm_mode_connector_init },
    { "drm_mode_plane_init",         (uintptr_t)drm_mode_plane_init },
    { "drm_crtc_find",               (uintptr_t)drm_crtc_find },
    { "drm_connector_find",          (uintptr_t)drm_connector_find },
    { "drm_encoder_find",            (uintptr_t)drm_encoder_find },
    { "drm_plane_find",              (uintptr_t)drm_plane_find },
    { "drm_connector_add_mode",      (uintptr_t)drm_connector_add_mode },
    { "drm_connector_set_edid",      (uintptr_t)drm_connector_set_edid },
    { "drm_connector_attach_encoder", (uintptr_t)drm_connector_attach_encoder },
    { "drm_encoder_attach_crtc",     (uintptr_t)drm_encoder_attach_crtc },
    { "drm_crtc_handle_vblank",      (uintptr_t)drm_crtc_handle_vblank },
    { "drm_gem_create",              (uintptr_t)drm_gem_create },
    { "drm_gem_vaddr",               (uintptr_t)drm_gem_vaddr },
    { "drm_gem_size",                (uintptr_t)drm_gem_size },
    { "drm_gem_page_count",          (uintptr_t)drm_gem_page_count },
    { "drm_gem_page_phys",           (uintptr_t)drm_gem_page_phys },
    { "drm_gem_ref",                 (uintptr_t)drm_gem_ref },
    { "drm_gem_unref",               (uintptr_t)drm_gem_unref },
    { "drm_gem_memfd",               (uintptr_t)drm_gem_memfd },
    { "drm_gem_map_offset",          (uintptr_t)drm_gem_map_offset },
    { "drm_gem_handle_create",       (uintptr_t)drm_gem_handle_create },
    { "drm_gem_handle_lookup",       (uintptr_t)drm_gem_handle_lookup },
    { "drm_gem_handle_close",        (uintptr_t)drm_gem_handle_close },
    { "drm_gem_prime_handle_to_fd",  (uintptr_t)drm_gem_prime_handle_to_fd },
    { "drm_gem_prime_fd_to_handle",  (uintptr_t)drm_gem_prime_fd_to_handle },

    /* Compiler runtime for 64-bit arithmetic in modules. */
    { "__divdi3",                    (uintptr_t)__divdi3 },
    { "__moddi3",                    (uintptr_t)__moddi3 },
    { "__udivdi3",                   (uintptr_t)__udivdi3 },

    /* USB — a USB driver module (see Cact/drivers/usb/loader/usb_mod.c) calls
     * usb_driver_register() with a static usb_driver_t and drives transfers
     * through the usb_device_t's host-controller ops. */
    { "usb_driver_register",   (uintptr_t)usb_driver_register },
    { "usb_driver_unregister", (uintptr_t)usb_driver_unregister },
    { "usb_get_descriptor",    (uintptr_t)usb_get_descriptor },
    { "usb_set_configuration", (uintptr_t)usb_set_configuration },
    { "usb_set_interface",     (uintptr_t)usb_set_interface },

    /* Firmware — modules stage blobs (rt2870.bin) out of cctkfs. */
    { "request_firmware", (uintptr_t)request_firmware },
    { "release_firmware", (uintptr_t)release_firmware },

    /* Timing — modules busy-wait for firmware boot and device settle, read the
     * monotonic clock, or block their thread for a number of scheduler ticks. */
    { "ktime_busy_wait_us", (uintptr_t)ktime_busy_wait_us },
    { "ktime_get_usec",     (uintptr_t)ktime_get_usec },
    { "sched_sleep_ticks",  (uintptr_t)sched_sleep_ticks },
};

uintptr_t ksym_resolve(const char* name) {
    if (!name) return 0;
    for (unsigned i = 0; i < sizeof(ksym_table) / sizeof(ksym_table[0]); i++) {
        if (streq((char*)name, (char*)ksym_table[i].name))
            return ksym_table[i].addr;
    }
    return 0;
}

/*
 * Module ABI fingerprint.  FNV-1a 32-bit over "CACT-MODVER-1\0" followed by
 * every exported symbol name (sorted) and a NUL separator.  The entry order in
 * ksym_table must not matter, hence the sort; adding, removing or renaming an
 * export changes the value automatically.
 *
 * tools/mod_vermagic.py implements the same algorithm over the same names, and
 * cact_check.sh asserts the two agree at boot.  Change one, change the other.
 */
#define KSYM_FNV_OFFSET 2166136261u
#define KSYM_FNV_PRIME  16777619u

static uint32_t ksym_fnv1a(uint32_t h, const char* s) {
    while (*s) { h ^= (uint8_t)*s++; h *= KSYM_FNV_PRIME; }
    h ^= 0u; h *= KSYM_FNV_PRIME;   /* NUL separator, matches the Python tool */
    return h;
}

uint32_t ksym_vermagic(void) {
    const unsigned n = sizeof(ksym_table) / sizeof(ksym_table[0]);
    const char* names[sizeof(ksym_table) / sizeof(ksym_table[0])];
    for (unsigned i = 0; i < n; i++) names[i] = ksym_table[i].name;
    for (unsigned i = 1; i < n; i++) {          /* insertion sort by name */
        const char* key = names[i];
        unsigned    j   = i;
        while (j > 0 && strcmp((char*)names[j - 1], (char*)key) > 0) {
            names[j] = names[j - 1];
            j--;
        }
        names[j] = key;
    }

    uint32_t h = KSYM_FNV_OFFSET;
    h = ksym_fnv1a(h, "CACT-MODVER-1");
    for (unsigned i = 0; i < n; i++) h = ksym_fnv1a(h, names[i]);
    return h;
}
