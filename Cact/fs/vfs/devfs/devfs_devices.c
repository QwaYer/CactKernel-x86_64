/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "devfs.h"
#include "devfs_internal.h"
#include "vfs.h"
#include "memory.h"
#include "klib.h"
#include "kernel.h"
#include "pipe.h"
#include "pci_driver.h"
#include "mouse.h"
#include "fb.h"
#include "validate.h"
#include "multiboot2.h"

// ── Built-in driver tables ────────────────────────────────────────────────

static int _null_read (void *p, uint64_t o, uint32_t s, char *b)
    { (void)p;(void)o;(void)s;(void)b; return 0; }
static int _null_write(void *p, uint64_t o, uint32_t s, char *b)
    { (void)p;(void)o;(void)b; return (int)s; }
devfs_driver_t drv_null = { .read=_null_read, .write=_null_write };

static int _zero_read(void *p, uint64_t o, uint32_t s, char *b)
    { (void)p;(void)o; memset(b,0,s); return (int)s; }
devfs_driver_t drv_zero = { .read=_zero_read, .write=_null_write };

// /dev/random + /dev/urandom — the kernel CSPRNG (ChaCha20 DRBG, cact_crypto).
// This is where getrandom(2), the crypto service and TLS key generation all get
// their bytes, so there is exactly one generator to trust.
extern int cact_csprng_fill(uint8_t *buf, uint32_t len);

static int _rand_read(void *p, uint64_t o, uint32_t s, char *b) {
    (void)p;(void)o;
    if (cact_csprng_fill((uint8_t *)b, s) != 0) return -1;
    return (int)s;
}
devfs_driver_t drv_random = { .read=_rand_read, .write=_null_write };

extern int keyboard_read_char(void);

// /dev/tty0 + /dev/ttyN are not devfs's business: the terminal driver owns its
// devfs_driver_t and registers every VT node itself (Cact/drivers/tty/tty.c).

// /dev/keyboard — raw character stream from keyboard circular buffer
static int _kbd_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;(void)off;
    uint32_t i=0;
    while(i<size){
        int c;
        while((c=keyboard_read_char())<0) schedule();
        buf[i++]=(char)c;
        if(size<=1) break;
    }
    return (int)i;
}
devfs_driver_t drv_keyboard = { .read=_kbd_read };

// /dev/mouse — raw mouse event packets (mouse_packet_t structs)
static int _mouse_read_dev(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;(void)off;
    if(size<sizeof(mouse_packet_t)) return -1;
    mouse_packet_t pkt;
    while(mouse_read_event(&pkt)<0) schedule();
    memcpy(buf,&pkt,sizeof(mouse_packet_t));
    return (int)sizeof(mouse_packet_t);
}
devfs_driver_t drv_mouse = { .read=_mouse_read_dev };

// /dev/fb0 — framebuffer device (read/write at byte offset, ioctl for screen info)
#define FBIOGET_VSCREENINFO 0x4600
struct fb_var_screeninfo {
    uint32_t xres;
    uint32_t yres;
    uint32_t xres_virtual;
    uint32_t yres_virtual;
    uint32_t xoffset;
    uint32_t yoffset;
    uint32_t bits_per_pixel;
    uint32_t grayscale;
};

static int _fb_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    uint32_t fb_sz = fb_get_pitch() * fb_get_height();
    if(off>=fb_sz) return 0;
    if(off+size>fb_sz) size=(uint32_t)(fb_sz-off);
    memcpy(buf, (char*)fb_get_buffer()+off, size);
    return (int)size;
}

static int _fb_write(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    uint32_t fb_sz = fb_get_pitch() * fb_get_height();
    if(off>=fb_sz) return 0;
    if(off+size>fb_sz) size=(uint32_t)(fb_sz-off);
    memcpy((char*)fb_get_buffer()+off, buf, size);
    fb_flush();
    return (int)size;
}

static int _fb_ioctl(void *p, uint32_t cmd, void *arg) {
    (void)p;
    if(cmd==FBIOGET_VSCREENINFO) {
        if(!validate_user_ptr(arg, sizeof(struct fb_var_screeninfo))) return -1;
        struct fb_var_screeninfo *info = (struct fb_var_screeninfo*)arg;
        info->xres          = fb_get_width();
        info->yres          = fb_get_height();
        info->xres_virtual  = fb_get_width();
        info->yres_virtual  = fb_get_height();
        info->xoffset       = 0;
        info->yoffset       = 0;
        info->bits_per_pixel = fb_get_bpp();
        info->grayscale     = 0;
        return 0;
    }
    return -1;
}
devfs_driver_t drv_fb = {
    .read=_fb_read, .write=_fb_write, .ioctl=_fb_ioctl
};

// /dev/firmrepo, /dev/localbinrepo — the two Multiboot2 modules GRUB hands over:
// the compressed firmrepo archive and the localbinrepo image.  Both are far too big
// to stage a second time, so they stay in place in physical memory and are
// served read-only.  The module's physical range lies inside the boot
// reservation, whose low identity alias a process PD can shadow (the ELF image
// is loaded in that same range), so the copy goes through the direct map, whose
// PML4 entry every address space shares.
static int _module_read(const mb2_module_info_t *mod, uint64_t off,
                        uint32_t size, char *buf) {
    uint32_t total = mod->mod_size;
    if (!total || off >= total) return 0;
    if (size > total - off) size = (uint32_t)(total - off);
    memcpy(buf, vmm_p2v((uint64_t)mod->mod_start + off), size);
    return (int)size;
}

static int _firmrepo_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    return _module_read(&mb2_firmrepo_module, off, size, buf);
}

static int _localbinrepo_read(void *p, uint64_t off, uint32_t size, char *buf) {
    (void)p;
    return _module_read(&mb2_localbinrepo_module, off, size, buf);
}

devfs_driver_t drv_firmrepo = { .read=_firmrepo_read };
devfs_driver_t drv_localbinrepo = { .read=_localbinrepo_read };

// Register this file's devices.  Each driver group registers the nodes it
// owns, so devfs_init() stays a generic bootstrap and carries no device list.
void devfs_devices_init(void) {
    register_chrdev("null",    DEVFS_F_CHAR, &drv_null,   0);
    register_chrdev("zero",    DEVFS_F_CHAR, &drv_zero,   0);
    register_chrdev("random",  DEVFS_F_CHAR, &drv_random, 0);
    register_chrdev("urandom", DEVFS_F_CHAR, &drv_random, 0);

    // Input devices live under /dev/input (Linux convention); register_chrdev()
    // also publishes /dev/keyboard and /dev/mouse as compat symlinks.
    register_chrdev("input/keyboard", DEVFS_F_CHAR, &drv_keyboard, 0);
    register_chrdev("input/mouse",    DEVFS_F_CHAR, &drv_mouse,    0);
    register_chrdev("fb0",      DEVFS_F_CHAR, &drv_fb,       0);

    // /dev/firmrepo serves whatever GRUB handed over; report its size so a
    // boot medium without the `module2 … firmrepo` line — or with a module
    // that turned out to be empty — is visible in the log instead of surfacing
    // as an empty archive at firmextr's first read.
    if (mb2_firmrepo_module.mod_start)
        pr_info("%s: firmrepo module %s, %u KiB (served as /dev/firmrepo)\n",
                "devfs", mb2_firmrepo_module.name,
                (unsigned)(mb2_firmrepo_module.mod_size / 1024));
    else
        pr_warn("%s: no firmrepo module — /dev/firmrepo reads empty\n", "devfs");

    if (mb2_localbinrepo_module.mod_start)
        pr_info("%s: localbinrepo module %s, %u KiB (served as /dev/localbinrepo)\n",
                "devfs", mb2_localbinrepo_module.name,
                (unsigned)(mb2_localbinrepo_module.mod_size / 1024));

    devfs_entry_t *lr =
        register_chrdev("firmrepo", DEVFS_F_CHAR, &drv_firmrepo, 0);
    // Publish the module size on the node: with no module it stays 0, which is
    // how cgoct/cact-install tell "this device carries no archive" (they skip
    // zero-size sources) instead of copying an empty file out of it.
    if (lr)
        lr->node.size = mb2_firmrepo_module.mod_size;

    // /dev/localbinrepo serves the boot localbinrepo image in place, so the installer can
    // put the image being booted — not a stale copy bundled inside it — onto a
    // target disk.  Same "size 0 means no module" contract as /dev/firmrepo.
    devfs_entry_t *cf =
        register_chrdev("localbinrepo", DEVFS_F_CHAR, &drv_localbinrepo, 0);
    if (cf)
        cf->node.size = mb2_localbinrepo_module.mod_size;
}
