/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * zram — a block device whose pages live compressed in RAM.
 *
 * The page-index table maps a device page to its zpool handle, or
 * ZRAM_HANDLE_NONE for a page that has never been written (which reads back as
 * zeros, like any sparse block device).  The blkdev whole-page callbacks
 * compress once per write and decompress once per read; the per-sector
 * callbacks exist only for the boot partition probe and any sector-level user,
 * and go through a one-page read-modify-write.
 *
 * There is no per-device context in a blkdev sector callback, so each device
 * slot gets its own small sector thunk (ZRAM_SECTOR_THUNKS); the page callbacks
 * do receive the device, so one shared pair finds it by pointer.
 */

#include "zram.h"
#include "blkdev.h"
#include "zpool.h"
#include "memory.h"
#include "klib.h"
#include "kernel.h"
#include "sync.h"
#include "swap.h"
#include "multiboot2.h"

#define ZRAM_HANDLE_NONE 0xFFFFFFFFu
#define ZRAM_SPP         BLKDEV_SECTORS_PER_PAGE   /* 512-byte sectors per page */

typedef struct {
    int            used;
    char           name[ZRAM_NAME_MAX];
    uint32_t       cap_pages;
    uint32_t      *index;    /* page -> zpool handle, or ZRAM_HANDLE_NONE */
    uint8_t       *scratch;  /* one page, for the per-sector RMW path     */
    zpool_t       *pool;
    blkdev_t      *dev;
    irq_spinlock_t lock;
    uint32_t       pages_in, pages_out, store_fail;
} zram_dev_t;

static zram_dev_t g_zram[ZRAM_MAX_DEVICES];

static zram_dev_t *zram_find(const char *name) {
    if (!name)
        return 0;
    for (int i = 0; i < ZRAM_MAX_DEVICES; i++)
        if (g_zram[i].used && strcmp(g_zram[i].name, (char *)name) == 0)
            return &g_zram[i];
    return 0;
}

static zram_dev_t *zram_from_dev(blkdev_t *dev) {
    for (int i = 0; i < ZRAM_MAX_DEVICES; i++)
        if (g_zram[i].used && g_zram[i].dev == dev)
            return &g_zram[i];
    return 0;
}

/* ── page store (both helpers require the device lock held) ────────────── */

static void zram_page_read_locked(zram_dev_t *zd, uint32_t pi, uint8_t *buf) {
    uint32_t h = zd->index[pi];
    if (h == ZRAM_HANDLE_NONE || zpool_load(zd->pool, h, buf) != 0) {
        // Never-written pages (and a load that failed) read back as zeros.
        memset(buf, 0, PAGE_SIZE);
        return;
    }
    zd->pages_in++;
}

static int zram_page_write_locked(zram_dev_t *zd, uint32_t pi, const uint8_t *buf) {
    // Release the page's old slot first: the pool is sized for one slot per
    // page, so a retry after a failure still has the slot free.
    uint32_t h = zd->index[pi];
    if (h != ZRAM_HANDLE_NONE) {
        zpool_free(zd->pool, h);
        zd->index[pi] = ZRAM_HANDLE_NONE;
    }
    uint32_t nh = 0;
    if (zpool_store(zd->pool, buf, &nh) != 0) {
        // Only reachable on allocation failure (the pool's own budget can
        // always hold one slot per page): the page is lost.
        zd->store_fail++;
        return -1;
    }
    zd->index[pi] = nh;
    zd->pages_out++;
    return 0;
}

/* ── whole-page blkdev callbacks ───────────────────────────────────────── */

static int zram_read_page(blkdev_t *dev, uint32_t pi, uint8_t *buf) {
    zram_dev_t *zd = zram_from_dev(dev);
    if (!zd || pi >= zd->cap_pages)
        return -1;
    irq_spinlock_acquire(&zd->lock);
    zram_page_read_locked(zd, pi, buf);
    irq_spinlock_release(&zd->lock);
    return 0;
}

static int zram_write_page(blkdev_t *dev, uint32_t pi, uint8_t *buf) {
    zram_dev_t *zd = zram_from_dev(dev);
    if (!zd || pi >= zd->cap_pages)
        return -1;
    irq_spinlock_acquire(&zd->lock);
    int rc = zram_page_write_locked(zd, pi, buf);
    irq_spinlock_release(&zd->lock);
    if (rc != 0)
        pr_err("zram: %s: page %u store failed\n", zd->name, (unsigned)pi);
    return rc;
}

/* ── sector path: boot partition probe / any sector-level user ──────────── */

static void zram_sector(int idx, uint32_t lba, uint8_t *buf, int write) {
    zram_dev_t *zd = &g_zram[idx];
    if (!zd->used)
        return;
    uint32_t pi  = lba / ZRAM_SPP;
    uint32_t off = (lba % ZRAM_SPP) * 512;
    if (pi >= zd->cap_pages) {
        if (!write)
            memset(buf, 0, 512);
        return;
    }
    irq_spinlock_acquire(&zd->lock);
    zram_page_read_locked(zd, pi, zd->scratch);
    if (write) {
        memcpy(zd->scratch + off, buf, 512);
        zram_page_write_locked(zd, pi, zd->scratch);
    } else {
        memcpy(buf, zd->scratch + off, 512);
    }
    irq_spinlock_release(&zd->lock);
}

#define ZRAM_SECTOR_THUNKS(i) \
    static void zram##i##_read_sector(uint32_t lba, uint8_t *buf)  { zram_sector(i, lba, buf, 0); } \
    static void zram##i##_write_sector(uint32_t lba, uint8_t *buf) { zram_sector(i, lba, buf, 1); }

ZRAM_SECTOR_THUNKS(0)
ZRAM_SECTOR_THUNKS(1)
ZRAM_SECTOR_THUNKS(2)
ZRAM_SECTOR_THUNKS(3)

static void (*const zram_read_sector_fn[ZRAM_MAX_DEVICES])(uint32_t, uint8_t *) = {
    zram0_read_sector, zram1_read_sector, zram2_read_sector, zram3_read_sector,
};
static void (*const zram_write_sector_fn[ZRAM_MAX_DEVICES])(uint32_t, uint8_t *) = {
    zram0_write_sector, zram1_write_sector, zram2_write_sector, zram3_write_sector,
};

/* ── public API ────────────────────────────────────────────────────────── */

int zram_create(const char *name, uint64_t size_bytes, int level) {
    if (!name || !name[0] || strlen((char *)name) >= ZRAM_NAME_MAX)
        return -1;
    if (zram_find(name))
        return -1;
    if (size_bytes < PAGE_SIZE)
        return -1;

    int idx = -1;
    for (int i = 0; i < ZRAM_MAX_DEVICES; i++)
        if (!g_zram[i].used) { idx = i; break; }
    if (idx < 0)
        return -1;

    uint64_t pages64 = size_bytes / PAGE_SIZE;
    if (pages64 == 0 || pages64 > 0xFFFFFFFFull / ZRAM_SPP)
        return -1;
    uint32_t pages = (uint32_t)pages64;

    // The device exposes `pages` addressable pages; one spare sector covers the
    // swap header sector, exactly as a swap partition is laid out.
    uint32_t max_lba = pages * ZRAM_SPP + 1;

    zpool_t *pool = zpool_create(pages, pages64 * PAGE_SIZE, level);
    if (!pool)
        return -1;

    uint32_t *index = kmalloc((size_t)pages * sizeof(uint32_t));
    if (!index) {
        zpool_destroy(pool);
        return -1;
    }
    for (uint32_t p = 0; p < pages; p++)
        index[p] = ZRAM_HANDLE_NONE;

    uint8_t *scratch = kmalloc(PAGE_SIZE);
    if (!scratch) {
        kfree(index);
        zpool_destroy(pool);
        return -1;
    }

    zram_dev_t *zd = &g_zram[idx];
    memset(zd, 0, sizeof *zd);
    strncpy(zd->name, (char *)name, ZRAM_NAME_MAX - 1);
    zd->name[ZRAM_NAME_MAX - 1] = '\0';
    zd->cap_pages = pages;
    zd->index     = index;
    zd->scratch   = scratch;
    zd->pool      = pool;
    irq_spinlock_init(&zd->lock);
    // Set `used` before registering: register_blkdev() probes the new disk
    // (reads sector 0), which reaches zram_sector() on this slot.
    zd->used      = 1;

    if (register_blkdev(zd->name, max_lba, zram_read_sector_fn[idx],
                        zram_write_sector_fn[idx]) != 0) {
        zd->used = 0;
        kfree(scratch);
        kfree(index);
        zpool_destroy(pool);
        return -1;
    }

    blkdev_t *dev = blkdev_find(zd->name);
    zd->dev = dev;
    // A RAM device carries no root filesystem: never let it become the boot
    // device (mntfs mounts the root from there).
    blkdev_set_boot_candidate(dev, 0);
    blkdev_set_page_ops(dev, zram_read_page, zram_write_page);

    pr_info("zram: %s ready — %u pages (%u MiB), zstd level %d\n",
            zd->name, (unsigned)pages, (unsigned)(size_bytes >> 20), level);
    return 0;
}

int zram_destroy(const char *name) {
    zram_dev_t *zd = zram_find(name);
    if (!zd)
        return ZRAM_DESTROY_NODEV;
    if (swap_is_backing_device(zd->dev)) {
        pr_warn("zram: %s is the swap backing device — detach swap first\n",
                zd->name);
        return ZRAM_DESTROY_BUSY;
    }

    // Drop the /dev node and the block-layer entry (no partitions: a zram
    // device is never partitioned), then free every stored page.
    blkdev_set_page_ops(zd->dev, 0, 0);
    unregister_blkdev(zd->name);
    zpool_destroy(zd->pool);
    kfree(zd->index);
    kfree(zd->scratch);

    pr_info("zram: %s destroyed\n", zd->name);
    memset(zd, 0, sizeof *zd);
    return ZRAM_DESTROY_OK;
}

int zram_exists(const char *name) {
    return zram_find(name) != 0;
}

int zram_count(void) {
    int n = 0;
    for (int i = 0; i < ZRAM_MAX_DEVICES; i++)
        if (g_zram[i].used)
            n++;
    return n;
}

int zram_get_info(int i, zram_info_t *out) {
    if (!out || i < 0 || i >= ZRAM_MAX_DEVICES || !g_zram[i].used)
        return -1;
    zram_dev_t *zd = &g_zram[i];
    zpool_stats_t st;
    if (zpool_get_stats(zd->pool, &st) != 0)
        return -1;

    memset(out, 0, sizeof *out);
    memcpy(out->name, zd->name, ZRAM_NAME_MAX);
    out->capacity_pages = zd->cap_pages;
    out->stored_pages   = st.live_pages;
    out->pages_in       = zd->pages_in;
    out->pages_out      = zd->pages_out;
    out->stored_bytes   = st.stored_bytes;
    out->original_bytes = st.original_bytes;
    return 0;
}

void zram_init(void) {
    const char *v = mb2_cmdline_get("zram");
    if (!v)
        return;  // no zram= on the command line: create nothing
    uint64_t bytes = 0;
    if (!mb2_cmdline_parse_size(v, &bytes) || bytes < PAGE_SIZE) {
        pr_warn("zram: bad zram= value, ignored\n");
        return;
    }
    if (zram_create("zram0", bytes, 0) != 0)
        pr_warn("zram: could not create zram0 from the command line\n");
}
