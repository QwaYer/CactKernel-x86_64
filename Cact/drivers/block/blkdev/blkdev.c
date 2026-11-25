/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "blkdev.h"
#include "vfsdev.h"
#include "kernel.h"
#include "klib.h"
#include "memory.h"
#include "swap.h"

// Static device table and boot device pointer. Slots are never compacted:
// blkdev_t* handed to fs modules / page cache must stay valid for the life
// of the mount, and device ids == slot indexes. Freed slots are reused.
static blkdev_t devices[BLKDEV_SLOTS];
static int      dev_used[BLKDEV_SLOTS];
// Whether a whole-disk device may become the boot device.  RAM-backed devices
// (zram) clear this: they carry no root filesystem, and must never displace the
// real boot disk.
static int      boot_ok[BLKDEV_SLOTS];
static blkdev_t *boot_dev   = 0;

// Partition-layer probe (set by part_probe_init); called when a disk appears.
static void (*probe_hook)(blkdev_t *disk) = 0;

void blkdev_set_probe_hook(void (*fn)(blkdev_t *disk)) {
    probe_hook = fn;
}

static int alloc_slot(void) {
    for (int i = 0; i < BLKDEV_SLOTS; i++)
        if (!dev_used[i])
            return i;
    return -1;
}

static int blkdev_is_disk(const blkdev_t *d);

static void blkdev_pick_boot(void) {
    boot_dev = 0;
    for (int i = 0; i < BLKDEV_SLOTS; i++) {
        if (dev_used[i] && boot_ok[i] && !devices[i].parent) {
            boot_dev = &devices[i];
            return;
        }
    }
}

// RAM-backed devices (zram) call this with candidate==0 so they are never
// chosen as the boot device: the boot device is what mntfs mounts the root
// filesystem from, and a volatile RAM device has none.
void blkdev_set_boot_candidate(blkdev_t *dev, int candidate) {
    if (!dev || !blkdev_is_disk(dev))
        return;
    int idx = (int)dev->id;
    if (idx < 0 || idx >= BLKDEV_SLOTS)
        return;
    boot_ok[idx] = candidate ? 1 : 0;
    if (!candidate && boot_dev == dev) {
        // register_blkdev() had picked it (it was the first disk); step it back
        // and hand the boot role to the next candidate to appear.
        pr_info("blkdev: %s: not a boot candidate (RAM device)\n",
                devices[idx].name);
        blkdev_pick_boot();
    }
}

// Is `dev` a whole-disk device (owns controller callbacks)?
static int blkdev_is_disk(const blkdev_t *d) {
    return d && d->parent == 0;
}

int register_blkdev(const char *name, uint32_t max_lba,
                    void (*read_sector)(uint32_t lba, uint8_t *buf),
                    void (*write_sector)(uint32_t lba, uint8_t *buf)) {
    if (!name || !name[0] || !read_sector || !write_sector)
        return -1;
    if (blkdev_find(name))
        return -3;
    if (max_lba == 0) {
        /* A device with no addressable sector cannot be used; callers that
         * could not read the geometry (bad IDENTIFY, unsupported layout) must
         * fail loudly rather than register a zero-length disk. */
        pr_err("blkdev: %s: zero capacity, registration refused\n", name);
        return -1;
    }

    int idx = alloc_slot();
    if (idx < 0)
        return -2;

    blkdev_t *d = &devices[idx];
    memset(d, 0, sizeof *d);
    strncpy(d->name, (char *)name, BLKDEV_NAME_MAX - 1);
    d->name[BLKDEV_NAME_MAX - 1] = '\0';
    d->id          = (uint32_t)idx;
    d->max_lba     = max_lba;
    d->parent      = 0;
    d->start_lba   = 0;
    d->part_no     = 0;
    d->read_sector   = read_sector;
    d->write_sector  = write_sector;
    dev_used[idx] = 1;
    boot_ok[idx]  = 1;

    if (!boot_dev)
        boot_dev = d;

    pr_info("blkdev: registered %s max_lba=0x%x%s\n", d->name,
            (unsigned)max_lba, boot_dev == d ? " *boot*" : "");

    // Let the partition layer look at the new disk immediately (hotplug and
    // late-loaded storage kmods both end up here).
    if (probe_hook)
        probe_hook(d);
    return 0;
}

// Attach the device's stable identity (model/serial) once the kmod knows it,
// and publish the /dev/disk/by-id links that expose it.
int blkdev_set_ident(const char *name, const char *ident) {
    if (!name || !name[0] || !ident || !ident[0])
        return -1;
    blkdev_t *d = blkdev_find(name);
    if (!d || !blkdev_is_disk(d))
        return -1;

    strncpy(d->ident, (char *)ident, BLKDEV_IDENT_MAX - 1);
    d->ident[BLKDEV_IDENT_MAX - 1] = '\0';

    vfsdev_set_block_ident(d);
    return 0;
}

void unregister_blkdev(const char *name) {
    if (!name)
        return;
    blkdev_t *d = blkdev_find(name);
    if (!d || !blkdev_is_disk(d))
        return;

    // Drop this disk's /dev nodes and partitions first (refuse while a
    // partition or the disk itself is mounted), then release the slots.
    for (int i = 0; i < blkdev_part_count(d); i++) {
        blkdev_t *p = blkdev_part_at(d, i);
        if (p) vfsdev_unregister_block_device(p);
    }
    vfsdev_unregister_block_device(d);
    blkdev_clear_partitions(d);

    int idx = (int)d->id;
    dev_used[idx] = 0;
    boot_ok[idx]  = 0;
    memset(&devices[idx], 0, sizeof(blkdev_t));

    blkdev_pick_boot();

    pr_info("blkdev: unregistered %s\n", (char *)name);
}

// Storage drivers call register_blkdev() during PCI probe (NVMe/AHCI kmods).
void blkdev_init(void) {
    memset(devices,   0, sizeof(devices));
    memset(dev_used,  0, sizeof(dev_used));
    memset(boot_ok,   0, sizeof(boot_ok));
    boot_dev  = 0;

    pr_info("%s: layer ready (kmods attach during PCI probe)\n", "block");
}

// Return the boot device (first successfully probed whole disk)
blkdev_t *blkdev_get_boot(void) {
    return boot_dev;
}

// Find a device by name (linear scan), returns NULL if not found
blkdev_t *blkdev_find(const char *name) {
    if (!name)
        return 0;
    for (int i = 0; i < BLKDEV_SLOTS; i++)
        if (dev_used[i] && strcmp(devices[i].name, (char *)name) == 0)
            return &devices[i];
    return 0;
}

blkdev_t *blkdev_by_id(uint32_t id) {
    if (id >= (uint32_t)BLKDEV_SLOTS)
        return 0;
    return dev_used[(int)id] ? &devices[(int)id] : 0;
}

// Returns true if lba is out of range; prints diagnostic
static int blkdev_lba_oob(const char *op, uint32_t lba, uint32_t max_lba) {
    if (lba < max_lba) return 0;
    pr_warn("blkdev: %s out of range: lba=0x%x >= max_lba=0x%x\n",
            op, (unsigned)(lba), (unsigned)(max_lba));
    return 1;
}

// Per-device sector I/O. Partition devices map their own LBA space into the
// parent disk at start_lba; the controller callbacks live on the disk.
int blkdev_read(blkdev_t *dev, uint32_t lba, uint8_t *buf) {
    if (!dev || !buf)
        return -1;
    if (blkdev_lba_oob("read", lba, dev->max_lba))
        return -1;
    if (blkdev_is_disk(dev)) {
        if (!dev->read_sector)
            return -1;
        dev->read_sector(lba, buf);
        return 0;
    }
    if (!dev->parent)
        return -1;
    uint64_t plba = (uint64_t)dev->start_lba + lba;
    if (plba > 0xFFFFFFFFull)
        return -1;
    return blkdev_read(dev->parent, (uint32_t)plba, buf);
}

int blkdev_write(blkdev_t *dev, uint32_t lba, uint8_t *buf) {
    if (!dev || !buf)
        return -1;
    if (blkdev_lba_oob("write", lba, dev->max_lba))
        return -1;
    if (blkdev_is_disk(dev)) {
        if (!dev->write_sector)
            return -1;
        dev->write_sector(lba, buf);
        return 0;
    }
    if (!dev->parent)
        return -1;
    uint64_t plba = (uint64_t)dev->start_lba + lba;
    if (plba > 0xFFFFFFFFull)
        return -1;
    return blkdev_write(dev->parent, (uint32_t)plba, buf);
}

// ── Whole-page I/O (RAM-backed devices) ───────────────────────────────────

// The page granularity is fixed at 4 KiB; a caller that changes PAGE_SIZE must
// keep BLKDEV_SECTORS_PER_PAGE in step (blkdev.h).
_Static_assert(BLKDEV_SECTORS_PER_PAGE * 512 == PAGE_SIZE,
               "BLKDEV_SECTORS_PER_PAGE must match PAGE_SIZE");

void blkdev_set_page_ops(blkdev_t *dev,
                         int (*read_page) (blkdev_t *dev, uint32_t page_index, uint8_t *buf),
                         int (*write_page)(blkdev_t *dev, uint32_t page_index, uint8_t *buf)) {
    if (!dev || !blkdev_is_disk(dev))
        return;
    dev->read_page  = read_page;
    dev->write_page = write_page;
}

int blkdev_read_page(blkdev_t *dev, uint32_t page_index, uint8_t *buf) {
    if (!dev || !buf)
        return -1;
    if (dev->read_page) {
        if (page_index >= dev->max_lba / BLKDEV_SECTORS_PER_PAGE)
            return blkdev_lba_oob("read_page", page_index, dev->max_lba / BLKDEV_SECTORS_PER_PAGE);
        return dev->read_page(dev, page_index, buf);
    }

    // No page callback: assemble the page from its sectors.
    uint64_t base = (uint64_t)page_index * BLKDEV_SECTORS_PER_PAGE;
    if (base + BLKDEV_SECTORS_PER_PAGE > dev->max_lba)
        return -1;
    for (uint32_t s = 0; s < BLKDEV_SECTORS_PER_PAGE; s++) {
        if (blkdev_read(dev, (uint32_t)base + s, buf + s * 512) != 0) {
            memset(buf + s * 512, 0, 512);
            return -1;
        }
    }
    return 0;
}

int blkdev_write_page(blkdev_t *dev, uint32_t page_index, uint8_t *buf) {
    if (!dev || !buf)
        return -1;
    if (dev->write_page) {
        if (page_index >= dev->max_lba / BLKDEV_SECTORS_PER_PAGE)
            return blkdev_lba_oob("write_page", page_index, dev->max_lba / BLKDEV_SECTORS_PER_PAGE);
        return dev->write_page(dev, page_index, buf);
    }

    uint64_t base = (uint64_t)page_index * BLKDEV_SECTORS_PER_PAGE;
    if (base + BLKDEV_SECTORS_PER_PAGE > dev->max_lba)
        return -1;
    for (uint32_t s = 0; s < BLKDEV_SECTORS_PER_PAGE; s++)
        if (blkdev_write(dev, (uint32_t)base + s, buf + s * 512) != 0)
            return -1;
    return 0;
}

// Compatibility helpers: read/write a sector on the boot device
// (zeroes buffer / no-op if no device).
void blkdev_read_sector(uint32_t lba, uint8_t *buf) {
    blkdev_t *dev = boot_dev;
    if (!dev) {
        pr_err("blkdev: no boot device for read\n");
        memset(buf, 0, 512);
        return;
    }
    if (blkdev_read(dev, lba, buf) != 0) {
        memset(buf, 0, 512);
        return;
    }
}

void blkdev_write_sector(uint32_t lba, uint8_t *buf) {
    blkdev_t *dev = boot_dev;
    if (!dev) {
        pr_err("blkdev: no boot device for write\n");
        return;
    }
    (void)blkdev_write(dev, lba, buf);
}

// ── Partition sub-devices ─────────────────────────────────────────────────

// Compose the conventional partition device name.
void blkdev_partition_name(const blkdev_t *disk, uint32_t part_no,
                           char *out, int cap) {
    if (!disk || !out || cap <= 0) {
        if (out && cap > 0) out[0] = '\0';
        return;
    }
    int l = 0;
    while (disk->name[l] && l < BLKDEV_NAME_MAX) l++;
    int digit = (l > 0 && disk->name[l-1] >= '0' && disk->name[l-1] <= '9');

    char num[12];
    snprintf(num, sizeof(num), "%u", (unsigned)part_no);

    int o = 0;
    for (int i = 0; i < l && o < cap - 1; i++)
        out[o++] = disk->name[i];
    if (digit)
        out[o++] = 'p';
    for (int i = 0; num[i] && o < cap - 1; i++)
        out[o++] = num[i];
    out[o] = '\0';
}

blkdev_t *blkdev_add_partition(blkdev_t *disk, uint32_t part_no,
                               uint32_t start_lba, uint32_t len_lba,
                               uint8_t ptype, uint8_t table) {
    if (!disk || !blkdev_is_disk(disk) || part_no == 0 || len_lba == 0)
        return 0;
    if (blkdev_part_count(disk) >= BLKDEV_PARTS_PER_DISK)
        return 0;

    // Ensure the partition actually lies inside the disk.
    if (start_lba >= disk->max_lba || len_lba > disk->max_lba - start_lba) {
        pr_warn("blkdev: partition %u on %s out of disk range "
                "(start=0x%x len=0x%x, max=0x%x), skipped\n",
                (unsigned)part_no, disk->name, (unsigned)start_lba,
                (unsigned)len_lba, (unsigned)disk->max_lba);
        return 0;
    }

    char name[BLKDEV_NAME_MAX];
    blkdev_partition_name(disk, part_no, name, sizeof(name));
    if (blkdev_find(name)) {
        pr_warn("blkdev: duplicate partition device: %s\n", name);
        return 0;
    }

    int idx = alloc_slot();
    if (idx < 0) {
        pr_err("blkdev: no free slot for partition %u on %s\n",
               (unsigned)part_no, disk->name);
        return 0;
    }

    blkdev_t *d = &devices[idx];
    memset(d, 0, sizeof *d);
    strncpy(d->name, name, BLKDEV_NAME_MAX - 1);
    d->name[BLKDEV_NAME_MAX - 1] = '\0';
    d->id          = (uint32_t)idx;
    d->max_lba     = len_lba;
    d->parent      = disk;
    d->start_lba   = start_lba;
    d->part_no     = part_no;
    d->ptype       = ptype;
    d->table       = table;
    if (disk->ident[0])
        snprintf(d->ident, BLKDEV_IDENT_MAX, "%s-part%u",
                 disk->ident, (unsigned)part_no);
    dev_used[idx] = 1;

    pr_info("blkdev: partition %s: start=0x%x len=0x%x on %s\n",
            name, (unsigned)(start_lba), (unsigned)(len_lba), disk->name);
    return d;
}

int blkdev_clear_partitions(blkdev_t *disk) {
    if (!disk)
        return 0;
    int n = 0;
    for (int i = 0; i < BLKDEV_SLOTS; i++) {
        if (!dev_used[i])
            continue;
        if (devices[i].parent != disk)
            continue;
        /* Whoever holds this partition is about to lose it: swap keeps its
         * backing device here and must let go before the slot is wiped. */
        swap_notify_device_gone(&devices[i]);
        dev_used[i] = 0;
        memset(&devices[i], 0, sizeof(blkdev_t));
        n++;
    }
    return n;
}

int blkdev_part_count(blkdev_t *disk) {
    if (!disk)
        return 0;
    int n = 0;
    for (int i = 0; i < BLKDEV_SLOTS; i++)
        if (dev_used[i] && devices[i].parent == disk)
            n++;
    return n;
}

blkdev_t *blkdev_part_at(blkdev_t *disk, int idx) {
    if (!disk || idx < 0)
        return 0;
    int n = 0;
    for (int i = 0; i < BLKDEV_SLOTS; i++) {
        if (!dev_used[i] || devices[i].parent != disk)
            continue;
        if (n++ == idx)
            return &devices[i];
    }
    return 0;
}
