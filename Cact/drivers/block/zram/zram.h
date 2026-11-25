/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef ZRAM_H
#define ZRAM_H

#include <stdint.h>

#include "blkdev.h"

/*
 * zram — a block device whose pages live compressed in RAM.
 *
 * The device exposes `size_bytes / PAGE_SIZE` addressable 4 KiB pages; each one
 * is stored in a zpool (kernel zstd), so the RAM it actually costs is the
 * compressed size (a page zstd cannot shrink is kept verbatim).  Pages are
 * allocated lazily, so an unused device costs only its page-index table.
 *
 * Created and destroyed through /dev/zmem (zram_create/zram_destroy); the
 * kernel creates one only when the `zram=` command line asks for it.
 */

#define ZRAM_MAX_DEVICES 4
#define ZRAM_NAME_MAX    16

/* Create a device named `name` ("zram0") of `size_bytes` capacity, compressing
 * pages at zstd `level` (0 = library default).  Returns 0, or -1 when the name
 * is in use, too many devices exist, the size is below one page, or memory ran
 * out. */
int zram_create(const char *name, uint64_t size_bytes, int level);

/* zram_destroy() outcomes. */
#define ZRAM_DESTROY_OK    0   /* freed */
#define ZRAM_DESTROY_NODEV 1   /* no device with that name */
#define ZRAM_DESTROY_BUSY  2   /* it backs swap — detach first */

/* Destroy a device: frees every stored page, removes its /dev node and gives up
 * its slot.  Returns a ZRAM_DESTROY_* code; refuses with BUSY while the device
 * still backs swap (its pages are live). */
int zram_destroy(const char *name);

/* True when a device of that name exists. */
int zram_exists(const char *name);

/* Number of live zram devices (for /proc/zmem). */
int zram_count(void);

/* Fill `*out` with the accounting of the device at index `i` (0..zram_count()-1).
 * Returns 0, or -1 for an out-of-range index. */
typedef struct {
    char     name[ZRAM_NAME_MAX];
    uint32_t capacity_pages;
    uint32_t stored_pages;   /* pages currently held in the pool   */
    uint32_t pages_in;       /* cumulative reads                   */
    uint32_t pages_out;      /* cumulative writes                  */
    uint64_t stored_bytes;   /* compressed bytes currently held    */
    uint64_t original_bytes; /* stored_pages * PAGE_SIZE           */
} zram_info_t;
int zram_get_info(int i, zram_info_t *out);

/* Boot hook: create zram0 when the command line carries `zram=<size>`.  Called
 * from kernel_setup_hardware() once the block layer is up. */
void zram_init(void);

#endif /* ZRAM_H */
