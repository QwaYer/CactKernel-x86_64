/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef SWAP_H
#define SWAP_H

#include <stdint.h>
#include "memory.h"

#define SWAP_MAX_SLOTS      65536u
#define SWAP_BITMAP_SIZE    (SWAP_MAX_SLOTS / 8)
#define SWAP_DATA_START_LBA 1u

/* The PTE encoding of a swapped-out page (marker bit + slot in the frame field)
 * lives entirely in the Rust side (`rust_mm/src/fault/swap.rs`): it is that code
 * which writes and decodes the entries, and a C mirror here once carried a
 * different marker bit (0x200, which is PAGE_COW in ffi.rs).  C only needs the
 * lifecycle and backing-device API below. */

typedef uint32_t swap_slot_t;

typedef struct {
    uint32_t total_slots;
    uint32_t used_slots;
    uint32_t pages_swapped_out;
    uint32_t pages_swapped_in;
    uint32_t swap_failures;
} swap_stats_t;

typedef int (*swap_read_fn) (uint32_t lba, void* buf,       uint32_t sectors);
typedef int (*swap_write_fn)(uint32_t lba, const void* buf, uint32_t sectors);

/* Install the backing-store I/O callbacks.  Swap stays disabled until a swap
 * device is attached with swap_enable() — a diskless boot must not advertise
 * swap capacity.  Returns 0, or -1 on a bad argument. */
int          swap_init(swap_read_fn read_fn, swap_write_fn write_fn);
/* Attach a backing store of `slots` pages and enable swap.  Rejected (swap left
 * off) for slots == 0 or missing I/O callbacks. */
int          swap_enable(uint32_t slots);
/* Detach the backing store: no capacity advertised, no further evictions.  The
 * slot bitmap is kept so swapped-out pages stay reserved. */
void         swap_disable(void);
int          swap_is_enabled(void);

/* Backing-device glue (kernel.c): attach/detach a swap partition.  Declared on
 * struct blkdev so this header does not need the block layer. */
struct blkdev;
int          swap_enable_device(struct blkdev *part);
void         swap_notify_device_gone(struct blkdev *part);
/* True when `dev` is the device swap is currently paging against — a caller
 * that wants to destroy `dev` (zram) must refuse while this holds. */
int          swap_is_backing_device(struct blkdev *dev);
int          swap_out_page(uint64_t phys_addr, swap_slot_t* out_slot);
int          swap_in_page(swap_slot_t slot, uint64_t phys_addr);
void         swap_free_slot(swap_slot_t slot);
swap_stats_t swap_get_stats(void);
void         swap_print_stats(void);
int          swap_evict_page(uint64_t* pd);
int          swap_handle_fault(uint64_t* pd, uint64_t fault_addr);

#endif
