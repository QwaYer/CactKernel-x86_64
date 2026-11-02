/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef PAGECACHE_H
#define PAGECACHE_H

#include <stdint.h>

// Cache sizing
#define PC_MAX_PAGES       256
#define PC_MAX_BLOCK_SIZE  4096
#define PC_HASH_SIZE       64    // must be power of 2

// Page flags
#define PC_FLAG_VALID   0x01       // page contains valid data from disk
#define PC_FLAG_DIRTY   0x02       // page has been modified, needs writeback
#define PC_FLAG_USED    0x04       // page slot is occupied

struct page;

// Initialise page cache pool, hash table, and LRU
void pc_init(void);

// Get a page from cache; on miss, read from disk
uint8_t *pc_get_page(uint32_t dev, uint32_t block_no, uint32_t block_size);

// Mark page dirty (triggers immediate writeback — aggressive)
void pc_mark_dirty(uint32_t dev, uint32_t block_no);

// Release one pin reference on a page
void pc_put_page(uint32_t dev, uint32_t block_no);

// Write back all dirty pages for a device
void pc_flush_dev(uint32_t dev);

#endif