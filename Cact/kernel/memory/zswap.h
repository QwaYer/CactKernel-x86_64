/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef ZSWAP_H
#define ZSWAP_H

#include <stdint.h>
#include <stddef.h>

/*
 * zswap — a compressed cache in front of the swap backing device.
 *
 * Evicted pages are held compressed in a zpool; only pages the pool cannot take
 * go on to the swap device.  The implementation is Rust
 * (`rust_mm/src/fault/zswap.rs`); this header is the C ABI the /dev/zmem
 * control handler uses.
 *
 * The pool is created once, on the first zswap_enable(), and lives for the rest
 * of the kernel's life: zswap_disable() only stops accepting new pages, and
 * already-pooled pages drain back through fault-in.  The limit and level are
 * therefore fixed at first enable.
 */

/* Accounting snapshot, mirrored by `ZswapStats` in rust_mm/src/ffi.rs. */
typedef struct {
    uint32_t enabled;         /* 1 while the front-end is active           */
    uint32_t writeback;       /* 1 when a full pool writes back first      */
    int32_t  level;           /* zstd level the pool compresses at         */
    uint32_t capacity_pages;  /* pool page capacity (0 when no pool)       */
    uint32_t pool_pages;      /* pages currently held compressed           */
    uint64_t budget_bytes;    /* payload budget in bytes                   */
    uint64_t stored_bytes;    /* compressed bytes currently held           */
    uint64_t original_bytes;  /* uncompressed size of the pooled pages     */
    uint32_t stores;          /* cumulative successful stores              */
    uint32_t store_fail;      /* cumulative stores the pool refused        */
    uint32_t loads;           /* cumulative pool loads back into a frame   */
    uint32_t writebacks;      /* cumulative pages migrated to the device   */
} zswap_stats_t;

/* The C and Rust definitions must agree byte for byte, or /proc/zmem would read
 * past the end of the snapshot. */
_Static_assert(sizeof(zswap_stats_t) == 64, "zswap_stats_t size drift");
_Static_assert(offsetof(zswap_stats_t, budget_bytes) == 24, "zswap_stats_t layout drift");
_Static_assert(offsetof(zswap_stats_t, stores) == 48, "zswap_stats_t layout drift");
_Static_assert(offsetof(zswap_stats_t, writebacks) == 60, "zswap_stats_t layout drift");

/* Create the pool (max_pool_pct % of RAM, zstd `level`) on first call and start
 * accepting pages; a later call only updates the enabled/writeback flags.
 * `writeback` != 0 makes a full pool migrate one of its own pages to the device
 * before refusing a store.  Returns 0, or -1 on a bad percentage or no memory. */
int zswap_enable(uint32_t max_pool_pct, int level, int writeback);

/* Stop accepting new pages; pooled pages drain back through fault-in. */
int zswap_disable(void);

/* 1 while the front-end is active. */
int zswap_is_enabled_ffi(void);

/* Fill `*out` with a snapshot.  Returns 0 or -1. */
int zswap_get_stats(zswap_stats_t *out);

#endif /* ZSWAP_H */
