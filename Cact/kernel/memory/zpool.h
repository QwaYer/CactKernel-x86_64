/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef ZPOOL_H
#define ZPOOL_H

#include <stdint.h>
#include <stddef.h>

/*
 * zpool — the compressed-page store behind zram and zswap.
 *
 * A pool holds up to `capacity_pages` 4 KiB pages, each compressed with the
 * kernel zstd; a page that does not shrink is kept verbatim, so a store never
 * fails for a compressible-size reason, only for capacity/budget/memory.  The
 * implementation and its pure slot allocator live in Rust
 * (`rust_mm/src/comp/{zpool,zpool_alloc}.rs`); this header is the C ABI zram
 * links against (zswap, being Rust, calls the same functions directly).
 *
 * Handles are opaque slot indices, valid only for the pool that issued them.
 */

struct zpool;
typedef struct zpool zpool_t;

/* Accounting snapshot, mirrored by `ZpoolStats` in rust_mm/src/ffi.rs. */
typedef struct {
    uint32_t capacity_pages;  /* slots the pool was created with            */
    uint32_t live_pages;      /* slots currently holding a page             */
    uint32_t pages_stored;    /* cumulative stores (monotonic)              */
    uint32_t pages_loaded;    /* cumulative loads  (monotonic)              */
    uint64_t budget_bytes;    /* payload budget in bytes                    */
    uint64_t stored_bytes;    /* compressed payload currently held          */
    uint64_t original_bytes;  /* live_pages * PAGE_SIZE                     */
} zpool_stats_t;

/* The C and Rust definitions must agree byte for byte, or /proc/zmem and
 * zram's stats would read past the end of the snapshot. */
_Static_assert(sizeof(zpool_stats_t) == 40, "zpool_stats_t size drift");
_Static_assert(offsetof(zpool_stats_t, budget_bytes) == 16, "zpool_stats_t layout drift");
_Static_assert(offsetof(zpool_stats_t, stored_bytes) == 24, "zpool_stats_t layout drift");
_Static_assert(offsetof(zpool_stats_t, original_bytes) == 32, "zpool_stats_t layout drift");

/* Create a pool of `capacity_pages` slots with a `budget_bytes` payload budget,
 * compressing every page at zstd `level`.  Returns NULL on a bad argument or an
 * allocation failure. */
zpool_t *zpool_create(uint32_t capacity_pages, uint64_t budget_bytes, int level);

/* Free a pool and every page it still holds.  The caller must have detached it
 * from any user (zram device, zswap). */
void zpool_destroy(zpool_t *p);

/* Compress `page` (a whole PAGE_SIZE page) into a new slot.  Returns 0 and
 * writes *out_handle, or -1 when the pool is out of slots, budget or memory. */
int zpool_store(zpool_t *p, const void *page, uint32_t *out_handle);

/* Decompress the page behind `handle` into `page`.  The slot stays allocated;
 * release it with zpool_free().  Returns 0 or -1. */
int zpool_load(zpool_t *p, uint32_t handle, void *page);

/* Release the slot behind `handle` (no-op for an already-free handle). */
void zpool_free(zpool_t *p, uint32_t handle);

/* Fill `out` with a snapshot of the pool's accounting.  Returns 0 or -1. */
int zpool_get_stats(zpool_t *p, zpool_stats_t *out);

#endif /* ZPOOL_H */
