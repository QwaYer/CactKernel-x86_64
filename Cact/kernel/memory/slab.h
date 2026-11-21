/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef SLAB_H
#define SLAB_H

#include <stdint.h>
#include <stddef.h>

#define SLAB_MAX_OBJ_SIZE  2048
#define SLAB_MIN_OBJ_SIZE  8
#define SLAB_NAME_LEN      32

/*
 * SLAB_MAGIC stamps every slab page header (rust_mm: alloc/slab_owner.rs), so
 * slab_kfree can tell a slab object's page from a plain kmalloc block's page by
 * the header word instead of guessing from the capacity field.  The value is
 * set and checked in Rust only; it is mirrored here so the struct stays in sync.
 */
#define SLAB_MAGIC 0x51AB5EEDu

typedef struct slab {
    uint32_t      magic;    /* SLAB_MAGIC — checked by the Rust allocator    */
    struct slab*  next;
    struct slab*  prev;
    void*         freelist;
    uint32_t      inuse;
    uint32_t      capacity;
    struct slab_cache* cache;
} slab_t;

typedef struct slab_cache {
    char     name[SLAB_NAME_LEN];
    uint32_t obj_size;
    uint32_t objs_per_slab;
    slab_t*  partial;
    slab_t*  full;
    slab_t*  free;
    uint32_t total_slabs;
    uint32_t total_allocs;
    uint32_t total_frees;
    void (*ctor)(void* obj);
    void (*dtor)(void* obj);
    struct slab_cache* next;
} slab_cache_t;

slab_cache_t* slab_cache_create(const char* name, uint32_t obj_size,
                                void (*ctor)(void*), void (*dtor)(void*));
void*         slab_alloc(slab_cache_t* cache);
void          slab_free(slab_cache_t* cache, void* obj);
void          slab_cache_destroy(slab_cache_t* cache);
void          slab_cache_shrink(slab_cache_t* cache);
/* Reclaim the free slabs of every cache; returns the 4 KiB frames handed back to
 * the PMM.  The PMM's kalloc OOM path calls it before swapping or OOM-killing. */
uint32_t      slab_shrink_all(void);
void          slab_print_stats(const slab_cache_t* cache);
void          slab_init(void);
void*         slab_kmalloc(size_t size);
void          slab_kfree(void* ptr);
uint32_t      slab_total_bytes(void);

#endif
