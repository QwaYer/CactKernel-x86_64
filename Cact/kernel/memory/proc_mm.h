/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef PROCESS_MM_H
#define PROCESS_MM_H

#include <stdint.h>
#include "memory.h"

#define PROC_INITIAL_PAGES 256
#define PROC_GROW_STEP     256

typedef struct proc_page_tracker_t {
    void**   pages;
    uint32_t count;
    uint32_t capacity;
    uint64_t* page_dir;
} proc_page_tracker_t;

static inline void proc_tracker_init(proc_page_tracker_t* t)
{
    t->pages    = 0;
    t->count    = 0;
    t->capacity = 0;
    t->page_dir = 0;
}

/* Record a frame the process owns.  `frame` is the pointer kalloc() handed out
 * (a direct-map VA) — the tracker only keeps the entries and releases the array
 * itself; the frames are reclaimed through the page directory by
 * vmm_free_address_space(). */
int  proc_tracker_add(proc_page_tracker_t* t, void* frame);
void proc_free_pages(proc_page_tracker_t* t);

#endif
