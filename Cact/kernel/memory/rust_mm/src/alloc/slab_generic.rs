// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Generic (kmalloc-style) size caches on top of the slab allocator.

use crate::ffi::*;
use crate::safe::{KStatic, kprint_str, klog_msg};
use crate::alloc::heap::{kmalloc, kfree};
use crate::alloc::slab::{
    slab_alloc, slab_cache_create, slab_free, G_CACHE_LOCK, G_GENERIC_CACHES, Slab,
    GENERIC_CACHE_COUNT,
};
use crate::alloc::slab_owner::is_slab_header;

const GENERIC_SIZES: [u32; GENERIC_CACHE_COUNT] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];

#[unsafe(no_mangle)]
pub extern "C" fn slab_init() {
    // SAFETY: boot-time init, single-threaded.
    unsafe { irq_spinlock_init(G_CACHE_LOCK.as_ptr()) };

    for (i, &size) in GENERIC_SIZES.iter().enumerate() {
        let mut name = [0u8; SLAB_NAME_LEN];
        let prefix = b"kmalloc-";
        name[..prefix.len()].copy_from_slice(prefix);

        let mut num_buf = [0u8; 8];
        let mut sz = size;
        let mut p: usize = 6;
        num_buf[7] = 0;
        loop {
            num_buf[p] = b'0' + (sz % 10) as u8;
            sz /= 10;
            if sz == 0 {
                break;
            }
            p -= 1;
        }
        let mut j = prefix.len();
        let mut k = p;
        while k < 7 && j < SLAB_NAME_LEN - 1 {
            name[j] = num_buf[k];
            j += 1;
            k += 1;
        }
        name[j] = 0;

        // SAFETY: `name` is the NUL-terminated stack buffer initialised just above
        // (shorter than `SLAB_NAME_LEN`), and `ctor`/`dtor` are `None`.
        let cache = unsafe { slab_cache_create(name.as_ptr(), size, None, None) };
        // SAFETY: `G_GENERIC_CACHES` is populated during single-threaded boot by
        // `slab_init`; no allocator call can race it yet.
        (unsafe { KStatic::get_mut(G_GENERIC_CACHES.as_ptr()) })[i] = cache;
        if cache.is_null() {
            // SAFETY: `printk_color` is a C function that takes a valid string;
            // the literal below is a NUL-terminated static.
            unsafe {
                printk_color(c"slab: failed to create cache: ".as_ptr() as *const u8, COLOR_LIGHT_RED);
            }
            // SAFETY: `name` is the NUL-terminated stack buffer built above.
            unsafe { printk_color(name.as_ptr(), COLOR_LIGHT_RED) };
            kprint_str(c"\n".as_ptr() as *const u8);
            klog_msg(LOG_FAIL, c"slab cache creation failed".as_ptr() as *const u8);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slab_kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `G_GENERIC_CACHES` entries are written once by `slab_init` at boot
    // and never mutated afterwards, so this read races nothing.
    let caches = unsafe { KStatic::get_mut(G_GENERIC_CACHES.as_ptr()) };
    for i in 0..GENERIC_CACHE_COUNT {
        if size <= GENERIC_SIZES[i] as usize {
            // SAFETY: `caches[i]` is a live cache pointer installed by `slab_init`
            // and never destroyed.
            return unsafe { slab_alloc(caches[i]) };
        }
    }
    kmalloc(size)
}

/// # Safety
///
/// `ptr` must be null, or a pointer to a live slab/heap block previously
/// returned by `slab_kmalloc`/`kmalloc` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slab_kfree(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: obj resides in a page whose start may be a Slab header.  Objects
    // are direct-map VAs (their slab page is a `kalloc` frame) and the direct map
    // is page-aligned, so masking the low 12 bits of the VA yields the page base.
    let s = (ptr as u64 & !(PAGE_SIZE as u64 - 1)) as *mut Slab;
    // SAFETY: `s` is the start of the page containing `ptr`; the header is only
    // read, and `is_slab_header` trusts it only when its magic matches.
    let s = unsafe { &*s };
    if is_slab_header(s.magic, s.capacity, !s.cache.is_null()) {
        // SAFETY: the page header is a live slab header, so `s.cache` is a live
        // cache and `ptr` is one of its objects, per the caller contract.
        unsafe { slab_free(s.cache, ptr) };
        return;
    }
    // SAFETY: `ptr` was not recognised as a live slab object, so it is handed to
    // the heap, which validates the block before touching it.
    unsafe { kfree(ptr); }
}
