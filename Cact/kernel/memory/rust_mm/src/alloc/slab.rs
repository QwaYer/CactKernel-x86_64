// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Slab allocator: per-cache freelists, optional ctor/dtor, and a set of generic size caches.

use crate::ffi::*;
use crate::safe::{lock_acquire, lock_release, kprint_str, kprint_int};
use crate::pmm::kalloc;
use crate::alloc::heap::{kmalloc_raw, kfree_raw};
use crate::alloc::slab_owner::{is_slab_header, SLAB_MAGIC};
use kernel_rust::cell::KCell;

#[repr(C)]
pub struct Slab {
    magic: u32,
    next: *mut Slab,
    prev: *mut Slab,
    freelist: *mut u8,
    inuse: u32,
    capacity: u32,
    cache: *mut SlabCache,
}

#[repr(C)]
pub struct SlabCache {
    name: [u8; SLAB_NAME_LEN],
    obj_size: u32,
    objs_per_slab: u32,
    partial: *mut Slab,
    full: *mut Slab,
    free: *mut Slab,
    total_slabs: u32,
    total_allocs: u32,
    total_frees: u32,
    ctor: Option<extern "C" fn(*mut u8)>,
    dtor: Option<extern "C" fn(*mut u8)>,
    next: *mut SlabCache,
}

static G_CACHE_LIST: KCell<*mut SlabCache> = KCell::new(core::ptr::null_mut());
pub(crate) static G_CACHE_LOCK: KCell<IrqSpinlock> = KCell::new(IrqSpinlock::new());

/// Number of generic (kmalloc-style) size caches.
pub(crate) const GENERIC_CACHE_COUNT: usize = 9;

pub(crate) static G_GENERIC_CACHES: KCell<[*mut SlabCache; GENERIC_CACHE_COUNT]> =
    KCell::new([core::ptr::null_mut(); GENERIC_CACHE_COUNT]);

fn align_up(size: u32, align: u32) -> u32 {
    (size + align - 1) & !(align - 1)
}

fn calc_objs_per_slab(obj_size: u32) -> u32 {
    let usable = PAGE_SIZE - core::mem::size_of::<Slab>() as u32;
    let n = usable / obj_size;
    if n < 1 { 1 } else { n }
}

/// Link `s` at the head of the `head` list.  The caller holds `G_CACHE_LOCK`.
fn list_push(head: *mut *mut Slab, s: *mut Slab) {
    kernel_rust::ptr::as_mut(s).prev = core::ptr::null_mut();
    let old_head = kernel_rust::ptr::read(head);
    kernel_rust::ptr::as_mut(s).next = old_head;
    if !old_head.is_null() {
        kernel_rust::ptr::as_mut(old_head).prev = s;
    }
    kernel_rust::ptr::write(head, s);
}

/// Unlink `s` from the `head` list.  The caller holds `G_CACHE_LOCK`.
fn list_remove(head: *mut *mut Slab, s: *mut Slab) {
    let prev = kernel_rust::ptr::as_ref(s).prev;
    let next = kernel_rust::ptr::as_ref(s).next;
    if !prev.is_null() {
        kernel_rust::ptr::as_mut(prev).next = next;
    } else {
        kernel_rust::ptr::write(head, next);
    }
    if !next.is_null() {
        kernel_rust::ptr::as_mut(next).prev = prev;
    }
    kernel_rust::ptr::as_mut(s).prev = core::ptr::null_mut();
    kernel_rust::ptr::as_mut(s).next = core::ptr::null_mut();
}

fn slab_create_slab(cache: *mut SlabCache) -> *mut Slab {
    let page = kalloc();
    if page.is_null() {
        return core::ptr::null_mut();
    }

    // `page` is the fresh `kalloc` page, a live, exclusively-owned slab header;
    // `cache` is the live cache whose slab this is and does not alias it.
    let s = kernel_rust::ptr::as_mut(page as *mut Slab);
    let cache_ref = kernel_rust::ptr::as_mut(cache);
    s.magic = SLAB_MAGIC;
    s.next = core::ptr::null_mut();
    s.prev = core::ptr::null_mut();
    s.inuse = 0;
    s.capacity = cache_ref.objs_per_slab;
    s.cache = cache;

    // `page` addresses the whole 4 KiB slab page and `size_of::<Slab>() <
    // PAGE_SIZE`, so this offset into the page is in bounds.
    let obj_base = page.wrapping_add(core::mem::size_of::<Slab>());
    let obj_size = cache_ref.obj_size;

    s.freelist = obj_base;
    let capacity = s.capacity;
    for i in 0..capacity {
        // Object `i`'s freelist slot lies inside the page's usable area.
        let slot = obj_base.wrapping_add((i * obj_size) as usize) as *mut *mut u8;
        if i + 1 < capacity {
            // `(i + 1) * obj_size` is the next freelist slot, still inside the
            // page's usable area.
            let next_slot = obj_base.wrapping_add(((i + 1) * obj_size) as usize);
            kernel_rust::ptr::write(slot, next_slot);
        } else {
            kernel_rust::ptr::write(slot, core::ptr::null_mut());
        }
        if let Some(ctor) = cache_ref.ctor {
            ctor(slot as *mut u8);
        }
    }

    cache_ref.total_slabs += 1;
    s as *mut Slab
}

fn slab_destroy_slab(cache: *mut SlabCache, s: *mut Slab) {
    // `cache` is the live cache that owns `s`, so this shared borrow is valid for
    // the whole teardown.
    let cache_ref = kernel_rust::ptr::as_ref(cache);
    if let Some(dtor) = cache_ref.dtor {
        // `s` is a live slab page and `size_of::<Slab>() < PAGE_SIZE`, so this
        // offset into the page is in bounds.
        let obj_base = (s as *mut u8).wrapping_add(core::mem::size_of::<Slab>());
        let capacity = kernel_rust::ptr::as_ref(s).capacity;
        for i in 0..capacity {
            // Object `i` lies inside the page's usable area.
            let obj = obj_base.wrapping_add((i * cache_ref.obj_size) as usize);
            dtor(obj);
        }
    }
    // `s` is a live `Slab` header owned by `cache`; hand its frame back to the PMM.
    kernel_rust::mem::free_page(s as *mut u8);
    // `s` is a live `Slab` header owned by `cache`, so this counter update is in
    // bounds; the caller serialises concurrent use.
    kernel_rust::ptr::as_mut(cache).total_slabs -= 1;
}

/// Create a cache named `name` (null or a readable, NUL-terminated byte string of
/// at most `SLAB_NAME_LEN` bytes; `ctor`/`dtor` valid function pointers for the
/// objects the cache will hand out).
#[unsafe(no_mangle)]
pub extern "C" fn slab_cache_create(
    name: *const u8,
    mut obj_size: u32,
    ctor: Option<extern "C" fn(*mut u8)>,
    dtor: Option<extern "C" fn(*mut u8)>,
) -> *mut SlabCache {
    if obj_size < SLAB_MIN_OBJ_SIZE {
        obj_size = SLAB_MIN_OBJ_SIZE;
    }
    if obj_size > SLAB_MAX_OBJ_SIZE {
        kprint_str(c"slab: obj_size too large (> 2048)\n".as_ptr() as *const u8);
        return core::ptr::null_mut();
    }
    if obj_size < core::mem::size_of::<*mut u8>() as u32 {
        obj_size = core::mem::size_of::<*mut u8>() as u32;
    }
    obj_size = align_up(obj_size, 8);

    let cache = kmalloc_raw(core::mem::size_of::<SlabCache>()) as *mut SlabCache;
    if cache.is_null() {
        return core::ptr::null_mut();
    }

    // `cache` was just allocated by `kmalloc` and is exclusively owned by this call.
    let cache_ref = kernel_rust::ptr::as_mut(cache);
    let mut i = 0usize;
    while i < SLAB_NAME_LEN - 1 {
        // `i < SLAB_NAME_LEN - 1` and `name` is a readable NUL-terminated string of
        // at most `SLAB_NAME_LEN` bytes, so this byte pointer is in bounds.
        let p = name.wrapping_add(i);
        let ch = kernel_rust::ptr::read(p);
        if ch == 0 {
            break;
        }
        cache_ref.name[i] = ch;
        i += 1;
    }
    cache_ref.name[i] = 0;

    cache_ref.obj_size = obj_size;
    cache_ref.objs_per_slab = calc_objs_per_slab(obj_size);
    cache_ref.partial = core::ptr::null_mut();
    cache_ref.full = core::ptr::null_mut();
    cache_ref.free = core::ptr::null_mut();
    cache_ref.total_slabs = 0;
    cache_ref.total_allocs = 0;
    cache_ref.total_frees = 0;
    cache_ref.ctor = ctor;
    cache_ref.dtor = dtor;

    lock_acquire(G_CACHE_LOCK.as_ptr());
    // `G_CACHE_LIST` is the global cache-list head; the lock is held, so this
    // publish is exclusive.
    let head = G_CACHE_LIST.get();
    cache_ref.next = head;
    G_CACHE_LIST.set(cache);
    lock_release(G_CACHE_LOCK.as_ptr());

    cache
}

/// Allocate one object from `cache` (null, or a live cache from
/// `slab_cache_create` that the caller does not destroy concurrently).
#[unsafe(no_mangle)]
pub extern "C" fn slab_alloc(cache: *mut SlabCache) -> *mut u8 {
    if cache.is_null() {
        return core::ptr::null_mut();
    }

    lock_acquire(G_CACHE_LOCK.as_ptr());

    let mut s = kernel_rust::ptr::as_ref(cache).partial;

    if s.is_null() {
        s = kernel_rust::ptr::as_ref(cache).free;
        if !s.is_null() {
            list_remove(&raw mut kernel_rust::ptr::as_mut(cache).free, s);
            list_push(&raw mut kernel_rust::ptr::as_mut(cache).partial, s);
        }
    }

    if s.is_null() {
        lock_release(G_CACHE_LOCK.as_ptr());
        s = slab_create_slab(cache);
        if s.is_null() {
            return core::ptr::null_mut();
        }
        lock_acquire(G_CACHE_LOCK.as_ptr());
        list_push(&raw mut kernel_rust::ptr::as_mut(cache).partial, s);
    }

    // `s` is a valid slab with free objects.
    let obj = kernel_rust::ptr::as_ref(s).freelist;
    // `obj` is the first free object of `s`, so the next-free pointer stored in
    // its first word is valid.
    let next_free = kernel_rust::ptr::read(obj as *const *mut u8);
    kernel_rust::ptr::as_mut(s).freelist = next_free;
    kernel_rust::ptr::as_mut(s).inuse += 1;
    kernel_rust::ptr::as_mut(cache).total_allocs += 1;

    let inuse = kernel_rust::ptr::as_ref(s).inuse;
    let capacity = kernel_rust::ptr::as_ref(s).capacity;
    if inuse == capacity {
        // Move the now-full slab from partial to full.
        list_remove(&raw mut kernel_rust::ptr::as_mut(cache).partial, s);
        list_push(&raw mut kernel_rust::ptr::as_mut(cache).full, s);
    }

    lock_release(G_CACHE_LOCK.as_ptr());
    obj
}

/// Free `obj` back to `cache` (`cache` a live cache from `slab_cache_create`,
/// `obj` a pointer currently allocated from it — or either null).
#[unsafe(no_mangle)]
pub extern "C" fn slab_free(cache: *mut SlabCache, obj: *mut u8) {
    if cache.is_null() || obj.is_null() {
        return;
    }

    lock_acquire(G_CACHE_LOCK.as_ptr());

    // `obj` resides within a page that starts with a Slab header.  The object
    // pointers are direct-map VAs (the slab page is a `kalloc` frame), and the
    // direct map is page-aligned, so masking the low 12 bits of the VA gives the
    // VA of the page base.
    let s = (obj as u64 & !(PAGE_SIZE as u64 - 1)) as *mut Slab;

    // `cache` is a live cache and `G_CACHE_LOCK` is held, so this borrow is
    // exclusive for the counter updates below.
    let cache_ref = kernel_rust::ptr::as_mut(cache);
    {
        // `s` is the slab page containing `obj`, and `G_CACHE_LOCK` is held, so
        // this borrow of the header is exclusive; it ends before the list
        // operations below re-touch `s` through the raw pointer.
        let s_ref = kernel_rust::ptr::as_mut(s);
        if s_ref.magic != SLAB_MAGIC || s_ref.cache != cache {
            kprint_str(c"slab: slab_free: bad slab header or wrong cache!\n".as_ptr() as *const u8);
            lock_release(G_CACHE_LOCK.as_ptr());
            return;
        }

        // `obj` is a live object of this slab, so storing the current freelist
        // head into its first word is in bounds.
        kernel_rust::ptr::write(obj as *mut *mut u8, s_ref.freelist);
        s_ref.freelist = obj;

        // The slab's counters are exclusive under `G_CACHE_LOCK`.
        let was_full = s_ref.inuse == s_ref.capacity;
        s_ref.inuse -= 1;
        cache_ref.total_frees += 1;

        if was_full {
            list_remove(&raw mut cache_ref.full, s);
            list_push(&raw mut cache_ref.partial, s);
        } else if s_ref.inuse == 0 {
            list_remove(&raw mut cache_ref.partial, s);
            list_push(&raw mut cache_ref.free, s);
        }
    }

    lock_release(G_CACHE_LOCK.as_ptr());
}

/// The size class of the slab object at `ptr`, or 0 when `ptr` is not a slab
/// object (so the caller treats it as a heap block).
///
/// `obj_size` is fixed when the cache is created, so this needs no lock — the same
/// reasoning `slab_print_stats` relies on.
pub extern "C" fn slab_object_size(ptr: *mut u8) -> u32 {
    if ptr.is_null() {
        return 0;
    }
    // `ptr` is a live allocation; its page base is read and trusted only when the
    // header magic matches.
    let s = (ptr as u64 & !(PAGE_SIZE as u64 - 1)) as *mut Slab;
    let s = kernel_rust::ptr::as_ref(s);
    if is_slab_header(s.magic, s.capacity, !s.cache.is_null()) {
        // A live slab header's `cache` is a live cache, and `obj_size` is
        // immutable after `slab_cache_create`.
        kernel_rust::ptr::as_ref(s.cache).obj_size
    } else {
        0
    }
}

/// Free `ptr` if it is a slab object; return false when it is not (the caller
/// then frees it as a heap block).  This is the ownership test the dispatcher
/// `kfree` runs on every free.
#[unsafe(no_mangle)]
pub extern "C" fn slab_try_free(ptr: *mut u8) -> bool {
    if ptr.is_null() {
        return false;
    }
    // `ptr` is a live allocation; its page base is read and trusted only when the
    // header magic matches.
    let s = (ptr as u64 & !(PAGE_SIZE as u64 - 1)) as *mut Slab;
    let s = kernel_rust::ptr::as_ref(s);
    if is_slab_header(s.magic, s.capacity, !s.cache.is_null()) {
        // The header is a live slab header, so `s.cache` is a live cache and `ptr`
        // is one of its objects.
        slab_free(s.cache, ptr);
        return true;
    }
    false
}

/// Shrink `cache` (null, or a live cache from `slab_cache_create` that the caller
/// does not destroy concurrently): destroy its free slabs.
#[unsafe(no_mangle)]
pub extern "C" fn slab_cache_shrink(cache: *mut SlabCache) {
    if cache.is_null() {
        return;
    }
    lock_acquire(G_CACHE_LOCK.as_ptr());
    slab_shrink_locked(cache);
    lock_release(G_CACHE_LOCK.as_ptr());
}

/// Destroy every slab on `cache`'s free list and return how many were released.
///
/// `Locking:` the caller must hold `G_CACHE_LOCK`, so the free list is
/// exclusively owned.
fn slab_shrink_locked(cache: *mut SlabCache) -> u32 {
    let mut freed = 0;
    // `cache` is a live cache and `G_CACHE_LOCK` is held, so the free-slab list
    // head is exclusively read here.
    let mut s = kernel_rust::ptr::as_ref(cache).free;
    while !s.is_null() {
        let next = kernel_rust::ptr::as_ref(s).next;
        slab_destroy_slab(cache, s);
        freed += 1;
        s = next;
    }
    // Clear the free-slab list head of the live cache, under the lock.
    kernel_rust::ptr::as_mut(cache).free = core::ptr::null_mut();
    freed
}

/// Reclaim the free slabs of every cache and return the number of 4 KiB frames
/// handed back to the PMM.
///
/// This is the slab shrinker: the PMM's `kalloc` out-of-memory path calls it
/// before evicting a page or killing a task, because an empty slab is the
/// cheapest memory to recover.  A cache's *partial* slabs are left alone — their
/// objects may still be in use.
#[unsafe(no_mangle)]
pub extern "C" fn slab_shrink_all() -> u32 {
    let mut freed: u32 = 0;
    lock_acquire(G_CACHE_LOCK.as_ptr());
    // `G_CACHE_LIST` head read under `G_CACHE_LOCK`, which serialises it against
    // cache creation/destruction and the list relinks.
    let mut c = G_CACHE_LIST.get();
    while !c.is_null() {
        freed = freed.saturating_add(slab_shrink_locked(c));
        c = kernel_rust::ptr::as_ref(c).next;
    }
    lock_release(G_CACHE_LOCK.as_ptr());
    freed
}

/// Destroy `cache` (null, or a pointer returned by `slab_cache_create`; it is
/// freed here and must not be used again afterwards).
#[unsafe(no_mangle)]
pub extern "C" fn slab_cache_destroy(cache: *mut SlabCache) {
    if cache.is_null() {
        return;
    }

    lock_acquire(G_CACHE_LOCK.as_ptr());

    // `cache` is a live cache and `G_CACHE_LOCK` is held, so the slab lists are
    // exclusively owned here.
    let mut s = kernel_rust::ptr::as_ref(cache).full;
    while !s.is_null() {
        let n = kernel_rust::ptr::as_ref(s).next;
        slab_destroy_slab(cache, s);
        s = n;
    }
    s = kernel_rust::ptr::as_ref(cache).partial;
    while !s.is_null() {
        let n = kernel_rust::ptr::as_ref(s).next;
        slab_destroy_slab(cache, s);
        s = n;
    }
    s = kernel_rust::ptr::as_ref(cache).free;
    while !s.is_null() {
        let n = kernel_rust::ptr::as_ref(s).next;
        slab_destroy_slab(cache, s);
        s = n;
    }
    // Clear the now-empty slab-list heads of the live cache.
    kernel_rust::ptr::as_mut(cache).full = core::ptr::null_mut();
    kernel_rust::ptr::as_mut(cache).partial = core::ptr::null_mut();
    kernel_rust::ptr::as_mut(cache).free = core::ptr::null_mut();

    let mut pp: *mut *mut SlabCache = G_CACHE_LIST.as_ptr();
    loop {
        // `pp` is the address of a `next` link of the global cache list (starting
        // at its head), so this reads a live link.
        let p = kernel_rust::ptr::read(pp);
        if p.is_null() || p == cache {
            break;
        }
        // `p` is a live cache node, so the address of its `next` link is valid.
        pp = &raw mut kernel_rust::ptr::as_mut(p).next;
    }
    // `pp` is the in-bounds list link that points at `cache` (or the list tail),
    // read under `G_CACHE_LOCK`.
    let slot = kernel_rust::ptr::read(pp);
    if !slot.is_null() {
        // `slot` is `cache`, so its `next` link is in bounds; relink the list past
        // `cache`.
        let next = kernel_rust::ptr::as_ref(cache).next;
        kernel_rust::ptr::write(pp, next);
    }

    lock_release(G_CACHE_LOCK.as_ptr());
    // `cache` was allocated with `kmalloc_raw` in `slab_cache_create` and has just
    // been unlinked from `G_CACHE_LIST`, so it is safe to return to the heap.
    kfree_raw(cache as *mut u8);
}

/// Print `cache`'s usage (null, or a live, initialised `SlabCache` that stays
/// valid for the call).
#[unsafe(no_mangle)]
pub extern "C" fn slab_print_stats(cache: *const SlabCache) {
    if cache.is_null() {
        return;
    }

    let mut partial_slabs: u32 = 0;
    let mut full_slabs: u32 = 0;
    let mut free_slabs: u32 = 0;
    let mut free_objs: u32 = 0;

    // `cache` is a valid `SlabCache` (checked non-null above); this shared borrow
    // is consumed by the field reads below, and no call in between mutates it.
    let cache = kernel_rust::ptr::as_ref(cache);
    let mut s = cache.partial;
    while !s.is_null() {
        partial_slabs += 1;
        // `s` is a live slab node of the partial list, so this shared borrow is in
        // bounds and consumed by the two field reads.
        let slab = kernel_rust::ptr::as_ref(s);
        free_objs += slab.capacity - slab.inuse;
        s = slab.next;
    }
    s = cache.full;
    while !s.is_null() {
        full_slabs += 1;
        s = kernel_rust::ptr::as_ref(s).next;
    }
    s = cache.free;
    while !s.is_null() {
        free_slabs += 1;
        free_objs += cache.objs_per_slab;
        s = kernel_rust::ptr::as_ref(s).next;
    }

    kprint_str(c"slab: cache=".as_ptr() as *const u8);
    printk(cache.name.as_ptr());
    kprint_str(c" obj_size=".as_ptr() as *const u8);
    kprint_int(cache.obj_size as i32);
    kprint_str(c" slabs(full/partial/free)=".as_ptr() as *const u8);
    kprint_int(full_slabs as i32);
    kprint_str(c"/".as_ptr() as *const u8);
    kprint_int(partial_slabs as i32);
    kprint_str(c"/".as_ptr() as *const u8);
    kprint_int(free_slabs as i32);
    kprint_str(c" free_objs=".as_ptr() as *const u8);
    kprint_int(free_objs as i32);
    kprint_str(c" allocs=".as_ptr() as *const u8);
    kprint_int(cache.total_allocs as i32);
    kprint_str(c"\n".as_ptr() as *const u8);
}

/// Bytes of physical frames currently held by all slab caches (full + partial +
/// free slabs).  Reported by /proc/meminfo as `Slab`.
#[unsafe(no_mangle)]
pub extern "C" fn slab_total_bytes() -> u32 {
    let mut bytes: u32 = 0;
    lock_acquire(G_CACHE_LOCK.as_ptr());
    // `G_CACHE_LIST` head read while holding `G_CACHE_LOCK`, which serialises it
    // against cache creation/destruction and the list relinks.
    let mut c = G_CACHE_LIST.get();
    while !c.is_null() {
        // `c` walks the locked cache list, so `total_slabs` is a live,
        // exclusively-read counter.
        let slabs = kernel_rust::ptr::as_ref(c).total_slabs;
        bytes = bytes.saturating_add(slabs.saturating_mul(PAGE_SIZE));
        c = kernel_rust::ptr::as_ref(c).next;
    }
    lock_release(G_CACHE_LOCK.as_ptr());
    bytes
}

/// One cache's summary, filled by [`slab_snapshot`] for /proc/slabinfo.
#[repr(C)]
pub struct SlabInfoC {
    pub name: [u8; SLAB_NAME_LEN],
    pub obj_size: u32,
    pub active: u32,
    pub num_objs: u32,
    pub slabs: u32,
}

/// Snapshot up to `max` slab caches into `out`; returns the number written.
/// `active` is the in-use object count (summed over the partial and full
/// lists), `num_objs` the active+free object count, `slabs` the page count.
#[unsafe(no_mangle)]
pub extern "C" fn slab_snapshot(out: *mut SlabInfoC, max: u32) -> u32 {
    if out.is_null() || max == 0 {
        return 0;
    }
    let mut n: u32 = 0;
    lock_acquire(G_CACHE_LOCK.as_ptr());
    // Head read while holding `G_CACHE_LOCK`, which serialises the list.
    let mut c = G_CACHE_LIST.get();
    while !c.is_null() && n < max {
        // `c` is a live cache from the locked list.
        let cache = kernel_rust::ptr::as_ref(c);
        let mut active: u32 = 0;
        let mut free: u32 = 0;

        let mut s = cache.partial;
        while !s.is_null() {
            // `s` is a live slab node of the partial list.
            let slab = kernel_rust::ptr::as_ref(s);
            active = active.saturating_add(slab.inuse);
            free = free.saturating_add(slab.capacity.saturating_sub(slab.inuse));
            s = slab.next;
        }
        s = cache.full;
        while !s.is_null() {
            // `s` is a live slab node of the full list (capacity == inuse).
            active = active.saturating_add(kernel_rust::ptr::as_ref(s).capacity);
            s = kernel_rust::ptr::as_ref(s).next;
        }
        s = cache.free;
        while !s.is_null() {
            // `s` is a live slab node of the free list, all objects free.
            free = free.saturating_add(cache.objs_per_slab);
            s = kernel_rust::ptr::as_ref(s).next;
        }

        // `out` holds room for `max` entries and `n < max`.
        let dst = kernel_rust::ptr::as_mut(out.wrapping_add(n as usize));
        dst.name = [0u8; SLAB_NAME_LEN];
        let mut i = 0;
        while i < SLAB_NAME_LEN - 1 && cache.name[i] != 0 {
            dst.name[i] = cache.name[i];
            i += 1;
        }
        dst.obj_size = cache.obj_size;
        dst.active = active;
        dst.num_objs = active.saturating_add(free);
        dst.slabs = cache.total_slabs;

        n += 1;
        // Follow `next` in the locked cache list.
        c = kernel_rust::ptr::as_ref(c).next;
    }
    lock_release(G_CACHE_LOCK.as_ptr());
    n
}

#[path = "slab_generic.rs"]
mod slab_generic;
pub use slab_generic::*;
