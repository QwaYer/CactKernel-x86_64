// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! `cact_mm`'s exported C ABI: every `#[no_mangle]` entry point the C side
//! (`Cact/kernel/memory/...`, syscalls, drivers) calls into the memory
//! manager.  Each is a thin thunk onto the `pub extern "C" fn` of the same
//! name in `cact_mm`, so the ABI stays byte-for-byte identical while the
//! attribute that Rust counts as `unsafe` lives only here.

use core::ffi::c_void;

use cact_mm::alloc::heap::HeapStats;
use cact_mm::alloc::slab::{SlabCache, SlabInfoC};
use cact_mm::fault::swap::SwapSlot;
use cact_mm::ffi::{
    ContextFrame, Mb2MmapTable, OomStats, PfStats, ProcMeta, SwapStats, ZpoolStats,
    ZswapStats,
};
use cact_mm::vmm::stats::VmmUserStats;
use cact_sync::kernel_types::{MmapRegion, MmapTable, ProcPageTracker};

// ---- pmm.rs ----
#[no_mangle]
pub extern "C" fn cact_mmio_window_base() -> u32 {
    cact_mm::pmm::cact_mmio_window_base()
}
#[no_mangle]
pub extern "C" fn pmm_reserve_boot_images(end: u32) -> u32 {
    cact_mm::pmm::pmm_reserve_boot_images(end)
}
#[no_mangle]
pub extern "C" fn pmm_init_from_mmap(mmap: *const Mb2MmapTable) {
    cact_mm::pmm::pmm_init_from_mmap(mmap)
}
#[no_mangle]
pub extern "C" fn init_memory_manager() {
    cact_mm::pmm::init_memory_manager()
}
#[no_mangle]
pub extern "C" fn kalloc() -> *mut u8 {
    cact_mm::pmm::kalloc()
}
#[no_mangle]
pub extern "C" fn free_page(ptr: *mut u8) {
    cact_mm::pmm::free_page(ptr)
}
#[no_mangle]
pub extern "C" fn pmm_total_frames() -> u32 {
    cact_mm::pmm::pmm_total_frames()
}
#[no_mangle]
pub extern "C" fn pmm_free_frames() -> u32 {
    cact_mm::pmm::pmm_free_frames()
}
#[no_mangle]
pub extern "C" fn pmm_reserved_end() -> u32 {
    cact_mm::pmm::pmm_reserved_end()
}

// ---- comp/zpool.rs ----
#[no_mangle]
pub extern "C" fn zpool_create(capacity_pages: u32, budget_bytes: u64, level: i32) -> *mut c_void {
    cact_mm::comp::zpool::zpool_create(capacity_pages, budget_bytes, level)
}
#[no_mangle]
pub extern "C" fn zpool_destroy(p: *mut c_void) {
    cact_mm::comp::zpool::zpool_destroy(p)
}
#[no_mangle]
pub extern "C" fn zpool_grow(p: *mut c_void, new_capacity: u32, new_budget: u64) -> i32 {
    cact_mm::comp::zpool::zpool_grow(p, new_capacity, new_budget)
}
#[no_mangle]
pub extern "C" fn zpool_set_level(p: *mut c_void, level: i32) -> i32 {
    cact_mm::comp::zpool::zpool_set_level(p, level)
}
#[no_mangle]
pub extern "C" fn zpool_store(p: *mut c_void, page: *const u8, out_handle: *mut u32) -> i32 {
    cact_mm::comp::zpool::zpool_store(p, page, out_handle)
}
#[no_mangle]
pub extern "C" fn zpool_load(p: *mut c_void, handle: u32, page: *mut u8) -> i32 {
    cact_mm::comp::zpool::zpool_load(p, handle, page)
}
#[no_mangle]
pub extern "C" fn zpool_free(p: *mut c_void, handle: u32) {
    cact_mm::comp::zpool::zpool_free(p, handle)
}
#[no_mangle]
pub extern "C" fn zpool_get_stats(p: *mut c_void, out: *mut ZpoolStats) -> i32 {
    cact_mm::comp::zpool::zpool_get_stats(p, out)
}

// ---- fault/swap.rs ----
#[no_mangle]
pub extern "C" fn swap_init(read_fn: extern "C" fn(u32, *mut u8, u32) -> i32, write_fn: extern "C" fn(u32, *const u8, u32) -> i32) -> i32 {
    cact_mm::fault::swap::swap_init(read_fn, write_fn)
}
#[no_mangle]
pub extern "C" fn swap_enable(slots: u32) -> i32 {
    cact_mm::fault::swap::swap_enable(slots)
}
#[no_mangle]
pub extern "C" fn swap_disable() {
    cact_mm::fault::swap::swap_disable()
}
#[no_mangle]
pub extern "C" fn swap_is_enabled_ffi() -> i32 {
    cact_mm::fault::swap::swap_is_enabled_ffi()
}
#[no_mangle]
pub extern "C" fn swap_out_page(phys_addr: u64, out_slot: *mut SwapSlot) -> i32 {
    cact_mm::fault::swap::swap_out_page(phys_addr, out_slot)
}
#[no_mangle]
pub extern "C" fn swap_in_page(slot: SwapSlot, phys_addr: u64) -> i32 {
    cact_mm::fault::swap::swap_in_page(slot, phys_addr)
}
#[no_mangle]
pub extern "C" fn swap_free_slot(slot: SwapSlot) {
    cact_mm::fault::swap::swap_free_slot(slot)
}
#[no_mangle]
pub extern "C" fn swap_migrate_begin() -> i32 {
    cact_mm::fault::swap::swap_migrate_begin()
}
#[no_mangle]
pub extern "C" fn swap_migrate_end() {
    cact_mm::fault::swap::swap_migrate_end()
}
#[no_mangle]
pub extern "C" fn swap_migrate_pd(pd: *mut u64) -> i32 {
    cact_mm::fault::swap::swap_migrate_pd(pd)
}
#[no_mangle]
pub extern "C" fn swap_release_slots() {
    cact_mm::fault::swap::swap_release_slots()
}
#[no_mangle]
pub extern "C" fn swap_evict_page(pd: *mut u64) -> i32 {
    cact_mm::fault::swap::swap_evict_page(pd)
}
#[no_mangle]
pub extern "C" fn swap_handle_fault(pd: *mut u64, fault_addr: u64) -> i32 {
    cact_mm::fault::swap::swap_handle_fault(pd, fault_addr)
}
#[no_mangle]
pub extern "C" fn swap_get_stats() -> SwapStats {
    cact_mm::fault::swap::swap_get_stats()
}
#[no_mangle]
pub extern "C" fn swap_print_stats() {
    cact_mm::fault::swap::swap_print_stats()
}

// ---- fault/zswap.rs ----
#[no_mangle]
pub extern "C" fn zswap_is_enabled_ffi() -> i32 {
    cact_mm::fault::zswap::zswap_is_enabled_ffi()
}
#[no_mangle]
pub extern "C" fn zswap_enable(max_pool_pct: u32, level: i32, writeback: i32) -> i32 {
    cact_mm::fault::zswap::zswap_enable(max_pool_pct, level, writeback)
}
#[no_mangle]
pub extern "C" fn zswap_disable() -> i32 {
    cact_mm::fault::zswap::zswap_disable()
}
#[no_mangle]
pub extern "C" fn zswap_get_stats(out: *mut ZswapStats) -> i32 {
    cact_mm::fault::zswap::zswap_get_stats(out)
}
#[no_mangle]
pub extern "C" fn zswap_init() {
    cact_mm::fault::zswap::zswap_init()
}

// ---- fault/oom.rs ----
#[no_mangle]
pub extern "C" fn oom_kill() -> i32 {
    cact_mm::fault::oom::oom_kill()
}
#[no_mangle]
pub extern "C" fn oom_get_stats() -> OomStats {
    cact_mm::fault::oom::oom_get_stats()
}
#[no_mangle]
pub extern "C" fn oom_print_stats() {
    cact_mm::fault::oom::oom_print_stats()
}

// ---- fault/page_fault.rs ----
#[no_mangle]
pub extern "C" fn page_fault_init() {
    cact_mm::fault::page_fault::page_fault_init()
}
#[no_mangle]
pub extern "C" fn page_fault_handler(regs: *mut ContextFrame) {
    cact_mm::fault::page_fault::page_fault_handler(regs)
}
#[no_mangle]
pub extern "C" fn pf_get_stats() -> PfStats {
    cact_mm::fault::page_fault::pf_get_stats()
}
#[no_mangle]
pub extern "C" fn pf_print_stats() {
    cact_mm::fault::page_fault::pf_print_stats()
}

// ---- fault/page_fault_map.rs (re-exported through fault::page_fault) ----
#[no_mangle]
pub extern "C" fn vmm_map_demand(pd: *mut u64, virtual_addr: u64, size: u32, flags: i32) -> i32 {
    cact_mm::fault::page_fault::vmm_map_demand(pd, virtual_addr, size, flags)
}
#[no_mangle]
pub extern "C" fn vmm_map_zero(pd: *mut u64, virtual_addr: u64, size: u32, flags: i32) -> i32 {
    cact_mm::fault::page_fault::vmm_map_zero(pd, virtual_addr, size, flags)
}
#[no_mangle]
pub extern "C" fn vmm_map_cow(pd: *mut u64, virtual_addr: u64) -> i32 {
    cact_mm::fault::page_fault::vmm_map_cow(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_is_cow_page(pd: *mut u64, virtual_addr: u64) -> i32 {
    cact_mm::fault::page_fault::vmm_is_cow_page(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_handle_cow(pd: *mut u64, virtual_addr: u64) -> i32 {
    cact_mm::fault::page_fault::vmm_handle_cow(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_setup_user_stack(pd: *mut u64, initial_size: u32) -> u32 {
    cact_mm::fault::page_fault::vmm_setup_user_stack(pd, initial_size)
}
#[no_mangle]
pub extern "C" fn vmm_pin_range(pd: *mut u64, va: u64, size: u64, out_phys: *mut u64) -> i64 {
    cact_mm::fault::page_fault::vmm_pin_range(pd, va, size, out_phys)
}
#[no_mangle]
pub extern "C" fn vmm_unpin_frames(phys: *const u64, count: u64) {
    cact_mm::fault::page_fault::vmm_unpin_frames(phys, count)
}

// ---- vmm/pat.rs ----
#[no_mangle]
pub extern "C" fn pat_init() {
    cact_mm::vmm::pat::pat_init()
}
#[no_mangle]
pub extern "C" fn pat_enable_wc_for_framebuffer(fb_va: u64, fb_pitch: u32, fb_height: u32) -> i32 {
    cact_mm::vmm::pat::pat_enable_wc_for_framebuffer(fb_va, fb_pitch, fb_height)
}

// ---- vmm/paging.rs ----
#[no_mangle]
pub extern "C" fn vmm_v2p(ptr: *const u8) -> u64 {
    cact_mm::vmm::paging::vmm_v2p(ptr)
}
#[no_mangle]
pub extern "C" fn vmm_p2v(phys: u64) -> *mut u8 {
    cact_mm::vmm::paging::vmm_p2v(phys)
}
#[no_mangle]
pub extern "C" fn init_paging() {
    cact_mm::vmm::paging::init_paging()
}
#[no_mangle]
pub extern "C" fn vmm_sync_kernel_mmio_mappings(pd: *mut u64) {
    cact_mm::vmm::paging::vmm_sync_kernel_mmio_mappings(pd)
}
#[no_mangle]
pub extern "C" fn vmm_map(pd: *mut u64, virtual_addr: u64, physical_addr: u64, flags: i32) {
    cact_mm::vmm::paging::vmm_map(pd, virtual_addr, physical_addr, flags)
}
#[no_mangle]
pub extern "C" fn vmm_get_phys(pd: *mut u64, virtual_addr: u64) -> u64 {
    cact_mm::vmm::paging::vmm_get_phys(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_pte_flags(pd: *mut u64, virtual_addr: u64) -> u32 {
    cact_mm::vmm::paging::vmm_pte_flags(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_unmap(pd: *mut u64, virtual_addr: u64) -> u64 {
    cact_mm::vmm::paging::vmm_unmap(pd, virtual_addr)
}
#[no_mangle]
pub extern "C" fn vmm_set_kernel_cache(va: u64, set: u64, clear: u64) {
    cact_mm::vmm::paging::vmm_set_kernel_cache(va, set, clear)
}
#[no_mangle]
pub extern "C" fn vmm_create_address_space() -> *mut u64 {
    cact_mm::vmm::paging::vmm_create_address_space()
}
#[no_mangle]
pub extern "C" fn vmm_free_address_space(pd: *mut u64) {
    cact_mm::vmm::paging::vmm_free_address_space(pd)
}
#[no_mangle]
pub extern "C" fn vmm_copy_address_space(src_pd: *mut u64, dst_pd: *mut u64) {
    cact_mm::vmm::paging::vmm_copy_address_space(src_pd, dst_pd)
}

// ---- vmm/cow.rs ----
#[no_mangle]
pub extern "C" fn vmm_fork_address_space(src_pd: *mut u64, dst_pd: *mut u64) {
    cact_mm::vmm::cow::vmm_fork_address_space(src_pd, dst_pd)
}

// ---- vmm/mmap.rs ----
#[no_mangle]
pub extern "C" fn mmap_table_init(tbl: *mut MmapTable) {
    cact_mm::vmm::mmap::mmap_table_init(tbl)
}
#[no_mangle]
pub extern "C" fn mmap_find_region(tbl: *mut MmapTable, addr: u32) -> *mut MmapRegion {
    cact_mm::vmm::mmap::mmap_find_region(tbl, addr)
}
#[no_mangle]
pub extern "C" fn do_mmap(pd: *mut u64, tbl: *mut MmapTable, hint: u32, length: u32, prot: i32, flags: i32, fd: i32, offset: u32) -> *mut u8 {
    cact_mm::vmm::mmap::do_mmap(pd, tbl, hint, length, prot, flags, fd, offset)
}
#[no_mangle]
pub extern "C" fn do_munmap(pd: *mut u64, tbl: *mut MmapTable, addr: u32, length: u32) -> i32 {
    cact_mm::vmm::mmap::do_munmap(pd, tbl, addr, length)
}
#[no_mangle]
pub extern "C" fn do_mprotect(pd: *mut u64, tbl: *mut MmapTable, addr: u32, length: u32, prot: i32, brk_start: u64, brk_end: u64) -> i32 {
    cact_mm::vmm::mmap::do_mprotect(pd, tbl, addr, length, prot, brk_start, brk_end)
}
#[no_mangle]
pub extern "C" fn mmap_print_regions(tbl: *const MmapTable) {
    cact_mm::vmm::mmap::mmap_print_regions(tbl)
}

// ---- vmm/mmap_clone.rs (re-exported through vmm::mmap) ----
#[no_mangle]
pub extern "C" fn mmap_table_clone(src: *mut MmapTable, dst: *mut MmapTable, src_pd: *mut u64, dst_pd: *mut u64) {
    cact_mm::vmm::mmap::mmap_table_clone(src, dst, src_pd, dst_pd)
}
#[no_mangle]
pub extern "C" fn mmap_table_free(tbl: *mut MmapTable, pd: *mut u64) {
    cact_mm::vmm::mmap::mmap_table_free(tbl, pd)
}

// ---- vmm/stats.rs ----
#[no_mangle]
pub extern "C" fn vmm_user_stats(pd: *mut u64, proc: *const ProcMeta) -> VmmUserStats {
    cact_mm::vmm::stats::vmm_user_stats(pd, proc)
}
#[no_mangle]
pub extern "C" fn vmm_kernel_ptable_pages() -> u32 {
    cact_mm::vmm::stats::vmm_kernel_ptable_pages()
}

// ---- alloc/heap.rs ----
#[no_mangle]
pub extern "C" fn init_heap() {
    cact_mm::alloc::heap::init_heap()
}
#[no_mangle]
pub extern "C" fn heap_get_stats() -> HeapStats {
    cact_mm::alloc::heap::heap_get_stats()
}
#[no_mangle]
pub extern "C" fn get_free_heap_memory() -> u32 {
    cact_mm::alloc::heap::get_free_heap_memory()
}
#[no_mangle]
pub extern "C" fn kmalloc_print_stats() {
    cact_mm::alloc::heap::kmalloc_print_stats()
}
#[no_mangle]
pub extern "C" fn kmalloc_usable_size(ptr: *mut u8) -> usize {
    cact_mm::alloc::heap::kmalloc_usable_size(ptr)
}
#[no_mangle]
pub extern "C" fn krealloc_aligned_raw(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    cact_mm::alloc::heap::krealloc_aligned_raw(ptr, new_size, align)
}
#[no_mangle]
pub extern "C" fn kmalloc(size: usize) -> *mut u8 {
    cact_mm::alloc::heap::kmalloc(size)
}
#[no_mangle]
pub extern "C" fn kmalloc_aligned(size: usize, align: usize) -> *mut u8 {
    cact_mm::alloc::heap::kmalloc_aligned(size, align)
}
#[no_mangle]
pub extern "C" fn kfree(ptr: *mut u8) {
    cact_mm::alloc::heap::kfree(ptr)
}
#[no_mangle]
pub extern "C" fn krealloc_aligned(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    cact_mm::alloc::heap::krealloc_aligned(ptr, new_size, align)
}

// ---- alloc/slab.rs ----
#[no_mangle]
pub extern "C" fn slab_cache_create(name: *const u8, obj_size: u32, ctor: Option<extern "C" fn(*mut u8)>, dtor: Option<extern "C" fn(*mut u8)>) -> *mut SlabCache {
    cact_mm::alloc::slab::slab_cache_create(name, obj_size, ctor, dtor)
}
#[no_mangle]
pub extern "C" fn slab_alloc(cache: *mut SlabCache) -> *mut u8 {
    cact_mm::alloc::slab::slab_alloc(cache)
}
#[no_mangle]
pub extern "C" fn slab_free(cache: *mut SlabCache, obj: *mut u8) {
    cact_mm::alloc::slab::slab_free(cache, obj)
}
#[no_mangle]
pub extern "C" fn slab_try_free(ptr: *mut u8) -> bool {
    cact_mm::alloc::slab::slab_try_free(ptr)
}
#[no_mangle]
pub extern "C" fn slab_cache_shrink(cache: *mut SlabCache) {
    cact_mm::alloc::slab::slab_cache_shrink(cache)
}
#[no_mangle]
pub extern "C" fn slab_shrink_all() -> u32 {
    cact_mm::alloc::slab::slab_shrink_all()
}
#[no_mangle]
pub extern "C" fn slab_cache_destroy(cache: *mut SlabCache) {
    cact_mm::alloc::slab::slab_cache_destroy(cache)
}
#[no_mangle]
pub extern "C" fn slab_print_stats(cache: *const SlabCache) {
    cact_mm::alloc::slab::slab_print_stats(cache)
}
#[no_mangle]
pub extern "C" fn slab_total_bytes() -> u32 {
    cact_mm::alloc::slab::slab_total_bytes()
}
#[no_mangle]
pub extern "C" fn slab_snapshot(out: *mut SlabInfoC, max: u32) -> u32 {
    cact_mm::alloc::slab::slab_snapshot(out, max)
}

// ---- alloc/slab_generic.rs (re-exported through alloc::slab) ----
#[no_mangle]
pub extern "C" fn slab_init() {
    cact_mm::alloc::slab::slab_init()
}
#[no_mangle]
pub extern "C" fn slab_kmalloc(size: usize) -> *mut u8 {
    cact_mm::alloc::slab::slab_kmalloc(size)
}
#[no_mangle]
pub extern "C" fn slab_kfree(ptr: *mut u8) {
    cact_mm::alloc::slab::slab_kfree(ptr)
}

// ---- process/proc_mm.rs ----
#[no_mangle]
pub extern "C" fn proc_tracker_add(t: *mut ProcPageTracker, frame: *mut u8) -> i32 {
    cact_mm::process::proc_mm::proc_tracker_add(t, frame)
}
#[no_mangle]
pub extern "C" fn proc_free_pages(t: *mut ProcPageTracker) {
    cact_mm::process::proc_mm::proc_free_pages(t)
}

// ---- process/memfd.rs ----
#[no_mangle]
pub extern "C" fn memfd_create(name: *const u8, name_len: u32, flags: i32) -> i32 {
    cact_mm::process::memfd::memfd_create(name, name_len, flags)
}
#[no_mangle]
pub extern "C" fn memfd_ref(handle: i32) -> i32 {
    cact_mm::process::memfd::memfd_ref(handle)
}
#[no_mangle]
pub extern "C" fn memfd_close(handle: i32) -> i32 {
    cact_mm::process::memfd::memfd_close(handle)
}
#[no_mangle]
pub extern "C" fn memfd_map_inc(handle: i32) -> i32 {
    cact_mm::process::memfd::memfd_map_inc(handle)
}
#[no_mangle]
pub extern "C" fn memfd_map_dec(handle: i32) -> i32 {
    cact_mm::process::memfd::memfd_map_dec(handle)
}
#[no_mangle]
pub extern "C" fn memfd_size(handle: i32) -> i64 {
    cact_mm::process::memfd::memfd_size(handle)
}
#[no_mangle]
pub extern "C" fn memfd_get_page(handle: i32, idx: u32) -> *mut u8 {
    cact_mm::process::memfd::memfd_get_page(handle, idx)
}
#[no_mangle]
pub extern "C" fn memfd_read(handle: i32, off: u64, buf: *mut u8, size: u32) -> i32 {
    cact_mm::process::memfd::memfd_read(handle, off, buf, size)
}
#[no_mangle]
pub extern "C" fn memfd_write(handle: i32, off: u64, buf: *const u8, size: u32) -> i32 {
    cact_mm::process::memfd::memfd_write(handle, off, buf, size)
}
#[no_mangle]
pub extern "C" fn memfd_truncate(handle: i32, new_size: u64) -> i32 {
    cact_mm::process::memfd::memfd_truncate(handle, new_size)
}
#[no_mangle]
pub extern "C" fn memfd_add_seals(handle: i32, seals: u32) -> i32 {
    cact_mm::process::memfd::memfd_add_seals(handle, seals)
}
#[no_mangle]
pub extern "C" fn memfd_get_seals(handle: i32) -> i32 {
    cact_mm::process::memfd::memfd_get_seals(handle)
}

// ---- process/shm.rs ----
#[no_mangle]
pub extern "C" fn shm_get(key: i32, size: u32, flags: i32) -> i32 {
    cact_mm::process::shm::shm_get(key, size, flags)
}
#[no_mangle]
pub extern "C" fn shm_total_bytes() -> u32 {
    cact_mm::process::shm::shm_total_bytes()
}

// ---- process/shm_api.rs (re-exported through process::shm) ----
#[no_mangle]
pub extern "C" fn shm_at(shmid: i32, shmaddr: u32, flags: i32) -> u32 {
    cact_mm::process::shm::shm_at(shmid, shmaddr, flags)
}
#[no_mangle]
pub extern "C" fn shm_dt(shmaddr: u32) -> i32 {
    cact_mm::process::shm::shm_dt(shmaddr)
}
#[no_mangle]
pub extern "C" fn shm_ctl(shmid: i32, cmd: i32, buf: *mut u8) -> i32 {
    cact_mm::process::shm::shm_ctl(shmid, cmd, buf)
}
#[no_mangle]
pub extern "C" fn shm_detach_all(pid: u32, page_directory: *mut u64) {
    cact_mm::process::shm::shm_detach_all(pid, page_directory)
}
