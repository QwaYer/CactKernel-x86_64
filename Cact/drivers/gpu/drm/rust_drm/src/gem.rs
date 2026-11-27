// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! GEM buffer objects, client handle tables, mmap offsets and the dumb-buffer
//! ioctls, plus PRIME buffer sharing.
//!
//! Objects are memfd-backed on purpose: a memfd already provides a page array,
//! an owner reference count, MAP_SHARED accounting and a fork()-safe lifetime,
//! so mmap(), munmap(), dup(), fork() and PRIME all work through
//! already-exercised paths.  The GEM object is therefore only a description
//! (size, dumb geometry, map offset) wrapped around a memfd handle.
//!
//! Handles, map offsets and global names are all allocator-backed maps, so a
//! client may hold as many handles and a device hand out as many offsets as it
//! likes.

use core::ffi::{c_int, c_void};

use kernel_rust::fs::{
    alloc_fd, memfd_close, memfd_create, memfd_fd_handle, memfd_get_page, memfd_ref, memfd_size,
    memfd_truncate, memfd_vnode_from_handle,
};
use kernel_rust::mem::{get_phys, kfree};
use kernel_rust::ptr;

use crate::ffi::{drm_copy_in, drm_copy_out};
use crate::structs::{DrmDevice, DrmFile, GemObject, IrqSpinlock};

/// Address of the device's bookkeeping lock.
#[inline]
pub(crate) fn lock_ptr(dev: *mut DrmDevice) -> *mut IrqSpinlock {
    // `dev` is a live device owned by the caller; `addr_of_mut!` only forms the
    // address of its `lock` field and never creates a reference.
    let dev = ptr::as_mut(dev);
    core::ptr::addr_of_mut!(dev.lock)
}

/* ── object lifecycle ───────────────────────────────────────────────────── */

/// `drm_gem_link` — link an object into the device's list.  Shared with PRIME
/// import, which adopts an object it did not allocate.  The caller holds the
/// device lock.
pub fn drm_gem_link(dev: *mut DrmDevice, obj: *mut GemObject) {
    if dev.is_null() || obj.is_null() {
        return;
    }
    // Caller's live device and object.
    ptr::as_mut(dev).gem_list.push(obj);
}

/// Create an object of `size` bytes (rounded up to a page) backed by a memfd,
/// and return it with one reference held.  NULL on failure.
pub fn drm_gem_create(dev: *mut DrmDevice, size: u32) -> *mut GemObject {
    if dev.is_null() || size == 0 {
        return core::ptr::null_mut();
    }
    let obj = cact_mm::kmalloc(core::mem::size_of::<GemObject>()) as *mut GemObject;
    if obj.is_null() {
        return core::ptr::null_mut();
    }
    // `obj` is the fresh `kmalloc` object just checked non-null, so zeroing one
    // `GemObject` covers exactly that allocation.
    ptr::write_bytes(obj, 0, 1);

    let rounded = (size + 4095) & !4095u32;

    // The name is a NUL-terminated literal and the flags are the values the C
    // path used.
    let h = memfd_create(c"drm-gem".as_ptr() as *const u8, 7, 0);
    if h <= 0 {
        // `obj` is the object allocated above and not yet published.
        kfree(obj as *mut u8);
        return core::ptr::null_mut();
    }
    // `h` is the live memfd just created and `rounded` its requested size.
    if memfd_truncate(h, rounded as u64) != 0 {
        // `h` is the live memfd; `obj` is the un-published object.
        memfd_close(h);
        kfree(obj as *mut u8);
        return core::ptr::null_mut();
    }

    {
        // `obj` is the fresh, exclusively-owned object; this borrow is consumed
        // by the field stores below and ends before the driver hook.
        let obj_ref = ptr::as_mut(obj);
        obj_ref.dev = dev;
        obj_ref.memfd = h;
        obj_ref.size = rounded;
        obj_ref.refcount = 1;
    }

    /* Let the driver refuse or constrain the object (e.g. a device that needs
     * physically contiguous scanout). */
    // `dev` is the caller's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if !ops.is_null() {
        // `ops` is the driver's live ops table; this copies the `gem_create` fn
        // pointer only.
        let create = ptr::as_ref(ops).gem_create;
        if let Some(create) = create {
            // `create` is the plain `extern "C"` driver hook and `dev`/`obj` are
            // the live device and object it expects.
            if create(dev, obj) != 0 {
                // On refusal the object and its memfd are still ours.
                memfd_close(h);
                kfree(obj as *mut u8);
                return core::ptr::null_mut();
            }
        }
    }

    // `dev` is the caller's live device.
    let lock = lock_ptr(dev);
    // `lock` is the device's lock word; the pair brackets the link update.
    ptr::as_mut(lock).acquire();
    drm_gem_link(dev, obj);
    // As above — releasing the same lock.
    ptr::as_mut(lock).release();
    obj
}

/// Take a reference.
pub fn drm_gem_ref(obj: *mut GemObject) -> c_int {
    if obj.is_null() {
        return -1;
    }
    // `obj` is the caller's live object (checked non-null above); this borrow is
    // consumed by the counter update and the read that follows it.
    let obj = ptr::as_mut(obj);
    obj.refcount += 1;
    obj.refcount
}

/// Drop a reference; the last one frees the object and its memfd.
pub fn drm_gem_unref(obj: *mut GemObject) -> c_int {
    if obj.is_null() {
        return -1;
    }
    // `obj` is the caller's live object (checked non-null above), so this
    // reference-count read is in bounds.
    if ptr::as_ref(obj).refcount == 0 {
        return -1;
    }
    // As above — dropping one reference.
    ptr::as_mut(obj).refcount -= 1;
    // As above — re-reading the count.
    if ptr::as_ref(obj).refcount > 0 {
        // As above.
        return ptr::as_ref(obj).refcount;
    }

    // `obj` is the live object; this reads its device pointer.
    let dev = ptr::as_ref(obj).dev;
    // `dev` is the object's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if !ops.is_null() {
        // `ops` is the driver's live ops table; this copies the `gem_free` fn
        // pointer only.
        let free = ptr::as_ref(ops).gem_free;
        if let Some(free) = free {
            // `free` is the plain `extern "C"` driver hook and `obj` the live
            // object it is releasing.
            free(obj);
        }
    }

    // `dev` is the object's live device.
    let lock = lock_ptr(dev);
    // `lock` is the device's lock word; the pair brackets the unlink below.
    ptr::as_mut(lock).acquire();
    /* Drop the map offsets first: a client may still have the object mapped, but
     * no new mmap may resolve to it.  Same for its global name. */
    // `dev` is the live device; this drops the object from its map-offset table
    // while the lock is held.
    ptr::as_mut(dev).map_offsets.retain(|_, &mut v| v != obj);
    // As above — the flink table.
    ptr::as_mut(dev).flink.retain(|_, &mut v| v != obj);
    // As above — the object list.
    ptr::as_mut(dev).gem_list.retain(|&p| p != obj);
    // As above — releasing the same lock.
    ptr::as_mut(lock).release();

    // `obj` is the live object; this reads its memfd handle.
    let memfd = ptr::as_ref(obj).memfd;
    if memfd > 0 {
        // That memfd was created by `drm_gem_create` and is closed once here.
        memfd_close(memfd);
    }
    // The object's last reference was just dropped, so reclaiming its allocation
    // is the matching free.
    kfree(obj as *mut u8);
    0
}

pub fn drm_gem_size(obj: *mut GemObject) -> u32 {
    if obj.is_null() {
        0
    } else {
        // Caller's object.
        ptr::as_ref(obj).size
    }
}

pub fn drm_gem_memfd(obj: *mut GemObject) -> c_int {
    if obj.is_null() {
        -1
    } else {
        // Caller's object.
        ptr::as_ref(obj).memfd
    }
}

/// Kernel-visible address of `off` inside the object.
///
/// Only the bytes up to the end of *that frame* are addressable through the
/// returned pointer: memfd frames are allocated individually and are not
/// contiguous, so callers must walk frame by frame (`off = i * 4096`).
pub fn drm_gem_vaddr(obj: *mut GemObject, off: u32) -> *mut c_void {
    if obj.is_null() {
        return core::ptr::null_mut();
    }
    // `obj` is the caller's live object (checked non-null above), so this `size`
    // read is in bounds.
    if off >= ptr::as_ref(obj).size {
        return core::ptr::null_mut();
    }
    // `obj` is the live object; this reads its memfd handle.
    let memfd = ptr::as_ref(obj).memfd;
    // `memfd` is that object's live memfd and `off / 4096` its page index.
    let page = memfd_get_page(memfd, off / 4096) as *mut u8;
    if page.is_null() {
        return core::ptr::null_mut();
    }
    // `page` is a live 4 KiB frame and `off & 4095` indexes within it.
    ptr::add(page, (off & 4095) as usize) as *mut c_void
}

/// Number of 4 KiB frames backing the object.
pub fn drm_gem_page_count(obj: *mut GemObject) -> u32 {
    if obj.is_null() {
        return 0;
    }
    // `obj` is the caller's live object (checked non-null above).
    ptr::as_ref(obj).size / 4096
}

/// Physical address of frame `index` of the object, or 0 when the index is out
/// of range or the frame is not mapped.
///
/// A device that reads the object itself (scanout, a GPU translation table)
/// needs physical addresses: memfd frames are allocated individually, so a
/// caller walks indices `0..drm_gem_page_count(obj)` to collect them.
pub fn drm_gem_page_phys(obj: *mut GemObject, index: u32) -> u64 {
    if obj.is_null() || index >= drm_gem_page_count(obj) {
        return 0;
    }
    // `drm_gem_vaddr`'s contract: `obj` is the caller's live object and
    // `index * 4096` is inside its size (checked above), so the page base is
    // returned (the low 12 bits of the offset are zero).
    let page = drm_gem_vaddr(obj, index * 4096) as u64;
    if page == 0 {
        return 0;
    }
    // `get_phys` translates `page` in the kernel page directory (a null
    // directory selects it); 0 is returned when unmapped.
    get_phys(core::ptr::null_mut(), page)
}

/* ── mmap offsets ───────────────────────────────────────────────────────── */

/// Resolve a faked mmap offset back to its object (used by the VFS mmap hook).
pub fn drm_gem_find_map_offset(dev: *mut DrmDevice, offset: u32) -> *mut GemObject {
    if dev.is_null() {
        return core::ptr::null_mut();
    }
    // Read-only walk of the caller's device.
    match ptr::as_ref(dev).map_offsets.get(&offset) {
        Some(&obj) => obj,
        None => core::ptr::null_mut(),
    }
}

/// The caller holds the device lock.
fn drm_gem_alloc_map_offset(dev: *mut DrmDevice, obj: *mut GemObject) -> u32 {
    // The caller holds the device lock (see the function's contract), so
    // `map_offsets` has no concurrent writer; `dev` is live and this borrow is
    // exclusive.
    let dev = ptr::as_mut(dev);
    let off = dev.next_map_offset;
    dev.next_map_offset = off.wrapping_add(0x1000_0000); // stay page aligned
    dev.map_offsets.insert(off, obj);
    off
}

/// An offset a client can pass to mmap(2).  It is stable for the object's
/// lifetime, so asking repeatedly returns the same one.
pub fn drm_gem_map_offset(
    dev: *mut DrmDevice,
    obj: *mut GemObject,
    offset_out: *mut u64,
) -> c_int {
    if dev.is_null() || obj.is_null() || offset_out.is_null() {
        return -22;
    }
    // `obj` is the caller's live object (checked non-null above); this reads its
    // cached map offset.
    let mut off = ptr::as_ref(obj).map_offset;
    if off == 0 {
        // `dev` is the caller's live device.
        let lock = lock_ptr(dev);
        // `lock` is the device's lock word; the pair brackets the allocation.
        ptr::as_mut(lock).acquire();
        // `drm_gem_alloc_map_offset`'s contract: the device lock is held.
        off = drm_gem_alloc_map_offset(dev, obj);
        // As above — releasing the same lock.
        ptr::as_mut(lock).release();
        // `obj` is the live object; caching the freshly-allocated offset.
        ptr::as_mut(obj).map_offset = off;
    }
    // `offset_out` is the caller's out-parameter for the offset.
    ptr::write(offset_out, off as u64);
    0
}

/* ── handle table ───────────────────────────────────────────────────────── */

/// Give `obj` a per-client handle.
pub fn drm_gem_handle_create(
    file: *mut DrmFile,
    obj: *mut GemObject,
    handle_out: *mut u32,
) -> c_int {
    if file.is_null() || obj.is_null() || handle_out.is_null() {
        return -1;
    }
    // `file` is the caller's live client (checked non-null above); this reads its
    // device pointer.
    let dev = ptr::as_ref(file).dev;
    // `dev` is the client's live device.
    let lock = lock_ptr(dev);
    // `lock` is the device's lock word; the pair brackets the handle insert.
    ptr::as_mut(lock).acquire();
    {
        // `file` is the live client; this borrow is consumed by the handle insert
        // below.
        let file = ptr::as_mut(file);
        file.next_handle += 1;
        let handle = file.next_handle;
        file.handles.insert(handle, obj);
        drm_gem_ref(obj);
        // As above — releasing the same lock.
        ptr::as_mut(lock).release();
        // `handle_out` is the caller's out-parameter for the handle.
        ptr::write(handle_out, handle);
    }
    0
}

pub fn drm_gem_handle_lookup(file: *mut DrmFile, handle: u32) -> *mut GemObject {
    if file.is_null() || handle == 0 {
        return core::ptr::null_mut();
    }
    // Read-only walk of the caller's file.
    match ptr::as_ref(file).handles.get(&handle) {
        Some(&obj) => obj,
        None => core::ptr::null_mut(),
    }
}

/// Release a handle, dropping the object reference it held.
pub fn drm_gem_handle_close(file: *mut DrmFile, handle: u32) -> c_int {
    if file.is_null() {
        return -1;
    }
    // Caller's file.
    match ptr::as_mut(file).handles.remove(&handle) {
        Some(obj) => {
            drm_gem_unref(obj);
            0
        }
        None => -9, // -EBADF
    }
}

/* ── PRIME ──────────────────────────────────────────────────────────────── */

/// Export a GEM object as a file descriptor.  Because the storage is a memfd,
/// this wraps that same memfd in a vnode — no copy, and both sides see one set
/// of frames.
pub fn drm_gem_prime_handle_to_fd(
    dev: *mut DrmDevice,
    file: *mut DrmFile,
    handle: u32,
    flags: u32,
    fd_out: *mut c_int,
) -> c_int {
    let _ = flags;
    if dev.is_null() || file.is_null() || fd_out.is_null() {
        return -22;
    }
    // `drm_gem_handle_lookup`'s contract: this only walks the caller's file.
    let obj = drm_gem_handle_lookup(file, handle);
    if obj.is_null() {
        return -9; // -EBADF
    }

    // `obj` is the live object named by the handle; this reads its memfd.
    let memfd = ptr::as_ref(obj).memfd;
    // As above — its size.
    let size = ptr::as_ref(obj).size;

    // `memfd` is that live object's backing memfd and `size` its length.
    let node = memfd_vnode_from_handle(memfd, c"drm-prime".as_ptr() as *const u8, size);
    if node.is_null() {
        return -12;
    }

    // `node` is the live vnode just created; install it as the new fd's file.
    let fd = alloc_fd(node);
    if fd < 0 {
        return -24; // -EMFILE
    }

    // `fd_out` is the caller's out-parameter for the fd.
    ptr::write(fd_out, fd);
    0
}

/// Import: find or create the object that owns the memfd behind `fd`.  A handle
/// exported by this very device resolves to the existing object; an fd from
/// elsewhere (another device, or a plain memfd) is adopted as a new object
/// sharing the same storage.
pub fn drm_gem_prime_fd_to_handle(
    dev: *mut DrmDevice,
    file: *mut DrmFile,
    fd: c_int,
    handle_out: *mut u32,
) -> c_int {
    if dev.is_null() || file.is_null() || handle_out.is_null() {
        return -22;
    }
    // `memfd_fd_handle` maps the fd to its memfd handle.
    let h = memfd_fd_handle(fd);
    if h <= 0 {
        return -22;
    }

    let mut obj: *mut GemObject = core::ptr::null_mut();
    // `dev` is the caller's live device.
    let lock = lock_ptr(dev);
    // `lock` is the device's lock word; the pair brackets the object-list walk.
    ptr::as_mut(lock).acquire();
    // `dev` is the live device; this borrow of its object list is consumed by the
    // walk below.
    let gem_list = &ptr::as_ref(dev).gem_list;
    for &o in gem_list.iter() {
        if !o.is_null() {
            // `o` is a live object (non-null, checked above).
            if ptr::as_ref(o).memfd == h {
                obj = o;
                break;
            }
        }
    }
    // As above — releasing the same lock.
    ptr::as_mut(lock).release();

    if !obj.is_null() {
        let mut handle = 0u32;
        if drm_gem_handle_create(file, obj, &mut handle) != 0 {
            return -12;
        }
        // `handle_out` is the caller's out-parameter for the handle.
        ptr::write(handle_out, handle);
        return 0;
    }

    // `memfd_size` reads the memfd's length.
    let size = memfd_size(h);
    if size <= 0 {
        return -22;
    }

    let obj = cact_mm::kmalloc(core::mem::size_of::<GemObject>()) as *mut GemObject;
    if obj.is_null() {
        return -12;
    }
    // `obj` is the fresh `kmalloc` object just checked non-null, so zeroing one
    // `GemObject` covers exactly that allocation.
    ptr::write_bytes(obj, 0, 1);
    {
        // `obj` is the fresh, exclusively-owned object; this borrow is consumed
        // by the field stores below.
        let obj_ref = ptr::as_mut(obj);
        obj_ref.dev = dev;
        obj_ref.memfd = h;
        obj_ref.size = size as u32;
        obj_ref.refcount = 1;
    }
    // `h` is the live memfd being adopted; the object now owns a reference of its
    // own.
    memfd_ref(h);

    // `dev` is the live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if !ops.is_null() {
        // `ops` is the driver's live ops table; this copies the `gem_create` fn
        // pointer only.
        let create = ptr::as_ref(ops).gem_create;
        if let Some(create) = create {
            // `create` is the plain `extern "C"` driver hook and `dev`/`obj` are
            // the live device and object it expects.
            if create(dev, obj) != 0 {
                // On refusal the adopted memfd and the object are still ours.
                memfd_close(h);
                kfree(obj as *mut u8);
                return -22;
            }
        }
    }

    // `lock` is the device's lock word; the pair brackets the link update.
    ptr::as_mut(lock).acquire();
    drm_gem_link(dev, obj);
    // As above — releasing the same lock.
    ptr::as_mut(lock).release();

    let mut handle = 0u32;
    if drm_gem_handle_create(file, obj, &mut handle) != 0 {
        drm_gem_unref(obj);
        return -12;
    }
    // `handle_out` is the caller's out-parameter for the handle.
    ptr::write(handle_out, handle);
    0
}

/* ── dumb buffers ───────────────────────────────────────────────────────── */

/* uapi/drm_mode.h, sizes pinned by the probe that filled these assertions. */
#[repr(C)]
struct ModeCreateDumb {
    height: u32,
    width: u32,
    bpp: u32,
    flags: u32,
    handle: u32,
    pitch: u32,
    size: u64,
}

#[repr(C)]
struct ModeMapDumb {
    handle: u32,
    pad: u32,
    offset: u64,
}

#[repr(C)]
struct ModeDestroyDumb {
    handle: u32,
}

const _: () = assert!(core::mem::size_of::<ModeCreateDumb>() == 32);
const _: () = assert!(core::mem::offset_of!(ModeCreateDumb, size) == 24);
const _: () = assert!(core::mem::size_of::<ModeMapDumb>() == 16);
const _: () = assert!(core::mem::offset_of!(ModeMapDumb, offset) == 8);
const _: () = assert!(core::mem::size_of::<ModeDestroyDumb>() == 4);

/// `_IOWR(0x64, nr, size)` — the ioctl numbers, spelled out so the payload
/// check in `drm_copy_in` sees exactly the size these structs have.
const fn drm_iowr(nr: u32, size: u32) -> u32 {
    (3u32 << 30) | (0x64u32 << 8) | nr | (size << 16)
}

const DRM_IOCTL_MODE_CREATE_DUMB: u32 = drm_iowr(0xB2, 32);
const DRM_IOCTL_MODE_MAP_DUMB: u32 = drm_iowr(0xB3, 16);
const DRM_IOCTL_MODE_DESTROY_DUMB: u32 = drm_iowr(0xB4, 4);

/// `DRM_IOCTL_MODE_CREATE_DUMB`.  Takes the *userspace* pointer and copies its
/// arguments in and the result back out — the same discipline every handler
/// follows, so a client cannot make the kernel write to an address of its
/// choosing.
pub fn drm_gem_dumb_create(file: *mut DrmFile, user: *mut c_void) -> c_int {
    if file.is_null() {
        return -22;
    }
    let mut args = ModeCreateDumb {
        height: 0,
        width: 0,
        bpp: 0,
        flags: 0,
        handle: 0,
        pitch: 0,
        size: 0,
    };
    if drm_copy_in(
        &mut args as *mut _ as *mut c_void,
        DRM_IOCTL_MODE_CREATE_DUMB,
        user,
        core::mem::size_of::<ModeCreateDumb>() as u32,
    ) != 0
    {
        return -22;
    }
    if args.width == 0 || args.height == 0 {
        return -22;
    }

    let bpp = if args.bpp != 0 { args.bpp } else { 32 };
    if bpp != 8 && bpp != 16 && bpp != 24 && bpp != 32 {
        return -22;
    }

    /* Scanout pitch: keep rows 64-byte aligned so a blitter or the device's
     * own refresh stays on cache-line boundaries. */
    let pitch = (args.width * (bpp / 8) + 63) & !63u32;
    if pitch == 0 {
        return -22;
    }
    if args.height > 0xFFFF_FFFFu32 / pitch {
        return -22;
    }
    let size = pitch * args.height;
    if size == 0 {
        return -22;
    }

    // `file` is the caller's live client (checked non-null above); this reads its
    // device pointer.
    let dev = ptr::as_ref(file).dev;
    // `drm_gem_create`'s contract: `dev` is the live device; it returns a fresh
    // object with one reference held.
    let obj = drm_gem_create(dev, size);
    if obj.is_null() {
        return -12;
    }

    {
        // `obj` is the fresh object created above and exclusively owned here;
        // this borrow is consumed by the field stores.
        let obj_ref = ptr::as_mut(obj);
        obj_ref.is_dumb = 1;
        obj_ref.width = args.width;
        obj_ref.height = args.height;
        obj_ref.bpp = bpp;
        obj_ref.pitch = pitch;
    }

    let mut off = 0u64;
    if drm_gem_map_offset(dev, obj, &mut off) != 0 {
        drm_gem_unref(obj);
        return -12;
    }

    let mut handle = 0u32;
    if drm_gem_handle_create(file, obj, &mut handle) != 0 {
        drm_gem_unref(obj);
        return -12;
    }

    /* No zeroing here: memfd frames are zeroed as they are allocated, and a linear
     * memset over the whole object would run off the first frame anyway — the
     * frames are individually allocated. */

    args.handle = handle;
    args.pitch = pitch;
    args.size = size as u64;
    drm_copy_out(user, &args as *const _ as *const c_void, core::mem::size_of::<ModeCreateDumb>() as u32)
}

pub fn drm_gem_dumb_map_offset(file: *mut DrmFile, user: *mut c_void) -> c_int {
    if file.is_null() {
        return -22;
    }
    let mut args = ModeMapDumb { handle: 0, pad: 0, offset: 0 };
    if drm_copy_in(
        &mut args as *mut _ as *mut c_void,
        DRM_IOCTL_MODE_MAP_DUMB,
        user,
        core::mem::size_of::<ModeMapDumb>() as u32,
    ) != 0
    {
        return -22;
    }

    // `drm_gem_handle_lookup`'s contract: this only walks the caller's file.
    let obj = drm_gem_handle_lookup(file, args.handle);
    if obj.is_null() {
        return -9;
    }
    // `obj` is the live object named by the handle; this reads its dumb flag.
    if ptr::as_ref(obj).is_dumb == 0 {
        return -22;
    }
    // As above — the object's cached map offset.
    args.offset = ptr::as_ref(obj).map_offset as u64;
    drm_copy_out(user, &args as *const _ as *const c_void, core::mem::size_of::<ModeMapDumb>() as u32)
}

pub fn drm_gem_dumb_destroy(file: *mut DrmFile, user: *mut c_void) -> c_int {
    if file.is_null() {
        return -22;
    }
    let mut args = ModeDestroyDumb { handle: 0 };
    if drm_copy_in(
        &mut args as *mut _ as *mut c_void,
        DRM_IOCTL_MODE_DESTROY_DUMB,
        user,
        core::mem::size_of::<ModeDestroyDumb>() as u32,
    ) != 0
    {
        return -22;
    }
    drm_gem_handle_close(file, args.handle)
}
