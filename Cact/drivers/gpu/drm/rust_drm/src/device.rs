// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Device lifecycle: allocation, registration (which publishes `/dev/dri/cardN`
//! and calls the driver's `load()`), unregistration, and the global device
//! table.
//!
//! The device table is a `Vec`, so there is no fixed maximum number of DRM
//! devices; a device itself is a boxed Rust value, so its pools are released
//! when it is freed.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};

use kernel_rust::mem::{box_free, kfree};
use kernel_rust::ptr;

use crate::devfs::{drm_devfs_add_device, drm_devfs_init};
use crate::ffi::{cstr, log_line};
use crate::gem::{drm_gem_unref, lock_ptr};
use crate::kms::framebuffer::{ClipRect, Framebuffer};
use crate::kms::mode_object::{Connector, Crtc, Plane};
use crate::structs::{DrmDevice, DriverOps, IrqSpinlock, ModeSet};

/// Every registered device, indexed by minor.  `None` marks a free minor.
static mut DEVICES: Option<Vec<Option<*mut DrmDevice>>> = None;

/// The device table, created on first use.
///
/// Device allocation/removal happens while the module loader holds the kernel's
/// module lock, which is also how the C table was protected.
fn devices() -> &'static mut Vec<Option<*mut DrmDevice>> {
    // `DEVICES` is this crate's own static and outlives every device; the module
    // lock serialises callers, so this borrow is never aliased.
    let table = ptr::as_mut(core::ptr::addr_of_mut!(DEVICES));
    if table.is_none() {
        // Installing the initial `Vec` exactly once.
        *table = Some(Vec::new());
    }
    table.as_mut().unwrap()
}

/// The device table for the devfs glue to walk.
pub(crate) fn device_table() -> &'static mut Vec<Option<*mut DrmDevice>> {
    // Forwards to `devices()`, so the same module-lock invariant holds.
    devices()
}

/* ── lifecycle ──────────────────────────────────────────────────────────── */

/// Allocate a DRM device.  `priv` is the driver's own per-device state and is
/// returned by `drm_dev_priv()`.  NULL on out-of-memory.
pub fn drm_dev_alloc(ops: *const DriverOps, priv_: *mut c_void) -> *mut DrmDevice {
    if ops.is_null() {
        return core::ptr::null_mut();
    }
    // `devices()` returns the module-locked device table, so the slot search and
    // the store below are serialised.
    let table = devices();
    let minor = match table.iter().position(|e| e.is_none()) {
        Some(i) => i,
        None => table.len(),
    };

    {

        let dev = Box::new(DrmDevice {
            ops,
            priv_,
            minor: minor as i32,
            in_use: 0,
            next_magic: 0x4000_0000u32.wrapping_add((minor as u32).wrapping_mul(0x1000)),
            next_fb_id: 0,
            next_prop_id: 0,
            next_blob_id: 0,
            lock: IrqSpinlock::new(),
            crtcs: Vec::new(),
            connectors: Vec::new(),
            encoders: Vec::new(),
            planes: Vec::new(),
            fbs: Vec::new(),
            props: Vec::new(),
            prop_attach: Vec::new(),
            blobs: Vec::new(),
            map_offsets: BTreeMap::new(),
            next_map_offset: 0x1000_0000u32
                .wrapping_add((minor as u32).wrapping_mul(0x1000_0000)),
            gem_list: Vec::new(),
            flink: BTreeMap::new(),
            next_flink_name: 1,
            clients: Vec::new(),
            syncobjs: Vec::new(),
            next_syncobj_id: 0,
            sync_fds: Vec::new(),
            syncobj_ev_fds: Vec::new(),
            card_node: core::ptr::null_mut(),
            render_node: core::ptr::null_mut(),
            have_render_node: 0,
        });
        let dev = Box::into_raw(dev);
        // The device is not published yet, so initialising its lock word in place
        // is exclusive.
        ptr::as_mut(lock_ptr(dev)).init();

        if table.len() <= minor {
            table.push(Some(dev));
        } else {
            table[minor] = Some(dev);
        }
        dev
    }
}

/// Tear a device down completely and release its slot.
pub fn drm_dev_free(dev: *mut DrmDevice) {
    if dev.is_null() {
        return;
    }
    drm_dev_unregister(dev);
    // `dev` is the caller's live device (checked non-null above); this reads its
    // slot index.
    let minor = ptr::as_ref(dev).minor as usize;
    // `devices()` returns the module-locked device table.
    let table = devices();
    if minor < table.len() {
        table[minor] = None;
    }
    // `dev` came from `Box::into_raw` in `drm_dev_alloc` and has just been
    // removed from the table, so reclaiming the Box here is the matching free.
    box_free(dev);
}

pub fn drm_dev_priv(dev: *mut DrmDevice) -> *mut c_void {
    if dev.is_null() {
        core::ptr::null_mut()
    } else {
        // Caller's device.
        ptr::as_ref(dev).priv_
    }
}

pub fn drm_dev_ops(dev: *mut DrmDevice) -> *const DriverOps {
    if dev.is_null() {
        core::ptr::null()
    } else {
        // Caller's device.
        ptr::as_ref(dev).ops
    }
}

/// Bring the device up: call `ops->load()`, then publish `/dev/dri/cardN` (and
/// the matching `renderDN`).  Returns 0 on success, negative on failure — a
/// driver that fails here must call `drm_dev_free()`.
pub fn drm_dev_register(dev: *mut DrmDevice) -> c_int {
    if dev.is_null() {
        return -1;
    }
    // `dev` is the caller's live device (checked non-null above); this reads its
    // ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if ops.is_null() {
        return -1;
    }

    /* Idempotent: the first device registers /dev/dri, later ones reuse it. */
    if drm_devfs_init() != 0 {
        return -1;
    }

    /* Create the device node first: a driver's load() often pushes its initial
     * mode through the KMS state, and clients may already open the node. */
    if drm_devfs_add_device(dev) != 0 {
        // `dev` is the live device; this reads its minor for the message.
        let minor = ptr::as_ref(dev).minor;
        log_line(b'3', format_args!("drm: cannot publish /dev/dri/card{}", minor));
        return -1;
    }

    // `ops` is the driver's live ops table; this copies the `load` fn pointer
    // only (a plain `extern "C"` pointer, so the call needs no block).
    let load = ptr::as_ref(ops).load;
    if let Some(load) = load {
        let rc = load(dev);
        if rc != 0 {
            // `ops` is the driver's live ops table; this reads its name.
            let mut nbuf = [0u8; 64];
            let name = cstr(ptr::as_ref(ops).name, &mut nbuf);
            log_line(b'3', format_args!("drm: '{}' load failed ({})", name, rc));
            return rc;
        }
    }

    // `dev` is the live device; marking it in use.
    ptr::as_mut(dev).in_use = 1;

    let count = |pool: &[*mut c_void]| pool.iter().filter(|&&p| !p.is_null()).count() as u32;
    // `dev` is the live device; these borrows of its pools are consumed by the
    // counts.
    let ncrtc = count(&ptr::as_ref(dev).crtcs);
    let nconn = count(&ptr::as_ref(dev).connectors);
    let nenc = count(&ptr::as_ref(dev).encoders);
    let nplane = count(&ptr::as_ref(dev).planes);
    let nfb = count(&ptr::as_ref(dev).fbs);

    // `dev` is the live device; this reads its minor for the banner.
    let minor = ptr::as_ref(dev).minor;
    // `ops` is the driver's live ops table; this reads its name.
    let mut nbuf = [0u8; 64];
    let name = cstr(ptr::as_ref(ops).name, &mut nbuf);
    log_line(
        b'6',
        format_args!(
            "  {:<11} : /dev/dri/card{} ready \u{2014} {} ({} crtc, {} conn, {} enc, {} plane, {} fb)",
            "drm", minor, name, ncrtc, nconn, nenc, nplane, nfb
        ),
    );
    0
}

/// Tear the device down.  Clients and their handles go first, then the driver,
/// then the core's own pools.
pub fn drm_dev_unregister(dev: *mut DrmDevice) {
    if dev.is_null() {
        return;
    }
    // `dev` is the caller's live device (checked non-null above); this reads its
    // in-use flag.
    if ptr::as_ref(dev).in_use == 0 {
        return;
    }

    /* Drop every client: their handles and framebuffers hold object references, so
     * this must happen before the driver tears its hardware down.  The list is
     * taken out first: `drm_client_destroy` unlinks the client from it. */
    let clients = core::mem::take(&mut ptr::as_mut(dev).clients);
    for f in clients {
        if !f.is_null() {
            // `drm_client_destroy`'s contract: `f` is one of this device's
            // clients.
            crate::file::drm_client_destroy(f);
        }
    }

    /* Pending syncobj→eventfd registrations hold an eventfd open.  They die with
     * the device and are not signalled, as a syncobj freed with entries waiting
     * on it is not signalled either. */
    crate::syncobj::eventfd_drop_all(dev);

    // `dev` is the live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if !ops.is_null() {
        // `ops` is the driver's live ops table; this copies the `unload` fn
        // pointer only (a plain `extern "C"` pointer).
        let unload = ptr::as_ref(ops).unload;
        if let Some(unload) = unload {
            unload(dev);
        }
    }

    /* CRTCs and encoders are plain kalloc'd structs … */
    let crtcs = &ptr::as_ref(dev).crtcs;
    for &p in crtcs.iter() {
        if !p.is_null() {
            /* A CRTC may still hold a reference on the cursor image it displays;
             * drop it before reclaiming the CRTC, or the object leaks. */
            let crtc = p as *mut Crtc;
            // `crtc` is a live CRTC owned by this device; this reads the cursor
            // image it holds.
            let cursor_obj = ptr::as_ref(crtc).cursor.obj;
            if !cursor_obj.is_null() {
                drm_gem_unref(cursor_obj);
            }
            // Each entry is a `kalloc`'d CRTC this device owns.
            kfree(p as *mut u8);
        }
    }
    // Clearing the (now-empty) CRTC list.
    ptr::as_mut(dev).crtcs.clear();
    let encoders = &ptr::as_ref(dev).encoders;
    for &p in encoders.iter() {
        if !p.is_null() {
            // Each entry is a `kalloc`'d encoder this device owns.
            kfree(p as *mut u8);
        }
    }
    // Clearing the encoder list.
    ptr::as_mut(dev).encoders.clear();

    /* … while connectors and planes own `Vec`s, so they are dropped. */
    let connectors = &ptr::as_ref(dev).connectors;
    for &p in connectors.iter() {
        if !p.is_null() {
            // Each entry came from `Box::into_raw` and is owned by this device.
            box_free(p as *mut Connector);
        }
    }
    // Clearing the connector list.
    ptr::as_mut(dev).connectors.clear();
    let planes = &ptr::as_ref(dev).planes;
    for &p in planes.iter() {
        if !p.is_null() {
            // Each entry came from `Box::into_raw` and is owned by this device.
            box_free(p as *mut Plane);
        }
    }
    // Clearing the plane list.
    ptr::as_mut(dev).planes.clear();

    // `dev` is the live device; this borrow of its framebuffer list is consumed
    // by the drain.
    let fbs = &ptr::as_ref(dev).fbs;
    for &p in fbs.iter() {
        let fb = p as *mut Framebuffer;
        if !fb.is_null() {
            // `fb` is a live framebuffer; this reads its GEM object.
            let obj = ptr::as_ref(fb).obj;
            if !obj.is_null() {
                drm_gem_unref(obj);
            }
            // `fb` is a `kalloc`'d framebuffer this device owns.
            kfree(fb as *mut u8);
        }
    }
    // Clearing the framebuffer list.
    ptr::as_mut(dev).fbs.clear();

    /* Vec-typed pools release themselves once cleared. */
    // Clearing each remaining pool.
    ptr::as_mut(dev).props.clear();
    // The property-attachment table.
    ptr::as_mut(dev).prop_attach.clear();
    // The blob table.
    ptr::as_mut(dev).blobs.clear();
    // The global-name table.
    ptr::as_mut(dev).flink.clear();
    // The map-offset table.
    ptr::as_mut(dev).map_offsets.clear();

    /* The /dev/dri nodes are ours (drm_devfs_add_device allocated them). */
    // `dev` is the live device; this reads its card-node pointer.
    let card_node = ptr::as_ref(dev).card_node;
    // The card node was allocated by `kmalloc` for this device.
    kfree(card_node as *mut u8);
    // Clearing the pointer after the free.
    ptr::as_mut(dev).card_node = core::ptr::null_mut();
    // `dev` is the live device; this reads its render-node pointer.
    let render_node = ptr::as_ref(dev).render_node;
    // The render node was allocated by `kmalloc` for this device.
    kfree(render_node as *mut u8);
    // Clearing the pointer after the free.
    ptr::as_mut(dev).render_node = core::ptr::null_mut();
    // Clearing the has-render-node flag.
    ptr::as_mut(dev).have_render_node = 0;

    // Marking the device slot free.
    ptr::as_mut(dev).in_use = 0;
}

/* ── driver-ops call-throughs ───────────────────────────────────────────── */

pub fn drm_driver_set_config(dev: *mut DrmDevice, set: *mut ModeSet) -> c_int {
    if dev.is_null() {
        return 0;
    }
    // `dev` is the caller's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if ops.is_null() {
        return 0;
    }
    // `ops` is the driver's live ops table; this copies the `set_config` fn
    // pointer only (a plain `extern "C"` pointer).
    let f = ptr::as_ref(ops).set_config;
    match f {
        Some(f) => f(dev, set),
        None => 0,
    }
}

pub fn drm_driver_dirty(
    dev: *mut DrmDevice,
    fb: *mut Framebuffer,
    clips: *const ClipRect,
    num_clips: u32,
) -> c_int {
    if dev.is_null() {
        return 0;
    }
    // `dev` is the caller's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if ops.is_null() {
        return 0;
    }
    // `ops` is the driver's live ops table; this copies the `dirty` fn pointer
    // only (a plain `extern "C"` pointer).
    let f = ptr::as_ref(ops).dirty;
    match f {
        Some(f) => f(fb as *mut c_void, clips as *const c_void, num_clips),
        None => 0,
    }
}

pub fn drm_driver_page_flip(
    dev: *mut DrmDevice,
    crtc: *mut Crtc,
    fb: *mut Framebuffer,
    flags: u32,
    user_data: *mut c_void,
) -> c_int {
    if dev.is_null() {
        return 0;
    }
    // `dev` is the caller's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if ops.is_null() {
        return 0;
    }
    // `ops` is the driver's live ops table; this copies the `page_flip` fn
    // pointer only (a plain `extern "C"` pointer).
    let f = ptr::as_ref(ops).page_flip;
    match f {
        Some(f) => f(crtc as *mut c_void, fb as *mut c_void, flags, user_data),
        None => 0,
    }
}

/// A driver without a vblank interrupt leaves `enable_vblank` NULL; 0 then means
/// "nothing to do", not "failed".
pub fn drm_driver_enable_vblank(dev: *mut DrmDevice, crtc: *mut Crtc) -> c_int {
    if dev.is_null() {
        return 0;
    }
    // `dev` is the caller's live device; this copies its ops pointer.
    let ops = ptr::as_ref(dev).ops;
    if ops.is_null() {
        return 0;
    }
    // `ops` is the driver's live ops table; this copies the `enable_vblank` fn
    // pointer only (a plain `extern "C"` pointer).
    let f = ptr::as_ref(ops).enable_vblank;
    match f {
        Some(f) => f(dev, crtc as *mut c_void),
        None => 0,
    }
}

/// Convenience for module probes: alloc + register in one step.
pub fn drm_dev_create(ops: *const DriverOps, priv_: *mut c_void) -> *mut DrmDevice {
    let dev = drm_dev_alloc(ops, priv_);
    if dev.is_null() {
        return core::ptr::null_mut();
    }
    if drm_dev_register(dev) != 0 {
        drm_dev_free(dev);
        return core::ptr::null_mut();
    }
    dev
}
