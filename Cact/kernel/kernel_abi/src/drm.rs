// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The DRM/KMS core's exported C ABI reached by a GPU driver module through
//! `ksym` (`ksym.c`, declared in `drm_drv.h`): the KMS object-model entry points
//! the driver builds its CRTCs/encoders/connectors/planes with, and — further
//! down the file — the device lifecycle (`drm_dev_*`) and GEM/handle/PRIME
//! (`drm_gem_*`) entry points.  Each is a thin thunk onto a safe `pub fn` in
//! `cact_drm`; the raw-pointer contract is the C caller's, as documented there.
//!
//! (The ioctl dispatcher is not here: `cact_drm` still emits that symbol itself.)

use core::ffi::{c_int, c_void};

use cact_drm::event::drm_crtc_handle_vblank as handle_vblank;
use cact_drm::kms::mode_object::{Connector, Crtc, Encoder};
use cact_drm::mode::DisplayMode;
use cact_drm::structs::{DrmDevice, DrmFile, DriverOps, GemObject};

#[no_mangle]
pub unsafe extern "C" fn drm_crtc_handle_vblank(crtc: *mut c_void) {
    handle_vblank(crtc as *mut Crtc);
}

#[no_mangle]
pub unsafe extern "C" fn drm_mode_crtc_init(dev: *mut DrmDevice, index: c_int, name: *const u8) -> c_int {
    cact_drm::kms::mode_object::drm_mode_crtc_init(dev, index, name)
}

#[no_mangle]
pub unsafe extern "C" fn drm_mode_encoder_init(
    dev: *mut DrmDevice,
    index: c_int,
    etype: u32,
    possible_crtcs: u32,
    possible_clones: u32,
) -> c_int {
    cact_drm::kms::mode_object::drm_mode_encoder_init(
        dev, index, etype, possible_crtcs, possible_clones,
    )
}

#[no_mangle]
pub unsafe extern "C" fn drm_mode_connector_init(
    dev: *mut DrmDevice,
    index: c_int,
    ctype: u32,
    type_id: u32,
) -> c_int {
    cact_drm::kms::mode_object::drm_mode_connector_init(dev, index, ctype, type_id)
}

#[no_mangle]
pub unsafe extern "C" fn drm_mode_plane_init(
    dev: *mut DrmDevice,
    index: c_int,
    ptype: u32,
    possible_crtcs: u32,
    formats: *const u32,
    format_count: c_int,
    format_type: u32,
) -> c_int {
    cact_drm::kms::mode_object::drm_mode_plane_init(
        dev, index, ptype, possible_crtcs, formats, format_count, format_type,
    )
}

#[no_mangle]
pub unsafe extern "C" fn drm_crtc_find(dev: *mut DrmDevice, id: u32) -> *mut c_void {
    cact_drm::kms::mode_object::drm_crtc_find(dev, id)
}

#[no_mangle]
pub unsafe extern "C" fn drm_encoder_find(dev: *mut DrmDevice, id: u32) -> *mut c_void {
    cact_drm::kms::mode_object::drm_encoder_find(dev, id)
}

#[no_mangle]
pub unsafe extern "C" fn drm_connector_find(dev: *mut DrmDevice, id: u32) -> *mut c_void {
    cact_drm::kms::mode_object::drm_connector_find(dev, id)
}

#[no_mangle]
pub unsafe extern "C" fn drm_plane_find(dev: *mut DrmDevice, id: u32) -> *mut c_void {
    cact_drm::kms::mode_object::drm_plane_find(dev, id)
}

#[no_mangle]
pub unsafe extern "C" fn drm_connector_add_mode(conn: *mut Connector, mode: *const DisplayMode) {
    cact_drm::kms::mode_object::drm_connector_add_mode(conn, mode);
}

#[no_mangle]
pub unsafe extern "C" fn drm_connector_set_edid(conn: *mut Connector, edid: *const c_void, len: u32) {
    cact_drm::kms::mode_object::drm_connector_set_edid(conn, edid, len);
}

#[no_mangle]
pub unsafe extern "C" fn drm_connector_attach_encoder(conn: *mut Connector, enc: *mut c_void) {
    cact_drm::kms::mode_object::drm_connector_attach_encoder(conn, enc);
}

#[no_mangle]
pub unsafe extern "C" fn drm_encoder_attach_crtc(enc: *mut Encoder, crtc: *mut c_void) {
    cact_drm::kms::mode_object::drm_encoder_attach_crtc(enc, crtc);
}

/* ── device lifecycle (drm_drv.h) ───────────────────────────────────────── */

#[no_mangle]
pub unsafe extern "C" fn drm_dev_alloc(ops: *const DriverOps, priv_: *mut c_void) -> *mut DrmDevice {
    cact_drm::device::drm_dev_alloc(ops, priv_)
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_free(dev: *mut DrmDevice) {
    cact_drm::device::drm_dev_free(dev);
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_priv(dev: *mut DrmDevice) -> *mut c_void {
    cact_drm::device::drm_dev_priv(dev)
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_ops(dev: *mut DrmDevice) -> *const DriverOps {
    cact_drm::device::drm_dev_ops(dev)
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_register(dev: *mut DrmDevice) -> c_int {
    cact_drm::device::drm_dev_register(dev)
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_unregister(dev: *mut DrmDevice) {
    cact_drm::device::drm_dev_unregister(dev);
}

#[no_mangle]
pub unsafe extern "C" fn drm_dev_create(ops: *const DriverOps, priv_: *mut c_void) -> *mut DrmDevice {
    cact_drm::device::drm_dev_create(ops, priv_)
}

/* ── GEM (drm_drv.h) ────────────────────────────────────────────────────── */

#[no_mangle]
pub unsafe extern "C" fn drm_gem_create(dev: *mut DrmDevice, size: u32) -> *mut GemObject {
    cact_drm::gem::drm_gem_create(dev, size)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_vaddr(obj: *mut GemObject, off: u32) -> *mut c_void {
    cact_drm::gem::drm_gem_vaddr(obj, off)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_size(obj: *mut GemObject) -> u32 {
    cact_drm::gem::drm_gem_size(obj)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_page_count(obj: *mut GemObject) -> u32 {
    cact_drm::gem::drm_gem_page_count(obj)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_page_phys(obj: *mut GemObject, index: u32) -> u64 {
    cact_drm::gem::drm_gem_page_phys(obj, index)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_ref(obj: *mut GemObject) -> c_int {
    cact_drm::gem::drm_gem_ref(obj)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_unref(obj: *mut GemObject) -> c_int {
    cact_drm::gem::drm_gem_unref(obj)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_memfd(obj: *mut GemObject) -> c_int {
    cact_drm::gem::drm_gem_memfd(obj)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_map_offset(
    dev: *mut DrmDevice,
    obj: *mut GemObject,
    offset_out: *mut u64,
) -> c_int {
    cact_drm::gem::drm_gem_map_offset(dev, obj, offset_out)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_handle_create(
    file: *mut DrmFile,
    obj: *mut GemObject,
    handle_out: *mut u32,
) -> c_int {
    cact_drm::gem::drm_gem_handle_create(file, obj, handle_out)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_handle_lookup(file: *mut DrmFile, handle: u32) -> *mut GemObject {
    cact_drm::gem::drm_gem_handle_lookup(file, handle)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_handle_close(file: *mut DrmFile, handle: u32) -> c_int {
    cact_drm::gem::drm_gem_handle_close(file, handle)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_prime_handle_to_fd(
    dev: *mut DrmDevice,
    file: *mut DrmFile,
    handle: u32,
    flags: u32,
    fd_out: *mut c_int,
) -> c_int {
    cact_drm::gem::drm_gem_prime_handle_to_fd(dev, file, handle, flags, fd_out)
}

#[no_mangle]
pub unsafe extern "C" fn drm_gem_prime_fd_to_handle(
    dev: *mut DrmDevice,
    file: *mut DrmFile,
    fd: c_int,
    handle_out: *mut u32,
) -> c_int {
    cact_drm::gem::drm_gem_prime_fd_to_handle(dev, file, fd, handle_out)
}
