// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The DRM/KMS core's exported C ABI reached by a GPU driver module through
//! `ksym` (`ksym.c`, declared in `drm_drv.h`): the KMS object-model entry points
//! the driver builds its CRTCs/encoders/connectors/planes with.  Each is a thin
//! thunk onto a safe `pub fn` in `cact_drm`; the raw-pointer contract is the C
//! caller's, as documented there.
//!
//! (The other half of the core — `drm_dev_*`, `drm_gem_*`, the ioctl dispatcher
//! — is still exported by `cact_drm` itself.)

use core::ffi::{c_int, c_void};

use cact_drm::kms::mode_object::{Connector, Encoder};
use cact_drm::mode::DisplayMode;
use cact_drm::structs::DrmDevice;

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
