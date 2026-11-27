// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The DRM/KMS core — entirely Rust.
//!
//! This crate owns the whole core: the device and object model, GEM, KMS,
//! events, properties and every ioctl handler, plus the VFS/devfs glue that
//! publishes `/dev/dri`.  What is left in C next to it is only the interface to
//! something else:
//!
//!   * `drm_drv.h` + `uapi/` — the ABI a hardware driver module compiles
//!     against (that driver is a separate C `.cctk`, so the header must stay
//!     C-parseable), and
//!   * the kernel itself — `kmalloc`, memfd, spinlocks and the VFS/devfs entry
//!     points, reached through `extern "C"` declarations.
//!
//! Object pools are allocator-backed (`alloc`), so nothing in the core is
//! capped: a device may hold any number of CRTCs, framebuffers or properties,
//! and a client any number of handles and events.  The `#[global_allocator]`
//! comes from the kernel's `rust_net` crate, so no second one is defined here.

#![no_std]
// This crate talks to the C kernel only through `kernel_rust`, the graph's one
// `unsafe` crate: the `extern "C"` surface and the raw-pointer/`static mut`
// plumbing both live there, so this crate holds no `unsafe` of its own and
// forbids it outright.
#![forbid(unsafe_code)]
// The C-ABI hooks this crate defines (`extern "C" fn` VFS operations) still have
// to be FFI-safe, so that check stays in addition to the `unsafe_code` ban.  The
// driver-facing ABI carries `*mut drm_device` / `*mut drm_file`, whose Rust
// types own `Vec`s; a driver only ever holds those as opaque pointers, so the
// pointee layout never crosses the boundary — anything this lint reports is a
// real ABI boundary and needs a local `#[allow]` with a reason.
#![deny(improper_ctypes, improper_ctypes_definitions)]

extern crate alloc;

// This crate's `Vec`/`BTreeMap` storage comes from the kernel heap, whose
// single `#[global_allocator]` lives in `cact_mm`, next to that heap.

// The kernel Rust graph's single `#[global_allocator]` lives in `cact_mm`;
// a crate graph may define exactly one.

pub mod device;
mod devfs;
pub mod event;
mod ffi;
mod file;
pub mod gem;
mod ioctl;
pub mod mode;
pub mod structs;
mod syncobj;
/// The syncobj state model, in a module of its own so the host-side unit tests
/// (`Kernel-Unit-Tests-for-Cact`) can include it: pure rules, no FFI.
mod syncobj_state;
mod vfs;

/// The KMS half of the core.  Its sources live in their own directory
/// (`Cact/drivers/gpu/kms/src`) and are pulled into this crate with `#[path]`
/// rather than built as a second crate: both halves share `DrmDevice`/
/// `DrmFile`, and two Rust staticlibs would duplicate those symbols at link
/// time.  Public so `kernel_abi` can thunk the C-facing KMS entry points.
#[path = "../../../kms/src/mod.rs"]
pub mod kms;

// The kernel Rust graph's single `#[panic_handler]` lives in `cact_mm`, which
// this crate depends on, so one is not defined here.
