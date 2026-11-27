// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! C ABI of the DRM core — the symbols the kernel's C half calls.
//!
//! Migrated slice 1: the ioctl payload plumbing that used to live in
//! `core/drm_ioctl.c` (`drm_ioctl_nr`, `drm_ioctl_size`, `drm_copy_in`,
//! `drm_copy_out`) and `kms/drm_mode_ioctl.c` (`drm_put_raw`).  They are
//! deliberately pure: no device state, only the `_IOC` encoding and the
//! kernel's user-memory primitives, so they are the cheapest thing to move
//! first and are exercised by every single ioctl.
//!
//! C keeps the dispatcher's shape (the three DRM command bands) and the driver
//! ABI; the object model (GEM, KMS objects, framebuffers, properties) follows in
//! later slices.

use core::ffi::{c_int, c_void};
use core::fmt::{self, Write};

use kernel_rust::{console, ptr, user};

/* ── the _IOC encoding (mirrors uapi/drm_ioctl.h) ───────────────────────── */

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;

const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
const IOC_SIZEMASK: u32 = (1 << IOC_SIZEBITS) - 1;

/* ── console logging (the C `printk` is variadic; this crate is not) ─────── */

/// A fixed-buffer `core::fmt::Write` sink for assembling one console line.
struct LogBuf {
    b: [u8; 256],
    n: usize,
}

impl Write for LogBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &c in s.as_bytes() {
            if self.n + 2 >= self.b.len() {
                break;
            }
            self.b[self.n] = c;
            self.n += 1;
        }
        Ok(())
    }
}

/// Emit one console line: `KERN_SOH` + `level`, `args`, then a newline.  The
/// level is the C `printk` severity digit (`'3'` err, `'6'` info, …).
pub(crate) fn log_line(level: u8, args: fmt::Arguments) {
    let mut buf = LogBuf { b: [0u8; 256], n: 0 };
    buf.b[0] = 0x01; // KERN_SOH
    buf.b[1] = level;
    buf.n = 2;
    let _ = fmt::write(&mut buf, args);
    buf.b[buf.n] = b'\n';
    buf.b[buf.n + 1] = 0;
    console::printk_bytes(&buf.b[..buf.n + 2]);
}

/// Read a NUL-terminated `*const u8` C string into `buf` and return it as a
/// `&str` (lossy, truncated to the buffer).  A null pointer yields `""`.
pub(crate) fn cstr<'a>(p: *const u8, buf: &'a mut [u8]) -> &'a str {
    if p.is_null() {
        return "";
    }
    let mut n = 0;
    while n + 1 < buf.len() {
        let b = ptr::read(ptr::add(p, n));
        if b == 0 {
            break;
        }
        buf[n] = b;
        n += 1;
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("?")
}

/// Sequence number of a DRM ioctl command.
#[no_mangle]
pub extern "C" fn drm_ioctl_nr(cmd: u32) -> u32 {
    (cmd >> IOC_NRSHIFT) & IOC_NRMASK
}

/// Payload size encoded in a DRM ioctl command.
#[no_mangle]
pub extern "C" fn drm_ioctl_size(cmd: u32) -> u32 {
    (cmd >> IOC_SIZESHIFT) & IOC_SIZEMASK
}

/// Copy `expect` bytes of an ioctl payload in from userspace.
///
/// A payload shorter than the handler needs is rejected: DRM clients always
/// pass the struct their ioctl number was generated from, and accepting a
/// shorter one would leave fields uninitialised.  Returns 0 or -1, like the C
/// version did.
#[no_mangle]
pub extern "C" fn drm_copy_in(
    dst: *mut c_void,
    cmd: u32,
    user: *mut c_void,
    expect: u32,
) -> c_int {
    if user.is_null() || dst.is_null() {
        return -1;
    }
    let size = drm_ioctl_size(cmd);
    if size != expect {
        console::printk_bytes(b"drm: ioctl payload size mismatch\n\0");
        return -1;
    }
    // `user` is a non-null userspace pointer the caller asked us to read; the
    // kernel's own range check guards it.
    if !user::validate_user_ptr(user, size) {
        return -1;
    }
    // the range check above passed, so `user` is a readable userspace range
    // of `size` bytes and `dst` is a kernel buffer of the same size.
    if !user::copy_from_user(dst, user, size) {
        return -1;
    }
    0
}

/// Copy `size` bytes of an ioctl result back to userspace.  Returns 0 or -1.
#[no_mangle]
pub extern "C" fn drm_copy_out(user: *mut c_void, src: *const c_void, size: u32) -> c_int {
    if user.is_null() || src.is_null() {
        return -1;
    }
    // `user` is a non-null userspace pointer; the kernel's own range check guards it.
    if !user::validate_user_ptr(user, size) {
        return -1;
    }
    // the range check above passed, so `user` is a writable userspace range
    // of `size` bytes and `src` is a kernel buffer of the same size.
    if !user::copy_to_user(user, src, size) {
        return -1;
    }
    0
}

/// A userspace pointer carried in a uapi struct (`__u64`), i.e. C's `UPTR()`.
///
/// The kernel is 64-bit, so a `__u64` userspace address widens to a pointer
/// without loss.
pub(crate) fn uptru(x: u64) -> *mut c_void {
    x as usize as *mut c_void
}

/// Copy a kernel buffer to an optional userspace pointer.
///
/// The uapi structs carry userspace addresses as `__u64`, and a client that
/// only wants the counts leaves such a field zero — that is a "no buffer"
/// request, not an error, so a null/zero-size request succeeds without copying.
#[no_mangle]
pub extern "C" fn drm_put_raw(user: *mut c_void, src: *const c_void, size: u32) -> c_int {
    if user.is_null() || size == 0 {
        return 0;
    }
    drm_copy_out(user, src, size)
}
