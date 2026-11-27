// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Small C-callable helpers: dotted IPv4 parsing and ping dispatch.
//!
//! String inputs are expected to be NUL-terminated C strings owned by the caller.

use core::ffi::{c_char, c_int};

use crate::ping;

fn parse_ipv4_host(bytes: &[u8]) -> Option<u32> {
    let s = core::str::from_utf8(bytes).ok()?;
    let mut parts = s.split('.');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let c: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if a > 255 || b > 255 || c > 255 || d > 255 {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

fn cstr_len(ptr: *const c_char) -> usize {
    let base = ptr.cast::<u8>();
    let mut len = 0usize;
    loop {
        // The caller guarantees `ptr` is NUL-terminated, so every offset below
        // the terminator is a readable byte.
        if kernel_rust::ptr::read(base.wrapping_add(len)) == 0 {
            break;
        }
        len += 1;
    }
    len
}

/// `input` must be a NUL-terminated string readable for its whole length, and
/// `out_host_ip` must point to a writable, properly aligned `u32`.  Both may be
/// null, in which case the call returns -1 without touching memory.
pub fn rust_net_parse_ipv4(input: *const c_char, out_host_ip: *mut u32) -> c_int {
    if input.is_null() || out_host_ip.is_null() {
        return -1;
    }

    let len = cstr_len(input);
    let bytes = kernel_rust::ptr::slice(input.cast::<u8>(), len);

    match parse_ipv4_host(bytes) {
        Some(ip) => {
            kernel_rust::ptr::write(out_host_ip, ip);
            0
        }
        None => -1,
    }
}

pub fn rust_net_ping_echo_host(dst_ip_host: u32, id: u16, seq: u16) -> c_int {
    ping::send_echo_request_host(dst_ip_host, id, seq)
}

/// Send one echo request and block until the matching reply arrives.
/// Returns the round-trip time in microseconds, or -1 on timeout.
///
/// `src_ip_out` and `bytes_out` may be null (that result is then dropped); a
/// non-null one must point to a writable, properly aligned `u32`.
pub fn rust_net_ping_wait(
    dst_ip_host: u32,
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_ip_out: *mut u32,
    bytes_out: *mut u32,
) -> c_int {
    ping::ping_wait_host(dst_ip_host, id, seq, timeout_ms, src_ip_out, bytes_out)
}

/// Send one ICMPv6 echo request to `addr` (sixteen big-endian octets).  0 on
/// success.
///
/// `addr` must point to 16 readable bytes that stay live for the call.
pub fn rust_net_ping_echo6(addr: *const u8, id: u16, seq: u16) -> c_int {
    if addr.is_null() {
        return -1;
    }
    let mut a6 = [0u8; 16];
    kernel_rust::ptr::copy_nonoverlapping(addr, a6.as_mut_ptr(), 16);
    ping::send_echo_request6_host(a6, id, seq)
}

/// Send one ICMPv6 echo request and block until the matching reply arrives.
/// Returns the round-trip time in microseconds, or -1 on timeout.
///
/// `addr` must point to 16 readable bytes.  `src_addr_out` (16 bytes) and
/// `bytes_out` may be null (that result is then dropped); a non-null one must be
/// writable.
pub fn rust_net_ping_wait6(
    addr: *const u8,
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_addr_out: *mut u8,
    bytes_out: *mut u32,
) -> c_int {
    if addr.is_null() {
        return -1;
    }
    let mut a6 = [0u8; 16];
    kernel_rust::ptr::copy_nonoverlapping(addr, a6.as_mut_ptr(), 16);
    ping::ping_wait6_host(a6, id, seq, timeout_ms, src_addr_out, bytes_out)
}
