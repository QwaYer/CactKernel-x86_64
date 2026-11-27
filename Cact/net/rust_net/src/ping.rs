// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! ICMP echo (ping) helper: validates the destination and forwards to the stack layer.

use core::ffi::c_int;

use kernel_rust::ptr;

pub fn send_echo_request_host(dst_ip_host: u32, id: u16, seq: u16) -> c_int {
    if dst_ip_host == 0 || dst_ip_host == 0xFFFF_FFFF {
        return -1;
    }
    if crate::stack::icmp_echo_request_host(dst_ip_host, id, seq) {
        0
    } else {
        -1
    }
}

/// Fire-and-forget ICMPv6 echo request (destination as sixteen big-endian
/// octets).  A multicast/unspecified destination is refused, as for IPv4.
pub fn send_echo_request6_host(addr: [u8; 16], id: u16, seq: u16) -> c_int {
    if addr == [0u8; 16] || addr[0] == 0xff {
        return -1;
    }
    if crate::stack::icmp_echo_request6_host(addr, id, seq) {
        0
    } else {
        -1
    }
}

/// Send one echo request and wait for its reply.
///
/// Returns the round-trip time in microseconds, or -1 on timeout/failure.  On
/// success `src_ip_out` receives the responder's address (host order) and
/// `bytes_out` the ICMP message length.
///
/// The wait is driven from here — this runs in the calling task's context — so
/// ping works even if the background poll task is busy elsewhere.  It spins
/// briefly to keep sub-millisecond RTT resolution, then falls back to a tick
/// sleep so a lost probe does not burn a whole timeout in the CPU.
///
/// `src_ip_out` and `bytes_out` may be null (the corresponding result is then
/// discarded); a non-null one must point to a writable, properly aligned `u32`.
pub fn ping_wait_host(
    dst_ip_host: u32,
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_ip_out: *mut u32,
    bytes_out: *mut u32,
) -> c_int {
    if send_echo_request_host(dst_ip_host, id, seq) != 0 {
        return -1;
    }
    let timeout_us = (timeout_ms as u64).saturating_mul(1000);
    // SAFETY: `ktime_get_usec` is a kernel C service, safe to call from task
    // context; it only reads the monotonic clock.
    let t0 = crate::ffi_kernel::ktime_get_usec();
    loop {
        crate::stack::stack_poll();
        if let Some((src_addr, bytes)) = crate::stack::icmp_try_recv_reply(id, seq) {
            // SAFETY: as for `t0` — the same monotonic-clock read.
            let rtt = crate::ffi_kernel::ktime_get_usec().saturating_sub(t0);
            // A v4 probe only accepts a v4 responder; a v6 reply with the same
            // id/seq is reported as 0.0.0.0 rather than mistaken for the answer.
            let src = match src_addr {
                smoltcp::wire::IpAddress::Ipv4(v4) => v4.to_bits(),
                _ => 0,
            };
            if !src_ip_out.is_null() {
                ptr::write(src_ip_out, src);
            }
            if !bytes_out.is_null() {
                ptr::write(bytes_out, bytes as u32);
            }
            return rtt.min(i32::MAX as u64) as c_int;
        }
        // A pending signal ends the wait with EINTR instead of burning the whole
        // timeout: Ctrl+C during `ping -W` should stop it, not be ignored.
        if crate::socket::signal_pending() {
            return -4; // EINTR
        }
        // SAFETY: as for `t0` — the same monotonic-clock read.
        let elapsed = crate::ffi_kernel::ktime_get_usec().saturating_sub(t0);
        if elapsed >= timeout_us {
            return -1;
        }
        if elapsed < 250_000 {
            // Poll every millisecond while the reply is still plausible: a 10 ms
            // tick sleep would inflate every WAN RTT by that much.
            // SAFETY: `ktime_busy_wait_us` is a kernel C service that spins for
            // the requested microseconds; it touches no memory of ours.
            crate::ffi_kernel::ktime_busy_wait_us(1000);
        } else {
            sched::timer_wheel::sleep_ticks(1);
        }
    }
}

/// ICMPv6 counterpart of [`ping_wait_host`]: send one echo request to `addr`
/// (sixteen big-endian octets) and wait for its reply.  Returns the round-trip
/// time in microseconds, or <0: `-1` on timeout/failure, `-2` (the caller should
/// report "no route/address") when the kernel has no IPv6 path to `addr` at all,
/// `-4` when a pending signal interrupted the wait.  On success `src_addr_out`
/// receives the responder's address (16 octets) and `bytes_out` the message size.
///
/// `src_addr_out` and `bytes_out` may be null (the corresponding result is then
/// discarded); a non-null `src_addr_out` must point to 16 writable bytes and a
/// non-null `bytes_out` to a writable, properly aligned `u32`.
pub fn ping_wait6_host(
    addr: [u8; 16],
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_addr_out: *mut u8,
    bytes_out: *mut u32,
) -> c_int {
    // Refuse up front when the kernel has no path to this destination (no global
    // address to source from, or no route): the TX path would otherwise drop the
    // echo silently and the caller would report a plain timeout — the same output
    // as a packet lost on the wire.
    if !crate::stack::ipv6_probe_reachable(addr) {
        return -2;
    }
    if send_echo_request6_host(addr, id, seq) != 0 {
        return -1;
    }
    let timeout_us = (timeout_ms as u64).saturating_mul(1000);
    // SAFETY: `ktime_get_usec` is a kernel C service, safe to call from task
    // context; it only reads the monotonic clock.
    let t0 = crate::ffi_kernel::ktime_get_usec();
    loop {
        crate::stack::stack_poll();
        if let Some((src, bytes)) = crate::stack::icmp_try_recv_reply(id, seq) {
            if let smoltcp::wire::IpAddress::Ipv6(v6) = src {
                // SAFETY: as for `t0` — the same monotonic-clock read.
                let rtt = crate::ffi_kernel::ktime_get_usec().saturating_sub(t0);
                if !src_addr_out.is_null() {
                    let o = v6.octets();
                    ptr::copy_nonoverlapping(o.as_ptr(), src_addr_out, 16);
                }
                if !bytes_out.is_null() {
                    ptr::write(bytes_out, bytes as u32);
                }
                return rtt.min(i32::MAX as u64) as c_int;
            }
            // A v4 reply with the same id/seq is not ours; keep waiting.
        }
        // A pending signal ends the wait with EINTR instead of burning the whole
        // timeout: Ctrl+C during `ping6 -W` should stop it, not be ignored.
        if crate::socket::signal_pending() {
            return -4; // EINTR
        }
        // SAFETY: as for `t0` — the same monotonic-clock read.
        let elapsed = crate::ffi_kernel::ktime_get_usec().saturating_sub(t0);
        if elapsed >= timeout_us {
            return -1;
        }
        if elapsed < 250_000 {
            // SAFETY: `ktime_busy_wait_us` is a kernel C service that spins for
            // the requested microseconds; it touches no memory of ours.
            crate::ffi_kernel::ktime_busy_wait_us(1000);
        } else {
            sched::timer_wheel::sleep_ticks(1);
        }
    }
}
