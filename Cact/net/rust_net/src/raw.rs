// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Raw IPv6 sockets (`SOCK_RAW`, `IPPROTO_ICMPV6`) on top of smoltcp — just
//! enough for a userspace SLAAC/DHCPv6 client.
//!
//! The buffer userspace exchanges is the **ICMPv6 message itself** (like
//! Linux's raw ICMPv6 sockets), not the IPv6 header: on receive the kernel
//! strips the IPv6 header and reports the source address; on send it prepends
//! the IPv6 header and computes the ICMPv6 checksum, because only the kernel
//! knows the interface's source address.  A raw socket is placed lazily on one
//! interface (like UDP), by `bind()` to a local address or by the destination
//! of the first send.

use kernel_rust::ptr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::raw;
use smoltcp::wire::{IpProtocol, IpVersion};

use crate::stack;

/// Raw sockets the kernel hands out at once (a SLAAC client needs one; leave a
/// little room for a DHCPv6 client / diagnostics).
pub const RAW_SOCK_MAX: usize = 4;
const RAW_RX_BUF: usize = 1536;
const RAW_TX_BUF: usize = 1536;

/// One raw socket's kernel-side state.
#[derive(Clone, Copy)]
struct RawSock {
    used: u8,
    /// Interface slot it is placed on, or -1 before the first bind/send.
    slot: i32,
    /// 1 while an ICMPv6 message is queued (for `poll()`).
    rx_ready: u8,
    /// Local address pinned by `bind()` (all-zero = unspecified).
    local6: [u8; 16],
}

static mut RAW_SOCKS: [RawSock; RAW_SOCK_MAX] = [RawSock {
    used: 0,
    slot: -1,
    rx_ready: 0,
    local6: [0u8; 16],
}; RAW_SOCK_MAX];

static mut RAW_HANDLE: [Option<SocketHandle>; RAW_SOCK_MAX] = [None; RAW_SOCK_MAX];

static mut RAW_RX_META: [[raw::PacketMetadata; 4]; RAW_SOCK_MAX] =
    [[raw::PacketMetadata::EMPTY; 4]; RAW_SOCK_MAX];
static mut RAW_RX_PAY: [[u8; RAW_RX_BUF]; RAW_SOCK_MAX] = [[0; RAW_RX_BUF]; RAW_SOCK_MAX];
static mut RAW_TX_META: [[raw::PacketMetadata; 4]; RAW_SOCK_MAX] =
    [[raw::PacketMetadata::EMPTY; 4]; RAW_SOCK_MAX];
static mut RAW_TX_PAY: [[u8; RAW_TX_BUF]; RAW_SOCK_MAX] = [[0; RAW_TX_BUF]; RAW_SOCK_MAX];

/// Reserve a raw socket slot.  Returns its index, or -1 (stack down / no room).
pub fn raw_sock_alloc() -> i32 {
    if !stack::stack_ready() {
        return -1;
    }
    stack::with_stack_lock(|| {
        for i in 0..RAW_SOCK_MAX {
            if ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[i].used != 0 {
                continue;
            }
            ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[i] = RawSock {
                used: 1,
                slot: -1,
                rx_ready: 0,
                local6: [0u8; 16],
            };
            ptr::as_mut(core::ptr::addr_of_mut!(RAW_HANDLE))[i] = None;
            return i as i32;
        }
        -1
    })
}

/// Release raw socket `idx` (removes it from its interface and clears the slot).
pub fn raw_sock_free(idx: i32) {
    if idx < 0 || idx as usize >= RAW_SOCK_MAX {
        return;
    }
    let i = idx as usize;
    // Take the handle before clearing it, so the smoltcp socket can be removed
    // from the interface it lived on.
    let (slot, handle) = stack::with_stack_lock(|| {
        let s = ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[i].slot;
        let h = ptr::as_ref(core::ptr::addr_of!(RAW_HANDLE))[i];
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_HANDLE))[i] = None;
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[i] = RawSock {
            used: 0,
            slot: -1,
            rx_ready: 0,
            local6: [0u8; 16],
        };
        (s, h)
    });
    if slot >= 0 {
        if let Some(h) = handle {
            let _ = stack::with_slot_socks(slot as usize, |socks| {
                let _ = socks.remove(h);
            });
        }
    }
}

/// Interface slot raw socket `idx` is placed on, or -1.
pub(crate) fn raw_sock_slot_of(idx: usize) -> i32 {
    if idx >= RAW_SOCK_MAX {
        return -1;
    }
    stack::with_stack_lock(|| ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[idx].slot)
}

/// Place raw socket `idx` on interface `slot`, building its smoltcp socket
/// there.  Idempotent.  Returns true when it ends up placed on `slot`.
fn ensure_raw_placed(idx: usize, slot: usize) -> bool {
    stack::with_slot_socks(slot, |socks| {
        let cur = ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[idx].slot;
        if cur >= 0 {
            return cur == slot as i32;
        }
        let rx_meta = ptr::slice_mut(ptr::as_mut(core::ptr::addr_of_mut!(RAW_RX_META))[idx].as_mut_ptr(), 4);
        let rx_pay = ptr::slice_mut(ptr::as_mut(core::ptr::addr_of_mut!(RAW_RX_PAY))[idx].as_mut_ptr(), RAW_RX_BUF);
        let rx = raw::PacketBuffer::new(rx_meta, rx_pay);
        let tx_meta = ptr::slice_mut(ptr::as_mut(core::ptr::addr_of_mut!(RAW_TX_META))[idx].as_mut_ptr(), 4);
        let tx_pay = ptr::slice_mut(ptr::as_mut(core::ptr::addr_of_mut!(RAW_TX_PAY))[idx].as_mut_ptr(), RAW_TX_BUF);
        let tx = raw::PacketBuffer::new(tx_meta, tx_pay);
        // Only ICMPv6 is exposed (that is what SLAAC/NDP speak).
        let sock = raw::Socket::new(IpVersion::Ipv6, IpProtocol::Icmpv6, rx, tx);
        let h = socks.add(sock);
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_HANDLE))[idx] = Some(h);
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[idx].slot = slot as i32;
        true
    })
    .unwrap_or(false)
}

/// `bind()` for a raw socket: pin the local address and place the socket on the
/// interface that owns it.  An all-zero address leaves the interface to be
/// chosen by the first send.
pub(crate) fn raw_sock_bind6(idx: usize, addr: [u8; 16]) -> i32 {
    if idx >= RAW_SOCK_MAX {
        return -1;
    }
    let r = stack::with_stack_lock(|| {
        if ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[idx].used == 0 {
            return -1;
        }
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[idx].local6 = addr;
        0
    });
    if r != 0 {
        return r;
    }
    if addr != [0u8; 16] {
        if let Some(slot) = crate::config::slot_owning_ipv6(addr) {
            let _ = ensure_raw_placed(idx, slot);
        }
    }
    0
}

/// Fresh readiness for `poll()`: 1 when an ICMPv6 message is queued.
pub fn raw_sock_ready(idx: i32) -> i32 {
    if idx < 0 || idx as usize >= RAW_SOCK_MAX {
        return 0;
    }
    let i = idx as usize;
    let slot = raw_sock_slot_of(i);
    if slot < 0 {
        return 0;
    }
    let r = stack::with_slot_socks(slot as usize, |socks| {
        let Some(h) = ptr::as_ref(core::ptr::addr_of!(RAW_HANDLE))[i] else {
            return 0;
        };
        let s = socks.get_mut::<raw::Socket>(h);
        if s.can_recv() {
            1
        } else {
            0
        }
    });
    r.unwrap_or(0)
}

/// Refresh the readiness flag of every raw socket placed on `slot`.  Called from
/// `stack_poll` under `STACK_LOCK`.
pub fn sync_raw_from_smoltcp(slot: usize, socks: &mut SocketSet<'static>) {
    for idx in 0..RAW_SOCK_MAX {
        let row = ptr::as_ref(core::ptr::addr_of!(RAW_SOCKS))[idx];
        if row.used == 0 || row.slot != slot as i32 {
            continue;
        }
        let Some(h) = ptr::as_ref(core::ptr::addr_of!(RAW_HANDLE))[idx] else {
            continue;
        };
        let s = socks.get_mut::<raw::Socket>(h);
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[idx].rx_ready = if s.can_recv() { 1 } else { 0 };
    }
}

/// # Safety
///
/// The caller must be tearing the stack down while holding `STACK_LOCK` with
/// `STACK_READY` cleared, so no other user of these statics can be running.
pub(crate) fn reset_raw_smoltcp_state() {
    *ptr::as_mut(core::ptr::addr_of_mut!(RAW_HANDLE)) = [None; RAW_SOCK_MAX];
    *ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS)) =
        [RawSock { used: 0, slot: -1, rx_ready: 0, local6: [0u8; 16] }; RAW_SOCK_MAX];
}

/// Choose the source address for a raw IPv6 packet to `dst`: the link-local for
/// a link-local or multicast destination (or when no global address is set), the
/// global address otherwise.
fn raw_source6(slot: usize, dst: [u8; 16]) -> [u8; 16] {
    let is_multicast = dst[0] == 0xff;
    let is_link_local = dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80;
    if is_multicast || is_link_local || !crate::config::ipv6_configured_of(slot) {
        crate::config::ipv6_link_local_of(slot)
    } else {
        crate::config::ipv6_addr_of(slot)
    }
}

/// The ICMPv6 checksum (RFC 8200 pseudo-header + message, one's complement).
fn icmpv6_checksum(src: [u8; 16], dst: [u8; 16], msg: &[u8]) -> u16 {
    fn fold(sum: u32) -> u16 {
        let mut s = sum;
        while (s >> 16) != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
    let mut sum: u32 = 0;
    for chunk in src.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | chunk[1] as u32;
    }
    for chunk in dst.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | chunk[1] as u32;
    }
    let len = msg.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += 58; // next header = ICMPv6
    let mut i = 0;
    while i + 1 < msg.len() {
        sum += ((msg[i] as u32) << 8) | msg[i + 1] as u32;
        i += 2;
    }
    if i < msg.len() {
        sum += (msg[i] as u32) << 8;
    }
    fold(sum)
}

/// Dequeue one ICMPv6 message, reporting its source (sixteen octets) — the v6
/// counterpart of `udp_sock_recv`.  Returns the message length, 0 when nothing
/// is queued, or -1 on a hard error.
///
/// `buf` may be null (then -1), else `max_len` writable bytes; `src_addr_out`
/// may be null, else 16 writable bytes.
pub fn raw_sock_recv6(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_addr_out: *mut u8,
) -> i32 {
    if idx < 0 || idx as usize >= RAW_SOCK_MAX || buf.is_null() {
        return -1;
    }
    let i = idx as usize;
    let slot = raw_sock_slot_of(i);
    if slot < 0 {
        return 0;
    }
    let r = stack::with_slot_socks(slot as usize, |socks| {
        let Some(h) = ptr::as_ref(core::ptr::addr_of!(RAW_HANDLE))[i] else {
            return -1;
        };
        let s = socks.get_mut::<raw::Socket>(h);
        let Ok(pkt) = s.recv() else {
            return 0;
        };
        // smoltcp's raw socket hands back the IPv6 header (40 bytes) followed by
        // the ICMPv6 message; strip the header and read the source from it.
        if pkt.len() < 40 {
            return 0;
        }
        let src = &pkt[8..24];
        let payload = &pkt[40..];
        let to_copy = core::cmp::min(payload.len(), max_len as usize);
        ptr::copy_nonoverlapping(payload.as_ptr(), buf, to_copy);
        if !src_addr_out.is_null() {
            ptr::copy_nonoverlapping(src.as_ptr(), src_addr_out, 16);
        }
        ptr::as_mut(core::ptr::addr_of_mut!(RAW_SOCKS))[i].rx_ready = if s.can_recv() { 1 } else { 0 };
        to_copy as i32
    });
    r.unwrap_or(-1)
}

/// Send one ICMPv6 message to `dst` (sixteen octets).  The kernel builds the
/// IPv6 header and the ICMPv6 checksum.  Returns the message length on success,
/// 0 when the TX buffer is momentarily full, or -1.
///
/// `dst` must point to 16 readable bytes; `data` must point to `len` readable
/// bytes.
pub fn raw_sock_send6(
    idx: i32,
    dst: *const u8,
    data: *const u8,
    len: u16,
) -> i32 {
    if idx < 0 || idx as usize >= RAW_SOCK_MAX || dst.is_null() || data.is_null() {
        return -1;
    }
    let i = idx as usize;
    let mut d6 = [0u8; 16];
    ptr::copy_nonoverlapping(dst, d6.as_mut_ptr(), 16);
    let slot = match raw_sock_slot_of(i) {
        s if s >= 0 => s as usize,
        _ => {
            let s = crate::config::route_slot_v6(d6);
            if !ensure_raw_placed(i, s) {
                return -1;
            }
            s
        }
    };
    let src = raw_source6(slot, d6);
    let msg_len = len as usize;
    if 40 + msg_len > RAW_TX_BUF {
        return -1;
    }
    let r = stack::with_slot_socks(slot, |socks| {
        let Some(h) = ptr::as_ref(core::ptr::addr_of!(RAW_HANDLE))[i] else {
            return -1;
        };
        let s = socks.get_mut::<raw::Socket>(h);
        // Build [IPv6 header][ICMPv6 message] in the socket's TX buffer.
        let total = 40 + msg_len;
        let buf = match s.send(total) {
            Ok(b) => b,
            Err(_) => return 0,
        };
        for b in buf.iter_mut() {
            *b = 0;
        }
        buf[0] = 0x60; // version 6, traffic class 0, flow label 0
        let plen = msg_len as u16;
        buf[4] = (plen >> 8) as u8;
        buf[5] = plen as u8;
        buf[6] = 58; // next header = ICMPv6
        buf[7] = 255; // hop limit (ND requires 255)
        buf[8..24].copy_from_slice(&src);
        buf[24..40].copy_from_slice(&d6);
        let msg = ptr::slice(data, msg_len);
        buf[40..40 + msg_len].copy_from_slice(msg);
        // Compute the ICMPv6 checksum over the pseudo-header and store it at
        // the ICMPv6 checksum field (offset 2 of the message).
        if msg_len >= 4 {
            buf[40 + 2] = 0;
            buf[40 + 3] = 0;
            let ck = icmpv6_checksum(src, d6, &buf[40..40 + msg_len]);
            buf[40 + 2] = (ck >> 8) as u8;
            buf[40 + 3] = ck as u8;
        }
        msg_len as i32
    });
    r.unwrap_or(-1)
}
