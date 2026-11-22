// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! UDP sockets implemented on top of smoltcp.
//!
//! A UDP socket is built lazily: `udp_sock_alloc` only reserves the C slot, and
//! the smoltcp socket is created (in one interface slot's `SocketSet`) the first
//! time the socket is used — `connect()`/`send()` route by destination, or a
//! `bind()`ed local address pins the interface.  A socket is placed once and then
//! stays on that interface (like Linux's per-route socket binding); one socket
//! does not float between interfaces.

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use crate::stack::{self};
use crate::types::{UdpSock, UDP_SOCK_MAX};

#[no_mangle]
pub static mut udp_socks: [UdpSock; UDP_SOCK_MAX] = [UdpSock {
    used: 0,
    local_port: 0,
    local_ip: 0,
    rx_buf: [0; crate::types::UDP_RX_BUF_SIZE],
    rx_len: 0,
    rx_ready: 0,
    last_src_ip: 0,
    last_src_port: 0,
}; UDP_SOCK_MAX];

static mut UDP_RX_META: [[udp::PacketMetadata; 4]; UDP_SOCK_MAX] =
    [[udp::PacketMetadata::EMPTY; 4]; UDP_SOCK_MAX];
static mut UDP_RX_PAY: [[u8; 2048]; UDP_SOCK_MAX] = [[0; 2048]; UDP_SOCK_MAX];
static mut UDP_TX_META: [[udp::PacketMetadata; 4]; UDP_SOCK_MAX] =
    [[udp::PacketMetadata::EMPTY; 4]; UDP_SOCK_MAX];
static mut UDP_TX_PAY: [[u8; 2048]; UDP_SOCK_MAX] = [[0; 2048]; UDP_SOCK_MAX];
static mut UDP_HANDLE: [Option<SocketHandle>; UDP_SOCK_MAX] = [None; UDP_SOCK_MAX];

/// Interface slot each UDP socket is placed on, or -1 before it is placed.
/// Rust-private (not part of the C `udp_sock_t` mirror); guarded by `STACK_LOCK`.
static mut UDP_SLOT: [i32; UDP_SOCK_MAX] = [-1; UDP_SOCK_MAX];

/// Next local port to hand to a socket that was never bind()ed.
static mut NEXT_EPHEMERAL: u16 = 49152;

/// Peer recorded by `connect()` on a datagram socket; (0, 0) = unconnected.
/// Kept out of `UdpSock`/`Ksock` on purpose: those are C-visible mirrors, and
/// the peer is private to this crate.
static mut UDP_PEER: [(u32, u16); UDP_SOCK_MAX] = [(0, 0); UDP_SOCK_MAX];

/// Interface slot UDP socket `idx` is placed on, or -1 if not placed yet.
pub(crate) fn udp_slot_of(idx: usize) -> i32 {
    if idx >= UDP_SOCK_MAX {
        return -1;
    }
    // SAFETY: `UDP_SLOT` is a kernel-lifetime `static mut` guarded by `STACK_LOCK`,
    // which `with_stack_lock` holds; `idx` is bounds-checked above.
    stack::with_stack_lock(|| unsafe { UDP_SLOT[idx] })
}

/// Interface slot that should carry UDP socket `idx`'s traffic to `dst_ip`.
///
/// A local address pinned by `bind()` wins (its owner interface), otherwise the
/// destination is routed (`route_slot`).
fn pick_slot(idx: usize, dst_ip: u32) -> usize {
    // SAFETY: `udp_socks` is guarded by `STACK_LOCK`, held by `with_stack_lock`;
    // `idx` is in range (callers bounds-check it).
    let bound = stack::with_stack_lock(|| unsafe { udp_socks[idx].local_ip });
    if bound != 0 {
        if let Some(slot) = crate::config::slot_owning_ip(bound) {
            return slot;
        }
    }
    crate::config::route_slot(dst_ip)
}

/// Place UDP socket `idx` on interface `slot`, building its smoltcp socket there.
/// Idempotent: a socket already placed stays wherever it is.  Returns true when it
/// is placed on `slot`.
fn ensure_placed(idx: usize, slot: usize) -> bool {
    let r = stack::with_slot_socks(slot, |socks| {
        // SAFETY: `with_slot_socks` holds `STACK_LOCK`, which guards `UDP_SLOT`/
        // `UDP_HANDLE`, and `idx` is in range.
        let cur = unsafe { UDP_SLOT[idx] };
        if cur >= 0 {
            return cur == slot as i32;
        }
        // SAFETY: `UDP_RX_META[idx]` is a kernel-lifetime packet-metadata static
        // owned by this socket, handed to smoltcp only through this one socket,
        // under the stack lock.
        let rx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(UDP_RX_META))[idx])[..] };
        // SAFETY: as above, for `UDP_RX_PAY`.
        let rx_pay = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(UDP_RX_PAY))[idx])[..] };
        let rx = udp::PacketBuffer::new(rx_meta, rx_pay);
        // SAFETY: as above, for `UDP_TX_META`.
        let tx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(UDP_TX_META))[idx])[..] };
        // SAFETY: as above, for `UDP_TX_PAY`.
        let tx_pay = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(UDP_TX_PAY))[idx])[..] };
        let tx = udp::PacketBuffer::new(tx_meta, tx_pay);
        let u = udp::Socket::new(rx, tx);
        let h = socks.add(u);
        // SAFETY: written under the stack lock, as every access to these tables is.
        unsafe { UDP_HANDLE[idx] = Some(h) };
        // SAFETY: as above.
        unsafe { UDP_SLOT[idx] = slot as i32 };
        true
    });
    r.unwrap_or(false)
}

/// Pick a local port not already held by another UDP socket.
/// # Safety
///
/// The caller must be the only user of the UDP tables — running under the stack
/// lock, or in `stack_teardown` with `STACK_READY` cleared — because this reads
/// and advances the shared `NEXT_EPHEMERAL` counter and scans `udp_socks`.
unsafe fn pick_ephemeral() -> u16 {
    for _ in 0..(65535 - 49152 + 1) {
        // SAFETY: the caller contract (see # Safety) excludes any concurrent
        // access to the UDP statics, and `NEXT_EPHEMERAL` is a plain `u16`, so
        // this read cannot race.
        let p = unsafe { NEXT_EPHEMERAL };
        let next = if p == u16::MAX { 49152 } else { p + 1 };
        // SAFETY: the advance happens under the caller's exclusive access.
        unsafe { NEXT_EPHEMERAL = next };
        let mut taken = false;
        // SAFETY: `udp_socks` is the kernel-lifetime slot array and the caller
        // contract makes this borrow exclusive; the scan walks only the
        // fixed-length inline array.
        for s in (unsafe { &mut *core::ptr::addr_of_mut!(udp_socks) }).iter_mut() {
            if s.used != 0 && s.local_port == p {
                taken = true;
                break;
            }
        }
        if !taken {
            return p;
        }
    }
    0
}

/// # Safety
///
/// The caller must be tearing the stack down (`stack_teardown`) while holding
/// `STACK_LOCK`, with `STACK_READY` already cleared, so no other CPU or task can
/// be using the UDP slots or their smoltcp sockets.
pub(crate) unsafe fn reset_udp_smoltcp_state() {
    // SAFETY: the caller contract (see # Safety) excludes every other user of
    // these statics for the duration of the call, so the writes below are the
    // only ones in flight.
    unsafe { UDP_HANDLE = [None; UDP_SOCK_MAX] };
    // SAFETY: as above.
    unsafe { UDP_SLOT = [-1; UDP_SOCK_MAX] };
    // SAFETY: as above.
    unsafe { NEXT_EPHEMERAL = 49152 };
    // SAFETY: as above.
    unsafe { UDP_PEER = [(0, 0); UDP_SOCK_MAX] };
    // SAFETY: as above; the borrow ends when this function returns.
    let udp = unsafe { &mut *core::ptr::addr_of_mut!(udp_socks) };
    {
        for s in udp.iter_mut() {
            *s = UdpSock {
                used: 0,
                local_port: 0,
                local_ip: 0,
                rx_buf: [0; crate::types::UDP_RX_BUF_SIZE],
                rx_len: 0,
                rx_ready: 0,
                last_src_ip: 0,
                last_src_port: 0,
            };
        }
    }
}

fn ensure_udp_bound(idx: usize, socks: &mut SocketSet<'static>) {
    // SAFETY: `idx < UDP_SOCK_MAX` is required by every caller (each one
    // bounds-checks its slot index first), so `UDP_HANDLE[idx]` is in bounds; all
    // accesses run under the stack lock, so no other task can be mutating the
    // slot at the same time.
    let Some(h) = (unsafe { UDP_HANDLE[idx] }) else {
        return;
    };
    // SAFETY: as `UDP_HANDLE[idx]` above — `idx` is in bounds and the slot is
    // only mutated under the stack lock this call holds.
    let port = unsafe { udp_socks[idx].local_port };
    if port == 0 {
        return;
    }
    let s = socks.get_mut::<udp::Socket>(h);
    if s.is_open() {
        return;
    }
    // A bind() may name a local address as well as a port (host order, 0 =
    // INADDR_ANY).  Honour it: without the address the socket answers on
    // whatever address the packet arrived on, which is not what bind(2)
    // promises.
    // SAFETY: as above, for the slot's local-address field.
    let local = unsafe { udp_socks[idx].local_ip };
    let ep = IpListenEndpoint {
        addr: if local != 0 {
            Some(IpAddress::Ipv4(crate::stack::ipv4_from_host(local)))
        } else {
            None
        },
        port,
    };
    let _ = s.bind(ep);
}

pub fn sync_udp_pcbs_from_smoltcp(slot: usize, socks: &mut SocketSet<'static>) {
    // Called from `stack_poll` under `STACK_LOCK`; only the sockets placed on
    // `slot` are synced (the others live in other slots' sets or are unplaced).
    for idx in 0..UDP_SOCK_MAX {
        // SAFETY: called under `STACK_LOCK`, the same lock every other user of
        // `udp_socks`/`UDP_SLOT`/`UDP_HANDLE` takes, and `idx` is bounded by
        // `UDP_SOCK_MAX`, so these reads are in bounds and uncontented.
        if unsafe { udp_socks[idx].used } == 0 {
            continue;
        }
        // SAFETY: as above, for the slot table.
        if unsafe { UDP_SLOT[idx] } != slot as i32 {
            continue;
        }
        ensure_udp_bound(idx, socks);
        // SAFETY: as above, for the handle table.
        let Some(h) = (unsafe { UDP_HANDLE[idx] }) else {
            continue;
        };
        let s = socks.get_mut::<udp::Socket>(h);
        // SAFETY: as above, for the slot's readiness flag.
        unsafe { udp_socks[idx].rx_ready = if s.can_recv() { 1 } else { 0 } };
    }
}

#[no_mangle]
pub extern "C" fn udp_sock_alloc() -> i32 {
    // SAFETY: `STACK_READY` is a `static mut bool` written by `stack_init`/
    // `stack_teardown`; a byte load cannot tear, and reading it as false makes
    // this call fail closed.
    if !unsafe { stack::STACK_READY } {
        return -1;
    }
    // The smoltcp socket is not built here: the interface is not known until the
    // socket is bound/connected/sent on.  Reserve the C slot and the metadata.
    stack::with_stack_lock(|| {
        for i in 0..UDP_SOCK_MAX {
            // SAFETY: `i` is in bounds, so this slot read is in bounds and
            // uncontented under the stack lock.
            if unsafe { udp_socks[i].used } != 0 {
                continue;
            }
            // SAFETY: `i` is in bounds and the stack lock is held.
            unsafe {
                let slot = &mut udp_socks[i];
                slot.used = 1;
                slot.local_port = 0;
                slot.local_ip = 0;
                slot.rx_ready = 0;
                slot.rx_len = 0;
            }
            // SAFETY: as above, for the metadata tables.
            unsafe { UDP_HANDLE[i] = None };
            // SAFETY: as above.
            unsafe { UDP_SLOT[i] = -1 };
            // SAFETY: as above.
            unsafe { UDP_PEER[i] = (0, 0) };
            return i as i32;
        }
        -1
    })
}

#[no_mangle]
pub extern "C" fn udp_sock_free(idx: i32) {
    if idx < 0 || idx as usize >= UDP_SOCK_MAX {
        return;
    }
    let i = idx as usize;
    // SAFETY: `i` is bounds-checked above; the reads are guarded by `STACK_LOCK`
    // (`with_stack_lock`), as every access to these tables is.
    let (slot, handle) = stack::with_stack_lock(|| unsafe { (UDP_SLOT[i], UDP_HANDLE[i]) });
    if let Some(h) = handle {
        if slot >= 0 {
            let _ = stack::with_slot_socks(slot as usize, |socks| {
                let _ = socks.remove(h);
            });
        }
    }
    // SAFETY: `i` is bounds-checked above and the stack lock is held; a slot is
    // only ever freed by the task that owns its file description, so there is no
    // concurrent mutation of this row.
    stack::with_stack_lock(|| unsafe {
        UDP_HANDLE[i] = None;
        UDP_SLOT[i] = -1;
        UDP_PEER[i] = (0, 0);
        udp_socks[i].used = 0;
    });
}

/// `connect()` on a datagram socket.  UDP is connectionless, so this only records
/// the peer (validated here) and pins the socket to the interface that will carry
/// it; `write()` afterwards sends one datagram to the peer, and reads are still
/// accepted from anyone.
#[no_mangle]
pub extern "C" fn udp_sock_connect(idx: i32, dst_ip: u32, dst_port: u16) -> i32 {
    if idx < 0 || idx as usize >= UDP_SOCK_MAX || dst_ip == 0 || dst_port == 0 {
        return -1;
    }
    let i = idx as usize;
    // SAFETY: `i` is bounds-checked above; the read is guarded by `STACK_LOCK`.
    if stack::with_stack_lock(|| unsafe { udp_socks[i].used }) == 0 {
        return -1;
    }
    let slot = pick_slot(i, dst_ip);
    if !ensure_placed(i, slot) {
        return -1;
    }
    // SAFETY: `i` is bounds-checked above; the write is guarded by `STACK_LOCK`.
    stack::with_stack_lock(|| unsafe { UDP_PEER[i] = (dst_ip, dst_port) });
    0
}

/// Peer recorded by [`udp_sock_connect`], or (0, 0) when unconnected.
pub(crate) fn udp_sock_peer(idx: i32) -> (u32, u16) {
    if idx < 0 || idx as usize >= UDP_SOCK_MAX {
        return (0, 0);
    }
    // SAFETY: `idx` is bounds-checked above, so the `UDP_PEER` read is in
    // bounds; the element is a plain `(u32, u16)` so the read cannot tear.
    unsafe { UDP_PEER[idx as usize] }
}

/// True when a datagram would find room in this socket's TX buffer right now —
/// the honest POLLOUT predicate for `sendto`/`write`, matching `tcp_can_send`.
pub(crate) fn udp_can_send(idx: usize) -> bool {
    if idx >= UDP_SOCK_MAX {
        return false;
    }
    let slot = udp_slot_of(idx);
    if slot < 0 {
        // Unplaced (never used): an unbound socket is not writable, as before.
        return false;
    }
    let r = stack::with_slot_socks(slot as usize, |socks| {
        // SAFETY: `idx < UDP_SOCK_MAX` is checked above, so `UDP_HANDLE[idx]` is
        // in bounds; the handle is an `Option<SocketHandle>` (Copy), so the read
        // cannot tear, and the socket is resolved through this closure's own
        // `SocketSet` under the stack lock.
        unsafe {
            let Some(h) = UDP_HANDLE[idx] else {
                return false;
            };
            socks.get_mut::<udp::Socket>(h).can_send()
        }
    });
    r.unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn udp_sock_find_by_port(port: u16) -> *mut UdpSock {
    // SAFETY: the scan walks only the fixed-length inline array `udp_socks`, so
    // it stays in bounds; the returned pointer refers to a kernel-lifetime
    // static that the caller only uses until the slot is freed.
    unsafe {
        for s in (*core::ptr::addr_of_mut!(udp_socks)).iter_mut() {
            if s.used != 0 && s.local_port == port {
                return s as *mut UdpSock;
            }
        }
    }
    core::ptr::null_mut()
}

/// `recv()` reported no datagram queued (nothing to read right now).  Distinct
/// from a queued zero-length datagram, which must be delivered as a read of 0
/// bytes rather than reported as "nothing yet".  Negative so it can never be
/// confused with a byte count (0 is a legal empty datagram).
pub(crate) const EAGAIN: i32 = -11;

/// Dequeue one datagram, distinguishing "nothing queued" from "a zero-length
/// datagram was queued".
///
/// Returns `-1` on a hard error, `EAGAIN` when no datagram is waiting, or the
/// number of bytes copied (which may be 0 for a legal zero-length datagram).
///
/// # Safety
///
/// `buf` may be null (the call then returns -1), but if non-null it must point
/// to `max_len` writable bytes that stay live for the call.  `src_ip_out` and
/// `src_port_out` may be null (that part of the result is dropped) but, if
/// non-null, must point to a writable, aligned `u32`/`u16` respectively.
pub(crate) unsafe fn udp_recv_buf(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_ip_out: *mut u32,
    src_port_out: *mut u16,
) -> i32 {
    if idx < 0 || idx as usize >= UDP_SOCK_MAX || buf.is_null() {
        return -1;
    }
    let i = idx as usize;
    let slot = udp_slot_of(i);
    if slot < 0 {
        // Unplaced: nothing has been sent on it, so nothing can be queued.
        return EAGAIN;
    }
    let r = stack::with_slot_socks(slot as usize, |socks| {
        // `with_slot_socks` holds `STACK_LOCK` for the whole closure, so no
        // other path can touch `udp_socks`/`UDP_HANDLE`/this socket, and `i` is
        // bounds-checked above.
        {
            ensure_udp_bound(i, socks);
            // SAFETY: `UDP_HANDLE[i]` is read under the stack lock this closure
            // holds, and `i` is in bounds.
            let Some(h) = (unsafe { UDP_HANDLE[i] }) else {
                return -1;
            };
            let s = socks.get_mut::<udp::Socket>(h);
            let Ok((data, meta)) = s.recv() else {
                return EAGAIN;
            };
            let to_copy = core::cmp::min(data.len(), max_len as usize);
            // SAFETY: the caller contract (see # Safety) makes `buf` a
            // `max_len`-byte buffer, and `to_copy` is clamped to `max_len`, so the
            // copy stays inside it; `data` is the received payload.
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), buf, to_copy) };
            let ep = meta.endpoint;
            if !src_ip_out.is_null() {
                // Only IPv4 datagrams exist at this stage; a v6 source has no
                // 32-bit output slot (the C mirror is v4-only) and is left 0.
                if let IpAddress::Ipv4(a) = ep.addr {
                    let o = a.octets();
                    // SAFETY: the caller contract makes `src_ip_out`, when
                    // non-null, a writable, aligned `u32`; the null check above
                    // excluded null.
                    unsafe {
                        *src_ip_out = u32::from(o[0]) << 24
                            | u32::from(o[1]) << 16
                            | u32::from(o[2]) << 8
                            | u32::from(o[3]);
                    }
                }
            }
            if !src_port_out.is_null() {
                // SAFETY: as above, for `src_port_out`.
                unsafe { *src_port_out = ep.port };
            }
            // SAFETY: the slot's readiness flag is only written under the stack
            // lock this closure holds.
            unsafe { udp_socks[i].rx_ready = if s.can_recv() { 1 } else { 0 } };
            to_copy as i32
        }
    });
    r.unwrap_or(-1)
}

/// C-ABI `recv()` for datagram sockets.  Keeps the long-standing contract that
/// "nothing queued" is reported as 0 (Cact-dhcpd's `recvfrom <= 0 → sleep(1)`
/// loop depends on it); the crate-internal path uses [`udp_recv_buf`] to tell
/// that apart from a zero-length datagram.
///
/// # Safety
///
/// As [`udp_recv_buf`].
#[no_mangle]
pub unsafe extern "C" fn udp_sock_recv(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_ip_out: *mut u32,
    src_port_out: *mut u16,
) -> i32 {
    // SAFETY: the caller contract is forwarded verbatim to `udp_recv_buf`.
    let r = unsafe { udp_recv_buf(idx, buf, max_len, src_ip_out, src_port_out) };
    if r == EAGAIN {
        0
    } else {
        r
    }
}

/// Send one datagram.
///
/// # Safety
///
/// `data` may be null (the call then returns -1), but if non-null it must point
/// to `len` readable bytes that stay live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn udp_sock_send(
    idx: i32,
    dst_ip: u32,
    dst_port: u16,
    data: *const u8,
    len: u16,
) -> i32 {
    if idx < 0 || idx as usize >= UDP_SOCK_MAX || data.is_null() {
        return -1;
    }
    let i = idx as usize;
    // Place the socket on the interface that will carry this datagram (idempotent:
    // an already-placed socket keeps its interface).
    let slot = pick_slot(i, dst_ip);
    if !ensure_placed(i, slot) {
        return -1;
    }
    let r = stack::with_slot_socks(slot, |socks| {
        // `with_slot_socks` holds `STACK_LOCK` for the whole closure, so the
        // `udp_socks`/`UDP_HANDLE` accesses and `pick_ephemeral` are serialized
        // against every other UDP path, and `i` is bounds-checked above.
        {
            // SAFETY: `i` is in bounds and the closure holds the stack lock, so
            // this slot read is in bounds and uncontented.
            if unsafe { udp_socks[i].used } == 0 {
                return -1;
            }
            // smoltcp refuses to transmit from a socket whose local port is still 0
            // (SendError::Unaddressable), so an unbound socket gets an ephemeral
            // port here — at first send, not earlier: an explicit bind() must win,
            // and sync_udp_pcbs_from_smoltcp runs long before the app can bind().
            // SAFETY: as above, for the slot's local-port field.
            if unsafe { udp_socks[i].local_port } == 0 {
                // SAFETY: `pick_ephemeral` needs its caller to be the only user of
                // the UDP tables, which is this closure under the stack lock.
                let p = unsafe { pick_ephemeral() };
                if p == 0 {
                    return -1;
                }
                // SAFETY: as above, for the slot's local-port field.
                unsafe { udp_socks[i].local_port = p };
            }
            ensure_udp_bound(i, socks);
            // SAFETY: as above, for the handle table.
            let Some(h) = (unsafe { UDP_HANDLE[i] }) else {
                return -1;
            };
            let s = socks.get_mut::<udp::Socket>(h);
            // SAFETY: the caller contract (see # Safety) makes `data` a `len`-byte
            // readable buffer, which is what `from_raw_parts` asserts.
            let slice = unsafe { core::slice::from_raw_parts(data, len as usize) };
            let dst_a = core::net::Ipv4Addr::from_bits(dst_ip);
            // A datagram bigger than the socket's payload capacity can never be
            // queued, so that is a hard error rather than "retry later".
            if len as usize > s.payload_send_capacity() {
                return -1;
            }
            let mut meta = udp::UdpMetadata::from((dst_a, dst_port));
            // Pin the IPv4 source explicitly where smoltcp's default (the first
            // interface address) would be wrong:
            //  * a 127/8 peer must be sourced from 127.0.0.1 (the interface also
            //    carries the configured NIC address, which is what smoltcp would
            //    otherwise pick);
            //  * a DHCP client broadcasts its DISCOVER before it has an address,
            //    and with no configured address smoltcp still picks the always
            //    present 127.0.0.1 instead of 0.0.0.0 — which the network would
            //    drop, silently, while `sendto` reports success ("no offer
            //    received").
            if crate::stack::is_loopback_ipv4_host(dst_ip) {
                meta.local_address = Some(IpAddress::Ipv4(core::net::Ipv4Addr::new(127, 0, 0, 1)));
            } else if dst_ip == u32::MAX && crate::stack::slot_unconfigured(slot) {
                meta.local_address = Some(IpAddress::Ipv4(core::net::Ipv4Addr::UNSPECIFIED));
            }
            match s.send_slice(slice, meta) {
                Ok(()) => len as i32,
                // Transient: the TX buffer still holds other datagrams.  0 means
                // "nothing queued, retry after POLLOUT" (same convention as
                // tcp_send); CACT_SOCKCTL_SENDTO turns it into -EAGAIN.
                Err(udp::SendError::BufferFull) => 0,
                Err(_) => -1,
            }
        }
    });
    r.unwrap_or(-1)
}

/// Fresh readiness for `poll()`: `(datagram waiting, slot unusable)`.
///
/// `can_recv()` is whether a datagram is queued — the honest POLLIN predicate.
pub(crate) fn udp_poll_status(idx: usize) -> (bool, bool) {
    if idx >= UDP_SOCK_MAX {
        return (false, true);
    }
    let slot = udp_slot_of(idx);
    if slot < 0 {
        // Unplaced (never used): not readable, and not an error.
        return (false, false);
    }
    let r = stack::with_slot_socks(slot as usize, |socks| {
        // SAFETY: `idx < UDP_SOCK_MAX` is checked above, so this slot read is in
        // bounds; it is plain Copy data whose read cannot tear, and the socket is
        // reached through this closure's own `SocketSet` under `STACK_LOCK`.
        if unsafe { udp_socks[idx].used } == 0 {
            return (false, true);
        }
        // SAFETY: as above, for the handle table.
        let Some(h) = (unsafe { UDP_HANDLE[idx] }) else {
            return (false, true);
        };
        (socks.get_mut::<udp::Socket>(h).can_recv(), false)
    });
    r.unwrap_or((false, true))
}
