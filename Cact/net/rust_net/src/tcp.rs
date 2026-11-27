// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! TCP sockets on smoltcp; keeps `tcp_sockets[]` aligned with the C ABI (state, accept, select).

use core::net::Ipv4Addr;

use kernel_rust::ptr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpAddress;

use crate::stack::{self};
use crate::types::*;

fn ipv4_u32(a: Ipv4Addr) -> u32 {
    let o = a.octets();
    u32::from(o[0]) << 24 | u32::from(o[1]) << 16 | u32::from(o[2]) << 8 | u32::from(o[3])
}

/// IPv4 bits of an endpoint address for the 32-bit C mirrors (`tcp_sockets`,
/// `TcpSocket`).  An IPv6 endpoint has no value there and reports 0.0.0.0.
fn addr_v4_bits(a: IpAddress) -> u32 {
    match a {
        IpAddress::Ipv4(v4) => ipv4_u32(v4),
        _ => 0,
    }
}

/// IPv6 local address pinned by `bind()` on a v6 socket (big-endian octets);
/// all-zero = unspecified.  Kept beside the C mirror's v4 `local_ip`.  Guarded
/// by `tcp_lock`.
static mut TCP_LOCAL6: [[u8; 16]; TCP_MAX_SOCKETS] = [[0u8; 16]; TCP_MAX_SOCKETS];

/// The v6 address `bind()`-pinned on TCP slot `idx` (all-zero = unspecified).
pub(crate) fn tcp_local6_of(idx: usize) -> [u8; 16] {
    if idx >= TCP_MAX_SOCKETS {
        return [0u8; 16];
    }
    tcp_lock();
    let v = ptr::as_ref(core::ptr::addr_of!(TCP_LOCAL6))[idx];
    tcp_unlock();
    v
}

/// Pin TCP slot `idx`'s v6 local address (`bind()`); guarded by `tcp_lock`.
pub(crate) fn tcp_set_local6(idx: usize, addr: [u8; 16]) {
    if idx >= TCP_MAX_SOCKETS {
        return;
    }
    tcp_lock();
    ptr::as_mut(core::ptr::addr_of_mut!(TCP_LOCAL6))[idx] = addr;
    tcp_unlock();
}

pub(crate) fn tcp_lock() {
    TCP_LOCK.lock();
}

pub(crate) fn tcp_unlock() {
    TCP_LOCK.unlock();
}

static TCP_LOCK: cact_sync::IrqLock = cact_sync::IrqLock::new();

/// Pointer to TCP slot `idx`'s C-mirror row, for the C-side accessor
/// (`kernel_abi::rust_net_tcp_socket`).  Null when `idx` is out of range.
pub fn tcp_socket_ptr(idx: u32) -> *mut core::ffi::c_void {
    if idx as usize >= TCP_MAX_SOCKETS {
        return core::ptr::null_mut();
    }
    // `idx` is bounds-checked above; this takes the address of a row of the
    // kernel-lifetime table.
    let row: &mut TcpSocket = &mut ptr::as_mut(core::ptr::addr_of_mut!(tcp_sockets))[idx as usize];
    row as *mut TcpSocket as *mut core::ffi::c_void
}

#[allow(non_upper_case_globals)]
pub static mut tcp_sockets: [TcpSocket; TCP_MAX_SOCKETS] = [TcpSocket {
    used: 0,
    state: TCP_CLOSED,
    local_ip: 0,
    local_port: 0,
    remote_ip: 0,
    remote_port: 0,
    snd_una: 0,
    snd_nxt: 0,
    snd_wnd: 0,
    rcv_nxt: 0,
    rcv_wnd: TCP_RX_BUF_SIZE as u32,
    rx_buf: [0; TCP_RX_BUF_SIZE],
    rx_head: 0,
    rx_tail: 0,
    on_data: core::ptr::null_mut(),
    on_event: core::ptr::null_mut(),
    listen_parent: -1,
    accept_ready: 0,
    nodelay: 0,
    keepalive: 0,
}; TCP_MAX_SOCKETS];

pub(crate) static mut TCP_RX_BUFS: [[u8; TCP_RX_BUF_SIZE]; TCP_MAX_SOCKETS] = [[0; TCP_RX_BUF_SIZE]; TCP_MAX_SOCKETS];
pub(crate) static mut TCP_TX_BUFS: [[u8; TCP_RX_BUF_SIZE]; TCP_MAX_SOCKETS] = [[0; TCP_RX_BUF_SIZE]; TCP_MAX_SOCKETS];
pub(crate) static mut TCP_HANDLE: [Option<SocketHandle>; TCP_MAX_SOCKETS] = [None; TCP_MAX_SOCKETS];

/// Interface slot each TCP socket lives on, or -1 before it has been placed.
/// Rust-private (not part of the C `tcp_socket_t` mirror): the smoltcp socket
/// backing slot `i` is in slot `TCP_SLOT[i]`'s `SocketSet`.  Guarded by `tcp_lock`
/// and reset wholesale by `reset_tcp_smoltcp_state`.
static mut TCP_SLOT: [i32; TCP_MAX_SOCKETS] = [-1; TCP_MAX_SOCKETS];

pub(crate) static mut NEXT_EPHEMERAL: u16 = 49152;

/// Interface slot TCP socket `idx` lives on, as an `i32` (-1 if unplaced).  Read
/// under `tcp_lock` so it cannot race a `connect`/`close` that moves the socket.
pub(crate) fn tcp_slot_of(idx: usize) -> i32 {
    if idx >= TCP_MAX_SOCKETS {
        return -1;
    }
    tcp_lock();
    let s = ptr::as_ref(core::ptr::addr_of!(TCP_SLOT))[idx];
    tcp_unlock();
    s
}

/// Pin TCP socket `idx` to interface slot `slot` (or -1 to unplace it).  Written
/// under `tcp_lock`, as every access to `TCP_SLOT` is.
pub(crate) fn tcp_set_slot(idx: usize, slot: i32) {
    if idx >= TCP_MAX_SOCKETS {
        return;
    }
    tcp_lock();
    ptr::as_mut(core::ptr::addr_of_mut!(TCP_SLOT))[idx] = slot;
    tcp_unlock();
}

/// Run `f` against the smoltcp TCP socket backing socket index `idx`, holding the
/// stack lock of the interface slot the socket lives on (so the poll thread cannot
/// race us on the socket) plus `tcp_lock` for the handle table.
pub(crate) fn with_tcp_socket<R>(idx: i32, f: impl FnOnce(&mut smoltcp::socket::tcp::Socket) -> R) -> Option<R> {
    if idx < 0 || idx as usize >= TCP_MAX_SOCKETS {
        return None;
    }
    let slot = tcp_slot_of(idx as usize);
    if slot < 0 {
        return None;
    }
    crate::stack::with_slot_socks(slot as usize, |socks| {
        tcp_lock();
        // SAFETY: the index is bounds-checked above (`idx < TCP_MAX_SOCKETS`), so
        // indexing the copied `TCP_HANDLE` array is in bounds; every read/write
        // of `TCP_HANDLE` and of the smoltcp `SocketSet` socket happens between
        // `tcp_lock`/`tcp_unlock` (interrupts off), which the poll thread also
        // takes, so no other context can mutate the handle or the socket
        // concurrently.
        let h = ptr::as_ref(core::ptr::addr_of!(TCP_HANDLE))[idx as usize];
        let r = h.map(|h| f(socks.get_mut::<smoltcp::socket::tcp::Socket>(h)));
        tcp_unlock();
        r
    })
    .flatten()
}

/// True when a `write()` on this socket would accept at least one byte right
/// now — the honest POLLOUT predicate (an ESTABLISHED socket whose TX buffer
/// or peer window is full is not writable).
pub(crate) fn tcp_can_send(idx: usize) -> bool {
    with_tcp_socket(idx as i32, |s| s.can_send()).unwrap_or(false)
}

/// Fresh readiness for `poll()`: `(byte buffered, inbound connection pending,
/// peer closed)`.
///
/// Queried from smoltcp rather than read out of the cached mirror so a
/// select()/poll() loop never acts on a state that is up to one poll period
/// old.  `None` means the slot has no smoltcp socket at all (closed or torn
/// down), which the caller reports as `POLLERR`.
///
/// `can_recv()` — not `may_recv()` — is the data predicate: `may_recv()` is
/// true for the whole life of an open connection, which made every established
/// socket look readable and turned select() loops into a spin.
pub(crate) fn tcp_poll_status(idx: usize) -> Option<(bool, bool, bool)> {
    if idx >= TCP_MAX_SOCKETS {
        return None;
    }
    tcp_lock();
    let (used, listen_parent, slot) = {
        let s = ptr::as_ref(core::ptr::addr_of!(tcp_sockets))[idx];
        let slot = ptr::as_ref(core::ptr::addr_of!(TCP_SLOT))[idx];
        (s.used, s.listen_parent, slot)
    };
    tcp_unlock();
    if used == 0 {
        return None;
    }
    if slot < 0 {
        // Created but not yet placed on an interface: behave like a CLOSED
        // socket (no data, but eof), as a fresh socket did when its smoltcp
        // socket was built eagerly.
        return Some((false, false, true));
    }
    with_tcp_socket(idx as i32, |s| {
        let st = s.state();
        let eof = matches!(
            st,
            tcp::State::CloseWait | tcp::State::Closed | tcp::State::TimeWait
        );
        // A pending inbound connection.  `listen_endpoint().port != 0` alone is
        // not enough: an accepted child keeps the endpoint it was listening on,
        // so it would keep claiming to be accept-ready.  Children are the slots
        // with a listen_parent, which is exactly what excludes them here.
        let accept = st == tcp::State::Established
            && s.listen_endpoint().port != 0
            && listen_parent < 0;
        (s.can_recv(), accept, eof)
    })
}

/// # Safety
///
/// The caller must be tearing the stack down (`stack_teardown`) while holding
/// `STACK_LOCK`, with `STACK_READY` already cleared, so no other CPU or task can
/// be touching the TCP slots or their smoltcp sockets.
pub(crate) fn reset_tcp_smoltcp_state() {
    *ptr::as_mut(core::ptr::addr_of_mut!(TCP_HANDLE)) = [None; TCP_MAX_SOCKETS];
    *ptr::as_mut(core::ptr::addr_of_mut!(TCP_SLOT)) = [-1; TCP_MAX_SOCKETS];
    ptr::write(core::ptr::addr_of_mut!(NEXT_EPHEMERAL), 49152);
    let sockets = ptr::as_mut(core::ptr::addr_of_mut!(tcp_sockets));
    {
        for s in sockets.iter_mut() {
            *s = TcpSocket {
                used: 0,
                state: TCP_CLOSED,
                local_ip: 0,
                local_port: 0,
                remote_ip: 0,
                remote_port: 0,
                snd_una: 0,
                snd_nxt: 0,
                snd_wnd: 0,
                rcv_nxt: 0,
                rcv_wnd: TCP_RX_BUF_SIZE as u32,
                rx_buf: [0; TCP_RX_BUF_SIZE],
                rx_head: 0,
                rx_tail: 0,
                on_data: core::ptr::null_mut(),
                on_event: core::ptr::null_mut(),
                listen_parent: -1,
                accept_ready: 0,
                nodelay: 0,
                keepalive: 0,
            };
        }
    }
}

pub fn sync_tcp_pcbs_from_smoltcp(slot: usize, socks: &mut SocketSet<'static>) {
    // This is called from `stack_poll`/`stack_teardown` while the slot's `STACK_LOCK`
    // is held, which is the same lock every other path takes before touching
    // `tcp_sockets`/`TCP_HANDLE`; `tcp_lock` additionally keeps the same accesses out
    // of syscall context on this CPU.  Only the sockets pinned to `slot` are synced:
    // the others live in other slots' sets.
    tcp_lock();
    for i in 0..TCP_MAX_SOCKETS {
        if ptr::as_ref(core::ptr::addr_of!(TCP_SLOT))[i] != slot as i32 {
            continue;
        }
        let row = &mut ptr::as_mut(core::ptr::addr_of_mut!(tcp_sockets))[i];
        if row.used == 0 {
            continue;
        }
        let Some(h) = ptr::as_ref(core::ptr::addr_of!(TCP_HANDLE))[i] else {
            continue;
        };
        let sock = socks.get_mut::<tcp::Socket>(h);
        let st = sock.state();
        row.state = st as u32;
        if let Some(ep) = sock.local_endpoint() {
            row.local_port = ep.port;
            row.local_ip = addr_v4_bits(ep.addr);
        }
        if let Some(ep) = sock.remote_endpoint() {
            row.remote_port = ep.port;
            row.remote_ip = addr_v4_bits(ep.addr);
        }
        // `accept_ready` marks a *listening* slot holding an unaccepted
        // connection.  The `listen_parent < 0` test keeps an accepted child
        // (which never clears the endpoint it was listening on) from
        // advertising itself as accept-ready again.
        row.accept_ready = 0;
        if st == tcp::State::Established && sock.listen_endpoint().port != 0 && row.listen_parent < 0 {
            row.accept_ready = 1;
        }
        // `rx_head`/`rx_tail` are the C-visible copy of "a byte is buffered".
        // It must track `can_recv()` (is there data), not `may_recv()` (may this
        // socket ever receive): the latter is true for the whole life of an open
        // connection, so it reported every socket as readable forever.
        if sock.can_recv() {
            if row.rx_head == row.rx_tail {
                row.rx_tail = row.rx_head.wrapping_add(1);
            }
        } else if row.rx_head != row.rx_tail {
            row.rx_tail = row.rx_head;
        }
        if row.nodelay != 0 {
            sock.set_nagle_enabled(false);
        } else {
            sock.set_nagle_enabled(true);
        }
        if row.keepalive != 0 {
            sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));
        } else {
            sock.set_keep_alive(None);
        }
    }
    tcp_unlock();
}

pub(crate) fn alloc_tcp_smoltcp(
    i: usize,
    socks: &mut SocketSet<'static>,
) -> Option<SocketHandle> {
    let rx_buf = &mut ptr::as_mut(core::ptr::addr_of_mut!(TCP_RX_BUFS))[i][..];
    let tx_buf = &mut ptr::as_mut(core::ptr::addr_of_mut!(TCP_TX_BUFS))[i][..];
    let rx = tcp::SocketBuffer::new(rx_buf);
    let tx = tcp::SocketBuffer::new(tx_buf);
    let s = tcp::Socket::new(rx, tx);
    Some(socks.add(s))
}

/// Remote endpoint of slot `idx` as `(address, port)`, straight from smoltcp.
///
/// The cached C mirror in `tcp_sockets` is only refreshed by `net_poll_task`, so
/// a connection that was accepted a moment ago still reads 0 there — which made
/// `accept()` report a peer port of 0.
pub(crate) fn tcp_socket_peer(idx: usize) -> Option<(IpAddress, u16)> {
    with_tcp_socket(idx as i32, |s| {
        s.remote_endpoint().map(|ep| (ep.addr, ep.port))
    })
    .flatten()
}

/// Local endpoint of slot `idx` as `(address, port)`: `None` for the address
/// when the socket knows only a port (a listener, or a bind-by-port), and `None`
/// port when the socket is not placed.  The caller supplies the family to turn
/// an unknown address into the wildcard.
pub(crate) fn tcp_socket_local(idx: usize) -> (Option<IpAddress>, u16) {
    with_tcp_socket(idx as i32, |s| {
        if let Some(ep) = s.local_endpoint() {
            (Some(ep.addr), ep.port)
        } else {
            (None, s.listen_endpoint().port)
        }
    })
    .unwrap_or((None, 0))
}

/// Give up slot `i` without a close handshake: unlink the smoltcp socket and
/// free the C slot.
///
/// Used to hand back a connection that was already moved into a child slot but
/// can no longer be reached through any fd (accept() ran out of Ksock rows) —
/// `tcp_close` would spend up to two seconds on the FIN first, and the point
/// here is that nobody can ever send or receive on this socket again.
pub(crate) fn tcp_free_slot(i: usize) {
    if i >= TCP_MAX_SOCKETS {
        return;
    }
    // SAFETY: `i < TCP_MAX_SOCKETS` is checked above, and this take happens under
    // `tcp_lock`, the same lock every other reader/writer of `TCP_HANDLE` takes.
    let h = {
        tcp_lock();
        let h = ptr::as_ref(core::ptr::addr_of!(TCP_HANDLE))[i];
        ptr::as_mut(core::ptr::addr_of_mut!(TCP_HANDLE))[i] = None;
        tcp_unlock();
        h
    };
    if let Some(h) = h {
        let slot = tcp_slot_of(i);
        if slot >= 0 {
            let _ = stack::with_slot_socks(slot as usize, |socks| {
                let _ = socks.remove(h);
            });
        }
    }
    tcp_set_slot(i, -1);
    tcp_lock();
    ptr::as_mut(core::ptr::addr_of_mut!(tcp_sockets))[i] = TcpSocket {
            used: 0,
            state: TCP_CLOSED,
            local_ip: 0,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            rcv_nxt: 0,
            rcv_wnd: TCP_RX_BUF_SIZE as u32,
            rx_buf: [0; TCP_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            on_data: core::ptr::null_mut(),
            on_event: core::ptr::null_mut(),
            listen_parent: -1,
            accept_ready: 0,
        nodelay: 0,
        keepalive: 0,
    };
    tcp_unlock();
}

#[path = "tcp_api.rs"]
mod tcp_api;
pub use tcp_api::*;
#[path = "tcp_accept.rs"]
mod tcp_accept;
pub use tcp_accept::*;
