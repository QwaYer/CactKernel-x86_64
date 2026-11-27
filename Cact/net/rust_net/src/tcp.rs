// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! TCP sockets on smoltcp; keeps `tcp_sockets[]` aligned with the C ABI (state, accept, select).

use core::net::Ipv4Addr;

use kernel_rust::ptr;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use crate::ffi_kernel;
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

// ── TCP C ABI entry points ────────────────────────────────────────────────────

/// Build the smoltcp TCP socket for C slot `idx` in interface `slot`'s set and
/// record it.  Returns 0 on success, -1 on failure (leaving the slot unplaced).
fn place_tcp(idx: usize, slot: usize) -> i32 {
    let r = stack::with_slot_socks(slot, |socks| match alloc_tcp_smoltcp(idx, socks) {
        Some(h) => {
            tcp_lock();
            // SAFETY: `idx < TCP_MAX_SOCKETS` is the caller's contract and
            // `tcp_lock` is held, so this handle store cannot race the poll thread.
            unsafe { TCP_HANDLE[idx] = Some(h) };
            tcp_unlock();
            0
        }
        None => -1,
    });
    match r {
        Some(0) => {
            tcp_set_slot(idx, slot as i32);
            0
        }
        _ => -1,
    }
}

pub fn tcp_socket() -> i32 {
    // SAFETY: `STACK_READY` is a `static mut bool` set by `stack_init` and
    // cleared by `stack_teardown`; a byte load cannot tear, and reading it as
    // false fails the call closed.
    if !unsafe { stack::STACK_READY } {
        return -1;
    }
    // SAFETY: `tcp_sockets` is the kernel-wide TCP slot table; this takes
    // `tcp_lock` and scans the fixed-size array end to end, so the accesses are
    // in bounds and serialized against the poll thread.
    let idx = unsafe {
        tcp_lock();
        let mut found = -1i32;
        for (i, slot) in (*core::ptr::addr_of_mut!(tcp_sockets)).iter_mut().enumerate() {
            if slot.used == 0 {
                slot.used = 1;
                slot.state = TCP_CLOSED;
                slot.rx_head = 0;
                slot.rx_tail = 0;
                slot.listen_parent = -1;
                slot.accept_ready = 0;
                slot.on_data = core::ptr::null_mut();
                slot.on_event = core::ptr::null_mut();
                slot.nodelay = 0;
                slot.keepalive = 0;
                found = i as i32;
                break;
            }
        }
        tcp_unlock();
        found
    };
    if idx < 0 {
        return -1;
    }
    // Not yet pinned to an interface; `connect`/`listen` does that.
    tcp_set_slot(idx as usize, -1);
    // Drop any v6 bind address a previous socket left on this slot.
    crate::tcp::tcp_set_local6(idx as usize, [0u8; 16]);
    idx
}

/// How long `connect()` waits for the handshake (ticks at 100 Hz, same budget
/// as the kernel HTTP client).  smoltcp keeps retransmitting the SYN for an
/// unreachable peer, so only this deadline turns "no answer" into a failure.
const CONNECT_TIMEOUT_TICKS: u32 = 600;

const ECONNREFUSED: i32 = 111;
const ETIMEDOUT: i32 = 110;
const EINTR: i32 = 4;

/// `connect()` only queues the SYN and leaves the socket in SYN-SENT; the SYN
/// is dispatched by the next stack poll and ESTABLISHED needs the peer's
/// answer.  Block until that happens — otherwise the caller's very next
/// `write()` lands on a socket that cannot send yet and fails with a bare -1.
fn wait_connected(sock: i32) -> i32 {
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    let deadline = ffi_kernel::timer_ticks_get().saturating_add(CONNECT_TIMEOUT_TICKS);
    loop {
        // Drive the interface here rather than waiting for `net_poll_task`: a
        // loopback handshake never reaches the NIC, so it would otherwise inch
        // forward only on the 100 ms timer kick.  This also matches
        // `wait_close_settled` (close waits for the FIN the same way).
        stack::stack_poll();
        match crate::tcp::with_tcp_socket(sock, |s| s.state()) {
            Some(tcp::State::Established) => return 0,
            // A RST (closed port) drops the socket straight back to CLOSED.
            Some(tcp::State::Closed) | Some(tcp::State::TimeWait) | None => {
                return -ECONNREFUSED;
            }
            _ => {}
        }
        // A pending signal ends the wait: otherwise Ctrl+C during a connect to
        // an unreachable peer would be ignored for the whole 6 s timeout.  The
        // SYN keeps retransmitting in the background, so a caller that retries
        // connect() is not left in a bad state.
        if crate::socket::signal_pending() {
            return -EINTR;
        }
        // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
        // counter; it takes no pointers and is callable from task context.
        if ffi_kernel::timer_ticks_get() >= deadline {
            return -ETIMEDOUT;
        }
        // SAFETY: `sched_sleep_ticks` is a kernel C service taking a plain tick
        // count; it takes no pointers and is callable from task context.
        unsafe { sched::timer_wheel::sched_sleep_ticks(1) };
    }
}

pub fn tcp_connect(sock: i32, dst_ip: u32, dst_port: u16) -> i32 {
    tcp_connect_addr(sock, SockAddr::V4(dst_ip), dst_port)
}

/// Sixteen-octet IPv6 variant of [`tcp_connect`] (big-endian octets).
///
/// # Safety
///
/// `addr` must point to 16 readable bytes that stay live for the call.
pub unsafe fn tcp_connect6(sock: i32, addr: *const u8, dst_port: u16) -> i32 {
    if addr.is_null() {
        return -1;
    }
    let mut a6 = [0u8; 16];
    // SAFETY: the caller contract (see # Safety) makes `addr` a live 16-byte
    // readable buffer and `a6` is a distinct local array.
    unsafe { core::ptr::copy_nonoverlapping(addr, a6.as_mut_ptr(), 16) };
    tcp_connect_addr(sock, SockAddr::V6(a6), dst_port)
}

fn tcp_connect_addr(sock: i32, dst: SockAddr, dst_port: u16) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS {
        return -1;
    }
    let i = sock as usize;
    // Pick the interface by destination subnet and create the socket there.
    let slot = match dst {
        SockAddr::V4(v) => crate::config::route_slot(v),
        SockAddr::V6(a) => crate::config::route_slot_v6(a),
    };
    if place_tcp(i, slot) != 0 {
        return -1;
    }
    let r = stack::with_slot(slot, |iface, socks| {
        // SAFETY: the handle is read under `tcp_lock`, as every access is; `i` was
        // bounds-checked above.
        let h = {
            tcp_lock();
            let h = unsafe { TCP_HANDLE[i] };
            tcp_unlock();
            h
        };
        let Some(h) = h else {
            return -1;
        };
        let s = socks.get_mut::<tcp::Socket>(h);
        if s.is_open() {
            return -1;
        }
        // A local port set by CACT_SOCKCTL_BIND wins over the ephemeral one:
        // bind() has to actually bind for connect() too, otherwise a caller
        // that asked for a specific source port silently got another one.
        // `tcp_sockets[sock]` and the shared `NEXT_EPHEMERAL` counter are touched
        // under `tcp_lock` (the counter's read/modify/write must not race another
        // `connect`), and `sock` was bounds-checked above.
        let local_port = {
            tcp_lock();
            // SAFETY: `i` is bounds-checked above and `tcp_lock` is held, so
            // this slot read cannot race another `connect`.
            let bound = unsafe { tcp_sockets[i].local_port };
            let p = if bound != 0 {
                bound
            } else {
                // Pick an ephemeral port no other TCP slot already holds, the way
                // UDP's `pick_ephemeral` does.  The old code just walked a
                // counter, so a long-lived system could hand out a source port
                // that an explicitly bound or already-connected socket was
                // using.
                let mut chosen = 0u16;
                for _ in 0..(65535 - 49152 + 1) {
                    // SAFETY: `NEXT_EPHEMERAL` is read/written under `tcp_lock`,
                    // so the counter cannot race another `connect`.
                    let cand = unsafe { NEXT_EPHEMERAL };
                    let next = if cand == u16::MAX { 49152 } else { cand + 1 };
                    // SAFETY: the advanced counter is stored under the same lock.
                    unsafe { NEXT_EPHEMERAL = next };
                    let mut taken = false;
                    for k in 0..TCP_MAX_SOCKETS {
                        // SAFETY: `k` is in range and `tcp_lock` is held, so the
                        // slot read cannot race the poll thread.
                        if unsafe { tcp_sockets[k].used != 0 && tcp_sockets[k].local_port == cand } {
                            taken = true;
                            break;
                        }
                    }
                    if !taken {
                        chosen = cand;
                        break;
                    }
                }
                chosen
            };
            tcp_unlock();
            p
        };
        if local_port == 0 {
            // Every ephemeral port is taken (or none could be picked); smoltcp
            // cannot connect without a source port.
            return -1;
        }
        let cx = iface.context();
        let dst_ip = dst.to_ip();
        // For a loopback peer, pin the local address to the loopback address:
        // smoltcp would otherwise pick the interface's first address (the
        // configured NIC address), stamping a loopback connection with the box's
        // real address.  Otherwise a v6 bind address, if one was set, pins the
        // source; with none, smoltcp chooses by RFC 6724.
        let pinned = match dst {
            SockAddr::V4(v) if stack::is_loopback_ipv4_host(v) => {
                Some(IpAddress::Ipv4(Ipv4Addr::new(127, 0, 0, 1)))
            }
            SockAddr::V6(a) if a == crate::config::IPV6_LOOPBACK => {
                Some(IpAddress::Ipv6(core::net::Ipv6Addr::LOCALHOST))
            }
            SockAddr::V6(_) => {
                let l6 = crate::tcp::tcp_local6_of(i);
                if l6 != [0u8; 16] {
                    Some(IpAddress::Ipv6(core::net::Ipv6Addr::from(l6)))
                } else {
                    None
                }
            }
            _ => None,
        };
        let local = IpListenEndpoint {
            addr: pinned,
            port: local_port,
        };
        if s.connect(cx, (dst_ip, dst_port), local).is_err() {
            return -1;
        }
        0
    });
    if r.unwrap_or(-1) != 0 {
        return -1;
    }
    wait_connected(sock)
}

pub fn tcp_listen(sock: i32, local_port: u16) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS {
        return -1;
    }
    let i = sock as usize;
    // A listener is not addressed to any peer yet, so it lives on the primary
    // interface.
    let slot = 0usize;
    if place_tcp(i, slot) != 0 {
        return -1;
    }
    let r = stack::with_slot_socks(slot, |socks| {
        // SAFETY: the handle is read under `tcp_lock`, as every access is; `i` was
        // bounds-checked above.
        let h = {
            tcp_lock();
            let h = unsafe { TCP_HANDLE[i] };
            tcp_unlock();
            h
        };
        let Some(h) = h else {
            return -1;
        };
        let s = socks.get_mut::<tcp::Socket>(h);
        if s.listen(local_port).is_err() {
            return -1;
        }
        0
    });
    r.unwrap_or(-1)
}

/// Send `len` bytes from `data` on TCP socket `sock`.  Returns the number of
/// bytes smoltcp accepted (may be a short count, 0 when nothing fit), or -1 on
/// error.
///
/// # Safety
///
/// `data` must point to `len` readable bytes that stay live for the duration of
/// the call (it may be null, in which case the call returns -1).
pub unsafe fn tcp_send(sock: i32, data: *mut u8, len: u16) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS || data.is_null() {
        return -1;
    }
    let r = crate::tcp::with_tcp_socket(sock, |s| {
        if !s.may_send() {
            return -1;
        }
        // SAFETY: `data` is non-null (checked above) and, per this function's caller
        // contract (see # Safety), points to `len` readable bytes that stay live for
        // the call, so the slice is valid.
        unsafe {
            let sl = core::slice::from_raw_parts(data, len as usize);
            // Hand back exactly what smoltcp enqueued.  It can be a short count
            // (the send window filled up mid-write) and it is 0 when nothing
            // fit at all — both mean "retry the rest after POLLOUT", not a
            // failure.  Err(SendError::InvalidState) is smoltcp's only error
            // variant and means the socket stopped being sendable.
            match s.send_slice(sl) {
                Ok(n) => n as i32,
                Err(_) => -1,
            }
        }
    });
    r.unwrap_or(-1)
}

/// How long `close()` waits for queued data and our FIN to reach the peer
/// (ticks at 100 Hz, same time base as `wait_connected`).  A live peer answers
/// within one round trip, so the deadline only bounds the wait when the peer
/// has gone silent — it is what keeps close() from holding the socket forever.
const CLOSE_TIMEOUT_TICKS: u32 = 200;

/// True once our FIN has been acknowledged (FIN-WAIT-2) or the connection is
/// gone for good.  Tearing the smoltcp socket down from here cannot discard
/// bytes we already promised the peer, which is what lets `close()` mean "the
/// peer got everything we sent" instead of "we stopped caring".
fn close_settled(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
    )
}

/// Queue the FIN and drive the slot's interface until it has been acknowledged.
/// LISTEN/SYN-SENT sockets move straight to CLOSED; a connected socket keeps
/// its buffered bytes until the peer acknowledges them and the FIN.
fn wait_close_settled(slot: usize, h: smoltcp::iface::SocketHandle) -> bool {
    if stack::with_slot_socks(slot, |socks| {
        socks.get_mut::<tcp::Socket>(h).close();
    })
    .is_none()
    {
        return false;
    }
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    let deadline = ffi_kernel::timer_ticks_get().saturating_add(CLOSE_TIMEOUT_TICKS);
    loop {
        // Poll here rather than waiting for `net_poll_task`: the timer task
        // only kicks it every NET_POLL_PERIOD_TICKS, and every close() would
        // pay that delay in full.
        stack::stack_poll();
        match stack::with_slot_socks(slot, |socks| socks.get_mut::<tcp::Socket>(h).state()) {
            Some(state) if close_settled(state) => return true,
            Some(_) => {}
            None => return false,
        }
        // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
        // counter; it takes no pointers and is callable from task context.
        if ffi_kernel::timer_ticks_get() >= deadline {
            return false;
        }
        // SAFETY: `sched_sleep_ticks` is a kernel C service taking a plain tick
        // count; it takes no pointers and is callable from task context.
        unsafe { sched::timer_wheel::sched_sleep_ticks(1) };
    }
}

pub fn tcp_close(sock: i32) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS {
        return -1;
    }
    let i = sock as usize;
    let slot = tcp_slot_of(i);
    // SAFETY: `TCP_HANDLE[i]` is read under `tcp_lock`, and `i` derives from the
    // bounds check at the top of the function, so the read is in bounds and cannot
    // race the poll thread.
    let handle = unsafe {
        tcp_lock();
        let h = TCP_HANDLE[i];
        tcp_unlock();
        h
    };
    if slot >= 0 {
        let slot = slot as usize;
        if let Some(h) = handle {
            if !wait_close_settled(slot, h) {
                // The peer never acknowledged the FIN (or the stack is down).
                // Sending an RST says so; dropping the socket without one would
                // leave the peer waiting on a half-open connection.
                stack::with_slot_socks(slot, |socks| {
                    socks.get_mut::<tcp::Socket>(h).abort();
                });
                stack::stack_poll();
            }
            // Unlink the handle before removing the socket: `stack_poll`'s mirror
            // update resolves the handle, and smoltcp panics on a stale one.
            // SAFETY: clears `TCP_HANDLE[i]` under `tcp_lock` so `stack_poll`'s mirror
            // update cannot resolve the handle while the socket is being removed.
            unsafe {
                tcp_lock();
                TCP_HANDLE[i] = None;
                tcp_unlock();
            }
            let _ = stack::with_slot_socks(slot, |socks| {
                let _ = socks.remove(h);
            });
        }
    }
    tcp_set_slot(i, -1);
    // SAFETY: resets slot `i` of the fixed-size `tcp_sockets` table under
    // `tcp_lock`; `i` comes from the bounds check at the top of the function.
    unsafe {
        tcp_lock();
        tcp_sockets[i] = TcpSocket {
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
    crate::tcp::tcp_set_local6(i, [0u8; 16]);
    0
}

pub fn tcp_shutdown_wr(sock: i32) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS {
        return -1;
    }
    let r = crate::tcp::with_tcp_socket(sock, |s| {
        s.close();
        0
    });
    r.unwrap_or(-1)
}

/// Receive up to `max_len` bytes into `buf` on TCP socket `sock`.  Returns the
/// byte count, 0 when nothing is buffered yet, or -1 on error.
///
/// # Safety
///
/// `buf` must point to `max_len` writable bytes that stay live for the duration
/// of the call (it may be null, in which case the call returns -1).
pub unsafe fn tcp_recv(sock: i32, buf: *mut u8, max_len: u16) -> i32 {
    if sock < 0 || sock as usize >= TCP_MAX_SOCKETS || buf.is_null() {
        return -1;
    }
    let r = crate::tcp::with_tcp_socket(sock, |s| {
        if !s.may_recv() {
            return 0;
        }
        // SAFETY: `buf` is non-null (checked above) and, per this function's caller
        // contract (see # Safety), points to `max_len` writable bytes that stay live
        // for the call, so the mutable slice is valid.
        unsafe {
            let sl = core::slice::from_raw_parts_mut(buf, max_len as usize);
            match s.recv_slice(sl) {
                Ok(n) => n as i32,
                Err(_) => 0,
            }
        }
    });
    r.unwrap_or(-1)
}

// ── accept() hand-off between a listening slot and an established child slot ──

/// Hand off an established inbound connection from listen slot `listen_idx` to `child_idx`,
/// then recreate the listening smoltcp socket on `listen_idx`.  Both slots live on
/// the interface the listener was pinned to.
pub fn tcp_accept_transfer(listen_idx: i32, child_idx: i32) -> i32 {
    if listen_idx < 0
        || child_idx < 0
        || listen_idx as usize >= TCP_MAX_SOCKETS
        || child_idx as usize >= TCP_MAX_SOCKETS
    {
        return -1;
    }
    let li = listen_idx as usize;
    let ci = child_idx as usize;
    // The parent listener's interface slot; the child connection stays on it.
    let slot = tcp_slot_of(li);
    if slot < 0 {
        return -1;
    }
    let slot = slot as usize;
    let (lh, lp) = {
        // SAFETY: `with_slot_socks` holds the slot's `STACK_LOCK` for the closure and
        // `tcp_lock` serializes `TCP_HANDLE` against the poll thread; both indices were
        // bounds-checked by the caller, so the handle read is in bounds.
        let r = stack::with_slot_socks(slot, |socks| unsafe {
            tcp_lock();
            let lh = TCP_HANDLE[li];
            tcp_unlock();
            let lh = match lh {
                Some(h) => h,
                None => return (None, 0u16),
            };
            let sock = socks.get_mut::<tcp::Socket>(lh);
            if sock.state() != tcp::State::Established {
                return (None, 0u16);
            }
            let lp = sock.listen_endpoint().port;
            if lp == 0 {
                return (None, 0u16);
            }
            (Some(lh), lp)
        });
        match r {
            Some((Some(lh), lp)) => (lh, lp),
            _ => return -1,
        }
    };
    // The closure runs under the slot's `STACK_LOCK`; `tcp_lock` serializes the
    // `TCP_HANDLE`/`tcp_sockets` updates against the poll thread, and `listen_idx`/
    // `child_idx` were bounds-checked at the top of the function.
    let rc = stack::with_slot_socks(slot, |socks| {
        tcp_lock();
        {
            // SAFETY: `ci` is bounds-checked and `tcp_lock` is held, so this
            // shared borrow of the child slot is valid and consumed immediately.
            let child = unsafe { &tcp_sockets[ci] };
            if child.used != 0 {
                tcp_unlock();
                return -1;
            }
        }
        // SAFETY: `TCP_HANDLE[ci]` is read under `tcp_lock`, the same lock every
        // other access takes.
        let old = unsafe { TCP_HANDLE[ci] };
        // SAFETY: as above — the clear happens under the same lock.
        unsafe { TCP_HANDLE[ci] = None };
        tcp_unlock();
        if let Some(old) = old {
            let _ = socks.remove(old);
        }
        tcp_lock();
        // SAFETY: `TCP_HANDLE` is written under `tcp_lock`, as every access is.
        unsafe { TCP_HANDLE[ci] = Some(lh) };
        // SAFETY: as above.
        unsafe { TCP_HANDLE[li] = None };
        // SAFETY: `ci` is bounds-checked and `tcp_lock` is held, so this row
        // borrow is exclusive; it ends within the block.
        unsafe {
            let child = &mut tcp_sockets[ci];
            child.used = 1;
            child.listen_parent = listen_idx as i8;
            child.accept_ready = 0;
        }
        tcp_unlock();
        let Some(nh) = alloc_tcp_smoltcp(li, socks) else {
            tcp_lock();
            // SAFETY: `TCP_HANDLE` is written under `tcp_lock`, as every access
            // is; this restores the pre-transfer state.
            unsafe { TCP_HANDLE[li] = Some(lh) };
            // SAFETY: as above.
            unsafe { TCP_HANDLE[ci] = None };
            // SAFETY: `ci` is bounds-checked and `tcp_lock` is held, so this row
            // borrow is exclusive; it ends within the block.
            unsafe {
                let child = &mut tcp_sockets[ci];
                child.used = 0;
                child.listen_parent = -1;
            }
            tcp_unlock();
            return -1;
        };
        tcp_lock();
        // SAFETY: `TCP_HANDLE` is written under `tcp_lock`, as every access is;
        // the listening slot gets the freshly-built socket.
        unsafe { TCP_HANDLE[li] = Some(nh) };
        // SAFETY: `li` is bounds-checked and `tcp_lock` is held, so this row
        // borrow is exclusive; it ends within the block.
        unsafe {
            let listen = &mut tcp_sockets[li];
            listen.used = 1;
            listen.accept_ready = 0;
        }
        tcp_unlock();
        let nls = socks.get_mut::<tcp::Socket>(nh);
        if nls.listen(lp).is_err() {
            return -1;
        }
        0
    })
    .unwrap_or(-1);
    if rc == 0 {
        // The accepted child lives on the same interface as the listener.
        tcp_set_slot(ci, slot as i32);
    }
    rc
}
