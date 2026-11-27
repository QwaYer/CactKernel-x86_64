// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! TCP C ABI entry points. Split out of `tcp.rs`; shared state lives there.
//!
//! A TCP socket is created (its smoltcp socket built) only when it is pinned to an
//! interface: `connect()` routes by destination subnet and creates it in that
//! interface's `SocketSet`; `listen()` creates it on the primary interface.  Until
//! then the C slot has no smoltcp socket (`TCP_SLOT == -1`).

use core::net::Ipv4Addr;

use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use crate::ffi_kernel;
use crate::stack::{self};
use crate::tcp::{
    alloc_tcp_smoltcp, tcp_lock, tcp_set_slot, tcp_slot_of, tcp_sockets, tcp_unlock, TCP_HANDLE,
    NEXT_EPHEMERAL,
};
use crate::types::*;

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
