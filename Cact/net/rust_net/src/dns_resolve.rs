// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Blocking DNS A/AAAA resolution over UDP port 53 using a dedicated smoltcp UDP
//! socket.
//!
//! The query goes to whichever resolver userspace configured: the interface's
//! IPv4 server when the IPv4 stack is up, otherwise its IPv6 server (`ip6_dns`,
//! which `dhcpd -6` fills from a Router Advertisement's RDNSS option or from
//! stateful DHCPv6).  The IPv6 server is queried over UDP/IPv6 — the only
//! transport that can work on an interface with no IPv4 address at all.

use core::ffi::{c_char, c_int};
use core::net::{Ipv4Addr, Ipv6Addr};

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::IpAddress;

use crate::ffi_kernel;
use crate::stack;
use crate::types::Semaphore;

const DNS_PORT: u16 = 53;
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

/// A DNS answer address in the family that was asked for.
#[derive(Clone, Copy)]
pub(crate) enum DnsAnswer {
    A(u32),
    Aaaa([u8; 16]),
}
const DNS_TIMEOUT_TICKS: u32 = 300;
/// Resend the query if no answer arrived within this long (one retry per lookup).
const DNS_RETRY_TICKS: u32 = 100;
const POLL_SLICE_TICKS: u32 = 2;

static mut DNS_RX_META: [udp::PacketMetadata; 4] = [udp::PacketMetadata::EMPTY; 4];
static mut DNS_RX_BUF: [u8; 2048] = [0; 2048];
static mut DNS_TX_META: [udp::PacketMetadata; 4] = [udp::PacketMetadata::EMPTY; 4];
static mut DNS_TX_BUF: [u8; 2048] = [0; 2048];
static mut DNS_HANDLE: Option<SocketHandle> = None;

/// Serializes resolvers, because there is exactly one DNS socket: two tasks
/// resolving at once would consume each other's replies.  `resolve_once` starts
/// by flushing whatever is buffered (a stale answer from a query that timed
/// out), which without this lock would throw away the other task's answer and
/// make both fail.  Initialised to 1 in [`init_socket`]; a second resolver
/// sleeps instead of corrupting the first one's exchange.
static mut DNS_SEMA: Semaphore = Semaphore {
    guard: cact_sync::spinlock_t::new(),
    count: core::sync::atomic::AtomicI32::new(0),
    waiters: [core::ptr::null_mut(); 64],
    waiter_count: 0,
};

/// # Safety
///
/// `socks` must be the crate's single `SocketSet`.  The caller must hold the
/// stack lock (or be `stack_init`, before the stack is published), because the
/// shared DNS socket handle and the `DNS_SEMA` semaphore below are also touched
/// by `resolve_once`/`remove_socket` under that lock.
pub unsafe fn init_socket(socks: &mut SocketSet<'static>) {
    // SAFETY: `DNS_HANDLE` is a `static mut Option<SocketHandle>` read and
    // written only under the stack lock that the caller contract (see # Safety)
    // requires, so this check cannot race `remove_socket`.
    if unsafe { DNS_HANDLE }.is_some() {
        return;
    }
    // SAFETY: `sema_init` expects a pointer to a live `Semaphore`; `DNS_SEMA` is
    // a kernel-lifetime static of exactly that type, and initialising it before
    // any resolver can wait on it is serialized by the caller's stack lock.
    unsafe { ffi_kernel::sema_init(core::ptr::addr_of_mut!(DNS_SEMA), 1) };
    // SAFETY: `DNS_RX_META` is a kernel-lifetime packet-buffer static; it is
    // handed to smoltcp only through this one shared socket, which the caller's
    // stack lock keeps exclusive, and the slice stays inside the array.
    let rx_meta = unsafe { &mut DNS_RX_META[..] };
    // SAFETY: as above, for `DNS_RX_BUF`.
    let rx_buf = unsafe { &mut DNS_RX_BUF[..] };
    let rx = udp::PacketBuffer::new(rx_meta, rx_buf);
    // SAFETY: as above — `DNS_TX_META` is a kernel-lifetime static whose only
    // user is this shared socket, created under the stack lock.
    let tx_meta = unsafe { &mut DNS_TX_META[..] };
    // SAFETY: as above, for `DNS_TX_BUF`.
    let tx_buf = unsafe { &mut DNS_TX_BUF[..] };
    let tx = udp::PacketBuffer::new(tx_meta, tx_buf);
    let u = udp::Socket::new(rx, tx);
    // SAFETY: `DNS_HANDLE` is written under the same stack lock as every other
    // access, so no other task can observe a half-updated handle.
    unsafe { DNS_HANDLE = Some(socks.add(u)) };
}

/// # Safety
///
/// `socks` must be the same `SocketSet` passed to [`init_socket`], and the
/// caller must hold the stack lock (or be tearing the stack down), so the shared
/// DNS handle cannot be in use by a concurrent resolver.
pub unsafe fn remove_socket(socks: &mut SocketSet<'static>) {
    // SAFETY: as in `init_socket`, `DNS_HANDLE` is only mutated under the stack
    // lock held by the caller, and `take` operates on that tear-free `Option`.
    if let Some(h) = unsafe { (*core::ptr::addr_of_mut!(DNS_HANDLE)).take() } {
        let _ = socks.remove(h);
    }
}

fn ipv4_host_from_smoltcp_v4(a: smoltcp::wire::Ipv4Address) -> u32 {
    let o = a.octets();
    u32::from(o[0]) << 24 | u32::from(o[1]) << 16 | u32::from(o[2]) << 8 | u32::from(o[3])
}

pub(crate) fn parse_ipv4_literal(host: &[u8]) -> Option<u32> {
    let s = core::str::from_utf8(host).ok()?;
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

/// The resolver a query is sent to — and therefore the transport it uses.
#[derive(Clone, Copy)]
enum DnsServer {
    /// An IPv4 server, queried over UDP/IPv4: needs a configured IPv4 address
    /// and mask, because the query is sourced from it.
    V4(u32),
    /// An IPv6 server (`ip6_dns`), queried over UDP/IPv6.  Needs no IPv4 at all:
    /// the query is sourced from the interface's own IPv6 address.
    V6([u8; 16]),
}

impl DnsServer {
    /// The UDP endpoint the query goes to (port 53 on the server).
    fn endpoint(self) -> (IpAddress, u16) {
        match self {
            DnsServer::V4(a) => (IpAddress::Ipv4(Ipv4Addr::from_bits(a)), DNS_PORT),
            DnsServer::V6(a) => (IpAddress::Ipv6(Ipv6Addr::from(a)), DNS_PORT),
        }
    }

    /// True when `addr` is this server — the only source a reply is accepted
    /// from, so an unrelated datagram cannot be mistaken for the answer.
    fn is_source(self, addr: IpAddress) -> bool {
        match (self, addr) {
            (DnsServer::V4(a), IpAddress::Ipv4(b)) => ipv4_host_from_smoltcp_v4(b) == a,
            (DnsServer::V6(a), IpAddress::Ipv6(b)) => b.octets() == a,
            _ => false,
        }
    }
}

/// The resolvers to try, in order: the IPv4 server (only when an IPv4 address,
/// mask and resolver are all configured, since the query is sourced from them),
/// then the IPv6 one.  The IPv6 entry is what lets a name resolve on an
/// interface that has no IPv4 address at all — `ping -6 <name>` on a box whose
/// only addressing is SLAAC.
fn dns_servers() -> [Option<DnsServer>; 2] {
    let v4 = if crate::config::dns_host() != 0
        && crate::config::ip_host() != 0
        && crate::config::netmask_host() != 0
    {
        Some(DnsServer::V4(crate::config::dns_host()))
    } else {
        None
    };
    // The shared resolver socket lives on interface slot 0, so that is the slot
    // whose IPv6 resolver it can reach (same as the IPv4 server above, which
    // `dns_host()` reports for slot 0).
    let d6 = crate::config::ipv6_dns_of(0);
    let v6 = if d6 != [0u8; 16] {
        Some(DnsServer::V6(d6))
    } else {
        None
    };
    [v4, v6]
}

/// Resolve `host` (already known not to be an IPv4 literal) to an address using
/// the configured resolvers.  Returns None when none of them answered.
fn resolve_host(host: &[u8], qtype: u16) -> Option<DnsAnswer> {
    let Ok(name_str) = core::str::from_utf8(host) else {
        return None;
    };
    let mut buf = [0u8; 512];
    for server in dns_servers().into_iter().flatten() {
        if let Some(answer) = resolve_once(name_str, server, &mut buf, qtype) {
            return Some(answer);
        }
    }
    None
}

/// Resolve a hostname or IPv4 literal to a host-order IPv4 address.
pub(crate) fn resolve_a(host: &[u8]) -> Option<u32> {
    if let Some(ip) = parse_ipv4_literal(host) {
        return Some(ip);
    }
    match resolve_host(host, QTYPE_A)? {
        DnsAnswer::A(ip) => Some(ip),
        DnsAnswer::Aaaa(_) => None,
    }
}

/// Resolve `host` to an IPv6 address (AAAA) through the configured resolver —
/// either transport (see [`dns_servers`]), so an AAAA name resolves without any
/// IPv4 addressing.
pub(crate) fn resolve_aaaa(host: &[u8]) -> Option<[u8; 16]> {
    match resolve_host(host, QTYPE_AAAA)? {
        DnsAnswer::Aaaa(a) => Some(a),
        DnsAnswer::A(_) => None,
    }
}

fn read_u16_be(pkt: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*pkt.get(i)?, *pkt.get(i + 1)?]))
}

fn read_u32_be(pkt: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *pkt.get(i)?,
        *pkt.get(i + 1)?,
        *pkt.get(i + 2)?,
        *pkt.get(i + 3)?,
    ]))
}

fn skip_name(pkt: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *pkt.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if (l & 0xc0) == 0xc0 {
            return Some(i + 2);
        }
        if l > 63 {
            return None;
        }
        i = i.checked_add(1)?.checked_add(l)?;
    }
}

fn encode_qname(out: &mut [u8], host: &str) -> Option<usize> {
    let mut w = 0usize;
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return None;
        }
        if w + 1 + b.len() > out.len() {
            return None;
        }
        out[w] = b.len() as u8;
        w += 1;
        out[w..w + b.len()].copy_from_slice(b);
        w += b.len();
    }
    if w >= out.len() {
        return None;
    }
    out[w] = 0;
    w += 1;
    Some(w)
}

fn flush_dns_recv(socks: &mut SocketSet<'static>) {
    // SAFETY: `DNS_HANDLE` is a `static mut Option<SocketHandle>` read and
    // written only under the stack lock; an `Option` read is tear-free, and a
    // stale `None` merely makes this flush a no-op.
    let Some(h) = (unsafe { DNS_HANDLE }) else {
        return;
    };
    let s = socks.get_mut::<udp::Socket>(h);
    while s.recv().is_ok() {}
}

fn pick_ephemeral_port() -> u16 {
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    let t = ffi_kernel::timer_ticks_get();
    0xc000u16 | (t as u16 & 0x3fff)
}

fn parse_dns_response(pkt: &[u8], expect_id: u16, qtype: u16) -> Option<DnsAnswer> {
    if pkt.len() < 12 {
        return None;
    }
    let id = read_u16_be(pkt, 0)?;
    if id != expect_id {
        return None;
    }
    let flags = read_u16_be(pkt, 2)?;
    if (flags & 0x8000) == 0 {
        return None;
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return None;
    }
    let qd = read_u16_be(pkt, 4)? as usize;
    let an = read_u16_be(pkt, 6)? as usize;
    if qd == 0 || an == 0 {
        return None;
    }
    let mut pos = 12usize;
    for _ in 0..qd {
        pos = skip_name(pkt, pos)?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..an {
        pos = skip_name(pkt, pos)?;
        let typ = read_u16_be(pkt, pos)?;
        pos += 2;
        let class = read_u16_be(pkt, pos)?;
        pos += 2;
        pos = pos.checked_add(4)?;
        let rdlen = read_u16_be(pkt, pos)? as usize;
        pos += 2;
        if class == QCLASS_IN {
            if qtype == QTYPE_A && typ == QTYPE_A && rdlen == 4 {
                return read_u32_be(pkt, pos).map(DnsAnswer::A);
            }
            if qtype == QTYPE_AAAA && typ == QTYPE_AAAA && rdlen == 16 {
                let mut a = [0u8; 16];
                a.copy_from_slice(pkt.get(pos..pos + 16)?);
                return Some(DnsAnswer::Aaaa(a));
            }
        }
        pos = pos.checked_add(rdlen)?;
    }
    None
}

fn try_recv_dns_reply(
    socks: &mut SocketSet<'static>,
    server: DnsServer,
    id: u16,
    qtype: u16,
) -> Option<DnsAnswer> {
    // SAFETY: as in `flush_dns_recv`, `DNS_HANDLE` is only mutated under the stack
    // lock; the tear-free `Option` read yields a live handle or `None`.
    let h = unsafe { DNS_HANDLE }?;
    let s = socks.get_mut::<udp::Socket>(h);
    let (data, meta) = s.recv().ok()?;
    // Only a datagram from the server we queried, on port 53, can be its answer —
    // and the source must be in the queried family (an IPv4 server never answers
    // from an IPv6 address, and vice versa).
    if !server.is_source(meta.endpoint.addr) {
        return None;
    }
    if meta.endpoint.port != DNS_PORT {
        return None;
    }
    parse_dns_response(data, id, qtype)
}

/// Send `query` from the shared DNS socket, binding an ephemeral port the first
/// time.  With `flush`, also drop whatever is still buffered — a stale answer to
/// a previous, timed-out lookup.  Only the first send of a lookup flushes, so a
/// retransmission cannot throw away the reply that is already on its way back.
/// Returns false when the socket is gone or the query could not be queued.
fn send_query(query: &[u8], server: DnsServer, flush: bool) -> bool {
    stack::with_iface_sockets(|_iface, socks| {
        // SAFETY: this closure runs under `with_iface_sockets` (stack lock held), the
        // same lock every writer of `DNS_HANDLE` takes; the `Option` read cannot tear.
        let h = match unsafe { DNS_HANDLE } {
            Some(h) => h,
            None => return false,
        };
        if flush {
            flush_dns_recv(socks);
        }
        let s = socks.get_mut::<udp::Socket>(h);
        if !s.is_open() {
            let p = pick_ephemeral_port();
            if s.bind(p).is_err() {
                return false;
            }
        }
        // The one socket carries both families: the endpoint decides which source
        // address smoltcp picks when it emits the datagram.
        s.send_slice(query, server.endpoint()).is_ok()
    })
    .unwrap_or(false)
}

fn resolve_once(name: &str, server: DnsServer, query_buf: &mut [u8], qtype: u16) -> Option<DnsAnswer> {
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    let id = (ffi_kernel::timer_ticks_get() as u16) ^ 0xa5a5;
    let mut w = 0usize;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&id.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&0x0100u16.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&1u16.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&0u16.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&0u16.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&0u16.to_be_bytes());
    w += 2;
    let qn_end = encode_qname(&mut query_buf[w..], name)?;
    w += qn_end;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&qtype.to_be_bytes());
    w += 2;
    query_buf.get_mut(w..w + 2)?.copy_from_slice(&QCLASS_IN.to_be_bytes());
    w += 2;
    let qlen = w;

    // `flush` drops anything still buffered — a stale answer to a query that
    // already timed out.  The retransmission below must not do it again, or it
    // could throw away the answer that arrived between the two sends.
    if !send_query(&query_buf[..qlen], server, true) {
        return None;
    }

    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    let start = ffi_kernel::timer_ticks_get();
    let deadline = start.saturating_add(DNS_TIMEOUT_TICKS);
    let mut next_wake = start;
    // One retransmission: a single lost UDP packet (or a server that dropped
    // the first query) used to fail the whole lookup after a silent 3 s wait.
    let mut next_retry = start.saturating_add(DNS_RETRY_TICKS);
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
    // counter; it takes no pointers and is callable from task context.
    while ffi_kernel::timer_ticks_get() < deadline {
        stack::stack_poll();
        // A pending signal ends the lookup instead of waiting out the whole
        // deadline: the resolver runs in the caller's task context, so Ctrl+C
        // must be able to stop it.
        if crate::socket::signal_pending() {
            return None;
        }
        // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick
        // counter; it takes no pointers and is callable from task context.
        let now = ffi_kernel::timer_ticks_get();
        if now >= next_wake {
            if let Some(ans) = stack::with_iface_sockets(|_iface, socks| {
                try_recv_dns_reply(socks, server, id, qtype)
            })
            .flatten()
            {
                return Some(ans);
            }
            next_wake = now.saturating_add(POLL_SLICE_TICKS);
        }
        if now >= next_retry {
            // Schedule no further retries; the deadline ends the wait.
            next_retry = deadline;
            let _ = send_query(&query_buf[..qlen], server, false);
        }
        // SAFETY: `sched_sleep_ticks` is a kernel C service taking a plain tick
        // count; it takes no pointers and is callable from task context.
        unsafe { sched::timer_wheel::sched_sleep_ticks(1) };
    }
    None
}

/// Borrow a NUL-terminated C name as a byte slice, rejecting one longer than the
/// 253-byte DNS limit.
///
/// # Safety
///
/// `name` must be a NUL-terminated string readable up to and including its
/// terminator.
unsafe fn c_name_bytes<'a>(name: *const c_char) -> Option<&'a [u8]> {
    let mut len = 0usize;
    loop {
        if len > 253 {
            return None;
        }
        // SAFETY: the caller contract makes `name` NUL-terminated, so `len <= 253`
        // keeps `add` within its first 254 bytes.
        let p = unsafe { name.add(len) };
        // SAFETY: `p` is the address checked just above; a conforming
        // NUL-terminated string has a byte at each of those offsets.
        if unsafe { *p } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `name` is NUL-terminated per the caller contract and `len` is the
    // byte count just scanned (<= 253), so exactly those initialised bytes are
    // readable.
    Some(unsafe { core::slice::from_raw_parts(name.cast::<u8>(), len) })
}

/// Take the shared resolver semaphore, returning 0 once held or -4 when a
/// pending signal interrupts the wait (so Ctrl+C can stop a lookup).  The wait
/// is a poll-and-sleep rather than `down()`, because `down()` parks the task in
/// a way no signal wakes — the resolver would then be unkillable for the
/// duration of the (up to 3 s) lookup held by the other task.
fn dns_lock() -> c_int {
    loop {
        if crate::socket::signal_pending() {
            return -4; // EINTR
        }
        // SAFETY: `DNS_SEMA` is a kernel-lifetime `Semaphore` initialised by
        // `init_socket`; `sema_try_down` is its matching non-blocking kernel
        // service and takes no other lock.
        if unsafe { ffi_kernel::sema_try_down(core::ptr::addr_of_mut!(DNS_SEMA)) } == 0 {
            return 0;
        }
        // SAFETY: `sched_sleep_ticks` is a kernel C service taking a plain tick
        // count; it takes no pointers and is callable from task context.
        unsafe { sched::timer_wheel::sched_sleep_ticks(1) };
    }
}

/// # Safety
/// `DNS_SEMA` is live whenever a lookup ran; this is the matching release.
unsafe fn dns_unlock() {
    // SAFETY: the caller holds a token taken by `dns_lock`, and `DNS_SEMA` is a
    // kernel-lifetime semaphore.
    unsafe { ffi_kernel::up(core::ptr::addr_of_mut!(DNS_SEMA)) };
}

pub unsafe fn rust_net_dns_resolve_a(name: *const c_char, out_ip_host: *mut u32) -> c_int {
    if name.is_null() || out_ip_host.is_null() {
        return -1;
    }
    // SAFETY: `STACK_READY` is a `static mut bool` set by `stack_init` and
    // cleared by `stack_teardown`; a byte load cannot tear, and reading it as
    // false fails the call closed.
    if !unsafe { stack::STACK_READY } {
        return -1;
    }
    // SAFETY: `name` is non-null (checked above) and, per the caller contract,
    // NUL-terminated.
    let Some(host) = (unsafe { c_name_bytes(name) }) else {
        return -1;
    };
    let r = dns_lock();
    if r != 0 {
        return r;
    }
    let resolved = resolve_a(host);
    // SAFETY: `dns_lock` returned 0, so this is the matching release.
    unsafe { dns_unlock() };
    if crate::socket::signal_pending() {
        return -4; // EINTR
    }
    match resolved {
        Some(ip) => {
            // SAFETY: the caller contract (see # Safety) makes `out_ip_host` a writable,
            // aligned `u32`; the null check at the top of the function excluded null.
            unsafe { *out_ip_host = ip };
            0
        }
        None => -1,
    }
}

/// Resolve a hostname to an IPv6 address (AAAA), writing the sixteen big-endian
/// octets to `out_addr`.  Returns 0 on success, -1 on failure, -4 if interrupted.
///
/// # Safety
///
/// `name` must be a NUL-terminated C string readable up to and including its
/// terminator, and `out_addr` must point to 16 writable bytes.  Either may be
/// null, in which case the call returns -1 without touching memory.
pub unsafe fn rust_net_dns_resolve_aaaa(
    name: *const c_char,
    out_addr: *mut u8,
) -> c_int {
    if name.is_null() || out_addr.is_null() {
        return -1;
    }
    // SAFETY: `STACK_READY` is a `static mut bool` set by `stack_init` and
    // cleared by `stack_teardown`; a byte load cannot tear, and reading it as
    // false fails the call closed.
    if !unsafe { stack::STACK_READY } {
        return -1;
    }
    // SAFETY: `name` is non-null (checked above) and, per the caller contract,
    // NUL-terminated.
    let Some(host) = (unsafe { c_name_bytes(name) }) else {
        return -1;
    };
    let r = dns_lock();
    if r != 0 {
        return r;
    }
    let resolved = resolve_aaaa(host);
    // SAFETY: `dns_lock` returned 0, so this is the matching release.
    unsafe { dns_unlock() };
    if crate::socket::signal_pending() {
        return -4; // EINTR
    }
    match resolved {
        Some(addr) => {
            // SAFETY: the caller contract (see # Safety) makes `out_addr` a
            // 16-byte writable buffer and `addr` is a distinct local array.
            unsafe { core::ptr::copy_nonoverlapping(addr.as_ptr(), out_addr, 16) };
            0
        }
        None => -1,
    }
}
