// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Connection tracking — the stateful half of the firewall.
//!
//! Every IP flow the stack sees is recorded as one bidirectional entry keyed by
//! its original 5-tuple; a packet is classified into `NEW` (no entry yet),
//! `ESTABLISHED` (its flow already exists, so this is a later packet of it) or
//! `RELATED` (an ICMP error that refers to a live flow).  Filter rules with a
//! non-zero `state_mask` consult that classification, which is what lets a
//! default-`DROP` input policy still admit the replies to connections the box
//! opened itself.
//!
//! As with the ARP table, every access happens under the stack lock.  The hooks
//! (`crate::fw`) run inside `iface.poll`, which holds it, so [`track`], [`age`]
//! and [`known`] take no lock of their own; only the enumeration entry points
//! below, reached from a syscall, take a [`StackGuard`].

use crate::ffi_kernel;
use crate::stack::StackGuard;

/// A packet with no matching entry yet.
pub const STATE_NEW: u8 = 0x01;
/// A packet of a flow already in the table (or the reply leg of one).
pub const STATE_ESTABLISHED: u8 = 0x02;
/// An ICMP error that refers to a live flow.
pub const STATE_RELATED: u8 = 0x04;
/// Mask of all defined states.
pub const STATE_MASK: u8 = STATE_NEW | STATE_ESTABLISHED | STATE_RELATED;

/// Maximum number of tracked flows.
pub const CONN_MAX: usize = 256;

/// `timer_ticks_get()` counts 10 ms ticks.
const TICKS_PER_SEC: u32 = 100;

/// TCP flag bits (the low byte of the TCP header's flags field).
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Timeouts, in seconds, by protocol and state.
const TCP_NEW_SECS: u32 = 60;
const TCP_ESTABLISHED_SECS: u32 = 3600;
const UDP_SECS: u32 = 60;
const ICMP_SECS: u32 = 30;

/// A flow's identity, in its original direction.  Addresses are big-endian; an
/// IPv4 address sits in the first four bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub family: u8,
    pub proto: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

impl Key {
    /// A zeroed key (no flow).
    const fn zero() -> Key {
        Key {
            family: 0,
            proto: 0,
            src: [0; 16],
            dst: [0; 16],
            sport: 0,
            dport: 0,
        }
    }

    /// The key with source and destination swapped.
    fn reverse(&self) -> Key {
        Key {
            family: self.family,
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

#[derive(Clone, Copy)]
struct Conn {
    used: bool,
    key: Key,
    /// The tuple as it appears on the wire in the forward direction once NAT has
    /// rewritten it; equal to `key` for an untranslated flow.
    xlate: Key,
    state: u8,
    /// `timer_ticks_get()` value at the last packet of this flow.
    last_tick: u32,
    packets: u32,
    bytes: u32,
}

impl Conn {
    const fn empty() -> Self {
        Self {
            used: false,
            key: Key {
                family: 0,
                proto: 0,
                src: [0; 16],
                dst: [0; 16],
                sport: 0,
                dport: 0,
            },
            xlate: Key {
                family: 0,
                proto: 0,
                src: [0; 16],
                dst: [0; 16],
                sport: 0,
                dport: 0,
            },
            state: 0,
            last_tick: 0,
            packets: 0,
            bytes: 0,
        }
    }
}

/// Must match `cact_fw_conn_t` in `ioctl_abi.h` byte for byte (92 bytes).
#[repr(C)]
pub struct CactFwConn {
    pub family: u8,
    pub proto: u8,
    pub state: u8,
    pub flags: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    /// Translated source (SNAT); all-zero when the flow is not translated.
    pub xsrc: [u8; 16],
    /// Translated destination (DNAT).
    pub xdst: [u8; 16],
    pub xsport: u16,
    pub xdport: u16,
    pub age_ms: u32,
    pub ttl_ms: u32,
    pub packets: u32,
    pub bytes: u32,
}

const _: () = assert!(core::mem::size_of::<CactFwConn>() == 92);

static mut CONNS: [Conn; CONN_MAX] = [Conn::empty(); CONN_MAX];

/// Seconds a flow of `proto`/`state` may stay idle before it is aged out.
fn timeout_secs(proto: u8, state: u8) -> u32 {
    match proto {
        6 => {
            if state & STATE_ESTABLISHED != 0 {
                TCP_ESTABLISHED_SECS
            } else {
                TCP_NEW_SECS
            }
        }
        17 => UDP_SECS,
        _ => ICMP_SECS,
    }
}

/// Index and direction of the entry matching `key` (`rev` is true when the
/// packet runs opposite to the stored flow).  A hit may be on the original tuple
/// or on its NAT translation, so a translated reply finds its flow.
fn find(table: &[Conn; CONN_MAX], key: &Key) -> Option<(usize, bool)> {
    for (i, c) in table.iter().enumerate() {
        if !c.used {
            continue;
        }
        if c.key == *key || c.xlate == *key {
            return Some((i, false));
        }
        if c.key.reverse() == *key || c.xlate.reverse() == *key {
            return Some((i, true));
        }
    }
    None
}

/// The slot a new flow should occupy: a free one, else the least recently seen.
fn free_slot(table: &[Conn; CONN_MAX], now: u32) -> usize {
    let mut oldest = 0usize;
    let mut oldest_age = 0u32;
    let mut first_free = None;
    for (i, c) in table.iter().enumerate() {
        if !c.used {
            if first_free.is_none() {
                first_free = Some(i);
            }
            continue;
        }
        let age = now.wrapping_sub(c.last_tick);
        if oldest_age == 0 || age > oldest_age {
            oldest_age = age;
            oldest = i;
        }
    }
    first_free.unwrap_or(oldest)
}

/// Whether `key` (either direction) matches a live flow.
///
/// The caller must hold the stack lock.
pub(crate) fn known(key: &Key) -> bool {
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow is shared and dead before returning.
    let table = unsafe { &*core::ptr::addr_of!(CONNS) };
    find(table, key).is_some()
}

/// The outcome of classifying one packet with [`track`].
pub(crate) struct Tracked {
    /// The packet's [`STATE_*`] value.
    pub state: u8,
    /// True when the packet runs opposite to the stored flow.
    pub rev: bool,
    /// The flow's entry index, for [`key_of`] / [`xlate_of`] / [`set_xlate`];
    /// [`NO_ENTRY`] for a RELATED packet, which matches no entry of its own.
    pub idx: u32,
}

/// `Tracked::idx` value meaning "no table entry" (a RELATED ICMP error).
pub(crate) const NO_ENTRY: u32 = u32::MAX;

/// Classify one packet and update the table.
///
/// `tcp_flags` is the TCP flags byte (0 for non-TCP); `len` is the L3 length for
/// the byte counter; `related` is the embedded packet of an ICMP error, when the
/// caller could extract one.
///
/// The caller must hold the stack lock.
pub(crate) fn track(key: &Key, tcp_flags: u8, len: u32, related: Option<&Key>) -> Tracked {
    // An ICMP error that names a live flow is RELATED, whatever its own tuple.
    if let Some(rk) = related {
        if known(rk) {
            return Tracked {
                state: STATE_RELATED,
                rev: false,
                idx: NO_ENTRY,
            };
        }
    }
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow ends before the function returns.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(CONNS) };
    // SAFETY: `timer_ticks_get` is a kernel service that reads the tick counter;
    // it takes no arguments and is callable from task/interrupt context.
    let now = ffi_kernel::timer_ticks_get();

    if let Some((i, rev)) = find(table, key) {
        let c = &mut table[i];
        c.last_tick = now;
        c.packets = c.packets.wrapping_add(1);
        c.bytes = c.bytes.wrapping_add(len);
        if c.key.proto == 6 && tcp_flags & TCP_RST != 0 {
            // A reset tears the flow down; report the closing packet and forget it.
            c.used = false;
            return Tracked {
                state: STATE_ESTABLISHED,
                rev,
                idx: i as u32,
            };
        }
        if c.state == STATE_NEW && (rev || (c.key.proto == 6 && tcp_flags & TCP_ACK != 0)) {
            c.state = STATE_ESTABLISHED;
        }
        let state = c.state;
        return Tracked {
            state,
            rev,
            idx: i as u32,
        };
    }

    let slot = free_slot(table, now);
    let c = &mut table[slot];
    *c = Conn {
        used: true,
        key: *key,
        xlate: *key,
        state: STATE_NEW,
        last_tick: now,
        packets: 1,
        bytes: len,
    };
    Tracked {
        state: STATE_NEW,
        rev: false,
        idx: slot as u32,
    }
}

/// The original tuple of flow `idx`.
///
/// The caller must hold the stack lock.
pub(crate) fn key_of(idx: u32) -> Key {
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow is shared and dead before returning.
    let table = unsafe { &*core::ptr::addr_of!(CONNS) };
    if (idx as usize) < CONN_MAX && table[idx as usize].used {
        table[idx as usize].key
    } else {
        Key::zero()
    }
}

/// The wire (translated) tuple of flow `idx`; equals the original key when the
/// flow is not translated.
///
/// The caller must hold the stack lock.
pub(crate) fn xlate_of(idx: u32) -> Key {
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow is shared and dead before returning.
    let table = unsafe { &*core::ptr::addr_of!(CONNS) };
    if (idx as usize) < CONN_MAX && table[idx as usize].used {
        table[idx as usize].xlate
    } else {
        Key::zero()
    }
}

/// Record that flow `idx` is translated to `xlate` in the forward direction.
///
/// The caller must hold the stack lock.
pub(crate) fn set_xlate(idx: u32, xlate: Key) {
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow ends before returning.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(CONNS) };
    if (idx as usize) < CONN_MAX && table[idx as usize].used {
        table[idx as usize].xlate = xlate;
    }
}

/// Drop every flow idle for longer than its protocol/state timeout.  Called once
/// per poll from `stack_poll`, which holds the stack lock.
pub(crate) fn age() {
    // SAFETY: `CONNS` is only touched under the stack lock, which the caller
    // holds; the borrow ends before the function returns.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(CONNS) };
    // SAFETY: `timer_ticks_get` is a kernel service that reads the tick counter;
    // it takes no arguments and is callable from this context.
    let now = ffi_kernel::timer_ticks_get();
    for c in table.iter_mut() {
        if !c.used {
            continue;
        }
        let ttl = timeout_secs(c.key.proto, c.state) * TICKS_PER_SEC;
        if now.wrapping_sub(c.last_tick) >= ttl {
            c.used = false;
        }
    }
}

/// Number of live flows.
#[no_mangle]
pub extern "C" fn rust_net_fw_conn_count() -> i32 {
    let _guard = StackGuard::new();
    // SAFETY: `CONNS` is only touched under the stack lock, which `_guard`
    // holds; the borrow is shared and dead before the guard drops.
    let table = unsafe { &*core::ptr::addr_of!(CONNS) };
    table.iter().filter(|c| c.used).count() as i32
}

/// Fill `*out` with the `idx`-th live flow.  Returns 0 on success, -1 when `out`
/// is NULL or `idx` is out of range (the range is `0 .. count`).
///
/// # Safety
///
/// `out` may be null (the call then returns -1); if non-null it must point to a
/// writable, properly aligned [`CactFwConn`] that stays live for the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_fw_conn_get(idx: u32, out: *mut CactFwConn) -> i32 {
    if out.is_null() {
        return -1;
    }
    let _guard = StackGuard::new();
    // SAFETY: `CONNS` is only touched under the stack lock, which `_guard`
    // holds; the borrow is shared and dead before the guard drops.
    let table = unsafe { &*core::ptr::addr_of!(CONNS) };
    // SAFETY: `timer_ticks_get` is a kernel service that reads the tick counter;
    // it takes no arguments and is callable from this context.
    let now = ffi_kernel::timer_ticks_get();
    let mut seen = 0u32;
    for c in table.iter() {
        if !c.used {
            continue;
        }
        if seen == idx {
            let age_ticks = now.wrapping_sub(c.last_tick);
            let ttl = timeout_secs(c.key.proto, c.state) * TICKS_PER_SEC;
            // SAFETY: the caller contract (see # Safety) makes `out` writable,
            // aligned and live, and the null check above excluded null; the
            // borrow is dead before returning.
            let dst = unsafe { &mut *out };
            dst.family = c.key.family;
            dst.proto = c.key.proto;
            dst.state = c.state;
            dst.flags = 0;
            dst.src = c.key.src;
            dst.dst = c.key.dst;
            dst.sport = c.key.sport;
            dst.dport = c.key.dport;
            // Report the translation only when the flow actually is translated.
            if c.xlate != c.key {
                dst.xsrc = c.xlate.src;
                dst.xdst = c.xlate.dst;
                dst.xsport = c.xlate.sport;
                dst.xdport = c.xlate.dport;
            } else {
                dst.xsrc = [0; 16];
                dst.xdst = [0; 16];
                dst.xsport = 0;
                dst.xdport = 0;
            }
            dst.age_ms = age_ticks * 10;
            dst.ttl_ms = ttl.saturating_sub(age_ticks) * 10;
            dst.packets = c.packets;
            dst.bytes = c.bytes;
            return 0;
        }
        seen += 1;
    }
    -1
}

/// Forget every tracked flow.
#[no_mangle]
pub extern "C" fn rust_net_fw_conn_flush() -> i32 {
    let _guard = StackGuard::new();
    // SAFETY: `CONNS` is only touched under the stack lock, which `_guard`
    // holds; the borrow is exclusive for the call and dead before the guard
    // drops.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(CONNS) };
    for c in table.iter_mut() {
        *c = Conn::empty();
    }
    0
}
