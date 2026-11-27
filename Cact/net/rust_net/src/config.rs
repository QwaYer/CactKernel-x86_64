// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Per-interface IPv4 settings in **host** byte order (mutable globals updated from C).
//!
//! Each interface slot keeps its own address/mask/gateway/DNS.  The boot state is
//! all-zero — "no address, no route, no resolver" — and `rust_net_set_ipv4_config`
//! overwrites slot 0 (the primary interface the legacy ioctls address).  There is
//! deliberately no compiled-in address: the kernel keeps no DHCP client, and
//! whatever is stored here was chosen by userspace (static configuration or a
//! userspace DHCP daemon), so a fresh interface must report itself unconfigured
//! rather than a placeholder that `sysinfo`/`ip` would show as if the user had set
//! it.

use kernel_rust::cell::KCell;
use kernel_rust::ptr;

use crate::runtime::NET_NIC_MAX;

/// The four IPv4 values of one interface, so a reader/writer needs a single
/// dereference rather than one per field.
#[derive(Clone, Copy)]
struct NetCfg {
    ip: u32,
    mask: u32,
    gateway: u32,
    dns: u32,
}

const EMPTY_CFG: NetCfg = NetCfg {
    ip: 0,
    mask: 0,
    gateway: 0,
    dns: 0,
};

static NET_CFG: KCell<[NetCfg; NET_NIC_MAX]> = KCell::new([EMPTY_CFG; NET_NIC_MAX]);

/// The six IPv6 values of one interface.  Addresses are the sixteen big-endian
/// octets `core::net::Ipv6Addr::from` expects, so a reader hands them straight
/// to smoltcp without a byte-order conversion.
#[derive(Clone, Copy)]
struct NetCfg6 {
    /// Global/ULA unicast address userspace set; all-zero = none.
    addr: [u8; 16],
    /// Prefix length for `addr`; meaningful only while `addr` is set.
    prefix: u8,
    /// Default-route next hop (a router's link-local or global address).
    gateway: [u8; 16],
    /// Resolver reached over IPv6 (from a Router Advertisement's RDNSS option or
    /// from stateful DHCPv6); used for lookups when the IPv4 resolver is not
    /// usable, and the reason a name can resolve on a v6-only interface.
    dns: [u8; 16],
    /// Link-local address the stack derives from the NIC MAC (EUI-64, fe80::/64).
    /// Userspace never sets it; all-zero until a NIC binds to the slot.  It is
    /// kept here (not recomputed on every route lookup) so the socket paths can
    /// resolve a bound link-local address without touching the interface slots.
    link_local: [u8; 16],
}

const EMPTY_CFG6: NetCfg6 = NetCfg6 {
    addr: [0; 16],
    prefix: 0,
    gateway: [0; 16],
    dns: [0; 16],
    link_local: [0; 16],
};

static NET_CFG6: KCell<[NetCfg6; NET_NIC_MAX]> = KCell::new([EMPTY_CFG6; NET_NIC_MAX]);

#[inline]
fn slot_cfg(slot: usize) -> NetCfg {
    if slot >= NET_NIC_MAX {
        return EMPTY_CFG;
    }
    NET_CFG.with(|t| t[slot])
}

#[inline]
fn slot_cfg6(slot: usize) -> NetCfg6 {
    if slot >= NET_NIC_MAX {
        return EMPTY_CFG6;
    }
    NET_CFG6.with(|t| t[slot])
}

#[inline]
pub fn ip_host() -> u32 {
    ip_host_of(0)
}

#[inline]
pub fn ip_host_of(slot: usize) -> u32 {
    slot_cfg(slot).ip
}

#[inline]
pub fn netmask_host() -> u32 {
    netmask_host_of(0)
}

#[inline]
pub fn netmask_host_of(slot: usize) -> u32 {
    slot_cfg(slot).mask
}

#[inline]
pub fn gateway_host() -> u32 {
    gateway_host_of(0)
}

#[inline]
pub fn gateway_host_of(slot: usize) -> u32 {
    slot_cfg(slot).gateway
}

#[inline]
pub fn dns_host() -> u32 {
    dns_host_of(0)
}

#[inline]
pub fn dns_host_of(slot: usize) -> u32 {
    slot_cfg(slot).dns
}

/// Store interface `slot`'s configuration and push it into the slot's smoltcp
/// interface when the stack is up.  All values are trusted from the (root-only)
/// netcfg path; zeros are meaningful: ip==0 clears the interface address, gw==0
/// clears the default route, dns==0 clears the resolver server.
pub fn set_ipv4_config_slot(slot: usize, ip_h: u32, mask_h: u32, gw_h: u32, dns_h: u32) -> i32 {
    if slot >= NET_NIC_MAX {
        return -1;
    }
    NET_CFG.with(|cfg| {
        cfg[slot] = NetCfg {
            ip: ip_h,
            mask: mask_h,
            gateway: gw_h,
            dns: dns_h,
        };
    });
    if crate::stack::stack_ready() {
        crate::stack::resync_slot_addrs(slot);
    }
    0
}

pub fn rust_net_set_ipv4_config(ip_h: u32, mask_h: u32, gw_h: u32, dns_h: u32) -> i32 {
    set_ipv4_config_slot(0, ip_h, mask_h, gw_h, dns_h)
}

/// Snapshot of the primary interface's IPv4 link configuration (host byte order).
/// All output pointers may be NULL.
///
/// Each of `ip_h`, `mask_h`, `gw_h` and `dns_h` may be null (it is then
/// skipped); a non-null one must point to a writable, properly aligned `u32`.
pub fn rust_net_get_ipv4_config(
    ip_h: *mut u32,
    mask_h: *mut u32,
    gw_h: *mut u32,
    dns_h: *mut u32,
) -> i32 {
    let cfg = slot_cfg(0);
    if !ip_h.is_null() {
        ptr::write(ip_h, cfg.ip);
    }
    if !mask_h.is_null() {
        ptr::write(mask_h, cfg.mask);
    }
    if !gw_h.is_null() {
        ptr::write(gw_h, cfg.gateway);
    }
    if !dns_h.is_null() {
        ptr::write(dns_h, cfg.dns);
    }
    0
}

pub fn rust_net_get_dns_host() -> u32 {
    dns_host()
}

pub fn rust_net_get_ip_host() -> u32 {
    ip_host()
}

/// Interface slot whose configured address is exactly `ip_host`, or `None`.
///
/// Used to pin a socket that `bind()`ed to a specific local address onto the
/// interface that owns it.
pub fn slot_owning_ip(ip_host: u32) -> Option<usize> {
    if ip_host == 0 {
        return None;
    }
    for slot in 0..NET_NIC_MAX {
        if ip_host_of(slot) == ip_host {
            return Some(slot);
        }
    }
    None
}

/// Interface slot that should carry traffic to `dst_ip` (host order).
///
/// Longest-prefix match over the configured slots; failing that, the first slot
/// that owns a default route (gateway set); otherwise slot 0.  Loopback (127/8),
/// the unspecified address, the limited broadcast, and multicast all go to slot 0.
/// This is the whole of the kernel's routing today: sockets are pinned to the
/// resulting slot when they are created.
pub fn route_slot(dst_ip_host: u32) -> usize {
    if dst_ip_host == 0
        || dst_ip_host == u32::MAX
        || (dst_ip_host >> 24) == 127
        || (dst_ip_host >> 28) == 0xE
    {
        return 0;
    }
    let mut best: Option<(u8, usize)> = None; // (prefix length, slot)
    let mut default_slot: Option<usize> = None;
    for slot in 0..NET_NIC_MAX {
        let ip = ip_host_of(slot);
        let mask = netmask_host_of(slot);
        if ip == 0 || mask == 0 {
            continue;
        }
        if gateway_host_of(slot) != 0 && default_slot.is_none() {
            default_slot = Some(slot);
        }
        if (dst_ip_host & mask) == (ip & mask) {
            let prefix = mask.count_ones() as u8;
            if best.map_or(true, |(bp, _)| prefix > bp) {
                best = Some((prefix, slot));
            }
        }
    }
    match best {
        Some((_, slot)) => slot,
        None => default_slot.unwrap_or(0),
    }
}

// ── IPv6 per-interface configuration ────────────────────────────────────────
//
// Same shape as the IPv4 block above, with sixteen-octet addresses.  The stack
// additionally fills `link_local` from the NIC MAC (see
// `stack::link_local_from_mac`); userspace sets only the global address and its
// prefix, the default-route next hop and the IPv6 resolver.

/// `::1`, the IPv6 loopback address.
pub const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[inline]
pub fn ipv6_addr_of(slot: usize) -> [u8; 16] {
    slot_cfg6(slot).addr
}

#[inline]
pub fn ipv6_prefix_of(slot: usize) -> u8 {
    slot_cfg6(slot).prefix
}

#[inline]
pub fn ipv6_gateway_of(slot: usize) -> [u8; 16] {
    slot_cfg6(slot).gateway
}

#[inline]
pub fn ipv6_dns_of(slot: usize) -> [u8; 16] {
    slot_cfg6(slot).dns
}

#[inline]
pub fn ipv6_link_local_of(slot: usize) -> [u8; 16] {
    slot_cfg6(slot).link_local
}

/// True while the slot carries a userspace-set global/ULA IPv6 address (as
/// opposed to only the stack-derived link-local).
#[inline]
pub fn ipv6_configured_of(slot: usize) -> bool {
    ipv6_addr_of(slot) != [0u8; 16]
}

/// Store the link-local address the stack derived from the NIC MAC.  Called only
/// on the single-threaded driver bring-up path, right before the interface is
/// resynced.
pub fn set_ipv6_link_local_slot(slot: usize, ll: [u8; 16]) {
    if slot >= NET_NIC_MAX {
        return;
    }
    NET_CFG6.with(|cfg| cfg[slot].link_local = ll);
}

/// Store interface `slot`'s IPv6 configuration and push it into the slot's
/// smoltcp interface when the stack is up.  All values are trusted from the
/// (root-only) netcfg path; an all-zero `addr` clears the interface's global
/// address, `gw` of all-zero clears the default route and `dns` of all-zero
/// clears the resolver.
pub fn set_ipv6_config_slot(
    slot: usize,
    addr: [u8; 16],
    prefix: u8,
    gw: [u8; 16],
    dns: [u8; 16],
) -> i32 {
    if slot >= NET_NIC_MAX {
        return -1;
    }
    // A multicast address can never be an interface address: smoltcp's
    // `check_ip_addrs` panics on one, and that panic would take the whole kernel
    // down when the resync below runs.  Refuse it instead (ff00::/8).
    if addr[0] == 0xff {
        return -1;
    }
    NET_CFG6.with(|cfg| {
        cfg[slot].addr = addr;
        // A cleared address has no meaningful prefix; keep it 0 so a stale
        // prefix can never make an empty slot look configured.
        cfg[slot].prefix = if addr == [0u8; 16] { 0 } else { prefix.min(128) };
        cfg[slot].gateway = gw;
        cfg[slot].dns = dns;
    });
    if crate::stack::stack_ready() {
        crate::stack::resync_slot_addrs(slot);
    }
    0
}

/// Interface slot that owns `addr` — matches its configured global address or
/// its stack-derived link-local address — or `None`.
pub fn slot_owning_ipv6(addr: [u8; 16]) -> Option<usize> {
    if addr == [0u8; 16] {
        return None;
    }
    for slot in 0..NET_NIC_MAX {
        let c = slot_cfg6(slot);
        if c.addr == addr || c.link_local == addr {
            return Some(slot);
        }
    }
    None
}

/// True when `dst` falls inside `net`/`prefix` (`prefix` leading bits compared,
/// big-endian octets).
pub(crate) fn v6_prefix_match(dst: [u8; 16], net: [u8; 16], prefix: u8) -> bool {
    let mut bits = prefix.min(128) as usize;
    let mut i = 0usize;
    while bits >= 8 {
        if dst[i] != net[i] {
            return false;
        }
        i += 1;
        bits -= 8;
    }
    if bits > 0 {
        let mask = 0xFFu8 << (8 - bits);
        if (dst[i] & mask) != (net[i] & mask) {
            return false;
        }
    }
    true
}

/// Interface slot that should carry traffic to IPv6 `dst`.
///
/// Longest-prefix match over the slots' configured global addresses and their
/// link-local /64s; failing that, the first slot that owns a default route
/// (gateway set); otherwise slot 0.  Loopback (`::1`), the unspecified address
/// and multicast (`ff00::/8`) go to slot 0, as for IPv4.
pub fn route_slot_v6(dst: [u8; 16]) -> usize {
    if dst == [0u8; 16] || dst[0] == 0xff || dst == IPV6_LOOPBACK {
        return 0;
    }
    let mut best: Option<(u8, usize)> = None; // (prefix length, slot)
    let mut default_slot: Option<usize> = None;
    for slot in 0..NET_NIC_MAX {
        let c = slot_cfg6(slot);
        if c.addr != [0u8; 16] {
            if c.gateway != [0u8; 16] && default_slot.is_none() {
                default_slot = Some(slot);
            }
            if v6_prefix_match(dst, c.addr, c.prefix) && best.map_or(true, |(bp, _)| c.prefix > bp) {
                best = Some((c.prefix, slot));
            }
        }
        // A link-local destination (fe80::/64 on the same link) is carried by
        // the interface whose derived link-local shares the /64.
        if c.link_local != [0u8; 16]
            && v6_prefix_match(dst, c.link_local, 64)
            && best.map_or(true, |(bp, _)| 64 > bp)
        {
            best = Some((64, slot));
        }
    }
    match best {
        Some((_, slot)) => slot,
        None => default_slot.unwrap_or(0),
    }
}

