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

static mut NET_CFG: [NetCfg; NET_NIC_MAX] = [EMPTY_CFG; NET_NIC_MAX];

#[inline]
fn slot_cfg(slot: usize) -> NetCfg {
    if slot >= NET_NIC_MAX {
        return EMPTY_CFG;
    }
    // SAFETY: `NET_CFG` is written only by `set_ipv4_config_slot`, which stores a
    // whole aligned `NetCfg` (four aligned 32-bit words), so this load cannot
    // tear — whatever is read is a complete configuration userspace set; `slot` is
    // bounds-checked above.
    unsafe { NET_CFG[slot] }
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
    // SAFETY: `NET_CFG` has no other writer (the getters above only read it) and the
    // borrow ends before the `stack` call below, so this whole-struct store is the
    // only access in flight here.
    let cfg = unsafe { &mut *core::ptr::addr_of_mut!(NET_CFG) };
    cfg[slot] = NetCfg {
        ip: ip_h,
        mask: mask_h,
        gateway: gw_h,
        dns: dns_h,
    };
    // SAFETY: `STACK_READY` is a `static mut bool` set by `stack_init` and cleared
    // by `stack_teardown`; a byte load reads either 0 or 1.
    if unsafe { crate::stack::STACK_READY } {
        let _ = crate::stack::with_slot(slot, |iface, _socks| {
            crate::stack::sync_iface_ipv4_from_config(iface, slot);
        });
    }
    0
}

#[no_mangle]
pub extern "C" fn rust_net_set_ipv4_config(ip_h: u32, mask_h: u32, gw_h: u32, dns_h: u32) -> i32 {
    set_ipv4_config_slot(0, ip_h, mask_h, gw_h, dns_h)
}

/// Snapshot of the primary interface's IPv4 link configuration (host byte order).
/// All output pointers may be NULL.
///
/// # Safety
///
/// Each of `ip_h`, `mask_h`, `gw_h` and `dns_h` may be null (it is then skipped),
/// but every non-null one must point to a writable, properly aligned `u32` that
/// stays live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_ipv4_config(
    ip_h: *mut u32,
    mask_h: *mut u32,
    gw_h: *mut u32,
    dns_h: *mut u32,
) -> i32 {
    let cfg = slot_cfg(0);
    // SAFETY: the caller contract (see # Safety) makes each non-null pointer a
    // writable, aligned `u32` for the call; the store is guarded by its own
    // `is_null` test, so no null is ever written through.
    unsafe {
        if !ip_h.is_null() {
            *ip_h = cfg.ip;
        }
    }
    // SAFETY: as above for `mask_h`.
    unsafe {
        if !mask_h.is_null() {
            *mask_h = cfg.mask;
        }
    }
    // SAFETY: as above for `gw_h`.
    unsafe {
        if !gw_h.is_null() {
            *gw_h = cfg.gateway;
        }
    }
    // SAFETY: as above for `dns_h`.
    unsafe {
        if !dns_h.is_null() {
            *dns_h = cfg.dns;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn rust_net_get_dns_host() -> u32 {
    dns_host()
}

#[no_mangle]
pub extern "C" fn rust_net_get_ip_host() -> u32 {
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
