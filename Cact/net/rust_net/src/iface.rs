// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Per-interface enumeration for userspace (`ip`, `sysinfo`).
//!
//! Before loopback existed the stack had exactly one interface, so userspace
//! read it through the single-NIC `CACT_NETCTL_IFNAME` / `CACT_NETCTL_NETCFG_GET`
//! ioctls.  Those are kept for compatibility; this module adds an indexed view so
//! a tool can list both the NIC and `lo`.

use crate::config;
use crate::runtime;
use crate::stack;

/// Interface is the loopback interface (`lo`).  Must match
/// `CACT_IFACE_FLAG_LOOPBACK` in `ioctl_abi.h`.
pub(crate) const IFACE_FLAG_LOOPBACK: u32 = 0x1;

/// Must match `cact_iface_info_t` in `ioctl_abi.h` byte for byte.
#[repr(C)]
pub struct CactIfaceInfo {
    /// NUL-terminated within `CACT_IFNAME_MAX` (16) bytes.
    pub name: [u8; 16],
    pub ip_host: u32,
    pub netmask_host: u32,
    pub gateway_host: u32,
    pub dns_host: u32,
    pub mac: [u8; 6],
    pub link_up: u32,
    pub flags: u32,
    /// Global/ULA IPv6 address (all-zero = none).
    pub ip6: [u8; 16],
    /// Prefix length for `ip6` (0 when `ip6` is absent).
    pub ip6_prefix: u32,
    /// Stack-derived link-local address (fe80::/64); always present on a NIC.
    pub ip6_link_local: [u8; 16],
    /// IPv6 default-route next hop (all-zero = none).
    pub ip6_gateway: [u8; 16],
    /// IPv6 resolver (all-zero = none).  Queried over IPv6, so a name can resolve
    /// on an interface that has no IPv4 address.
    pub ip6_dns: [u8; 16],
}

// The C `cact_iface_info_t` must stay byte-identical: 16 (name) + 4*4 (v4) + 6
// (mac) + 4 (link_up) + 4 (flags) + 16 (ip6) + 4 (prefix) + 16*3 (ll/gw/dns).
const _: () = assert!(core::mem::size_of::<CactIfaceInfo>() == 116);

/// Number of interfaces currently present: every registered NIC, then loopback,
/// or 0 when the stack is not up.  With no NIC the list is loopback-only, so `lo`
/// is index 0 and is alone; each NIC takes a leading index and `lo` stays last
/// (so a single NIC keeps the `[nic, lo]` view userspace already knows).
#[no_mangle]
pub extern "C" fn rust_net_iface_count() -> i32 {
    // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool` set by
    // `stack_init` and cleared by `stack_teardown`; a byte load cannot tear and
    // reading it as false simply reports "no interfaces".
    if !unsafe { stack::STACK_READY } {
        0
    } else {
        crate::runtime::rust_net_nic_count() + 1
    }
}

/// Fill `out` with interface `idx`.  Indices `0..nic_count` are the registered
/// NICs (in registration order, so index 0 is the primary) and the last index is
/// `lo`.  Returns 0 on success, -1 when `out` is NULL, the stack is down, or
/// `idx` is out of range.
///
/// # Safety
///
/// `out` may be null (the call then returns -1), but if non-null it must point to
/// a writable, properly aligned [`CactIfaceInfo`] that stays live for the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_iface_get(idx: u32, out: *mut CactIfaceInfo) -> i32 {
    if out.is_null() {
        return -1;
    }
    // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool`; a byte load
    // cannot tear.
    if !unsafe { stack::STACK_READY } {
        return -1;
    }
    let nics = crate::runtime::rust_net_nic_count();
    if idx as i32 >= nics + 1 {
        return -1;
    }
    // SAFETY: the caller contract (see # Safety) makes `out` a live, aligned
    // `CactIfaceInfo`, so this borrow is exclusive for the call and the byte
    // write below stays within the struct.
    let info = unsafe { &mut *out };
    // Zero first so an entry that is only partly filled never leaks whatever was
    // in the caller's buffer.
    // SAFETY: `info` points at one fully initialised `CactIfaceInfo`, so a
    // one-element byte fill is in bounds.
    unsafe { core::ptr::write_bytes(info as *mut CactIfaceInfo, 0, 1) };
    if (idx as i32) < nics {
        fill_nic(info, idx);
    } else {
        fill_loopback(info);
    }
    0
}

/// Configure interface `index`'s IPv4 (`CACT_NETCTL_IFACE_SETCFG`, root only).
/// Returns 0 on success, or -1 (`ENODEV`) when `index` is beyond the last NIC —
/// which also covers `lo`, the final index, since it owns no address of its own.
#[no_mangle]
pub extern "C" fn rust_net_iface_set_cfg(
    index: u32,
    ip_h: u32,
    mask_h: u32,
    gw_h: u32,
    dns_h: u32,
) -> i32 {
    let slot = runtime::rust_net_nic_slot(index);
    if slot < 0 {
        return -1;
    }
    crate::config::set_ipv4_config_slot(slot as usize, ip_h, mask_h, gw_h, dns_h)
}

/// Fill `info` with the `index`-th registered NIC and its own interface slot's
/// addressing.
fn fill_nic(info: &mut CactIfaceInfo, index: u32) {
    // SAFETY: `info.name` is a live 16-byte buffer and `rust_net_nic_ifname`
    // copies at most `cap` bytes, stopping at the terminator; it only fails
    // (returns -1) for an out-of-range index, which leaves the name empty.
    unsafe { runtime::rust_net_nic_ifname(index, info.name.as_mut_ptr(), info.name.len() as u32) };
    // SAFETY: as above, for the 6-byte MAC buffer.
    unsafe { runtime::rust_net_nic_mac(index, info.mac.as_mut_ptr()) };
    // Report the interface slot's own addressing.  A NIC that has not been
    // configured by userspace shows 0.0.0.0 (unnumbered) rather than the primary's
    // address, so `ip addr` never paints a secondary NIC with the wrong address.
    let slot = runtime::rust_net_nic_slot(index);
    if slot >= 0 {
        let s = slot as usize;
        info.ip_host = config::ip_host_of(s);
        info.netmask_host = config::netmask_host_of(s);
        info.gateway_host = config::gateway_host_of(s);
        info.dns_host = config::dns_host_of(s);
        info.ip6 = config::ipv6_addr_of(s);
        info.ip6_prefix = config::ipv6_prefix_of(s) as u32;
        info.ip6_link_local = config::ipv6_link_local_of(s);
        info.ip6_gateway = config::ipv6_gateway_of(s);
        info.ip6_dns = config::ipv6_dns_of(s);
    }
    info.link_up = 1;
    info.flags = 0;
}

fn fill_loopback(info: &mut CactIfaceInfo) {
    let name = stack::LOOPBACK_IFNAME;
    info.name[..name.len()].copy_from_slice(name);
    info.ip_host = stack::LOOPBACK_IP_HOST;
    info.netmask_host = stack::LOOPBACK_MASK_HOST;
    info.gateway_host = 0;
    info.dns_host = 0;
    // Loopback's IPv6 address is `::1/128`, the analogue of the 127.0.0.1/8 above.
    info.ip6 = config::IPV6_LOOPBACK;
    info.ip6_prefix = 128;
    info.link_up = 1;
    info.flags = IFACE_FLAG_LOOPBACK;
}

/// Configure interface `index`'s IPv6 global address (`CACT_NETCTL_IFACE_SETCFG6`,
/// root only).  Returns 0 on success, or -1 (`ENODEV`) when `index` is beyond the
/// last NIC — which also covers `lo`, the final index, since it owns no
/// configurable address of its own.
///
/// # Safety
///
/// `addr`, `gw` and `dns` must each point to 16 readable bytes that stay live for
/// the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_iface_set_cfg6(
    index: u32,
    addr: *const u8,
    prefix: u32,
    gw: *const u8,
    dns: *const u8,
) -> i32 {
    if addr.is_null() || gw.is_null() || dns.is_null() {
        return -1;
    }
    let slot = runtime::rust_net_nic_slot(index);
    if slot < 0 {
        return -1;
    }
    let mut a = [0u8; 16];
    let mut g = [0u8; 16];
    let mut d = [0u8; 16];
    // SAFETY: the caller contract (see # Safety) makes each pointer a live
    // 16-byte readable buffer, and each destination is a distinct 16-byte array.
    unsafe { core::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 16) };
    // SAFETY: as above, for `gw` into `g`.
    unsafe { core::ptr::copy_nonoverlapping(gw, g.as_mut_ptr(), 16) };
    // SAFETY: as above, for `dns` into `d`.
    unsafe { core::ptr::copy_nonoverlapping(dns, d.as_mut_ptr(), 16) };
    crate::config::set_ipv6_config_slot(slot as usize, a, prefix.min(128) as u8, g, d)
}

/// Configure the primary interface's (socket slot 0's) IPv6 global address
/// (`CACT_NETCTL_NETCFG6`, root only) — the dual-stack counterpart of
/// `rust_net_set_ipv4_config`.
///
/// # Safety
///
/// `addr`, `gw` and `dns` must each point to 16 readable bytes that stay live for
/// the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_set_ipv6_config(
    addr: *const u8,
    prefix: u32,
    gw: *const u8,
    dns: *const u8,
) -> i32 {
    if addr.is_null() || gw.is_null() || dns.is_null() {
        return -1;
    }
    let mut a = [0u8; 16];
    let mut g = [0u8; 16];
    let mut d = [0u8; 16];
    // SAFETY: the caller contract (see # Safety) makes each pointer a live
    // 16-byte readable buffer, and each destination is a distinct 16-byte array.
    unsafe { core::ptr::copy_nonoverlapping(addr, a.as_mut_ptr(), 16) };
    // SAFETY: as above, for `gw` into `g`.
    unsafe { core::ptr::copy_nonoverlapping(gw, g.as_mut_ptr(), 16) };
    // SAFETY: as above, for `dns` into `d`.
    unsafe { core::ptr::copy_nonoverlapping(dns, d.as_mut_ptr(), 16) };
    crate::config::set_ipv6_config_slot(0, a, prefix.min(128) as u8, g, d)
}
