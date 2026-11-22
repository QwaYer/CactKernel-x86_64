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
}

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

/// Fill `info` with the `index`-th registered NIC.
///
/// Only the primary NIC (index 0) carries the active datapath's IPv4
/// configuration.  A further NIC reports its real name and MAC but no address
/// and no link: it is registered and visible, yet the stack does not route
/// through it until per-NIC interfaces attach it.
fn fill_nic(info: &mut CactIfaceInfo, index: u32) {
    // SAFETY: `info.name` is a live 16-byte buffer and `rust_net_nic_ifname`
    // copies at most `cap` bytes, stopping at the terminator; it only fails
    // (returns -1) for an out-of-range index, which leaves the name empty.
    unsafe { runtime::rust_net_nic_ifname(index, info.name.as_mut_ptr(), info.name.len() as u32) };
    // SAFETY: as above, for the 6-byte MAC buffer.
    unsafe { runtime::rust_net_nic_mac(index, info.mac.as_mut_ptr()) };
    if index == 0 {
        info.ip_host = config::ip_host();
        info.netmask_host = config::netmask_host();
        info.gateway_host = config::gateway_host();
        info.dns_host = config::dns_host();
        info.link_up = 1;
    }
    info.flags = 0;
}

fn fill_loopback(info: &mut CactIfaceInfo) {
    let name = stack::LOOPBACK_IFNAME;
    info.name[..name.len()].copy_from_slice(name);
    info.ip_host = stack::LOOPBACK_IP_HOST;
    info.netmask_host = stack::LOOPBACK_MASK_HOST;
    info.gateway_host = 0;
    info.dns_host = 0;
    info.link_up = 1;
    info.flags = IFACE_FLAG_LOOPBACK;
}
