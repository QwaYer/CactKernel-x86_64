// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! smoltcp integration: one L3 interface per NIC slot, the Ethernet PHY shim, ICMP,
//! and the central poll loop.
//!
//! A NIC is bound to a fixed slot (`IFACES[i]`); the slot owns its `Interface`, its
//! own receive/transmit/loopback rings (`CactPhy`) and its own smoltcp `SocketSet`.
//! Per-slot socket sets are not a choice: smoltcp dispatches *every* socket through
//! the interface it is polled with, so two interfaces sharing one set would each
//! process the other's sockets.  A socket therefore lives on exactly one slot and is
//! polled only by it.
//!
//! Slot 0 always exists: it is the boot interface that keeps loopback alive before
//! any NIC registers, and the first NIC adopts it.  IPv4 addressing is owned by
//! userspace and stored per slot (see `config`).

use core::net::{Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicUsize, Ordering};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::icmp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

use crate::config;
use crate::ffi_kernel;
use crate::runtime;
use crate::skb;
use crate::types::{NetDriver, SockAddr, Skb};

/// Size of one frame buffer: a 1500-MTU Ethernet frame is 1514 bytes (14-byte
/// header + 1500 payload), so 1536 leaves room for VLAN tags.
const PHY_MTU: usize = 1536;

/// Frame MTU advertised to smoltcp.  smoltcp's `max_transmission_unit` is the
/// *frame* size including the Ethernet header (its `ip_mtu()` subtracts 14), so
/// the standard 1500-byte IP MTU is 1514 here.  Advertising the buffer size
/// instead made smoltcp build 1522-byte IP packets — oversized on every
/// 1500-MTU link, and a silent drop for a peer that is not QEMU/slirp.
const PHY_FRAME_MTU: usize = 1514;

/// Depth of the receive queue staged between the driver and `stack_poll`.
const RX_QUEUE_LEN: usize = 8;

pub(crate) const SOCKET_SET_SIZE: usize = 40;

/// Number of L3 interface slots; one per possible NIC, plus the boot slot 0 that
/// the first NIC adopts.
pub const NET_IF_MAX: usize = runtime::NET_NIC_MAX;

/// Loopback (`lo`) support.
///
/// The NIC interface additionally carries `127.0.0.1/8`, so 127/8 is *on-link*
/// (`in_same_network`), which makes smoltcp route such a packet to 127.0.0.1
/// itself (never through the default route to the gateway) and accept inbound
/// packets addressed to it.  Frames the stack emits to a 127/8 peer are then
/// looped back by the slot's PHY instead of being handed to the NIC, and a `lo`
/// entry is reported to userspace by [`crate::iface`].  Every slot carries the
/// loopback address, so a socket loops back within its own interface.
const LOOPBACK_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// The loopback prefix length (`127.0.0.0/8`).
const LOOPBACK_PREFIX: u8 = 8;

/// The loopback address in host byte order (most significant octet first).
pub(crate) const LOOPBACK_IP_HOST: u32 = 0x7F00_0001; // 127.0.0.1
/// The loopback prefix mask in host byte order (`255.0.0.0`, a `/8`).
pub(crate) const LOOPBACK_MASK_HOST: u32 = 0xFF00_0000;
/// The interface name of the loopback interface.
pub(crate) const LOOPBACK_IFNAME: &[u8] = b"lo";

/// The prefix length of an IPv6 link-local address (`fe80::/64`).
const LINK_LOCAL_PREFIX: u8 = 64;

/// The prefix length of the IPv6 loopback address (`::1/128`).
const IPV6_LOOPBACK_PREFIX: u8 = 128;

/// ff02::1, the IPv6 all-nodes link-local multicast group.  Every IPv6 host
/// joins it so Router Advertisements (sent there) are delivered.
const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Placeholder MAC for the boot slot before a NIC is registered.  Locally
/// administered and unicast.  `iface_attach` replaces it with the real hardware
/// address.
const DEFAULT_NIC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// True for an address in `127.0.0.0/8`.
#[inline]
pub(crate) fn is_loopback_ipv4_host(ip: u32) -> bool {
    ip >> 24 == 127
}

/// Serializes the interface slots between the background poll task and syscall
/// contexts.  With more than one CPU the poll task and a syscall can otherwise
/// run `iface.poll()` at the same time: that corrupts smoltcp's rings and, because
/// each slot's PHY stages received frames in its own ring, one frame is silently
/// overwritten and lost.
static mut STACK_LOCK: [u32; 2] = [0; 2]; // kernel irq_spinlock_t: spin + saved flags

/// Protects the RX rings (`phy.rx*`) alone.
///
/// It exists so the frame hand-off from a NIC driver (`stack_enqueue_rx`, which a
/// driver's `poll()` reaches through `netif_rx`) never waits on `STACK_LOCK`:
/// `stack_poll` calls the driver's `poll()` *while holding `STACK_LOCK`*, so taking
/// `STACK_LOCK` again there deadlocked the CPU on the first received frame —
/// interrupts off, no timer, no Ctrl+C, dhcpd hanging after one request.
///
/// Lock order is `STACK_LOCK` -> `RX_LOCK` and never the reverse: `receive()` runs
/// under `STACK_LOCK` (via `iface.poll`) and takes `RX_LOCK` inside it, while the RX
/// path takes `RX_LOCK` alone.
static mut RX_LOCK: [u32; 2] = [0; 2]; // kernel irq_spinlock_t: spin + saved flags

pub(crate) struct StackGuard;

impl StackGuard {
    #[inline]
    pub(crate) fn new() -> Self {
        // SAFETY: `STACK_LOCK` is a kernel-lifetime `irq_spinlock_t` static;
        // `addr_of_mut!` yields its stable, properly aligned address, which is what the
        // kernel's C acquire/release pair expects.
        unsafe {
            ffi_kernel::irq_spinlock_acquire(core::ptr::addr_of_mut!(STACK_LOCK).cast());
        }
        StackGuard
    }
}

impl Drop for StackGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: as in `StackGuard::new` — `STACK_LOCK` is a live kernel-lifetime
        // lock, and this is the matching release for the acquire in `StackGuard::new`.
        unsafe {
            ffi_kernel::irq_spinlock_release(core::ptr::addr_of_mut!(STACK_LOCK).cast());
        }
    }
}

/// Guard for the RX rings; see [`RX_LOCK`] for why it is separate from
/// [`StackGuard`].
pub(crate) struct RxGuard;

impl RxGuard {
    #[inline]
    fn new() -> Self {
        // SAFETY: `RX_LOCK` is a kernel-lifetime `irq_spinlock_t` static;
        // `addr_of_mut!` yields its stable, properly aligned address for the kernel's
        // C acquire/release pair.
        unsafe {
            ffi_kernel::irq_spinlock_acquire(core::ptr::addr_of_mut!(RX_LOCK).cast());
        }
        RxGuard
    }
}

impl Drop for RxGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: as in `RxGuard::new` — `RX_LOCK` is a live kernel-lifetime lock, and
        // this is the matching release for the acquire in `RxGuard::new`.
        unsafe {
            ffi_kernel::irq_spinlock_release(core::ptr::addr_of_mut!(RX_LOCK).cast());
        }
    }
}

/// Set after `stack_init` publishes the boot slot.
pub static mut STACK_READY: bool = false;

/// Slot a NIC driver's `poll()` is running for, so `netif_rx` (which lives in the
/// driver and carries no slot) can land the frame on the right interface.  Set
/// immediately around each driver `poll()` call in `stack_poll` and read from the
/// driver's RX callback, hence atomic.
static CURRENT_RX_SLOT: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn ticks_to_instant(ticks: u32) -> Instant {
    Instant::from_millis((ticks as i64).saturating_mul(10))
}

pub(crate) fn ipv4_from_host(ip: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ((ip >> 24) & 0xff) as u8,
        ((ip >> 16) & 0xff) as u8,
        ((ip >> 8) & 0xff) as u8,
        (ip & 0xff) as u8,
    )
}

fn mask_prefix_len(mask_host: u32) -> u8 {
    mask_host.count_ones() as u8
}

/// True while slot `slot` owns no real IPv4 address (nothing configured yet).
///
/// Userspace decides addressing, so between boot and the first lease the interface
/// carries only loopback.  This is the single source of truth for that state:
/// [`sync_iface_addrs_from_config`] keys the `any_ip` receive hack on it, and the
/// TX path uses it to keep the unconfigured stack from emitting off-link unicast
/// (see `SlotTxToken`'s `TxToken::consume`).
pub(crate) fn slot_unconfigured(slot: usize) -> bool {
    config::ip_host_of(slot) == 0 || config::netmask_host_of(slot) == 0
}

/// True when `frame` is an IPv4 Ethernet frame whose destination is neither
/// loopback (127/8) nor the limited broadcast (255.255.255.255).
///
/// Only consulted for the unconfigured stack; see `TxToken::consume`.
fn ipv4_dst_is_offlink_unicast(frame: &[u8]) -> bool {
    // 14-byte Ethernet header plus an IPv4 header far enough to reach the 4-byte
    // destination address at offset 30..34.
    if frame.len() < 34 {
        return false;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return false;
    }
    let dst = [frame[30], frame[31], frame[32], frame[33]];
    // 127/8 and the limited broadcast are the only destinations the stack may
    // legitimately reach while it owns no address of its own.
    !(dst[0] == 127 || dst == [0xff, 0xff, 0xff, 0xff])
}

/// True while slot `slot` owns no userspace-configured IPv6 address, i.e. it
/// carries only the stack-derived link-local.
///
/// The TX path uses it to keep an unaddressed interface from emitting off-link
/// global IPv6 sourced from the link-local address (see `TxToken::consume`).
pub(crate) fn slot_unconfigured_v6(slot: usize) -> bool {
    !config::ipv6_configured_of(slot)
}

/// The IPv6 link-local address for a 48-bit MAC (RFC 4291 Appendix A): fe80::/64
/// followed by the MAC with its universal/local bit flipped and `ff:fe`
/// inserted.  Every interface carries one so IPv6 neighbour discovery and any
/// SLAAC exchange work before userspace configures a global address.
pub(crate) fn link_local_from_mac(mac: [u8; 6]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[0] = 0xfe;
    o[1] = 0x80;
    o[8] = mac[0] ^ 0x02;
    o[9] = mac[1];
    o[10] = mac[2];
    o[11] = 0xff;
    o[12] = 0xfe;
    o[13] = mac[3];
    o[14] = mac[4];
    o[15] = mac[5];
    Ipv6Addr::from(o)
}

/// True when `frame` is an IPv6 Ethernet frame whose destination is global
/// unicast — neither link-local (fe80::/10) nor multicast (ff00::/8).
///
/// Only consulted for an interface with no configured global address; see
/// `TxToken::consume`.
fn ipv6_dst_is_offlink_global(frame: &[u8]) -> bool {
    // 14-byte Ethernet header plus the 16-byte IPv6 destination address, which
    // starts 24 octets into the IPv6 header (after version/flow, payload length,
    // next header and hop limit), i.e. frame offset 38..54.
    if frame.len() < 54 {
        return false;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x86DD {
        return false;
    }
    let dst = &frame[38..54];
    let is_multicast = dst[0] == 0xff;
    let is_link_local = dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80;
    // `::1` is the host's own loopback, not an off-link destination, so it must
    // pass this gate to reach the loopback staging in `TxToken::consume`.
    let is_loopback = dst == &config::IPV6_LOOPBACK[..];
    !(is_multicast || is_link_local || is_loopback)
}

/// Push slot `slot`'s IPv4 and IPv6 addressing and routes into its smoltcp
/// interface.  `mac` is the interface's hardware address, from which the IPv6
/// link-local is derived (and cached in `config` for the routing paths).
///
/// IPv4 addressing is owned by userspace and stored per slot; IPv6 likewise, on
/// top of the link-local every interface always carries.
pub(crate) fn sync_iface_addrs_from_config(iface: &mut Interface, slot: usize, mac: [u8; 6]) {
    let ip = ipv4_from_host(config::ip_host_of(slot));
    let gw = ipv4_from_host(config::gateway_host_of(slot));
    // "No address yet": addressing is decided in userspace, so between boot and
    // the first lease the interface owns nothing on the wire — yet the DHCP
    // client still has to receive its OFFER/ACK then (see the `any_ip` note).
    let unconfigured = slot_unconfigured(slot);

    // The link-local address is a pure function of the MAC; compute it and keep
    // the cached copy in `config` in step, so `route_slot_v6` / `slot_owning_ipv6`
    // agree with what the interface carries.
    let ll = link_local_from_mac(mac);
    config::set_ipv6_link_local_slot(slot, ll.octets());
    let addr6 = config::ipv6_addr_of(slot);
    let has_v6_global = addr6 != [0u8; 16];

    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        // The NIC address first: `get_source_address_ipv4` returns the first
        // entry, so this keeps the configured address as the default source for
        // off-box traffic (the loopback path pins 127.0.0.1 explicitly).
        if !unconfigured {
            let prefix = mask_prefix_len(config::netmask_host_of(slot));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ip), prefix));
        }
        // Always present: it makes 127/8 on-link (see the loopback note above)
        // and lets the interface accept packets addressed to 127.0.0.1.
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(LOOPBACK_IP), LOOPBACK_PREFIX));
        // IPv6: the configured global address (when set) goes before the
        // link-local so an off-link destination is sourced from a globally
        // scoped address; the link-local is always present.
        if has_v6_global {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Addr::from(addr6)),
                config::ipv6_prefix_of(slot),
            ));
        }
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(ll), LINK_LOCAL_PREFIX));
        // The IPv6 loopback goes on-link just as `127.0.0.1/8` does above, so
        // smoltcp routes to `::1` and accepts frames addressed to it.  It is last
        // so it is never the initial source-address candidate; RFC 6724 selection
        // still passes it over for every other destination (it is not a candidate
        // source for a link-local destination, and it never wins the scope or
        // prefix rules for a global one).
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv6(Ipv6Addr::from(config::IPV6_LOOPBACK)),
            IPV6_LOOPBACK_PREFIX,
        ));
    });
    iface.routes_mut().remove_default_ipv4_route();
    iface.routes_mut().remove_default_ipv6_route();

    if unconfigured {
        // smoltcp's IPv4 ingress drops a datagram unless its destination is one
        // of the interface's addresses, a multicast group, or a broadcast it
        // recognises.  With nothing but 127.0.0.1/8 configured, a DHCPOFFER
        // addressed to the *offered* address (unicast) or to the LAN's subnet
        // broadcast is therefore dropped before any socket sees it — dhcpd then
        // reports "no offer received" although the frame was received and
        // decrypted on the air.  `any_ip` lets such a datagram through once a
        // route resolves to an address the interface owns, so point the default
        // route at the loopback address we always carry.  Egress is untouched:
        // the client broadcasts (resolved straight to the Ethernet broadcast
        // address, never through the route table) from source 0.0.0.0, see
        // `udp::udp_sock_send`.  `any_ip` is switched back off the moment a real
        // address is configured.
        iface.set_any_ip(true);
        let _ = iface.routes_mut().add_default_ipv4_route(LOOPBACK_IP);
    } else {
        iface.set_any_ip(false);
        if config::gateway_host_of(slot) != 0 && !gw.is_unspecified() {
            let _ = iface.routes_mut().add_default_ipv4_route(gw);
        }
    }

    // IPv6 default route: the configured next hop (a router's link-local or
    // global address).  With none, off-link IPv6 has no path — honest, and what
    // an interface with only a link-local address should report.
    let gw6 = config::ipv6_gateway_of(slot);
    if gw6 != [0u8; 16] {
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::from(gw6));
    }

    // Join ff02::1 (all-nodes) so Router Advertisements reach the interface and
    // userspace can run SLAAC/DHCPv6.  Joining is idempotent; the solicited-node
    // groups for the addresses above are joined by smoltcp itself when the
    // address list is updated.
    let _ = iface.join_multicast_group(IpAddress::Ipv6(ALL_NODES_MULTICAST));
}

/// Resync slot `slot`'s interface addresses after a config change, holding the
/// stack lock (the callers are the userspace netcfg paths, which do not already
/// hold it).
pub(crate) fn resync_slot_addrs(slot: usize) {
    if slot >= NET_IF_MAX {
        return;
    }
    let _stack_guard = StackGuard::new();
    // SAFETY: `IFACES` is only used under `STACK_LOCK`, held here; `slot` is
    // bounds-checked above, so this is an in-bounds, exclusive borrow.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    let mac = s.mac;
    if let Some(iface) = s.iface.as_mut() {
        sync_iface_addrs_from_config(iface, slot, mac);
    }
}

/// One slot's PHY: the RX/TX/loopback rings.  It is deliberately PHY-only — the
/// driver it belongs to lives on the owning [`IfaceSlot`], so the same ring code
/// serves every slot.
struct CactPhy {
    /// Frames copied out of the driver's `Skb` by `stack_enqueue_rx` and drained by
    /// `receive()`.  A single slot used to hold the frame, so a NIC that delivered
    /// two frames before `net_poll_task` ran silently lost the first one.
    rx: [[u8; PHY_MTU]; RX_QUEUE_LEN],
    rx_len: [usize; RX_QUEUE_LEN],
    rx_head: usize,
    rx_tail: usize,
    /// Frames dropped because the queue was full; never reset while running.
    rx_dropped: u32,
    tx: [u8; PHY_MTU],
    /// Frames the stack emitted to a `127/8` peer.  Instead of the NIC they are
    /// staged here and re-injected into `rx` by [`Device::receive`], so loopback
    /// traffic never reaches the wire (see the loopback note above).
    lo: [[u8; PHY_MTU]; RX_QUEUE_LEN],
    lo_len: [usize; RX_QUEUE_LEN],
    lo_head: usize,
    lo_tail: usize,
    lo_dropped: u32,
}

impl CactPhy {
    const fn new() -> Self {
        Self {
            rx: [[0; PHY_MTU]; RX_QUEUE_LEN],
            rx_len: [0; RX_QUEUE_LEN],
            rx_head: 0,
            rx_tail: 0,
            rx_dropped: 0,
            tx: [0; PHY_MTU],
            lo: [[0; PHY_MTU]; RX_QUEUE_LEN],
            lo_len: [0; RX_QUEUE_LEN],
            lo_head: 0,
            lo_tail: 0,
            lo_dropped: 0,
        }
    }
}

/// One L3 interface slot: the NIC bound to it (if any) plus its smoltcp interface,
/// PHY rings and socket set.
struct IfaceSlot {
    /// The NIC descriptor bound to this slot, or null for the boot/loopback slot.
    drv: *mut NetDriver,
    mac: [u8; 6],
    name: [u8; 16],
    /// True once `iface`/`socks` have been built by `slot_build`.
    inited: bool,
    iface: Option<Interface>,
    socks: Option<SocketSet<'static>>,
    phy: CactPhy,
    icmp_handle: Option<SocketHandle>,
    icmp_ident_bound: u16,
}

impl IfaceSlot {
    const fn new() -> Self {
        Self {
            drv: core::ptr::null_mut(),
            mac: [0; 6],
            name: [0; 16],
            inited: false,
            iface: None,
            socks: None,
            phy: CactPhy::new(),
            icmp_handle: None,
            icmp_ident_bound: 0xFFFF,
        }
    }
}

/// The interface slots.  Only mutated under `STACK_LOCK` (via `StackGuard`), so a
/// syscall path and the poll task never build or tear down a slot concurrently.
static mut IFACES: [IfaceSlot; NET_IF_MAX] = [const { IfaceSlot::new() }; NET_IF_MAX];

/// Backing storage for each slot's `SocketSet`, kept as its own static (not a field
/// of [`IfaceSlot`]) so a `'static` borrow of the storage does not alias the slot.
/// Reset to `EMPTY` in `stack_teardown` before a slot is rebuilt.
static mut SOCKET_STORAGE: [[SocketStorage<'static>; SOCKET_SET_SIZE]; NET_IF_MAX] =
    [const { [SocketStorage::EMPTY; SOCKET_SET_SIZE] }; NET_IF_MAX];

/// Per-slot ICMP packet buffers.  Each slot owns its own kernel ICMP socket, so the
/// buffers cannot be shared between slots.
static mut ICMP_RX_META: [[icmp::PacketMetadata; 4]; NET_IF_MAX] =
    [[icmp::PacketMetadata::EMPTY; 4]; NET_IF_MAX];
static mut ICMP_RX_PAYLOAD: [[u8; 512]; NET_IF_MAX] = [[0; 512]; NET_IF_MAX];
static mut ICMP_TX_META: [[icmp::PacketMetadata; 4]; NET_IF_MAX] =
    [[icmp::PacketMetadata::EMPTY; 4]; NET_IF_MAX];
static mut ICMP_TX_PAYLOAD: [[u8; 512]; NET_IF_MAX] = [[0; 512]; NET_IF_MAX];

/// The solicited-node multicast address of `addr` (RFC 4291 § 2.7.1):
/// `ff02::1:ff00:0/104` with the low 24 bits of `addr`, matching smoltcp's own
/// `Ipv6Address::solicited_node`.  A Neighbor Solicitation is the only thing ever
/// addressed to this group, so matching it is what keeps our own resolution
/// probes local.
fn solicited_node(addr: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = 0xff;
    o[1] = 0x02;
    o[11] = 0x01;
    o[12] = 0xff;
    o[13] = addr[13];
    o[14] = addr[14];
    o[15] = addr[15];
    o
}

/// True when an IPv6 frame is addressed to an address the slot itself owns — the
/// loopback `::1`, its link-local, or its configured global — or to that
/// address's solicited-node multicast group.
///
/// Such a frame is meant for us, not the wire.  Neighbour resolution for our own
/// address would otherwise never finish: the solicitation goes out and nothing
/// answers.  Looping the *solicitation* back is what completes it — `process_ndisc`
/// learns the solicitation's source address and link-layer address *before* it
/// decides whether to answer — and every frame that follows then returns the same
/// way.
fn ipv6_is_self_addressed(frame: &[u8], slot: usize) -> bool {
    if frame.len() < 54 {
        return false;
    }
    let dst = &frame[38..54];
    for own in [
        config::IPV6_LOOPBACK,
        config::ipv6_addr_of(slot),
        config::ipv6_link_local_of(slot),
    ] {
        if own == [0u8; 16] {
            continue;
        }
        let sn = solicited_node(&own);
        if dst == &own[..] || dst == &sn[..] {
            return true;
        }
    }
    false
}

/// True when an Ethernet frame belongs to a loopback exchange and must be looped
/// back by the slot's PHY rather than transmitted.
///
/// IPv4 frames match on the source *or* destination being in 127/8: the
/// destination covers the request leg, and the source covers the reply leg when a
/// socket's local address was pinned to 127.0.0.1 while its peer is a 127/8
/// address.  ARP frames match on the sender or target protocol address, because
/// smoltcp resolves a 127/8 peer with ARP even though the exchange stays local.
/// IPv6 frames match on `::1` on either side, or on the destination being one of
/// the slot's own addresses ([`ipv6_is_self_addressed`]).
fn frame_involves_loopback(frame: &[u8], slot: usize) -> bool {
    if frame.len() < 14 {
        return false;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        // IPv4: the source address is at frame offset 26, the destination at 30
        // (14-byte Ethernet header + 12 bytes before the addresses).
        0x0800 => frame.len() >= 34 && (frame[26] == 127 || frame[30] == 127),
        // ARP over Ethernet/IPv4: sender protocol address at 28, target at 38.
        0x0806 => frame.len() >= 42 && (frame[28] == 127 || frame[38] == 127),
        // IPv6: the source address is at frame offset 22, the destination at 38
        // (14-byte Ethernet header + 8 bytes before the addresses).  `::1` on
        // either side marks a loopback exchange.
        0x86DD => {
            frame.len() >= 54
                && (frame[22..38] == config::IPV6_LOOPBACK
                    || frame[38..54] == config::IPV6_LOOPBACK
                    || ipv6_is_self_addressed(frame, slot))
        }
        _ => false,
    }
}

/// The driver bound to slot `slot`, or null.  Read-only fast path for the TX
/// token, which runs under `STACK_LOCK` and only needs the pointer.
fn slot_drv(slot: usize) -> *mut NetDriver {
    // SAFETY: `IFACES` is a kernel-lifetime static only mutated under `STACK_LOCK`,
    // which the caller holds; `slot < NET_IF_MAX` is the caller's contract, and an
    // aligned pointer load cannot tear.
    unsafe { (*core::ptr::addr_of!(IFACES))[slot].drv }
}

/// The device view handed to `Interface::poll`: it borrows a slot's PHY and carries
/// the slot's driver pointer so `TxToken::consume` can transmit on the right NIC.
struct SlotDev<'a> {
    phy: &'a mut CactPhy,
    drv: *mut NetDriver,
    /// Interface slot this device belongs to, so received ARP frames are learned
    /// against the right self-address ([`crate::arp::note_frame`]).
    slot: usize,
    unconfigured: bool,
    /// True when the slot carries no userspace-set global IPv6 address (only the
    /// derived link-local); used by the TX token to drop off-link global IPv6.
    unconfigured_v6: bool,
}

struct CactRxToken<'a> {
    slice: &'a [u8],
}

impl RxToken for CactRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.slice)
    }
}

/// TX token.  Besides the frame buffer it carries the loopback staging ring and the
/// slot's driver, so [`TxToken::consume`] can either divert a 127/8 frame into the
/// ring or hand the frame to the right NIC.  Every field is a distinct borrow of
/// the PHY, which is what keeps the split borrow-free.
struct CactTxToken<'a> {
    buf: &'a mut [u8; PHY_MTU],
    lo: &'a mut [[u8; PHY_MTU]; RX_QUEUE_LEN],
    lo_len: &'a mut [usize; RX_QUEUE_LEN],
    lo_head: &'a mut usize,
    lo_tail: &'a mut usize,
    lo_dropped: &'a mut u32,
    drv: *mut NetDriver,
    /// Interface slot this token transmits for; the loopback check needs its own
    /// addresses to recognise a self-addressed IPv6 frame.
    slot: usize,
    unconfigured: bool,
    unconfigured_v6: bool,
}

impl CactTxToken<'_> {
    /// Stage one already-built frame for loopback.  Drops it (counting the loss)
    /// when the staging ring is full — the peer's retransmission recovers it.
    fn push_loopback(&mut self, len: usize) {
        let next = (*self.lo_tail + 1) % RX_QUEUE_LEN;
        if next == *self.lo_head {
            *self.lo_dropped = self.lo_dropped.wrapping_add(1);
            return;
        }
        self.lo[*self.lo_tail][..len].copy_from_slice(&self.buf[..len]);
        self.lo_len[*self.lo_tail] = len;
        *self.lo_tail = next;
    }
}

impl TxToken for CactTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut this = self;
        let r = f(&mut this.buf[..len]);
        // While no address is configured the interface carries only loopback and
        // a default route pointing at it (see `sync_iface_addrs_from_config`), so
        // smoltcp sources *every* off-link flow from 127.0.0.1 and then accepts
        // the frame right back on ingress (`any_ip`).  For ICMP that means the
        // stack answers its own echo request: `ping` to any address "succeeds"
        // with a sub-millisecond RTT even with no network at all.  Drop such a
        // frame instead, so the failure is honest.  The DHCP client's broadcast
        // DISCOVER/REQUEST (destination 255.255.255.255) is not off-link unicast
        // and still leaves the box.
        if this.unconfigured && ipv4_dst_is_offlink_unicast(&this.buf[..len]) {
            return r;
        }
        // An interface that owns only a link-local IPv6 address must not emit
        // off-link global IPv6 sourced from that link-local (a router would drop
        // it); drop it so the failure is honest, as for IPv4 above.  Link-local
        // and multicast destinations are still allowed through.
        if this.unconfigured_v6 && ipv6_dst_is_offlink_global(&this.buf[..len]) {
            return r;
        }
        // The OUTPUT chain sees every frame the stack emits, before it is looped
        // back or handed to the NIC.
        if !crate::fw::hook_output(&this.buf[..len], this.slot) {
            return r;
        }
        if frame_involves_loopback(&this.buf[..len], this.slot) {
            this.push_loopback(len);
            return r;
        }
        let nic = this.drv;
        if !nic.is_null() {
            let skb = skb::skb_alloc();
            if !skb.is_null() {
                // SAFETY: `skb` is a fresh `Skb` this call exclusively owns and
                // `len` is bounded by `PHY_MTU` (the token's buffer length), so
                // `skb_put` writes inside its payload.
                let p = unsafe { skb::skb_put(skb, len as u16) };
                if !p.is_null() {
                    // SAFETY: `p` points to `len` writable bytes inside `skb`
                    // and `this.buf` is a local frame buffer, so the two ranges
                    // cannot overlap.
                    unsafe { core::ptr::copy_nonoverlapping(this.buf.as_ptr(), p, len) };
                    // SAFETY: `nic` is the slot's driver pointer (non-null checked
                    // above) and reading its `send` field only copies the function
                    // pointer.
                    let send = unsafe { (*nic).send };
                    if let Some(send) = send {
                        // The driver's TX entry point consumes `skb` (or frees
                        // it); it is a plain `extern "C"` pointer, so the call
                        // needs no `unsafe` block of its own.
                        let _ = send(skb);
                    } else {
                        skb::kfree_skb(skb);
                    }
                } else {
                    skb::kfree_skb(skb);
                }
            }
        }
        r
    }
}

impl Device for SlotDev<'_> {
    type RxToken<'a> = CactRxToken<'a> where Self: 'a;
    type TxToken<'a> = CactTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let drv = self.drv;
        let unconfigured = self.unconfigured;
        let unconfigured_v6 = self.unconfigured_v6;
        let phy: &mut CactPhy = &mut *self.phy;
        loop {
            let (slot, n) = {
                // Only the ring indices need the lock.  The producer never writes
                // the slot `rx_head` points at (it stops one short of it), so the
                // bytes cannot change after `rx_head` advances.
                let _rx_guard = RxGuard::new();
                // Re-inject frames looped back last egress into the RX ring first, so
                // the stack sees them on this poll.  A frame is left in `lo` if the RX
                // ring is momentarily full; the next call retries.
                while phy.lo_head != phy.lo_tail {
                    let next = (phy.rx_tail + 1) % RX_QUEUE_LEN;
                    if next == phy.rx_head {
                        break;
                    }
                    let lo_slot = phy.lo_head;
                    let m = phy.lo_len[lo_slot].min(PHY_MTU);
                    phy.rx[phy.rx_tail][..m].copy_from_slice(&phy.lo[lo_slot][..m]);
                    phy.rx_len[phy.rx_tail] = m;
                    phy.rx_tail = next;
                    phy.lo_head = (phy.lo_head + 1) % RX_QUEUE_LEN;
                }
                if phy.rx_head == phy.rx_tail {
                    return None;
                }
                let slot = phy.rx_head;
                phy.rx_head = (phy.rx_head + 1) % RX_QUEUE_LEN;
                (slot, phy.rx_len[slot].min(PHY_MTU))
            };
            // The INPUT chain sees every frame before the stack does, including
            // frames looped back from our own egress.  A dropped frame is simply
            // skipped; the next one in the ring is considered in its place.
            if !crate::fw::hook_input(&phy.rx[slot][..n], self.slot) {
                continue;
            }
            // Learn the neighbor from any ARP frame before smoltcp consumes it, so
            // the kernel's ARP table (`ip neigh`) mirrors the traffic on the wire.
            // Safe to touch the table directly here: `receive` runs under `STACK_LOCK`.
            crate::arp::note_frame(&phy.rx[slot][..n], self.slot);
            return Some((
                CactRxToken {
                    slice: &phy.rx[slot][..n],
                },
                CactTxToken {
                    buf: &mut phy.tx,
                    lo: &mut phy.lo,
                    lo_len: &mut phy.lo_len,
                    lo_head: &mut phy.lo_head,
                    lo_tail: &mut phy.lo_tail,
                    lo_dropped: &mut phy.lo_dropped,
                    drv,
                    slot: self.slot,
                    unconfigured,
                    unconfigured_v6,
                },
            ));
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let drv = self.drv;
        let unconfigured = self.unconfigured;
        let unconfigured_v6 = self.unconfigured_v6;
        let phy: &mut CactPhy = &mut *self.phy;
        Some(CactTxToken {
            buf: &mut phy.tx,
            lo: &mut phy.lo,
            lo_len: &mut phy.lo_len,
            lo_head: &mut phy.lo_head,
            lo_tail: &mut phy.lo_tail,
            lo_dropped: &mut phy.lo_dropped,
            drv,
            slot: self.slot,
            unconfigured,
            unconfigured_v6,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = PHY_FRAME_MTU;
        c.max_burst_size = Some(1);
        c.medium = Medium::Ethernet;
        c
    }
}

/// Build the smoltcp interface, socket set and kernel ICMP socket for slot `slot`
/// with hardware address `mac`.  Idempotent.  Runs under `STACK_LOCK`.
fn slot_build(slot: usize, mac: [u8; 6]) {
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    if s.inited {
        return;
    }
    let eth = EthernetAddress::from_bytes(&mac);
    let mut cfg = Config::new(HardwareAddress::Ethernet(eth));
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick counter;
    // it takes no pointers and is callable from this path.
    cfg.random_seed = u64::from(unsafe { ffi_kernel::timer_ticks_get() });
    // SAFETY: as above — the same monotonic tick read.
    let now = ticks_to_instant(unsafe { ffi_kernel::timer_ticks_get() });
    // The device is a view over this slot's PHY; `Interface::new` does not retain
    // it, so the borrow ends before `s.iface` is stored below.
    let mut dev = SlotDev {
        phy: &mut s.phy,
        drv: s.drv,
        slot,
        unconfigured: slot_unconfigured(slot),
        unconfigured_v6: slot_unconfigured_v6(slot),
    };
    let new_iface = Interface::new(cfg, &mut dev, now);
    s.iface = Some(new_iface);
    // SAFETY: `SOCKET_STORAGE[slot]` is the kernel-lifetime backing array for this
    // slot's one `SocketSet`; the `'static` borrow it yields cannot alias `IFACES`.
    let storage: &'static mut [SocketStorage<'static>] =
        unsafe { &mut (&mut (*core::ptr::addr_of_mut!(SOCKET_STORAGE))[slot])[..] };
    let new_set = SocketSet::new(storage);
    s.socks = Some(new_set);

    // Per-slot kernel ICMP socket (used by the `ping` syscall).
    let socks = s.socks.as_mut().unwrap();
    // SAFETY: `ICMP_RX_META[slot]` is a kernel-lifetime packet-metadata static owned
    // by this slot, handed to smoltcp only through this one socket, under the lock.
    let rx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_RX_META))[slot])[..] };
    // SAFETY: as above, for `ICMP_RX_PAYLOAD`.
    let rx_payload = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_RX_PAYLOAD))[slot])[..] };
    let icmp_rx = icmp::PacketBuffer::new(rx_meta, rx_payload);
    // SAFETY: as above, for `ICMP_TX_META`.
    let tx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_TX_META))[slot])[..] };
    // SAFETY: as above, for `ICMP_TX_PAYLOAD`.
    let tx_payload = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_TX_PAYLOAD))[slot])[..] };
    let icmp_tx = icmp::PacketBuffer::new(tx_meta, tx_payload);
    let icmp_sock = icmp::Socket::new(icmp_rx, icmp_tx);
    s.icmp_handle = Some(socks.add(icmp_sock));

    if let Some(iface) = s.iface.as_mut() {
        sync_iface_addrs_from_config(iface, slot, mac);
    }

    // The shared DNS resolver socket lives on slot 0 only; other slots carry no
    // resolver (DNS follows the default interface).
    if slot == 0 {
        // SAFETY: `init_socket`'s contract needs the caller to hold the stack lock
        // (or be `stack_init`, before the stack is published), which is this call.
        unsafe { crate::dns_resolve::init_socket(socks) };
    }

    s.inited = true;
}

pub fn stack_init() {
    let _stack_guard = StackGuard::new();
    // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool` read under
    // `STACK_LOCK`; a byte load reads either 0 or 1.
    if unsafe { STACK_READY } {
        return;
    }
    // The boot slot carries a placeholder MAC; a NIC adopts it on registration.
    slot_build(0, DEFAULT_NIC_MAC);
    // SAFETY: `STACK_READY` is published last, under the stack lock, once slot 0
    // is fully built.
    unsafe { STACK_READY = true };
    ffi_kernel::klog_static(
        ffi_kernel::LOG_OK,
        b"net: smoltcp stack ready (per-NIC slots, poll from net_poll_task)\0",
    );
}

/// Bind NIC `drv` (hardware address `mac`) to slot `slot`, building the slot's
/// interface if needed.  The interface name is read from the descriptor.  Called
/// from `register_netdev` on the single-threaded driver bring-up path.
pub(crate) fn iface_attach(slot: usize, drv: *mut NetDriver, mac: [u8; 6]) {
    let _stack_guard = StackGuard::new();
    slot_build(slot, mac);
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    s.drv = drv;
    s.mac = mac;
    s.name = [0; 16];
    if !drv.is_null() {
        // SAFETY: `drv` is a live descriptor (the caller's contract) and every
        // in-tree driver points `name` at a `'static` NUL-terminated literal.
        let np = unsafe { (*drv).name };
        if !np.is_null() {
            let cap = s.name.len();
            let mut k = 0usize;
            while k + 1 < cap {
                // SAFETY: `np` is a NUL-terminated literal, so byte `k` is in bounds
                // until the terminator is reached.
                let c = unsafe { *np.add(k) } as u8;
                if c == 0 {
                    break;
                }
                s.name[k] = c;
                k += 1;
            }
        }
    }
    if let Some(iface) = s.iface.as_mut() {
        iface.set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac)));
        sync_iface_addrs_from_config(iface, slot, mac);
    }
    // Drop any frames staged by the placeholder before the NIC was attached.
    {
        let _rx_guard = RxGuard::new();
        // SAFETY: the RX lock and the stack lock are held and no other stack user
        // exists on this single-threaded driver path, so this reset cannot race the
        // RX producer.
        s.phy = CactPhy::new();
    }
}

/// Release NIC `drv` from slot `slot`.  Slot 0 keeps its interface (loopback and any
/// live sockets survive a NIC unload); a higher slot only loses its driver binding.
pub(crate) fn iface_detach(slot: usize) {
    let _stack_guard = StackGuard::new();
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    s.drv = core::ptr::null_mut();
    s.name = [0; 16];
    if slot == 0 {
        // Restore the placeholder MAC so the boot slot stays loopback-capable.
        let mac = DEFAULT_NIC_MAC;
        s.mac = mac;
        if let Some(iface) = s.iface.as_mut() {
            iface.set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac)));
            sync_iface_addrs_from_config(iface, 0, mac);
        }
    }
    {
        let _rx_guard = RxGuard::new();
        // SAFETY: the RX lock and the stack lock are held and no other stack user
        // exists on this single-threaded teardown path, so this reset cannot race
        // the RX producer.
        s.phy = CactPhy::new();
    }
}

/// # Safety
///
/// The caller must be tearing the stack down from the single-threaded
/// driver-teardown path and must not be using the stack concurrently: this resets
/// every slot, so a concurrent `stack_poll` or syscall would observe a half-torn-down
/// stack.
pub unsafe fn stack_teardown() {
    let _stack_guard = StackGuard::new();
    // Release the shared DNS socket from slot 0's set before it is dropped.
    // SAFETY: the caller contract (see # Safety) excludes every other user of the
    // stack, and `STACK_LOCK` is held, so slot 0's `SocketSet` may be borrowed here.
    let socks0 = unsafe { (*core::ptr::addr_of_mut!(IFACES))[0].socks.as_mut() };
    if let Some(socks) = socks0 {
        // SAFETY: `socks` is the live slot-0 `SocketSet` and this call holds the
        // stack lock, which `remove_socket`'s contract requires.
        unsafe { crate::dns_resolve::remove_socket(socks) };
    }
    // SAFETY: exclusive access to the stack statics (see # Safety); the RX lock is
    // taken so a frame arriving concurrently is either already queued (and goes
    // away with the reset) or sees the cleared flag and is freed.
    {
        let _rx_guard = RxGuard::new();
        // SAFETY: exclusive access to `IFACES` (see # Safety) under the RX lock.
        let slots = unsafe { &mut *core::ptr::addr_of_mut!(IFACES) };
        for s in slots.iter_mut() {
            *s = IfaceSlot::new();
        }
        // SAFETY: exclusive access to `SOCKET_STORAGE` (see # Safety); every slot set
        // was just dropped, so its backing storage is reset before a rebuild.
        let storage = unsafe { &mut *core::ptr::addr_of_mut!(SOCKET_STORAGE) };
        for arr in storage.iter_mut() {
            for st in arr.iter_mut() {
                *st = SocketStorage::EMPTY;
            }
        }
        // SAFETY: `STACK_READY` is cleared under the RX lock so a concurrent frame
        // either is already queued or is freed.
        unsafe { STACK_READY = false };
    }
    // SAFETY: still under `STACK_LOCK` with the stack torn down, so the TCP and
    // UDP reset helpers have exclusive access to their tables, as their own
    // contracts require.
    unsafe { crate::tcp::reset_tcp_smoltcp_state() };
    // SAFETY: as above, for the UDP tables.
    unsafe { crate::udp::reset_udp_smoltcp_state() };
    // SAFETY: as above — stack teardown, `STACK_READY` already cleared.
    unsafe { crate::raw::reset_raw_smoltcp_state() };
}

/// Poll every slot: first drain each NIC's RX (calling its `poll()` while tagging
/// the current slot so `netif_rx` lands frames correctly), then advance every
/// interface's smoltcp state.
pub fn stack_poll() {
    let _stack_guard = StackGuard::new();
    // 1. Drain every NIC.  The driver's `poll()` reaches `netif_rx` through its RX
    //    path, which reads `CURRENT_RX_SLOT` to pick the destination interface.
    for slot in 0..NET_IF_MAX {
        let drv = slot_drv(slot);
        if drv.is_null() {
            continue;
        }
        // SAFETY: `drv` is a live registered descriptor (non-null checked) and
        // reading its `poll` field only copies the function pointer.
        let poll = unsafe { (*drv).poll };
        if let Some(poll) = poll {
            // `poll` is the driver's RX entry point; it is called here while
            // `STACK_LOCK` is held, as the driver contract requires.
            CURRENT_RX_SLOT.store(slot, Ordering::Release);
            poll();
        }
    }
    CURRENT_RX_SLOT.store(0, Ordering::Release);
    // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool`; a byte load
    // reads either 0 or 1.
    if !unsafe { STACK_READY } {
        return;
    }
    // SAFETY: `timer_ticks_get` is a kernel C service that reads the tick counter;
    // it is callable from task context.
    let now = ticks_to_instant(unsafe { ffi_kernel::timer_ticks_get() });
    for slot in 0..NET_IF_MAX {
        // SAFETY: `IFACES` is only used under `STACK_LOCK`, held here, so these are
        // disjoint field borrows of one live slot.
        let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
        if !s.inited {
            continue;
        }
        let drv = s.drv;
        let unconfigured = slot_unconfigured(slot);
        let unconfigured_v6 = slot_unconfigured_v6(slot);
        let mut dev = SlotDev {
            phy: &mut s.phy,
            drv,
            slot,
            unconfigured,
            unconfigured_v6,
        };
        if let (Some(iface), Some(socks)) = (s.iface.as_mut(), s.socks.as_mut()) {
            iface.poll(now, &mut dev, socks);
            crate::tcp::sync_tcp_pcbs_from_smoltcp(slot, socks);
            crate::udp::sync_udp_pcbs_from_smoltcp(slot, socks);
            crate::raw::sync_raw_from_smoltcp(slot, socks);
        }
    }
    // Age out idle connection-tracking entries once per poll.  Safe here: the
    // hooks that feed the table run under this same lock, and `age` takes no
    // lock of its own.
    crate::conntrack::age();
}

/// Copy one Ethernet frame from the driver's `Skb` into the current slot's RX queue
/// and wake `net_poll_task`.
///
/// Entered from a NIC driver's RX path, which `stack_poll` drives by calling the
/// driver's `poll()` with `CURRENT_RX_SLOT` set to the slot being polled, so the
/// hand-off takes only [`RX_LOCK`] — the inner lock — and never `STACK_LOCK`.
///
/// # Safety
///
/// `skb` must be null or a live, initialised [`Skb`] that this call owns (a frame
/// received by a NIC driver): it is either queued or freed exactly once here, so
/// the caller must not use it afterwards.
pub unsafe fn stack_enqueue_rx(skb: *mut Skb) {
    if skb.is_null() {
        return;
    }
    // SAFETY: the caller contract (see # Safety) makes `skb` a live, initialised
    // `Skb` this call owns, so `skb_len` reads a real length.
    let len = unsafe { skb::skb_len(skb) } as usize;
    if len == 0 || len > PHY_MTU {
        skb::kfree_skb(skb);
        return;
    }
    // SAFETY: as above — `skb` is live and initialised for this call, so
    // `skb_data` returns a pointer to its payload.
    let src = unsafe { skb::skb_data(skb) };
    let slot = CURRENT_RX_SLOT.load(Ordering::Acquire);
    let slot = if slot < NET_IF_MAX { slot } else { 0 };
    let queued = {
        let _rx_guard = RxGuard::new();
        // STACK_READY is read under the lock so a frame cannot slip into the ring
        // between `stack_teardown` resetting it and clearing the flag.
        // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool`; a byte load
        // reads either 0 or 1 and cannot tear.
        if !unsafe { STACK_READY } {
            skb::kfree_skb(skb);
            return;
        }
        // SAFETY: `IFACES` is the kernel-lifetime slot table whose ring is protected
        // by the `RX_LOCK` just taken, so this borrow is exclusive and is dead before
        // the wake-up below; `slot` is in range.
        let phy = unsafe { &mut (*core::ptr::addr_of_mut!(IFACES))[slot].phy };
        let next = (phy.rx_tail + 1) % RX_QUEUE_LEN;
        if next == phy.rx_head {
            // Full: the stack is not draining as fast as the NIC fills it.  Drop the
            // newest frame (the older ones are already in flight) and keep a counter,
            // so the loss is at least visible.
            phy.rx_dropped = phy.rx_dropped.wrapping_add(1);
            false
        } else {
            // SAFETY: `src` points to `len` initialised bytes of `skb` and
            // `phy.rx[phy.rx_tail]` is a `PHY_MTU`-byte slot with `len <= PHY_MTU`; the
            // two are distinct objects.
            unsafe { core::ptr::copy_nonoverlapping(src, phy.rx[phy.rx_tail].as_mut_ptr(), len) };
            phy.rx_len[phy.rx_tail] = len;
            phy.rx_tail = next;
            true
        }
    };
    skb::kfree_skb(skb);
    if queued {
        // Woken outside the lock: `up` can reach the scheduler, and this path may
        // hold interrupts off.
        // SAFETY: `runtime::net_sema` is a kernel-lifetime semaphore; `up` is the
        // matching kernel C release service.
        unsafe { ffi_kernel::up(core::ptr::addr_of_mut!(runtime::net_sema)) };
    }
}

/// Frames dropped because slot 0's RX queue was full (diagnostics).
pub fn stack_rx_dropped() -> u32 {
    let _rx_guard = RxGuard::new();
    // SAFETY: `IFACES` is a kernel-lifetime static whose `rx_dropped` counter is only
    // written under `RX_LOCK`, which `_rx_guard` holds here; a `u32` load cannot tear.
    unsafe { (*core::ptr::addr_of!(IFACES))[0].phy.rx_dropped }
}

/// Run `f` against slot `slot`'s interface and socket set, holding `STACK_LOCK`.
/// Returns `None` when the slot is out of range or not built.
pub(crate) fn with_slot<R, F>(slot: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut Interface, &mut SocketSet<'static>) -> R,
{
    if slot >= NET_IF_MAX {
        return None;
    }
    let _stack_guard = StackGuard::new();
    // SAFETY: `IFACES` is only used under `STACK_LOCK`, which this call holds, so the
    // borrow is exclusive for the closure body; `slot` is bounds-checked above.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    let iface = s.iface.as_mut()?;
    let socks = s.socks.as_mut()?;
    Some(f(iface, socks))
}

/// Run `f` against slot `slot`'s socket set only, holding `STACK_LOCK` — the common
/// case for socket operations that do not need the interface.
pub(crate) fn with_slot_socks<R, F>(slot: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut SocketSet<'static>) -> R,
{
    with_slot(slot, |_iface, socks| f(socks))
}

/// Run `f` holding `STACK_LOCK` without touching any slot — for the UDP metadata
/// tables, which are guarded by the same lock but do not need a slot's socket set.
/// Must not be called with `STACK_LOCK` already held (it is not recursive).
pub(crate) fn with_stack_lock<R, F>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _stack_guard = StackGuard::new();
    f()
}

/// Backwards-compatible accessor for the primary slot (index 0).
pub(crate) fn with_iface_sockets<R, F>(f: F) -> Option<R>
where
    F: FnOnce(&mut Interface, &mut SocketSet<'static>) -> R,
{
    with_slot(0, f)
}

/// Fire-and-forget ICMPv4/IPv6 echo request for the interface that would carry
/// `dst`.  The family is decided by `dst`.
fn icmp_echo_request(dst: SockAddr, id: u16, seq: u16) -> bool {
    let slot = match dst {
        SockAddr::V4(v) => crate::config::route_slot(v),
        SockAddr::V6(a) => crate::config::route_slot_v6(a),
    };
    let _stack_guard = StackGuard::new();
    // SAFETY: `STACK_READY` is a kernel-lifetime `static mut bool` read under
    // `STACK_LOCK`; a byte load reads either 0 or 1.
    if !unsafe { STACK_READY } {
        return false;
    }
    // SAFETY: `IFACES` is only used under `STACK_LOCK`, which this call holds; `slot`
    // comes from `route_slot` and is in range.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
    // SAFETY: `icmp_handle` is only accessed under `STACK_LOCK`; copying the
    // `Option` cannot tear.
    let Some(icmp_h) = (unsafe { *core::ptr::addr_of!(s.icmp_handle) }) else {
        return false;
    };
    let (Some(_iface), Some(socks)) = (s.iface.as_mut(), s.socks.as_mut()) else {
        return false;
    };
    // SAFETY: `icmp_ident_bound` is a kernel-lifetime slot field read under the stack
    // lock.
    let ident_bound = s.icmp_ident_bound;
    let need_replace = {
        let sock = socks.get_mut::<icmp::Socket>(icmp_h);
        sock.is_open() && ident_bound != id
    };
    if need_replace {
        let _ = socks.remove(icmp_h);
        // SAFETY: `ICMP_*[slot]` are kernel-lifetime packet-buffer statics owned by
        // this slot, handed to smoltcp only through this one socket, under the lock.
        let rx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_RX_META))[slot])[..] };
        // SAFETY: as above, for `ICMP_RX_PAYLOAD`.
        let rx_payload = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_RX_PAYLOAD))[slot])[..] };
        let icmp_rx = icmp::PacketBuffer::new(rx_meta, rx_payload);
        // SAFETY: as above, for `ICMP_TX_META`.
        let tx_meta = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_TX_META))[slot])[..] };
        // SAFETY: as above, for `ICMP_TX_PAYLOAD`.
        let tx_payload = unsafe { &mut (&mut (*core::ptr::addr_of_mut!(ICMP_TX_PAYLOAD))[slot])[..] };
        let icmp_tx = icmp::PacketBuffer::new(tx_meta, tx_payload);
        let icmp_sock = icmp::Socket::new(icmp_rx, icmp_tx);
        s.icmp_handle = Some(socks.add(icmp_sock));
        s.icmp_ident_bound = 0xFFFF;
    }
    let Some(icmp_h) = s.icmp_handle else {
        return false;
    };
    let sock = socks.get_mut::<icmp::Socket>(icmp_h);
    if !sock.is_open() {
        if sock.bind(icmp::Endpoint::Ident(id)).is_err() {
            return false;
        }
        s.icmp_ident_bound = id;
    }
    let ip_dst = dst.to_ip();
    use smoltcp::phy::ChecksumCapabilities;
    /* 56 bytes of data make the ICMP message 64 bytes, matching the default
     * Linux `ping` payload so the reply sizes read the same. */
    const PAYLOAD: &[u8] = b"CactOS ping! 0123456789012345678901234567890123456789012";
    match dst {
        SockAddr::V4(_) => {
            use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
            let repr = Icmpv4Repr::EchoRequest {
                ident: id,
                seq_no: seq,
                data: PAYLOAD,
            };
            let total = repr.buffer_len();
            let buf = match sock.send(total, ip_dst) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let mut pkt = Icmpv4Packet::new_unchecked(buf);
            repr.emit(&mut pkt, &ChecksumCapabilities::default());
        }
        SockAddr::V6(a) => {
            use smoltcp::wire::{Icmpv6Packet, Icmpv6Repr, Ipv6Address};
            let repr = Icmpv6Repr::EchoRequest {
                ident: id,
                seq_no: seq,
                data: PAYLOAD,
            };
            let total = repr.buffer_len();
            let buf = match sock.send(total, ip_dst) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let mut pkt = Icmpv6Packet::new_unchecked(buf);
            // The ICMPv6 checksum covers the IPv6 pseudo-header; the socket
            // re-emits the frame with the interface's real source address (and
            // recomputes it there), so this best-effort value is not what goes
            // on the wire.
            repr.emit(
                &Ipv6Address::LOCALHOST,
                &Ipv6Address::from(a),
                &mut pkt,
                &ChecksumCapabilities::default(),
            );
        }
    }
    true
}

/// Fire-and-forget ICMPv4 echo request for the interface that would carry `dst`.
pub fn icmp_echo_request_host(dst_ip_host: u32, id: u16, seq: u16) -> bool {
    icmp_echo_request(SockAddr::V4(dst_ip_host), id, seq)
}

/// Fire-and-forget ICMPv6 echo request (destination as sixteen big-endian octets).
pub fn icmp_echo_request6_host(addr: [u8; 16], id: u16, seq: u16) -> bool {
    icmp_echo_request(SockAddr::V6(addr), id, seq)
}

/// Dequeue the echo reply matching `(id, seq)` from the kernel ICMP socket of the
/// interface that would carry `src_hint` (the probe's destination).
///
/// The socket is bound to `Ident(id)`, so smoltcp already filters by identifier; the
/// sequence check is what tells one probe from the next.  Returns `(source address,
/// ICMP message length)`; the address is the responder's, in either family.
pub fn icmp_try_recv_reply(id: u16, seq: u16) -> Option<(IpAddress, usize)> {
    let _stack_guard = StackGuard::new();
    // Search every built slot: the reply may arrive on the interface the request
    // was routed to, which the caller does not pass back to us.
    for slot in 0..NET_IF_MAX {
        // SAFETY: `IFACES` is only used under `STACK_LOCK`, held here.
        let s = unsafe { &mut *core::ptr::addr_of_mut!(IFACES[slot]) };
        if !s.inited {
            continue;
        }
        // SAFETY: `icmp_handle` is read under the stack lock; copying the `Option`
        // cannot tear.
        let Some(handle) = (unsafe { *core::ptr::addr_of!(s.icmp_handle) }) else {
            continue;
        };
        let Some(socks) = s.socks.as_mut() else {
            continue;
        };
        let sock = socks.get_mut::<icmp::Socket>(handle);
        loop {
            let Ok((payload, addr)) = sock.recv() else {
                break;
            };
            let caps = smoltcp::phy::ChecksumCapabilities::ignored();
            // The one kernel ICMP socket feeds both families; try ICMPv4 first,
            // then ICMPv6.  `addr` picks which family this datagram is.
            match addr {
                IpAddress::Ipv4(_) => {
                    let Ok(pkt) = smoltcp::wire::Icmpv4Packet::new_checked(payload) else {
                        continue;
                    };
                    let Ok(smoltcp::wire::Icmpv4Repr::EchoReply { ident, seq_no, .. }) =
                        smoltcp::wire::Icmpv4Repr::parse(&pkt, &caps)
                    else {
                        continue;
                    };
                    if ident == id && seq_no == seq {
                        return Some((addr, payload.len()));
                    }
                }
                IpAddress::Ipv6(v6) => {
                    let Ok(pkt) = smoltcp::wire::Icmpv6Packet::new_checked(payload) else {
                        continue;
                    };
                    // The ICMPv6 checksum covers the pseudo-header; the socket
                    // already verified it on ingress, so parse with ignored caps
                    // (the src/dst are then not consulted).
                    let Ok(smoltcp::wire::Icmpv6Repr::EchoReply { ident, seq_no, .. }) =
                        smoltcp::wire::Icmpv6Repr::parse(&v6, &v6, &pkt, &caps)
                    else {
                        continue;
                    };
                    if ident == id && seq_no == seq {
                        return Some((addr, payload.len()));
                    }
                }
            }
        }
    }
    None
}
