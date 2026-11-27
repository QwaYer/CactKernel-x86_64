// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! In-kernel packet filter (firewall) — a small netfilter.
//!
//! A chain holds ordered rules and a default policy; the first rule that matches
//! a frame decides its verdict and, when no rule matches, the chain's policy
//! applies.  Rules and policies are set from userspace through `/dev/net`
//! (`CACT_NETCTL_FW_*`); with no rules the policy is `ACCEPT`, so an
//! unconfigured kernel behaves exactly as before the firewall existed.
//!
//! Evaluation sits where the stack meets the wire and is family-agnostic: the
//! INPUT chain sees every frame pulled off a slot's receive ring, the OUTPUT
//! chain every frame the stack is about to emit.  ARP is never filtered — it is
//! L2 and belongs to a bridge, not to an IP firewall — so an INPUT `DROP` policy
//! still leaves neighbour resolution working.  A frame whose L3 header cannot be
//! parsed is likewise accepted untouched.
//!
//! On top of the filter there is NAT.  The PREROUTING and POSTROUTING chains hold
//! translation rules (`SNAT`/`MASQUERADE`/`DNAT`/`REDIRECT`); when one matches,
//! the frame is rewritten in place — addresses, ports and the affected checksums
//! — and the translation is recorded in the flow's conntrack entry so the reply
//! leg is translated back.  NAT here applies to flows the box terminates or
//! originates (a `DNAT`/`REDIRECT` to a local address, an `SNAT`/`MASQUERADE` of
//! the box's own traffic); routing packets *between* interfaces needs a
//! forwarding layer the stack does not have yet.

use kernel_rust::ptr;

use crate::config;
use crate::conntrack::{self, Key};
use crate::stack::StackGuard;

// ── ABI constants (mirror CACT_FW_* in ioctl_abi.h) ─────────────────────────

/// Frame delivered to the local stack.
pub const FW_CHAIN_INPUT: u8 = 0;
/// Frame emitted by the local stack.
pub const FW_CHAIN_OUTPUT: u8 = 1;
/// Frame routed through the box (reserved for the forwarding path).
pub const FW_CHAIN_FORWARD: u8 = 2;
/// DNAT/redirect hook, before the routing decision.
pub const FW_CHAIN_PREROUTING: u8 = 3;
/// SNAT/masquerade hook, after the routing decision.
pub const FW_CHAIN_POSTROUTING: u8 = 4;
/// Number of chains; must match `CACT_FW_CHAIN_COUNT`.
pub const FW_CHAIN_COUNT: usize = 5;

pub const FW_ACTION_ACCEPT: u8 = 0;
pub const FW_ACTION_DROP: u8 = 1;
const FW_ACTION_SNAT: u8 = 2;
const FW_ACTION_DNAT: u8 = 3;
const FW_ACTION_MASQUERADE: u8 = 4;
const FW_ACTION_REDIRECT: u8 = 5;

const FW_FAMILY_V4: u8 = 4;
const FW_FAMILY_V6: u8 = 6;

const FW_PROTO_ANY: u8 = 0;
const FW_PROTO_ICMP: u8 = 1;
const FW_PROTO_TCP: u8 = 6;
const FW_PROTO_UDP: u8 = 17;
const FW_PROTO_ICMPV6: u8 = 58;

const FW_IFACE_ANY: u8 = 0xFF;
const FW_ICMP_ANY: u8 = 0xFF;

/// Maximum rules per chain; must match `CACT_FW_RULES_MAX`.
pub const FW_RULES_MAX: usize = 64;

/// Policy values share the `CACT_FW_ACTION_ACCEPT` / `_DROP` numbering.

/// One filter rule, byte-for-byte the C `cact_fw_rule_t` (88 bytes).  Addresses
/// are big-endian; an IPv4 address lives in the first four bytes (`src[0..4]`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwRule {
    pub chain: u8,
    pub action: u8,
    pub family: u8,
    pub proto: u8,
    pub has_src: u8,
    pub has_dst: u8,
    pub src_prefix: u8,
    pub dst_prefix: u8,
    pub state_mask: u8,
    pub icmp_type: u8,
    pub in_iface: u8,
    pub _pad: u8,
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub nat_port: u16,
    pub _pad2: u16,
    pub packets: u64,
    pub bytes: u64,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub nat_addr: [u8; 16],
}

impl FwRule {
    const fn empty() -> Self {
        Self {
            chain: 0,
            action: 0,
            family: 0,
            proto: 0,
            has_src: 0,
            has_dst: 0,
            src_prefix: 0,
            dst_prefix: 0,
            state_mask: 0,
            icmp_type: FW_ICMP_ANY,
            in_iface: FW_IFACE_ANY,
            _pad: 0,
            src_port_min: 0,
            src_port_max: 0,
            dst_port_min: 0,
            dst_port_max: 0,
            nat_port: 0,
            _pad2: 0,
            packets: 0,
            bytes: 0,
            src: [0; 16],
            dst: [0; 16],
            nat_addr: [0; 16],
        }
    }
}

// The C `cact_fw_rule_t` must stay byte-identical.
const _: () = assert!(core::mem::size_of::<FwRule>() == 88);

/// The rule tables, one array per chain.  Mutated only under `STACK_LOCK`: the
/// configuration ioctls take the guard, and the hooks already run under it
/// (`SlotDev::receive` and the TX token are reached from `iface.poll`), so a
/// rule cannot change under a frame being evaluated.
static mut RULES: [[FwRule; FW_RULES_MAX]; FW_CHAIN_COUNT] =
    [[FwRule::empty(); FW_RULES_MAX]; FW_CHAIN_COUNT];

/// Live rule count per chain (the rule at index `RULE_COUNT[ch]` is unused).
static mut RULE_COUNT: [u32; FW_CHAIN_COUNT] = [0; FW_CHAIN_COUNT];

/// Default policy per chain (`FW_ACTION_ACCEPT` / `FW_ACTION_DROP`).
static mut POLICY: [u8; FW_CHAIN_COUNT] = [FW_ACTION_ACCEPT; FW_CHAIN_COUNT];

/// The parsed L3/L4 view of one frame, copied out so the match loop holds no
/// borrow of the frame buffer.
struct Pkt {
    family: u8,
    proto: u8,
    icmp_type: u8,
    tcp_flags: u8,
    /// False when there is no usable L4 header (fragment, or an unparsed IPv6
    /// extension header), so port rules cannot match.
    has_l4: bool,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    /// Offset of the L4 header inside the frame (used to locate an ICMP error's
    /// embedded packet).
    l4: usize,
    /// Length of the L3 datagram, for the byte counters.
    l3_len: u32,
}

impl Pkt {
    /// Parse an Ethernet frame into its L3/L4 fields.  `None` when it is not IP
    /// (ARP, and anything else the filter does not police).
    fn parse(frame: &[u8]) -> Option<Pkt> {
        if frame.len() < 14 {
            return None;
        }
        match u16::from_be_bytes([frame[12], frame[13]]) {
            0x0800 => Self::parse_ipv4(frame),
            0x86DD => Self::parse_ipv6(frame),
            _ => None,
        }
    }

    fn parse_ipv4(frame: &[u8]) -> Option<Pkt> {
        if frame.len() < 34 {
            return None;
        }
        let ihl = (frame[14] & 0x0F) as usize * 4;
        if ihl < 20 || 14 + ihl > frame.len() {
            return None;
        }
        let proto = frame[23];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src[..4].copy_from_slice(&frame[26..30]);
        dst[..4].copy_from_slice(&frame[30..34]);
        let l3_len = u16::from_be_bytes([frame[16], frame[17]]) as u32;
        // A non-first fragment carries no L4 header.
        let fragmented = u16::from_be_bytes([frame[20], frame[21]]) & 0x1FFF != 0;
        let l4 = 14 + ihl;
        let (has_l4, sport, dport, icmp_type, tcp_flags) =
            Self::parse_l4(frame, proto, l4, fragmented);
        Some(Pkt {
            family: FW_FAMILY_V4,
            proto,
            icmp_type,
            tcp_flags,
            has_l4,
            src,
            dst,
            sport,
            dport,
            l4,
            l3_len,
        })
    }

    fn parse_ipv6(frame: &[u8]) -> Option<Pkt> {
        if frame.len() < 54 {
            return None;
        }
        let proto = frame[20];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&frame[22..38]);
        dst.copy_from_slice(&frame[38..54]);
        let l3_len = 40 + u16::from_be_bytes([frame[18], frame[19]]) as u32;
        // Extension headers are not walked: only a directly following L4 header
        // is parsed, so a rule with a port constraint simply does not match a
        // frame that carries one.
        let (has_l4, sport, dport, icmp_type, tcp_flags) =
            Self::parse_l4(frame, proto, 54, false);
        Some(Pkt {
            family: FW_FAMILY_V6,
            proto,
            icmp_type,
            tcp_flags,
            has_l4,
            src,
            dst,
            sport,
            dport,
            l4: 54,
            l3_len,
        })
    }

    /// Extract the `(has_l4, sport, dport, icmp_type, tcp_flags)` tuple.  `no_l4`
    /// is set when the L3 header already says there is no L4 header (an IPv4
    /// fragment).
    fn parse_l4(
        frame: &[u8],
        proto: u8,
        l4: usize,
        no_l4: bool,
    ) -> (bool, u16, u16, u8, u8) {
        match proto {
            FW_PROTO_TCP | FW_PROTO_UDP => {
                if no_l4 || l4 + 4 > frame.len() {
                    return (false, 0, 0, FW_ICMP_ANY, 0);
                }
                let sport = u16::from_be_bytes([frame[l4], frame[l4 + 1]]);
                let dport = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
                // The TCP flags byte is the low byte of the 14th octet.
                let flags = if proto == FW_PROTO_TCP && l4 + 14 <= frame.len() {
                    frame[l4 + 13]
                } else {
                    0
                };
                (true, sport, dport, FW_ICMP_ANY, flags)
            }
            FW_PROTO_ICMP | FW_PROTO_ICMPV6 => {
                if no_l4 || l4 >= frame.len() {
                    return (false, 0, 0, FW_ICMP_ANY, 0);
                }
                (true, 0, 0, frame[l4], 0)
            }
            _ => (false, 0, 0, FW_ICMP_ANY, 0),
        }
    }
}

/// True when `a` and `b` agree in the top `prefix` bits of a `family` address.
fn addr_eq_prefix(a: &[u8; 16], b: &[u8; 16], prefix: u8, family: u8) -> bool {
    let len = if family == FW_FAMILY_V4 { 4 } else { 16 };
    let mut bits = prefix as u32;
    for i in 0..len {
        let mask = if bits >= 8 {
            0xFFu8
        } else if bits == 0 {
            0x00u8
        } else {
            (!0u8) << (8 - bits)
        };
        if (a[i] & mask) != (b[i] & mask) {
            return false;
        }
        bits = bits.saturating_sub(8);
    }
    true
}

/// Port range match: `min == 0` means "any port"; otherwise `port` must lie in
/// `min..=max` (`max == 0` meaning `min..=65535`).
fn port_match(port: u16, min: u16, max: u16) -> bool {
    if min == 0 {
        return true;
    }
    port >= min && port <= if max == 0 { u16::MAX } else { max }
}

/// Whether rule `r` matches packet `p` (with conntrack state `state`) arriving
/// on interface `slot`.
fn rule_matches(r: &FwRule, p: &Pkt, slot: usize, state: u8) -> bool {
    if r.family != 0 && r.family != p.family {
        return false;
    }
    if r.proto != FW_PROTO_ANY && r.proto != p.proto {
        return false;
    }
    // A non-zero state mask selects only the listed connection states.
    if r.state_mask != 0 && (r.state_mask & state) == 0 {
        return false;
    }
    if r.in_iface != FW_IFACE_ANY && r.in_iface as usize != slot {
        return false;
    }
    if r.icmp_type != FW_ICMP_ANY && (r.icmp_type != p.icmp_type || !p.has_l4) {
        return false;
    }
    if r.has_src != 0 && !addr_eq_prefix(&r.src, &p.src, r.src_prefix, p.family) {
        return false;
    }
    if r.has_dst != 0 && !addr_eq_prefix(&r.dst, &p.dst, r.dst_prefix, p.family) {
        return false;
    }
    if (r.src_port_min != 0 || r.dst_port_min != 0) && !p.has_l4 {
        return false;
    }
    if !port_match(p.sport, r.src_port_min, r.src_port_max) {
        return false;
    }
    if !port_match(p.dport, r.dst_port_min, r.dst_port_max) {
        return false;
    }
    true
}

/// True while any chain has a rule or a `DROP` policy — the fast path that keeps
/// an unconfigured firewall completely free.
fn configured() -> bool {
    let counts = ptr::as_ref(core::ptr::addr_of!(RULE_COUNT));
    let policy = ptr::as_ref(core::ptr::addr_of!(POLICY));
    if policy.iter().any(|&p| p == FW_ACTION_DROP) {
        return true;
    }
    counts.iter().any(|&c| c != 0)
}

/// The original packet embedded in an ICMP/ICMPv6 error, as a flow key, so a
/// conntrack lookup can mark the error `RELATED`.  `None` when the frame is not
/// an ICMP error or the embedded header is too short to read.
fn related_key(frame: &[u8], p: &Pkt) -> Option<Key> {
    let is_error = match (p.family, p.proto, p.icmp_type) {
        (FW_FAMILY_V4, FW_PROTO_ICMP, t) => t == 3 || t == 11 || t == 12,
        (FW_FAMILY_V6, FW_PROTO_ICMPV6, t) => t == 1 || t == 2 || t == 3 || t == 4,
        _ => false,
    };
    if !is_error {
        return None;
    }
    // The 8-byte ICMP header is followed by the offending packet's IP header and
    // at least its first 8 payload bytes.
    let emb = p.l4.checked_add(8)?;
    if p.family == FW_FAMILY_V4 {
        if emb + 20 > frame.len() {
            return None;
        }
        let ihl = (frame[emb] & 0x0F) as usize * 4;
        if ihl < 20 || emb + ihl > frame.len() {
            return None;
        }
        let proto = frame[emb + 9];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src[..4].copy_from_slice(&frame[emb + 12..emb + 16]);
        dst[..4].copy_from_slice(&frame[emb + 16..emb + 20]);
        let (sport, dport) = embedded_ports(frame, emb + ihl, proto);
        Some(Key {
            family: FW_FAMILY_V4,
            proto,
            src,
            dst,
            sport,
            dport,
        })
    } else {
        if emb + 40 > frame.len() {
            return None;
        }
        let proto = frame[emb + 6];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&frame[emb + 8..emb + 24]);
        dst.copy_from_slice(&frame[emb + 24..emb + 40]);
        let (sport, dport) = embedded_ports(frame, emb + 40, proto);
        Some(Key {
            family: FW_FAMILY_V6,
            proto,
            src,
            dst,
            sport,
            dport,
        })
    }
}

/// The ports of a TCP/UDP header at `off`, or `(0, 0)` for another protocol (or
/// when the frame is too short, which an 8-byte payload still covers).
fn embedded_ports(frame: &[u8], off: usize, proto: u8) -> (u16, u16) {
    match proto {
        FW_PROTO_TCP | FW_PROTO_UDP => {
            if off + 4 > frame.len() {
                return (0, 0);
            }
            (
                u16::from_be_bytes([frame[off], frame[off + 1]]),
                u16::from_be_bytes([frame[off + 2], frame[off + 3]]),
            )
        }
        _ => (0, 0),
    }
}

/// Evaluate filter chain `chain` against an already-classified packet.  Returns
/// the decided action; with no matching rule the chain's default policy applies.
fn eval_chain(chain: u8, p: &Pkt, slot: usize, state: u8) -> u8 {
    let ch = chain as usize;
    let count = ptr::as_ref(core::ptr::addr_of!(RULE_COUNT))[ch];
    let rules = ptr::as_mut(core::ptr::addr_of_mut!(RULES));
    for i in 0..count as usize {
        let r = &mut rules[ch][i];
        if rule_matches(r, p, slot, state) {
            r.packets = r.packets.wrapping_add(1);
            r.bytes = r.bytes.wrapping_add(p.l3_len as u64);
            return r.action;
        }
    }
    ptr::as_ref(core::ptr::addr_of!(POLICY))[ch]
}

/// The conntrack key that identifies one frame.
fn key_of_pkt(p: &Pkt) -> Key {
    Key {
        family: p.family,
        proto: p.proto,
        src: p.src,
        dst: p.dst,
        sport: p.sport,
        dport: p.dport,
    }
}

/// Handle an inbound frame for interface `slot`: PREROUTING (DNAT, or the
/// reverse of an outbound translation) then the INPUT filter.  Returns `true`
/// when the stack may have the frame.  Runs under `STACK_LOCK`.
pub(crate) fn hook_input(frame: &mut [u8], slot: usize) -> bool {
    if !configured() {
        return true;
    }
    let Some(mut p) = Pkt::parse(frame) else {
        return true;
    };
    let key = key_of_pkt(&p);
    let related = related_key(frame, &p);
    let t = conntrack::track(&key, p.tcp_flags, p.l3_len, related.as_ref());
    if t.rev {
        nat_reverse(frame, &mut p, t.idx);
    } else {
        nat_forward(frame, &mut p, slot, t.state, t.idx, FW_CHAIN_PREROUTING);
    }
    eval_chain(FW_CHAIN_INPUT, &p, slot, t.state) == FW_ACTION_ACCEPT
}

/// Handle an outbound frame produced by interface `slot`: the OUTPUT filter then
/// POSTROUTING (SNAT, or the reverse of an inbound translation).  Returns `true`
/// when the frame may leave.  Runs under `STACK_LOCK`.
pub(crate) fn hook_output(frame: &mut [u8], slot: usize) -> bool {
    if !configured() {
        return true;
    }
    let Some(mut p) = Pkt::parse(frame) else {
        return true;
    };
    let key = key_of_pkt(&p);
    let related = related_key(frame, &p);
    let t = conntrack::track(&key, p.tcp_flags, p.l3_len, related.as_ref());
    // The OUTPUT filter sees the packet before POSTROUTING rewrites it.
    if eval_chain(FW_CHAIN_OUTPUT, &p, slot, t.state) == FW_ACTION_DROP {
        return false;
    }
    if t.rev {
        nat_reverse(frame, &mut p, t.idx);
    } else {
        nat_forward(frame, &mut p, slot, t.state, t.idx, FW_CHAIN_POSTROUTING);
    }
    true
}

// ── NAT ─────────────────────────────────────────────────────────────────────

/// The interface `slot`'s own address in `family`, for MASQUERADE.
fn egress_addr(slot: usize, family: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    if family == FW_FAMILY_V4 {
        let h = config::ip_host_of(slot);
        out[0] = (h >> 24) as u8;
        out[1] = (h >> 16) as u8;
        out[2] = (h >> 8) as u8;
        out[3] = h as u8;
    } else {
        let g = config::ipv6_addr_of(slot);
        out = if g != [0u8; 16] {
            g
        } else {
            config::ipv6_link_local_of(slot)
        };
    }
    out
}

/// The loopback address in `family`, for REDIRECT.
fn loopback_addr(family: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    if family == FW_FAMILY_V4 {
        out[..4].copy_from_slice(&[127, 0, 0, 1]);
    } else {
        out = config::IPV6_LOOPBACK;
    }
    out
}

/// Byte offset of the source or destination address within a frame.
fn addr_off(p: &Pkt, src: bool) -> usize {
    match (p.family == FW_FAMILY_V4, src) {
        (true, true) => 26,
        (true, false) => 30,
        (_, true) => 22,
        (_, false) => 38,
    }
}

/// Byte offset of a TCP/UDP source or destination port.
fn port_off(p: &Pkt, src: bool) -> usize {
    if src {
        p.l4
    } else {
        p.l4 + 2
    }
}

/// Write address `addr` into a frame's source or destination field.
fn write_addr(frame: &mut [u8], p: &Pkt, src: bool, addr: &[u8; 16]) {
    let off = addr_off(p, src);
    let n = if p.family == FW_FAMILY_V4 { 4 } else { 16 };
    if off + n <= frame.len() {
        frame[off..off + n].copy_from_slice(&addr[..n]);
    }
}

/// Write `port` into a frame's TCP/UDP source or destination field.
fn write_port(frame: &mut [u8], p: &Pkt, src: bool, port: u16) {
    let off = port_off(p, src);
    if off + 2 <= frame.len() {
        frame[off..off + 2].copy_from_slice(&port.to_be_bytes());
    }
}

/// Forward translation of flow `idx`: evaluate NAT chain `chain` (PREROUTING for
/// inbound, POSTROUTING for outbound), record the translation and rewrite the
/// frame in place.  Running on later packets of the same flow re-derives the same
/// `xlate`, so it is idempotent.
fn nat_forward(frame: &mut [u8], p: &mut Pkt, slot: usize, state: u8, idx: u32, chain: u8) {
    if idx == conntrack::NO_ENTRY {
        return;
    }
    let key = conntrack::key_of(idx);
    let mut xlate = key;
    let ch = chain as usize;
    let count = ptr::as_ref(core::ptr::addr_of!(RULE_COUNT))[ch];
    let rules = ptr::as_mut(core::ptr::addr_of_mut!(RULES));
    for i in 0..count as usize {
        let r = &mut rules[ch][i];
        if !rule_matches(r, p, slot, state) {
            continue;
        }
        r.packets = r.packets.wrapping_add(1);
        r.bytes = r.bytes.wrapping_add(p.l3_len as u64);
        match r.action {
            FW_ACTION_SNAT => {
                xlate.src = r.nat_addr;
                if r.nat_port != 0 {
                    xlate.sport = r.nat_port;
                }
            }
            FW_ACTION_MASQUERADE => {
                xlate.src = egress_addr(slot, p.family);
                if r.nat_port != 0 {
                    xlate.sport = r.nat_port;
                }
            }
            FW_ACTION_DNAT => {
                xlate.dst = r.nat_addr;
                if r.nat_port != 0 {
                    xlate.dport = r.nat_port;
                }
            }
            FW_ACTION_REDIRECT => {
                xlate.dst = loopback_addr(p.family);
                if r.nat_port != 0 {
                    xlate.dport = r.nat_port;
                }
            }
            _ => {}
        }
        break;
    }
    conntrack::set_xlate(idx, xlate);
    if xlate == key {
        return;
    }
    let mut changed = false;
    if xlate.src != key.src {
        write_addr(frame, p, true, &xlate.src);
        p.src = xlate.src;
        changed = true;
    }
    if p.has_l4 && xlate.sport != key.sport {
        write_port(frame, p, true, xlate.sport);
        p.sport = xlate.sport;
        changed = true;
    }
    if xlate.dst != key.dst {
        write_addr(frame, p, false, &xlate.dst);
        p.dst = xlate.dst;
        changed = true;
    }
    if p.has_l4 && xlate.dport != key.dport {
        write_port(frame, p, false, xlate.dport);
        p.dport = xlate.dport;
        changed = true;
    }
    if changed {
        fix_checksums(frame, p);
    }
}

/// Undo the NAT of flow `idx` on a reply packet: the reply's source is the
/// translation's destination and its destination the translation's source, so
/// both are restored to the original tuple.
fn nat_reverse(frame: &mut [u8], p: &mut Pkt, idx: u32) {
    if idx == conntrack::NO_ENTRY {
        return;
    }
    let key = conntrack::key_of(idx);
    let xlate = conntrack::xlate_of(idx);
    // An endpoint may differ in address or in port alone, so compare both.
    let src_translated = xlate.src != key.src || xlate.sport != key.sport;
    let dst_translated = xlate.dst != key.dst || xlate.dport != key.dport;
    if !src_translated && !dst_translated {
        return;
    }
    let mut changed = false;
    if dst_translated {
        // The reply's source is the translation's destination.
        write_addr(frame, p, true, &key.dst);
        p.src = key.dst;
        changed = true;
        if p.has_l4 {
            write_port(frame, p, true, key.dport);
            p.sport = key.dport;
        }
    }
    if src_translated {
        // The reply's destination is the translation's source.
        write_addr(frame, p, false, &key.src);
        p.dst = key.src;
        changed = true;
        if p.has_l4 {
            write_port(frame, p, false, key.sport);
            p.dport = key.sport;
        }
    }
    if changed {
        fix_checksums(frame, p);
    }
}

// ── Checksums ───────────────────────────────────────────────────────────────

/// Recompute the L3/L4 checksums a rewrite invalidated.
fn fix_checksums(frame: &mut [u8], p: &Pkt) {
    if p.family == FW_FAMILY_V4 {
        let ihl = (frame[14] & 0x0F) as usize * 4;
        if 14 + ihl <= frame.len() {
            frame[24] = 0;
            frame[25] = 0;
            let be = (!fold(byte_sum(&frame[14..14 + ihl]))).to_be_bytes();
            frame[24] = be[0];
            frame[25] = be[1];
        }
        let l4len = (p.l3_len as usize).saturating_sub(ihl);
        if p.proto == FW_PROTO_TCP || p.proto == FW_PROTO_UDP {
            fix_l4(frame, p, l4len, p.l4 + 16);
        }
    } else if p.family == FW_FAMILY_V6 {
        let l4len = (p.l3_len as usize).saturating_sub(40);
        if p.proto == FW_PROTO_TCP || p.proto == FW_PROTO_UDP {
            fix_l4(frame, p, l4len, p.l4 + 16);
        } else if p.proto == FW_PROTO_ICMPV6 {
            fix_l4(frame, p, l4len, p.l4 + 2);
        }
    }
}

/// Zero the checksum field at `ck_off`, recompute the TCP/UDP/ICMPv6 checksum
/// (pseudo-header + segment) and store it back.
fn fix_l4(frame: &mut [u8], p: &Pkt, l4len: usize, ck_off: usize) {
    if ck_off + 2 > frame.len() {
        return;
    }
    frame[ck_off] = 0;
    frame[ck_off + 1] = 0;
    let be = (!fold(l4_sum(frame, p, l4len))).to_be_bytes();
    frame[ck_off] = be[0];
    frame[ck_off + 1] = be[1];
}

/// One's-complement sum of `bytes` (an odd trailing byte is padded with zero).
fn byte_sum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

/// Fold a 32-bit one's-complement accumulator down to 16 bits.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// One's-complement sum of the TCP/UDP/ICMPv6 pseudo-header plus the L4 segment
/// (whose checksum field the caller has zeroed).
fn l4_sum(frame: &[u8], p: &Pkt, l4len: usize) -> u32 {
    let mut sum = 0u32;
    if p.family == FW_FAMILY_V4 {
        sum += u16::from_be_bytes([p.src[0], p.src[1]]) as u32;
        sum += u16::from_be_bytes([p.src[2], p.src[3]]) as u32;
        sum += u16::from_be_bytes([p.dst[0], p.dst[1]]) as u32;
        sum += u16::from_be_bytes([p.dst[2], p.dst[3]]) as u32;
        sum += p.proto as u32;
        sum += (l4len & 0xFFFF) as u32;
    } else {
        let mut i = 0;
        while i < 16 {
            sum += u16::from_be_bytes([p.src[i], p.src[i + 1]]) as u32;
            sum += u16::from_be_bytes([p.dst[i], p.dst[i + 1]]) as u32;
            i += 2;
        }
        sum += (l4len >> 16) as u32;
        sum += (l4len & 0xFFFF) as u32;
        sum += p.proto as u32;
    }
    let end = (p.l4 + l4len).min(frame.len());
    if p.l4 < end {
        sum += byte_sum(&frame[p.l4..end]);
    }
    sum
}

/// Whether `chain` accepts `action`: the filter chains take ACCEPT/DROP, the NAT
/// chains their own translation actions.
fn chain_accepts_action(chain: u32, action: u32) -> bool {
    let is_filter = chain == FW_CHAIN_INPUT as u32
        || chain == FW_CHAIN_OUTPUT as u32
        || chain == FW_CHAIN_FORWARD as u32;
    if is_filter {
        action == FW_ACTION_ACCEPT as u32 || action == FW_ACTION_DROP as u32
    } else if chain == FW_CHAIN_PREROUTING as u32 {
        action == FW_ACTION_DNAT as u32 || action == FW_ACTION_REDIRECT as u32
    } else if chain == FW_CHAIN_POSTROUTING as u32 {
        action == FW_ACTION_SNAT as u32 || action == FW_ACTION_MASQUERADE as u32
    } else {
        false
    }
}

// ── Configuration entry points (`CACT_NETCTL_FW_*`) ─────────────────────────

/// Append `*rule` to its chain.  Returns 0 on success, -1 on a bad argument:
/// null pointer, unknown chain, an action the chain does not take, an unknown
/// connection-state bit, or a full table.  `rule` must be null or point to a
/// live, properly aligned [`FwRule`] that stays readable for the call.
pub fn rust_net_fw_rule_add(rule: *const FwRule) -> i32 {
    if rule.is_null() {
        return -1;
    }
    let _guard = StackGuard::new();
    let r = ptr::as_ref(rule);
    if !chain_accepts_action(r.chain as u32, r.action as u32) {
        return -1;
    }
    // A state mask may only name defined connection states; an unknown bit is an
    // error rather than a silently ignored constraint.
    if r.state_mask & !conntrack::STATE_MASK != 0 {
        return -1;
    }
    let ch = r.chain as usize;
    let counts = ptr::as_mut(core::ptr::addr_of_mut!(RULE_COUNT));
    let n = counts[ch] as usize;
    if n >= FW_RULES_MAX {
        return -1;
    }
    let mut copy = *r;
    copy.packets = 0;
    copy.bytes = 0;
    ptr::as_mut(core::ptr::addr_of_mut!(RULES))[ch][n] = copy;
    counts[ch] += 1;
    0
}

/// Delete rule `index` from chain `chain`, shifting later rules down.  Returns 0
/// on success, -1 on a bad chain or an out-of-range index.
pub fn rust_net_fw_rule_del(chain: u32, index: u32) -> i32 {
    if chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    let ch = chain as usize;
    let _guard = StackGuard::new();
    let counts = ptr::as_mut(core::ptr::addr_of_mut!(RULE_COUNT));
    let n = counts[ch] as usize;
    let i = index as usize;
    if i >= n {
        return -1;
    }
    let rules = ptr::as_mut(core::ptr::addr_of_mut!(RULES));
    for k in i..n - 1 {
        rules[ch][k] = rules[ch][k + 1];
    }
    rules[ch][n - 1] = FwRule::empty();
    counts[ch] = (n - 1) as u32;
    0
}

/// Number of rules in `chain`, or -1 for an unknown chain.
pub fn rust_net_fw_rule_count(chain: u32) -> i32 {
    if chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    let _guard = StackGuard::new();
    ptr::as_ref(core::ptr::addr_of!(RULE_COUNT))[chain as usize] as i32
}

/// Copy rule `index` of `chain` (with its counters) into `*out`.  Returns 0 on
/// success, -1 on a bad chain, an out-of-range index, or a null `out`.  `out`,
/// when non-null, must point to a writable, properly aligned [`FwRule`].
pub fn rust_net_fw_rule_get(chain: u32, index: u32, out: *mut FwRule) -> i32 {
    if out.is_null() || chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    let ch = chain as usize;
    let _guard = StackGuard::new();
    let n = ptr::as_ref(core::ptr::addr_of!(RULE_COUNT))[ch] as usize;
    let i = index as usize;
    if i >= n {
        return -1;
    }
    let rule = ptr::as_ref(core::ptr::addr_of!(RULES))[ch][i];
    ptr::write(out, rule);
    0
}

/// Remove every rule from `chain`.  Returns 0 on success, -1 for an unknown
/// chain.
pub fn rust_net_fw_flush(chain: u32) -> i32 {
    if chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    let ch = chain as usize;
    let _guard = StackGuard::new();
    let rules = ptr::as_mut(core::ptr::addr_of_mut!(RULES));
    rules[ch] = [FwRule::empty(); FW_RULES_MAX];
    ptr::as_mut(core::ptr::addr_of_mut!(RULE_COUNT))[ch] = 0;
    0
}

/// Set `chain`'s default policy to `policy` (`FW_ACTION_ACCEPT` / `_DROP`).
/// Returns 0 on success, -1 on an unknown chain or policy.
pub fn rust_net_fw_policy_set(chain: u32, policy: u32) -> i32 {
    if chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    if policy != FW_ACTION_ACCEPT as u32 && policy != FW_ACTION_DROP as u32 {
        return -1;
    }
    let _guard = StackGuard::new();
    ptr::as_mut(core::ptr::addr_of_mut!(POLICY))[chain as usize] = policy as u8;
    0
}

/// Read `chain`'s default policy, or -1 for an unknown chain.
pub fn rust_net_fw_policy_get(chain: u32) -> i32 {
    if chain as usize >= FW_CHAIN_COUNT {
        return -1;
    }
    let _guard = StackGuard::new();
    ptr::as_ref(core::ptr::addr_of!(POLICY))[chain as usize] as i32
}

/// Flush every chain and reset every policy to `ACCEPT`.
pub fn rust_net_fw_reset() -> i32 {
    let _guard = StackGuard::new();
    let rules = ptr::as_mut(core::ptr::addr_of_mut!(RULES));
    *rules = [[FwRule::empty(); FW_RULES_MAX]; FW_CHAIN_COUNT];
    *ptr::as_mut(core::ptr::addr_of_mut!(RULE_COUNT)) = [0; FW_CHAIN_COUNT];
    *ptr::as_mut(core::ptr::addr_of_mut!(POLICY)) = [FW_ACTION_ACCEPT; FW_CHAIN_COUNT];
    0
}


