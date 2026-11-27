// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The network stack's exported C ABI: every `#[no_mangle]` entry point the C
//! side (`Cact/net/...`, syscalls, drivers) calls into `cact_net`.  Each is a
//! thin thunk onto a `pub fn` of the same name in `cact_net`.

#![allow(unsafe_code)] // for `#[no_mangle]` only; the bodies are plain calls

use core::ffi::{c_char, c_int, c_void};

use cact_net::arp::CactArpEntry;
use cact_net::conntrack::CactFwConn;
use cact_net::fw::FwRule;
use cact_net::http::HttpResp;
use cact_net::iface::CactIfaceInfo;
use cact_net::types::{Ksock, NetDriver, Skb, SockAddrIn, UdpSock, VfsNode};

// ---- arp -------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn rust_net_arp_count() -> i32 {
    cact_net::arp::rust_net_arp_count()
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_arp_get(idx: u32, out: *mut CactArpEntry) -> i32 {
    cact_net::arp::rust_net_arp_get(idx, out)
}

// ---- config ----------------------------------------------------------------
#[no_mangle]
pub extern "C" fn rust_net_set_ipv4_config(ip_h: u32, mask_h: u32, gw_h: u32, dns_h: u32) -> i32 {
    cact_net::config::rust_net_set_ipv4_config(ip_h, mask_h, gw_h, dns_h)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_ipv4_config(
    ip_h: *mut u32,
    mask_h: *mut u32,
    gw_h: *mut u32,
    dns_h: *mut u32,
) -> i32 {
    cact_net::config::rust_net_get_ipv4_config(ip_h, mask_h, gw_h, dns_h)
}
#[no_mangle]
pub extern "C" fn rust_net_get_dns_host() -> u32 {
    cact_net::config::rust_net_get_dns_host()
}
#[no_mangle]
pub extern "C" fn rust_net_get_ip_host() -> u32 {
    cact_net::config::rust_net_get_ip_host()
}

// ---- conntrack -------------------------------------------------------------
#[no_mangle]
pub extern "C" fn rust_net_fw_conn_count() -> i32 {
    cact_net::conntrack::rust_net_fw_conn_count()
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_fw_conn_get(idx: u32, out: *mut CactFwConn) -> i32 {
    cact_net::conntrack::rust_net_fw_conn_get(idx, out)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_conn_flush() -> i32 {
    cact_net::conntrack::rust_net_fw_conn_flush()
}

// ---- dns -------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn rust_net_dns_resolve_a(name: *const c_char, out_ip_host: *mut u32) -> c_int {
    cact_net::dns_resolve::rust_net_dns_resolve_a(name, out_ip_host)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_dns_resolve_aaaa(name: *const c_char, out_addr: *mut u8) -> c_int {
    cact_net::dns_resolve::rust_net_dns_resolve_aaaa(name, out_addr)
}

// ---- ffi (ipv4 parse + ping) -----------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn rust_net_parse_ipv4(input: *const c_char, out_host_ip: *mut u32) -> c_int {
    cact_net::ffi::rust_net_parse_ipv4(input, out_host_ip)
}
#[no_mangle]
pub extern "C" fn rust_net_ping_echo_host(dst_ip_host: u32, id: u16, seq: u16) -> c_int {
    cact_net::ffi::rust_net_ping_echo_host(dst_ip_host, id, seq)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_ping_wait(
    dst_ip_host: u32,
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_ip_out: *mut u32,
    bytes_out: *mut u32,
) -> c_int {
    cact_net::ffi::rust_net_ping_wait(dst_ip_host, id, seq, timeout_ms, src_ip_out, bytes_out)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_ping_echo6(addr: *const u8, id: u16, seq: u16) -> c_int {
    cact_net::ffi::rust_net_ping_echo6(addr, id, seq)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_ping_wait6(
    addr: *const u8,
    id: u16,
    seq: u16,
    timeout_ms: u32,
    src_addr_out: *mut u8,
    bytes_out: *mut u32,
) -> c_int {
    cact_net::ffi::rust_net_ping_wait6(addr, id, seq, timeout_ms, src_addr_out, bytes_out)
}

// ---- firewall --------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn rust_net_fw_rule_add(rule: *const FwRule) -> i32 {
    cact_net::fw::rust_net_fw_rule_add(rule)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_rule_del(chain: u32, index: u32) -> i32 {
    cact_net::fw::rust_net_fw_rule_del(chain, index)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_rule_count(chain: u32) -> i32 {
    cact_net::fw::rust_net_fw_rule_count(chain)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_fw_rule_get(chain: u32, index: u32, out: *mut FwRule) -> i32 {
    cact_net::fw::rust_net_fw_rule_get(chain, index, out)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_flush(chain: u32) -> i32 {
    cact_net::fw::rust_net_fw_flush(chain)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_policy_set(chain: u32, policy: u32) -> i32 {
    cact_net::fw::rust_net_fw_policy_set(chain, policy)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_policy_get(chain: u32) -> i32 {
    cact_net::fw::rust_net_fw_policy_get(chain)
}
#[no_mangle]
pub extern "C" fn rust_net_fw_reset() -> i32 {
    cact_net::fw::rust_net_fw_reset()
}

// ---- http ------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn cact_http_request(
    out: *mut HttpResp,
    url: *const c_char,
    method: c_int,
    headers: *const c_char,
    body: *const c_void,
    body_len: u32,
    flags: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> c_int {
    cact_net::http::cact_http_request(out, url, method, headers, body, body_len, flags, out_buf, out_len)
}
#[no_mangle]
pub unsafe extern "C" fn cact_http_get(
    out: *mut HttpResp,
    url: *const c_char,
    headers: *const c_char,
    flags: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> c_int {
    cact_net::http::cact_http_get(out, url, headers, flags, out_buf, out_len)
}
#[no_mangle]
pub unsafe extern "C" fn cact_http_post(
    out: *mut HttpResp,
    url: *const c_char,
    headers: *const c_char,
    body: *const c_void,
    body_len: u32,
    flags: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> c_int {
    cact_net::http::cact_http_post(out, url, headers, body, body_len, flags, out_buf, out_len)
}

// ---- iface -----------------------------------------------------------------
#[no_mangle]
pub extern "C" fn rust_net_iface_count() -> i32 {
    cact_net::iface::rust_net_iface_count()
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_iface_get(idx: u32, out: *mut CactIfaceInfo) -> i32 {
    cact_net::iface::rust_net_iface_get(idx, out)
}
#[no_mangle]
pub extern "C" fn rust_net_iface_set_cfg(
    index: u32,
    ip_h: u32,
    mask_h: u32,
    gw_h: u32,
    dns_h: u32,
) -> i32 {
    cact_net::iface::rust_net_iface_set_cfg(index, ip_h, mask_h, gw_h, dns_h)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_iface_set_cfg6(
    index: u32,
    addr: *const u8,
    prefix: u32,
    gw: *const u8,
    dns: *const u8,
) -> i32 {
    cact_net::iface::rust_net_iface_set_cfg6(index, addr, prefix, gw, dns)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_set_ipv6_config(
    addr: *const u8,
    prefix: u32,
    gw: *const u8,
    dns: *const u8,
) -> i32 {
    cact_net::iface::rust_net_set_ipv6_config(addr, prefix, gw, dns)
}

// ---- raw sockets -----------------------------------------------------------
#[no_mangle]
pub extern "C" fn raw_sock_alloc() -> i32 {
    cact_net::raw::raw_sock_alloc()
}
#[no_mangle]
pub unsafe extern "C" fn raw_sock_recv6(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_addr_out: *mut u8,
) -> i32 {
    cact_net::raw::raw_sock_recv6(idx, buf, max_len, src_addr_out)
}
#[no_mangle]
pub unsafe extern "C" fn raw_sock_send6(idx: i32, dst: *const u8, data: *const u8, len: u16) -> i32 {
    cact_net::raw::raw_sock_send6(idx, dst, data, len)
}

// ---- runtime (NIC registration, stack glue) --------------------------------
#[no_mangle]
pub unsafe extern "C" fn register_netdev(drv: *mut NetDriver) {
    cact_net::runtime::register_netdev(drv)
}
#[no_mangle]
pub extern "C" fn unregister_netdev(drv: *mut NetDriver) {
    cact_net::runtime::unregister_netdev(drv)
}
#[no_mangle]
pub extern "C" fn rust_net_nic_count() -> i32 {
    cact_net::runtime::rust_net_nic_count()
}
#[no_mangle]
pub extern "C" fn rust_net_nic_slot(index: u32) -> i32 {
    cact_net::runtime::rust_net_nic_slot(index)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_nic_mac(index: u32, out: *mut u8) -> i32 {
    cact_net::runtime::rust_net_nic_mac(index, out)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_nic_ifname(index: u32, out: *mut u8, cap: u32) -> i32 {
    cact_net::runtime::rust_net_nic_ifname(index, out, cap)
}
#[no_mangle]
pub extern "C" fn rust_net_link_is_up() -> i32 {
    cact_net::runtime::rust_net_link_is_up()
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_mac(out: *mut u8) -> i32 {
    cact_net::runtime::rust_net_get_mac(out)
}
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_ifname(out: *mut u8, cap: u32) -> i32 {
    cact_net::runtime::rust_net_get_ifname(out, cap)
}
#[no_mangle]
pub extern "C" fn net_init() {
    cact_net::runtime::net_init()
}
#[no_mangle]
pub unsafe extern "C" fn netif_rx(skb: *mut Skb) {
    cact_net::runtime::netif_rx(skb)
}
#[no_mangle]
pub unsafe extern "C" fn net_receive_packet(skb: *mut Skb) {
    cact_net::runtime::net_receive_packet(skb)
}
#[no_mangle]
pub extern "C" fn net_driver_irq_wake() {
    cact_net::runtime::net_driver_irq_wake()
}
#[no_mangle]
pub extern "C" fn net_poll() {
    cact_net::runtime::net_poll()
}

// ---- skb -------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn skb_alloc() -> *mut Skb {
    cact_net::skb::skb_alloc()
}
#[no_mangle]
pub extern "C" fn kfree_skb(skb: *mut Skb) {
    cact_net::skb::kfree_skb(skb)
}
#[no_mangle]
pub unsafe extern "C" fn skb_push(skb: *mut Skb, len: u16) -> *mut u8 {
    cact_net::skb::skb_push(skb, len)
}
#[no_mangle]
pub unsafe extern "C" fn skb_put(skb: *mut Skb, len: u16) -> *mut u8 {
    cact_net::skb::skb_put(skb, len)
}
#[no_mangle]
pub unsafe extern "C" fn skb_data(skb: *mut Skb) -> *mut u8 {
    cact_net::skb::skb_data(skb)
}
#[no_mangle]
pub unsafe extern "C" fn skb_len(skb: *mut Skb) -> u16 {
    cact_net::skb::skb_len(skb)
}

// ---- kernel sockets (the /dev/socket glue) ---------------------------------
#[no_mangle]
pub extern "C" fn ksock_init() {
    cact_net::socket::ksock_init()
}
#[no_mangle]
pub unsafe extern "C" fn ksock_from_node(node: *mut VfsNode) -> *mut Ksock {
    cact_net::socket::ksock_from_node(node)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_set_nonblock(node: *mut VfsNode, on: c_int) -> c_int {
    cact_net::socket::ksock_set_nonblock(node, on)
}
#[no_mangle]
pub extern "C" fn ksock_bind(node: *mut VfsNode, port: u16, ip_host: u32, reuseaddr: c_int) -> c_int {
    cact_net::socket::ksock_bind(node, port, ip_host, reuseaddr)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_bind6(
    node: *mut VfsNode,
    port: u16,
    addr: *const u8,
    reuseaddr: c_int,
) -> c_int {
    cact_net::socket::ksock_bind6(node, port, addr, reuseaddr)
}
#[no_mangle]
pub extern "C" fn ksock_getsockname(node: *mut VfsNode, out: *mut SockAddrIn) -> c_int {
    cact_net::socket::ksock_getsockname(node, out)
}
#[no_mangle]
pub extern "C" fn ksock_getpeername(node: *mut VfsNode, out: *mut SockAddrIn) -> c_int {
    cact_net::socket::ksock_getpeername(node, out)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_sockname6(
    node: *mut VfsNode,
    peer: c_int,
    out_addr: *mut u8,
    out_port: *mut u16,
) -> c_int {
    cact_net::socket::ksock_sockname6(node, peer, out_addr, out_port)
}
#[no_mangle]
pub extern "C" fn ksock_create(domain: c_int, type_: c_int, protocol: c_int) -> *mut VfsNode {
    cact_net::socket::ksock_create(domain, type_, protocol)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_tcp_accept(
    listen_node: *mut VfsNode,
    peer_out: *mut SockAddrIn,
) -> *mut VfsNode {
    cact_net::socket::ksock_tcp_accept(listen_node, peer_out)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_tcp_accept6(
    listen_node: *mut VfsNode,
    out_addr: *mut u8,
    out_port: *mut u16,
) -> *mut VfsNode {
    cact_net::socket::ksock_tcp_accept6(listen_node, out_addr, out_port)
}
#[no_mangle]
pub unsafe extern "C" fn ksock_shutdown(node: *mut VfsNode, how: c_int) -> c_int {
    cact_net::socket::ksock_shutdown(node, how)
}

// ---- tcp -------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn tcp_socket() -> i32 {
    cact_net::tcp::tcp_socket()
}
#[no_mangle]
pub extern "C" fn tcp_connect(sock: i32, dst_ip: u32, dst_port: u16) -> i32 {
    cact_net::tcp::tcp_connect(sock, dst_ip, dst_port)
}
#[no_mangle]
pub unsafe extern "C" fn tcp_connect6(sock: i32, addr: *const u8, dst_port: u16) -> i32 {
    cact_net::tcp::tcp_connect6(sock, addr, dst_port)
}
#[no_mangle]
pub extern "C" fn tcp_listen(sock: i32, local_port: u16) -> i32 {
    cact_net::tcp::tcp_listen(sock, local_port)
}
#[no_mangle]
pub unsafe extern "C" fn tcp_send(sock: i32, data: *mut u8, len: u16) -> i32 {
    cact_net::tcp::tcp_send(sock, data, len)
}
#[no_mangle]
pub extern "C" fn tcp_close(sock: i32) -> i32 {
    cact_net::tcp::tcp_close(sock)
}
#[no_mangle]
pub extern "C" fn tcp_shutdown_wr(sock: i32) -> i32 {
    cact_net::tcp::tcp_shutdown_wr(sock)
}
#[no_mangle]
pub unsafe extern "C" fn tcp_recv(sock: i32, buf: *mut u8, max_len: u16) -> i32 {
    cact_net::tcp::tcp_recv(sock, buf, max_len)
}

// ---- tls -------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn cact_tls_init() {
    cact_net::tls::cact_tls_init()
}
#[no_mangle]
pub unsafe extern "C" fn cact_tls_connect(sock: c_int, server_name: *const c_void) -> c_int {
    cact_net::tls::cact_tls_connect(sock, server_name)
}
#[no_mangle]
pub unsafe extern "C" fn cact_tls_connect_ex(
    sock: c_int,
    server_name: *const c_void,
    skip_verify: c_int,
) -> c_int {
    cact_net::tls::cact_tls_connect_ex(sock, server_name, skip_verify)
}
#[no_mangle]
pub unsafe extern "C" fn cact_tls_send(conn_idx: c_int, data: *const u8, len: u16) -> c_int {
    cact_net::tls::cact_tls_send(conn_idx, data, len)
}
#[no_mangle]
pub unsafe extern "C" fn cact_tls_recv(conn_idx: c_int, buf: *mut u8, max_len: u16) -> c_int {
    cact_net::tls::cact_tls_recv(conn_idx, buf, max_len)
}
#[no_mangle]
pub extern "C" fn cact_tls_close(conn: c_int) {
    cact_net::tls::cact_tls_close(conn)
}

// ---- udp -------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn udp_sock_alloc() -> i32 {
    cact_net::udp::udp_sock_alloc()
}
#[no_mangle]
pub extern "C" fn udp_sock_free(idx: i32) {
    cact_net::udp::udp_sock_free(idx)
}
#[no_mangle]
pub extern "C" fn udp_sock_connect(idx: i32, dst_ip: u32, dst_port: u16) -> i32 {
    cact_net::udp::udp_sock_connect(idx, dst_ip, dst_port)
}
#[no_mangle]
pub unsafe extern "C" fn udp_sock_connect6(idx: i32, addr: *const u8, dst_port: u16) -> i32 {
    cact_net::udp::udp_sock_connect6(idx, addr, dst_port)
}
#[no_mangle]
pub extern "C" fn udp_sock_find_by_port(port: u16) -> *mut UdpSock {
    cact_net::udp::udp_sock_find_by_port(port)
}
#[no_mangle]
pub unsafe extern "C" fn udp_sock_recv(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_ip_out: *mut u32,
    src_port_out: *mut u16,
) -> i32 {
    cact_net::udp::udp_sock_recv(idx, buf, max_len, src_ip_out, src_port_out)
}
#[no_mangle]
pub unsafe extern "C" fn udp_sock_send(
    idx: i32,
    dst_ip: u32,
    dst_port: u16,
    data: *const u8,
    len: u16,
) -> i32 {
    cact_net::udp::udp_sock_send(idx, dst_ip, dst_port, data, len)
}
#[no_mangle]
pub unsafe extern "C" fn udp_sock_send6(
    idx: i32,
    addr: *const u8,
    dst_port: u16,
    data: *const u8,
    len: u16,
) -> i32 {
    cact_net::udp::udp_sock_send6(idx, addr, dst_port, data, len)
}
#[no_mangle]
pub unsafe extern "C" fn udp_sock_recv6(
    idx: i32,
    buf: *mut u8,
    max_len: u16,
    src_addr_out: *mut u8,
    src_port_out: *mut u16,
) -> i32 {
    cact_net::udp::udp_sock_recv6(idx, buf, max_len, src_addr_out, src_port_out)
}

// ---- C-visible state (the storage moved here from cact_net) -----------------
/// The active NIC driver pointer — a `#[no_mangle]` **data** symbol that C and
/// driver modules (via ksym) read as `net_driver_t *active_nic`.  `cact_net`
/// reads/writes it through `kernel_rust::net`.
#[no_mangle]
pub static mut active_nic: *mut c_void = core::ptr::null_mut();

/// Accessor for `cact_net`'s TCP slot table.  C used to read the `tcp_sockets`
/// array symbol directly; the table stays owned by `cact_net`, so C gets a
/// pointer to a slot instead.
#[no_mangle]
pub extern "C" fn rust_net_tcp_socket(idx: u32) -> *mut c_void {
    cact_net::tcp::tcp_socket_ptr(idx)
}
