#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

// This crate talks to the C kernel only through `kernel_rust`, the graph's one
// `unsafe` crate: the `extern "C"` surface and the raw-pointer/`static mut`
// plumbing both live there, so this crate holds no `unsafe` of its own and
// forbids it outright.
#![forbid(unsafe_code)]
// The C-ABI hooks this crate defines (`extern "C" fn` VFS operations) still have
// to be FFI-safe, so that check stays in addition to the `unsafe_code` ban.
#![deny(improper_ctypes, improper_ctypes_definitions)]

//! In-kernel TCP/IP stack (smoltcp): Ethernet shim, sockets, DNS helpers, and
//! integration hooks for the C networking layer.

extern crate alloc;


// This crate's `Vec`/`BTreeMap` storage comes from the kernel heap, whose
// single `#[global_allocator]` lives in `cact_mm`, next to that heap.

// The kernel Rust graph's single `#[global_allocator]` lives in `cact_mm`;
// a crate graph may define exactly one.

pub mod arp;
pub mod config;
pub mod conntrack;
pub mod dns_resolve;
pub mod ffi;
pub mod ffi_kernel;
pub mod fw;
pub mod http;
pub mod iface;
pub mod ping;
pub mod raw;
pub mod runtime;
pub mod socket;
pub mod stack;
pub mod skb;
pub mod tcp;
pub mod tls;
pub mod types;
pub mod udp;

// The kernel Rust graph's single `#[panic_handler]` lives in `cact_mm`,
// which this crate depends on, so it is not defined here.
