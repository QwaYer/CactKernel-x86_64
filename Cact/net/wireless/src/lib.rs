#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

// This crate talks to the C kernel only through `kernel_rust`, the graph's one
// `unsafe` crate: the `extern "C"` surface, the raw-pointer plumbing and the
// devfs/user-copy helpers all live there, so this crate holds no `unsafe` of its
// own and forbids it outright.
#![forbid(unsafe_code)]
// The netdev and devfs callbacks this crate defines (`extern "C" fn`) still have
// to be FFI-safe, so that check stays in addition to the `unsafe_code` ban.
#![deny(improper_ctypes, improper_ctypes_definitions)]

//! In-kernel 802.11 station engine — the mac80211-equivalent for CactKernel.
//!
//! The Wi-Fi driver is a dumb radio: it brings up the chip, sets the channel,
//! and moves raw 802.11 MPDUs.  This engine owns the 802.11 protocol — scan,
//! open-system auth/association, the 802.3↔802.11 datapath and CCMP — and
//! registers `wlan0` as the NIC.  The WPA2 4-way handshake stays in userspace
//! (`wljoin`), which drives the engine through `/dev/wlan0` (`CACT_WLANCTL_*`).
//!
//! A radio registers through [`hw::Cact80211Hw`] (see `cact80211.h`); the
//! `#[no_mangle]` module entry points (`cact80211_register` / `cact80211_rx`,
//! exported through `ksym`) live in `kernel_abi` and thunk onto [`hw`].

mod aes;
mod ccmp;
mod control;
mod dev;
mod ffi;
mod frame;
pub mod hw;
