// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The 802.11 engine's exported C ABI: the `#[no_mangle]` entry points the
//! Wi-Fi driver reaches through `ksym` (`ksym.c`).  Each is a thin thunk onto a
//! safe `pub fn` in `cact80211::hw`; the raw-pointer contract is the C caller's,
//! as documented there.

use core::ffi::c_int;

use cact80211::hw::Cact80211Hw;

#[no_mangle]
pub extern "C" fn cact80211_register(hw: *mut Cact80211Hw) -> c_int {
    cact80211::hw::cact80211_register(hw)
}

#[no_mangle]
pub extern "C" fn cact80211_unregister(hw: *mut Cact80211Hw) {
    cact80211::hw::cact80211_unregister(hw);
}

/// `frame` must point to `len` readable bytes; both live only for the call.
#[no_mangle]
pub unsafe extern "C" fn cact80211_rx(hw: *mut Cact80211Hw, frame: *const u8, len: c_int) {
    cact80211::hw::cact80211_rx(hw, frame, len);
}
