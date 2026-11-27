// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Socket buffer (`Skb`) helpers: allocate/free and push/put data for the C networking path.


use kernel_rust::ptr;

use crate::ffi_kernel;
use crate::types::{Skb, SKB_MAX_SIZE};

pub fn skb_alloc() -> *mut Skb {
    let ptr = ffi_kernel::kmalloc(core::mem::size_of::<Skb>()) as *mut Skb;
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    // `kmalloc` returned `size_of::<Skb>()` writable bytes and the null check
    // above guarantees `ptr` is valid, so this zeroes exactly the new `Skb`.
    ptr::write_bytes(ptr.cast::<u8>(), 0, core::mem::size_of::<Skb>());
    ptr::as_mut(ptr).data_offset = (SKB_MAX_SIZE / 2) as u16;
    ptr
}

pub fn kfree_skb(skb: *mut Skb) {
    if skb.is_null() {
        return;
    }
    kernel_rust::mem::kfree(skb.cast::<u8>());
}

/// `skb` must be non-null and point to a live [`Skb`] allocated by [`skb_alloc`]
/// (or an equivalent kernel allocation cleared the same way).
pub fn skb_push(skb: *mut Skb, len: u16) -> *mut u8 {
    if skb.is_null() {
        return core::ptr::null_mut();
    }
    let s = ptr::as_mut(skb);
    if s.data_offset < len {
        return core::ptr::null_mut();
    }
    s.data_offset -= len;
    s.total_len = s.total_len.wrapping_add(len);
    s.data[s.data_offset as usize..].as_mut_ptr()
}

/// `skb` must be non-null and point to a live [`Skb`] allocated by [`skb_alloc`].
pub fn skb_put(skb: *mut Skb, len: u16) -> *mut u8 {
    if skb.is_null() {
        return core::ptr::null_mut();
    }
    let s = ptr::as_mut(skb);
    let offset = s.data_offset as usize;
    let cur_len = s.total_len as usize;
    let new_total = offset + cur_len + len as usize;
    if new_total > SKB_MAX_SIZE {
        return core::ptr::null_mut();
    }
    let dst = s.data[offset + cur_len..].as_mut_ptr();
    ptr::write_bytes(dst, 0, len as usize);
    s.total_len = s.total_len.wrapping_add(len);
    dst
}

/// `skb` must be non-null and point to a live, initialised [`Skb`] whose
/// `data_offset` is kept within `SKB_MAX_SIZE`.
pub fn skb_data(skb: *mut Skb) -> *mut u8 {
    if skb.is_null() {
        return core::ptr::null_mut();
    }
    let s = ptr::as_mut(skb);
    s.data[s.data_offset as usize..].as_mut_ptr()
}

/// `skb` must be non-null and point to a live, initialised [`Skb`].
pub fn skb_len(skb: *mut Skb) -> u16 {
    if skb.is_null() {
        return 0;
    }
    ptr::as_ref(skb).total_len
}
