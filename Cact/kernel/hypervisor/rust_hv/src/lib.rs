// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! CactOS hypervisor — the model half.
//!
//! The low-level primitives (the VMX/SVM instructions, the VMCS field
//! encodings, the VM-exit stub) live in C/asm in the parent directory; this is
//! where the VM/vCPU model and the VM-exit dispatch live.  The crate is an rlib
//! pulled into `kernel.bin` by `Cact/kernel/kernel_rust`, so its `#[no_mangle]`
//! entry points are called from C (currently `hypervisor_host_init()`).

#![no_std]

use core::ffi::c_char;

extern "C" {
    /// C `printk` (`kernel/klog.c`): printf-style.  Calls from here pass a
    /// single pre-formatted string, so there is no format argument.
    fn printk(s: *const c_char);
}

/// Boot-time probe, called from the C hypervisor core once host mode has been
/// brought up.  Phase H3.2 grows this into "set up a VMCS and launch a guest";
/// for now it only proves the C <-> Rust bridge is linked in.
#[no_mangle]
pub extern "C" fn hv_selftest() -> i32 {
    // SAFETY: a static NUL-terminated string literal, valid for the call.
    unsafe { printk(c"hv: rust vcpu model online\n".as_ptr()) };
    0
}
