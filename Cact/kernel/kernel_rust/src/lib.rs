// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! The kernel's safe Rust <-> C interface crate.
//!
//! This is the **one** Rust crate in the graph allowed to contain `unsafe`: it
//! declares every `extern "C"` symbol the Rust side calls into the C kernel and
//! wraps each in a safe Rust API, so the rest of the Rust graph talks to the C
//! kernel without any `unsafe` of its own.  Every other crate carries
//! `#![forbid(unsafe_code)]` and calls this crate instead.
//!
//! It is a **leaf**: it depends on no other crate in the graph.  The single
//! staticlib that meson links into `kernel.bin` is `Cact/kernel/kernel_link`,
//! which depends on this crate and on every other rlib.

#![no_std]

// Safety baseline: implicit unsafe ops inside `unsafe fn` bodies are rejected,
// and every `unsafe` block must carry a SAFETY comment (the latter enforced
// under clippy).  This crate is the graph's only `unsafe`, so it keeps the
// strongest settings the rest of the graph used to carry.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_unsafe)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![deny(static_mut_refs)]
#![deny(improper_ctypes, improper_ctypes_definitions)]
#![deny(clippy::transmute_ptr_to_ref)]
#![deny(clippy::transmute_ptr_to_ptr)]
#![deny(clippy::useless_transmute)]
#![deny(clippy::size_of_in_element_count)]
#![deny(clippy::uninit_assumed_init)]
#![deny(invalid_reference_casting)]
#![deny(clippy::multiple_unsafe_ops_per_block)]
