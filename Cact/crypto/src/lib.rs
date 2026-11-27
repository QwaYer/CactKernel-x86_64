#![no_std]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// This crate talks to the C kernel only through `kernel_rust` (the graph's one
// `unsafe` crate): the CSPRNG's entropy/timing instructions, the leaf mutex and
// the raw-pointer plumbing all live there, so this crate holds no `unsafe` of
// its own and forbids it outright.
#![forbid(unsafe_code)]
// The `/dev/crypto` entry points are exported through `kernel_abi` and still
// have to be FFI-safe, so that check stays in addition to the `unsafe_code` ban.
#![deny(improper_ctypes, improper_ctypes_definitions)]

extern crate alloc;

mod ffi;

pub mod hash;
pub mod hkdf;
pub mod aead;
pub mod kx;
pub mod random;
pub mod rng;
pub mod sig;
pub mod x509;
pub mod provider;
pub mod signer;
// `/dev/crypto` entry points (formerly the standalone `cact_hmac_ffi` crate).
pub mod crypt;
